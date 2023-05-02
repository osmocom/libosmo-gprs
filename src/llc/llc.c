/* GPRS LLC as per 3GPP TS 44.064 */
/*
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/gprs/llc/llc.h>
#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/llc/llc_private.h>


struct gprs_llc_ctx *g_llc_ctx;

const struct value_string gprs_llc_llme_state_names[] = {
	{ OSMO_GPRS_LLC_LLMS_UNASSIGNED,	"UNASSIGNED" },
	{ OSMO_GPRS_LLC_LLMS_ASSIGNED,		"ASSIGNED" },
	{ 0, NULL }
};

const struct value_string gprs_llc_lle_state_names[] = {
	{ OSMO_GPRS_LLC_LLES_UNASSIGNED,	"UNASSIGNED" },
	{ OSMO_GPRS_LLC_LLES_ASSIGNED_ADM,	"ASSIGNED_ADM" },
	{ OSMO_GPRS_LLC_LLES_LOCAL_EST,		"LOCAL_EST" },
	{ OSMO_GPRS_LLC_LLES_REMOTE_EST,	"REMOTE_EST" },
	{ OSMO_GPRS_LLC_LLES_ABM,		"ABM" },
	{ OSMO_GPRS_LLC_LLES_LOCAL_REL,		"LOCAL_REL" },
	{ OSMO_GPRS_LLC_LLES_TIMER_REC,		"TIMER_REC" },
	{ 0, NULL }
};

/* Section 8.9.9 LLC layer parameter default values */
static const struct gprs_llc_params llc_default_params[NUM_SAPIS] = {
	[1] = {
		.t200_201	= 5,
		.n200		= 3,
		.n201_u		= 400,
	},
	[2] = {
		.t200_201	= 5,
		.n200		= 3,
		.n201_u		= 270,
	},
	[3] = {
		.iov_i_exp	= 27,
		.t200_201	= 5,
		.n200		= 3,
		.n201_u		= 500,
		.n201_i		= 1503,
		.mD		= 1520,
		.mU		= 1520,
		.kD		= 16,
		.kU		= 16,
	},
	[5] = {
		.iov_i_exp	= 27,
		.t200_201	= 10,
		.n200		= 3,
		.n201_u		= 500,
		.n201_i		= 1503,
		.mD		= 760,
		.mU		= 760,
		.kD		= 8,
		.kU		= 8,
	},
	[7] = {
		.t200_201	= 20,
		.n200		= 3,
		.n201_u		= 270,
	},
	[8] = {
		.t200_201	= 20,
		.n200		= 3,
		.n201_u		= 270,
	},
	[9] = {
		.iov_i_exp	= 27,
		.t200_201	= 20,
		.n200		= 3,
		.n201_u		= 500,
		.n201_i		= 1503,
		.mD		= 380,
		.mU		= 380,
		.kD		= 4,
		.kU		= 4,
	},
	[11] = {
		.iov_i_exp	= 27,
		.t200_201	= 40,
		.n200		= 3,
		.n201_u		= 500,
		.n201_i		= 1503,
		.mD		= 190,
		.mU		= 190,
		.kD		= 2,
		.kU		= 2,
	},
};

static void gprs_llc_ctx_free(void)
{
	struct gprs_llc_llme *llme;

	while ((llme = llist_first_entry_or_null(&g_llc_ctx->llme_list, struct gprs_llc_llme, list)))
		gprs_llc_llme_free(llme);

	talloc_free(g_llc_ctx);
}

int osmo_gprs_llc_init(enum osmo_gprs_llc_location location, const char *cipher_plugin_path)
{
	int rc;
	OSMO_ASSERT(location == OSMO_GPRS_LLC_LOCATION_MS || location == OSMO_GPRS_LLC_LOCATION_SGSN)

	if ((rc = gprs_cipher_load(cipher_plugin_path)) != 0) {
		LOGLLC(LOGL_NOTICE, "Failed loading GPRS cipher plugins from %s\n", cipher_plugin_path);
		return rc;
	}

	if (g_llc_ctx)
		gprs_llc_ctx_free();

	g_llc_ctx = talloc_zero(NULL, struct gprs_llc_ctx);
	g_llc_ctx->location = location;
	INIT_LLIST_HEAD(&g_llc_ctx->llme_list);
	return 0;
}

static void lle_init(struct gprs_llc_llme *llme, uint8_t sapi)
{
	struct gprs_llc_lle *lle = &llme->lle[sapi];

	lle->llme = llme;
	lle->sapi = sapi;
	lle->state = OSMO_GPRS_LLC_LLES_UNASSIGNED;

	/* Initialize according to parameters */
	memcpy(&lle->params, &llc_default_params[sapi], sizeof(lle->params));
}

struct gprs_llc_llme *gprs_llc_llme_alloc(uint32_t tlli)
{
	struct gprs_llc_llme *llme;
	uint32_t i;

	llme = talloc_zero(g_llc_ctx, struct gprs_llc_llme);
	if (!llme)
		return NULL;

	llme->tlli = tlli;
	llme->old_tlli = TLLI_UNASSIGNED;
	llme->state = OSMO_GPRS_LLC_LLMS_UNASSIGNED;
	llme->age_timestamp = GPRS_LLME_RESET_AGE;
	llme->cksn = GSM_KEY_SEQ_INVAL;

	for (i = 0; i < ARRAY_SIZE(llme->lle); i++)
		lle_init(llme, i);

	llist_add(&llme->list, &g_llc_ctx->llme_list);

	//llme->comp.proto = gprs_sndcp_comp_alloc(llme);
	//llme->comp.data = gprs_sndcp_comp_alloc(llme);

	return llme;
}

void gprs_llc_llme_free(struct gprs_llc_llme *llme)
{
	/* TODO: here we probably need to trigger LLGMM-RESET or LLGMM-SUSPEND towards upper layers! */
	//gprs_sndcp_sm_deactivate_ind_by_llme(llme);
	//gprs_sndcp_comp_free(llme->comp.proto);
	//gprs_sndcp_comp_free(llme->comp.data);
	llist_del(&llme->list);
	talloc_free(llme);
}

/* lookup LLC Entity based on TLLI */
struct gprs_llc_llme *gprs_llc_find_llme_by_tlli(uint32_t tlli)
{
	struct gprs_llc_llme *llme;

	llist_for_each_entry(llme, &g_llc_ctx->llme_list, list) {
		if (llme->tlli == tlli || llme->old_tlli == tlli)
			return llme;
	}
	return NULL;
}

/* lookup LLC Entity based on DLCI (TLLI+SAPI tuple) */
struct gprs_llc_lle *gprs_llc_find_lle_by_tlli_sapi(uint32_t tlli, uint8_t sapi)
{
	struct gprs_llc_llme *llme = gprs_llc_find_llme_by_tlli(tlli);
	if (!llme)
		return NULL;
	return &llme->lle[sapi];
}

static int gprs_llc_lle_tx_dm(const struct gprs_llc_lle *lle)
{
	int rc;
	struct msgb *msg;
	struct gprs_llc_pdu_decoded pdu_dec = {
		.sapi = lle->sapi,
		.fmt = OSMO_GPRS_LLC_FMT_U,
		.func = OSMO_GPRS_LLC_FUNC_DM,
		.flags = OSMO_GPRS_LLC_PDU_F_FOLL_FIN,
	};
	struct osmo_gprs_llc_prim *llc_prim;

	/* LLC payload is put directly below: */
	llc_prim = gprs_llc_prim_alloc_bssgp_dl_unitdata_req(lle->llme->tlli, NULL, 4096 - sizeof(llc_prim));
	msg = llc_prim->oph.msg;
	msg->l3h = msg->tail;

	rc = gprs_llc_pdu_encode(msg, &pdu_dec);
	if (rc < 0) {
		LOGLLC(LOGL_NOTICE, "Failed to encode U DM\n");
		msgb_free(msg);
		return rc;
	}
	llc_prim->bssgp.ll_pdu = msgb_l3(msg);
	llc_prim->bssgp.ll_pdu_len = msgb_l3len(msg);

	/* Send BSSGP-DL-UNITDATA.req */
	gprs_llc_prim_call_down_cb(llc_prim);
	return 0;
}

int gprs_llc_lle_tx_xid(const struct gprs_llc_lle *lle, uint8_t *xid_payload, unsigned int xid_payload_len, bool is_cmd)
{
	int rc;
	struct msgb *msg;
	struct osmo_gprs_llc_prim *llc_prim;
	struct gprs_llc_pdu_decoded pdu_dec = {
		.sapi = lle->sapi,
		.fmt = OSMO_GPRS_LLC_FMT_U,
		.func = OSMO_GPRS_LLC_FUNC_XID,
		.flags = OSMO_GPRS_LLC_PDU_F_FOLL_FIN,
		.data_len = xid_payload_len,
		.data = xid_payload,
	};
	gprs_llc_encode_is_cmd_as_cr(is_cmd, &pdu_dec.flags);

	/* LLC payload is put directly below: */
	llc_prim = gprs_llc_prim_alloc_bssgp_dl_unitdata_req(lle->llme->tlli, NULL, 4096 - sizeof(llc_prim));
	msg = llc_prim->oph.msg;
	msg->l3h = msg->tail;

	rc = gprs_llc_pdu_encode(msg, &pdu_dec);
	if (rc < 0) {
		LOGLLC(LOGL_NOTICE, "Failed to encode U DM\n");
		msgb_free(msg);
		return rc;
	}
	llc_prim->bssgp.ll_pdu = msgb_l3(msg);
	llc_prim->bssgp.ll_pdu_len = msgb_l3len(msg);

	/* Send BSSGP-DL-UNITDATA.req */
	gprs_llc_prim_call_down_cb(llc_prim);
	return 0;
}

/* Transmit a UI frame over the given SAPI:
   'encryptable' indicates whether particular message can be encrypted according
   to 3GPP TS 24.008 § 4.7.1.2
 */
int gprs_llc_lle_tx_ui(struct gprs_llc_lle *lle, uint8_t *l3_pdu, size_t l3_pdu_len, bool encryptable)
{
	struct osmo_gprs_llc_prim *llc_prim;
	struct msgb *msg;
	int rc;

	struct gprs_llc_pdu_decoded pdu_dec = {
		.sapi = lle->sapi,
		.fmt = OSMO_GPRS_LLC_FMT_UI,
		.func = 0,
		.flags = OSMO_GPRS_LLC_PDU_F_PROT_MODE,
		.seq_tx = lle->vu_send,
		.data_len = l3_pdu_len,
		.data = l3_pdu,
	};
	gprs_llc_encode_is_cmd_as_cr(false, &pdu_dec.flags);
	//TODO: what to do with:
	// oc = lle->oc_ui_send;

	if (pdu_dec.data_len > lle->params.n201_u) {
		LOGLLE(lle, LOGL_ERROR, "Cannot Tx %zu bytes (N201-U=%u)\n",
			pdu_dec.data_len, lle->params.n201_u);
		return -EFBIG;
	}

	if (lle->llme->algo != GPRS_ALGO_GEA0 && encryptable)
		pdu_dec.flags |= OSMO_GPRS_LLC_PDU_F_ENC_MODE;

	/* TODO: we are probably missing the ciphering enc part, see osmo-sgsn apply_gea() */

	/* LLC payload is put directly below: */
	if (g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN)
		llc_prim = gprs_llc_prim_alloc_bssgp_dl_unitdata_req(lle->llme->tlli, NULL, 4096 - sizeof(llc_prim));
	else
		llc_prim = gprs_llc_prim_alloc_grr_unitdata_req(lle->llme->tlli, NULL, 4096 - sizeof(llc_prim));
	msg = llc_prim->oph.msg;
	msg->l3h = msg->tail;

	rc = gprs_llc_pdu_encode(msg, &pdu_dec);
	if (rc < 0) {
		LOGLLE(lle, LOGL_NOTICE, "Failed to encode U DM\n");
		msgb_free(msg);
		return rc;
	}

	if (g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN) {
		llc_prim->bssgp.ll_pdu = msgb_l3(msg);
		llc_prim->bssgp.ll_pdu_len = msgb_l3len(msg);
	} else {
		llc_prim->grr.ll_pdu = msgb_l3(msg);
		llc_prim->grr.ll_pdu_len = msgb_l3len(msg);
		llc_prim->grr.unitdata_req.sapi = lle->sapi;
	}

	/* Increment V(U) */
	lle->vu_send = (lle->vu_send + 1) % 512;
	/* Increment Overflow Counter, if needed */
	if ((lle->vu_send + 1) / 512)
		lle->oc_ui_send += 512;

	/* Send BSSGP-DL-UNITDATA.req (SGSN) / GRR-UNITDATA.req (MS) */
	rc = gprs_llc_prim_call_down_cb(llc_prim);
	return rc;
}

/* lookup LLC Entity for RX based on DLCI (TLLI+SAPI tuple) */
struct gprs_llc_lle *gprs_llc_lle_for_rx_by_tlli_sapi(const uint32_t tlli,
					uint8_t sapi, enum gprs_llc_frame_func cmd)
{
	struct gprs_llc_lle *lle;

	/* We already know about this TLLI */
	lle = gprs_llc_find_lle_by_tlli_sapi(tlli, sapi);
	if (lle)
		return lle;

	/* Maybe it is a routing area update but we already know this sapi? */
	if (gprs_tlli_type(tlli) == TLLI_FOREIGN) {
		lle = gprs_llc_find_lle_by_tlli_sapi(tlli, sapi);
		if (lle) {
			LOGLLC(LOGL_NOTICE,
			       "LLC RX: Found a local entry for TLLI 0x%08x\n", tlli);
			return lle;
		}
	}

	/* 7.2.1.1 LLC belonging to unassigned TLLI+SAPI shall be discarded,
	 * except UID and XID frames with SAPI=1 */
	if (sapi == OSMO_GPRS_LLC_SAPI_GMM &&
		    (cmd == OSMO_GPRS_LLC_FUNC_XID || cmd == OSMO_GPRS_LLC_FUNC_UI)) {
		struct gprs_llc_llme *llme;
		/* FIXME: don't use the TLLI but the 0xFFFF unassigned? */
		llme = gprs_llc_llme_alloc(tlli);
		LOGLLME(llme, LOGL_NOTICE, "LLC RX: unknown TLLI 0x%08x, "
			"creating LLME on the fly\n", tlli);
		lle = &llme->lle[sapi];
		return lle;
	}

	LOGLLC(LOGL_NOTICE, "unknown TLLI(0x%08x)/SAPI(%d): Silently dropping\n",
	       tlli, sapi);
	return NULL;
}

/* Generate XID message */
static int gprs_llc_lle_generate_xid(struct gprs_llc_lle *lle, uint8_t *bytes, int bytes_len,
				     const uint8_t *l3par, unsigned int l3par_len)
{
	unsigned int xid_fields_len = 3 + (l3par ? 1 : 0);
	struct gprs_llc_xid_field *xid_fields =
		(struct gprs_llc_xid_field *)talloc_zero_size(lle->llme, sizeof(*xid_fields) * xid_fields_len);
	int rc;

	OSMO_ASSERT(xid_fields);

	xid_fields[0].type = OSMO_GPRS_LLC_XID_T_VERSION;
	xid_fields[0].val = 0;

	xid_fields[1].type = OSMO_GPRS_LLC_XID_T_N201_U;
	xid_fields[1].val = lle->params.n201_u;

	xid_fields[2].type = OSMO_GPRS_LLC_XID_T_N201_I;
	xid_fields[2].val = lle->params.n201_i;

	if (l3par_len > 0) {
		xid_fields[3].type = OSMO_GPRS_LLC_XID_T_L3_PAR;
		xid_fields[3].var.val_len = l3par_len;
		if (l3par_len > 0) {
			xid_fields[3].var.val = talloc_size(xid_fields, l3par_len);
			memcpy(xid_fields[3].var.val, l3par, l3par_len);
		}
	} else {
		xid_fields_len--;
	}

	/* Store generated XID for later reference */
	talloc_free(lle->xid);
	lle->xid = xid_fields;
	lle->xid_len = xid_fields_len;

	rc = gprs_llc_xid_encode(bytes, bytes_len, lle->xid, lle->xid_len);
	return rc;
}

/* LL-ESTABLISH negotiation (See also: TS 101 351, Section 7.2.2.2) */
int gprs_llc_lle_tx_sabm(struct gprs_llc_lle *lle, uint8_t *l3par, unsigned int l3par_len)
{
	LOGLLE(lle, LOGL_ERROR, "Tx SABM: ABM mode not supported yet!\n");
	return -ENOTSUP;
}

/* Set of LL-XID negotiation (See also: TS 101 351, Section 7.2.2.4) */
int gprs_llc_lle_tx_xid_req(struct gprs_llc_lle *lle, uint8_t *l3par, unsigned int l3par_len)
{
	uint8_t xid_bytes[1024];
	int xid_bytes_len;
	int rc;

	/* Generate XID */
	xid_bytes_len =
	    gprs_llc_lle_generate_xid(lle, xid_bytes, sizeof(xid_bytes), l3par, l3par_len);

	/* Only perform XID sending if the XID message contains something */
	if (xid_bytes_len > 0) {
		/* Transmit XID bytes */
		LOGLLE(lle, LOGL_NOTICE, "Sending XID type %s (%d bytes) request to MS...\n",
		       l3par ? "L3-Params" : "NULL", xid_bytes_len);
		rc = gprs_llc_lle_tx_xid(lle, xid_bytes, xid_bytes_len, true);
	} else {
		LOGLLE(lle, LOGL_ERROR,
		       "XID-Message generation failed, XID not sent!\n");
		rc = -EINVAL;
	}

	return rc;
}

/* Generate XID response from XID-Ind received from peer */
int gprs_llc_lle_tx_xid_resp(struct gprs_llc_lle *lle, uint8_t *l3par, unsigned int l3par_len)
{
	uint8_t bytes_response[1024];
	unsigned int rc, i;

	/* Replace the SNDCP L3 xid_field with response from our upper layer: */
	for (i = 0; i < lle->rx_xid_len; i++) {
		struct gprs_llc_xid_field *xid_field_l3;
		if (lle->rx_xid[i].type != OSMO_GPRS_LLC_XID_T_L3_PAR)
			continue;
		xid_field_l3 = &lle->rx_xid[i];
		xid_field_l3->var.val = l3par;
		xid_field_l3->var.val_len = l3par_len;
		break;
	}

	rc = gprs_llc_xid_encode(bytes_response, sizeof(bytes_response),
				      lle->rx_xid, lle->rx_xid_len);
	TALLOC_FREE(lle->rx_xid);
	lle->rx_xid_len = 0;
	if (rc < 0)
		return rc;

	rc = gprs_llc_lle_tx_xid(lle, bytes_response, rc, false);
	return rc;
}

/* Process an incoming XID indication and generate an appropriate response */
static int gprs_llc_lle_process_xid_ind(struct gprs_llc_lle *lle,
					uint8_t *bytes_request,
					int bytes_request_len)
{
	/* Note: This function computes the response that is sent back to the
	 * MS when a mobile originated XID is received. */
	struct gprs_llc_xid_field xid_fields[16] = { 0 };
	unsigned int xid_fields_len;
	int rc, i;
	struct gprs_llc_xid_field *xid_field_request_l3 = NULL;

	/* Parse and analyze XID-Request */
	rc = gprs_llc_xid_decode(xid_fields, ARRAY_SIZE(xid_fields),
				 bytes_request, bytes_request_len);
	if (rc < 0) {
		LOGLLE(lle, LOGL_ERROR, "Failed decoding XID Fields\n");
		return rc;
	}
	xid_fields_len = rc;

	/* FIXME: Check the incoming XID parameters for
	* for validity. Currently we just blindly
	* accept all XID fields by just echoing them.
	* There is a remaining risk of malfunction
	* when a MS submits values which defer from
	* the default! */

	/* Store last received XID-Ind from peer: */
	lle->rx_xid = gprs_llc_xid_deepcopy(lle->llme, xid_fields, xid_fields_len);
	OSMO_ASSERT(lle->rx_xid);
	lle->rx_xid_len = xid_fields_len;

	/* Forward SNDCP-XID fields to Layer 3 (SNDCP) */
	for (i = 0; i < xid_fields_len; i++) {
		if (xid_fields[i].type == OSMO_GPRS_LLC_XID_T_L3_PAR) {
			xid_field_request_l3 = &xid_fields[i];
			gprs_llc_lle_submit_prim_ll_xid_ind(lle, xid_field_request_l3);
			/* delay answer until we get LL-XID.resp from SNDCP: */
			return rc;
		}
	}

	rc = gprs_llc_lle_tx_xid_resp(lle, NULL, 0);
	return rc;
}

/* Process an incoming XID confirmation. 8.5.3.0 */
static int gprs_llc_lle_process_xid_conf(struct gprs_llc_lle *lle, uint8_t *bytes, int bytes_len)
{
	/* Note: This function handles the response of a network originated
	 * XID-Request. There XID messages reflected by the MS are analyzed
	 * and processed here. The caller is called by rx_llc_xid(). */

	struct gprs_llc_xid_field xid_fields[16] = { 0 };
	unsigned int xid_fields_len;
	struct gprs_llc_xid_field *xid_field;
	struct gprs_llc_xid_field *xid_field_request_l3 = NULL;
	unsigned int i;
	int rc;

	/* Pick layer3 XID from the XID request we have sent last */
	if (lle->xid) {
		for (i = 0; i < lle->xid_len; i++) {
			if (lle->xid[i].type == OSMO_GPRS_LLC_XID_T_L3_PAR)
				xid_field_request_l3 = &lle->xid[i];
		}
	}

	/* Parse and analyze XID-Response */
	rc = gprs_llc_xid_decode(xid_fields, ARRAY_SIZE(xid_fields),
				      bytes, bytes_len);
	if (rc < 0) {
		LOGLLE(lle, LOGL_ERROR, "Failed decoding XID Fields\n");
		return rc;
	}
	xid_fields_len = rc;

	for (i = 0; i < xid_fields_len; i++) {
		xid_field = &xid_fields[i];

		/* Forward SNDCP-XID fields to Layer 3 (SNDCP) */
		if (xid_field->type == OSMO_GPRS_LLC_XID_T_L3_PAR && xid_field_request_l3) {
			gprs_llc_lle_submit_prim_ll_xid_cnf(lle, xid_field, xid_field_request_l3);
			/* TODO: sndcp_sn_xid_conf is basically primitive LL-XID.cnf. See 8.5.3.0 */
		} else { /* Process LLC-XID fields: */

			/* FIXME: Do something more useful with the
			 * echoed XID-Information. Currently we
			 * just ignore the response completely and
			 * by doing so we blindly accept any changes
			 * the MS might have done to the our XID
			 * inquiry. There is a remainig risk of
			 * malfunction! */
			LOGLLE(lle, LOGL_NOTICE,
			       "Ignoring XID-Field: XID: type %s\n",
			       gprs_llc_xid_type_name(xid_field->type));
		}
	}

	/* Flush pending XID fields */
	TALLOC_FREE(lle->xid);
	lle->xid_len = 0;

	return 0;
}

/* Dispatch XID indications and responses coming from the MS */
static int gprs_llc_lle_rx_llc_xid(struct gprs_llc_lle *lle, struct gprs_llc_pdu_decoded *pdu_dec)
{
	int rc = 0;

	/* FIXME: 8.5.3.3: check if XID is invalid */
	if (gprs_llc_received_cr_is_cmd(pdu_dec->flags & OSMO_GPRS_LLC_PDU_F_CMD_RSP)) {
		LOGLLE(lle, LOGL_NOTICE, "Received XID indication from MS.\n");

		rc = gprs_llc_lle_process_xid_ind(lle, pdu_dec->data, pdu_dec->data_len);
	} else {
		LOGLLE(lle, LOGL_NOTICE, "Received XID confirmation from MS\n");
		rc = gprs_llc_lle_process_xid_conf(lle, pdu_dec->data, pdu_dec->data_len);
		/* FIXME: if we had sent a XID reset, send
		 * LLGMM-RESET.conf to GMM */
	}
	return rc;
}

/* Receive and process decoded LLC PDU from lower layer (GRR/BSSGP): */
static int gprs_llc_lle_hdr_rx(struct gprs_llc_lle *lle, struct gprs_llc_pdu_decoded *pdu_dec)
{
	const char *llc_pdu_name = gprs_llc_pdu_hdr_dump(pdu_dec);

	LOGLLE(lle, LOGL_DEBUG, "Rx %s\n", llc_pdu_name);

	switch (pdu_dec->func) {
	case OSMO_GPRS_LLC_FUNC_SABM:
	case OSMO_GPRS_LLC_FUNC_DISC:
		/* send DM to properly signal we don't do ABM */
		gprs_llc_lle_tx_dm(lle);
		break;
	case OSMO_GPRS_LLC_FUNC_XID: /* Section 6.4.1.6 */
		gprs_llc_lle_rx_llc_xid(lle, pdu_dec);
		break;
	case OSMO_GPRS_LLC_FUNC_UI:
		if (gprs_llc_is_retransmit(pdu_dec->seq_tx, lle->vu_recv)) {
			LOGLLE(lle, LOGL_NOTICE,
			       "TLLI=%08x dropping UI, N(U=%d) not in window V(URV(UR:%d).\n",
			       lle->llme ? lle->llme->tlli : -1,
			       pdu_dec->seq_tx, lle->vu_recv);

			/* HACK: non-standard recovery handling.  If remote LLE
			 * is re-transmitting the same sequence number for
			 * three times, don't discard the frame but pass it on
			 * and 'learn' the new sequence number */
			if (pdu_dec->seq_tx != lle->vu_recv_last) {
				lle->vu_recv_last = pdu_dec->seq_tx;
				lle->vu_recv_duplicates = 0;
			} else {
				lle->vu_recv_duplicates++;
				if (lle->vu_recv_duplicates < 3)
					return -EIO;
				LOGLLE(lle, LOGL_NOTICE, "TLLI=%08x recovering "
				       "N(U=%d) after receiving %u duplicates\n",
				       lle->llme ? lle->llme->tlli : -1,
				       pdu_dec->seq_tx, lle->vu_recv_duplicates);
			}
		}
		/* Increment the sequence number that we expect in the next frame */
		lle->vu_recv = (pdu_dec->seq_tx + 1) % 512;
		/* Increment Overflow Counter */
		if ((pdu_dec->seq_tx + 1) / 512)
			lle->oc_ui_recv += 512;
		break;
	case OSMO_GPRS_LLC_FUNC_NULL:
		LOGLLE(lle, LOGL_DEBUG, "TLLI=%08x sends us LLC NULL\n", lle->llme ? lle->llme->tlli : -1);
		break;
	default:
		LOGLLE(lle, LOGL_NOTICE, "Unhandled command: %s\n",
		       gprs_llc_frame_func_name(pdu_dec->func));
		break;
	}

	return 0;
}

/* encrypt information field + FCS, if needed! */
static int apply_gea(const struct gprs_llc_lle *lle, uint16_t crypt_len, uint16_t nu,
		     uint32_t oc, uint8_t sapi, uint8_t *fcs, uint8_t *data)
{
	uint8_t cipher_out[GSM0464_CIPH_MAX_BLOCK];

	if (lle->llme->algo == GPRS_ALGO_GEA0)
		return -EINVAL;

	/* Compute the 'Input' Paraemeter */
	uint32_t fcs_calc, iv = gprs_cipher_gen_input_ui(lle->llme->iov_ui, sapi,
							 nu, oc);
	/* Compute gamma that we need to XOR with the data */
	int r = gprs_cipher_run(cipher_out, crypt_len, lle->llme->algo,
				lle->llme->kc, iv,
				fcs ? GPRS_CIPH_SGSN2MS : GPRS_CIPH_MS2SGSN);
	if (r < 0) {
		LOGLLC(LOGL_ERROR, "Error producing %s gamma for UI "
		     "frame: %d\n", get_value_string(gprs_cipher_names,
						     lle->llme->algo), r);
		return -ENOMSG;
	}

	if (fcs) {
		/* Mark frame as encrypted and update FCS */
		data[2] |= 0x02;
		fcs_calc = gprs_llc_fcs(data, fcs - data);
		fcs[0] = fcs_calc & 0xff;
		fcs[1] = (fcs_calc >> 8) & 0xff;
		fcs[2] = (fcs_calc >> 16) & 0xff;
		data += 3;
	}

	/* XOR the cipher output with the data */
	for (r = 0; r < crypt_len; r++)
		*(data + r) ^= cipher_out[r];

	return 0;
}

/* Shared upper part handling of BSSGP-UNITDATA.ind and GRR-UNITDATA.ind */
int gprs_llc_lle_rx_unitdata_ind(struct gprs_llc_lle *lle, uint8_t *ll_pdu, size_t ll_pdu_len, struct gprs_llc_pdu_decoded *pdu_dec)
{
	struct osmo_gprs_llc_prim *llc_prim_tx;
	bool drop_cipherable = false;
	int rc;

	/* reset age computation */
	lle->llme->age_timestamp = GPRS_LLME_RESET_AGE;

	/* decrypt information field + FCS, if needed! */
	if (pdu_dec->flags & OSMO_GPRS_LLC_PDU_F_ENC_MODE) {
		if (lle->llme->algo != GPRS_ALGO_GEA0) {
			rc = apply_gea(lle, pdu_dec->data_len + 3, pdu_dec->seq_tx,
				       lle->oc_ui_recv, lle->sapi, NULL,
				       (uint8_t *)pdu_dec->data); /*TODO: either copy buffer or remove "const" from pdu_dec field "data" */
			if (rc < 0)
				return rc;
			pdu_dec->fcs = *(pdu_dec->data + pdu_dec->data_len);
			pdu_dec->fcs |= *(pdu_dec->data + pdu_dec->data_len + 1) << 8;
			pdu_dec->fcs |= *(pdu_dec->data + pdu_dec->data_len + 2) << 16;
		} else {
			LOGLLME(lle->llme, LOGL_NOTICE, "encrypted frame for LLC that "
				"has no KC/Algo! Dropping.\n");
			return 0;
		}
	} else {
		if (lle->llme->algo != GPRS_ALGO_GEA0 &&
		    lle->llme->cksn != GSM_KEY_SEQ_INVAL)
			drop_cipherable = true;
	}

	/* We have to do the FCS check _after_ decryption */
	uint16_t crc_length = ll_pdu_len - CRC24_LENGTH;
	if (~pdu_dec->flags & OSMO_GPRS_LLC_PDU_F_PROT_MODE)
		crc_length = OSMO_MIN(crc_length, UI_HDR_LEN + N202);
	if (pdu_dec->fcs != gprs_llc_fcs(ll_pdu, crc_length)) {
		LOGLLE(lle, LOGL_NOTICE, "Dropping frame with invalid FCS 0x%06x vs exp 0x%06x\n",
		       pdu_dec->fcs, gprs_llc_fcs(ll_pdu, crc_length));
		return -EIO;
	}

	/* Receive and Process the actual LLC frame */
	rc = gprs_llc_lle_hdr_rx(lle, pdu_dec);
	if (rc < 0)
		return rc;

	/* pdu_dec->data is only set when we need to send LL_[UNIT]DATA_IND up */
	if (pdu_dec->func == OSMO_GPRS_LLC_FUNC_UI && pdu_dec->data && pdu_dec->data_len) {
		switch (pdu_dec->sapi) {
		case OSMO_GPRS_LLC_SAPI_GMM:
			/* send LL-UNITDATA-IND to GMM */
			llc_prim_tx = gprs_llc_prim_alloc_ll_unitdata_ind(lle->llme->tlli,
									  pdu_dec->sapi,
									  pdu_dec->data,
									  pdu_dec->data_len);
			llc_prim_tx->ll.unitdata_ind.apply_gea = !drop_cipherable; /* TODO: is this correct? */
			llc_prim_tx->ll.unitdata_ind.apply_gia = false; /* TODO: how to set this? */
			gprs_llc_prim_call_up_cb(llc_prim_tx);
			break;
		case OSMO_GPRS_LLC_SAPI_SNDCP3:
		case OSMO_GPRS_LLC_SAPI_SNDCP5:
		case OSMO_GPRS_LLC_SAPI_SNDCP9:
		case OSMO_GPRS_LLC_SAPI_SNDCP11:
			/* send LL_DATA_IND/LL_UNITDATA_IND to SNDCP */
			llc_prim_tx = gprs_llc_prim_alloc_ll_unitdata_ind(lle->llme->tlli,
									  pdu_dec->sapi,
									  pdu_dec->data,
									  pdu_dec->data_len);
			llc_prim_tx->ll.unitdata_ind.apply_gea = !drop_cipherable; /* TODO: is this correct? */
			llc_prim_tx->ll.unitdata_ind.apply_gia = false; /* TODO: how to set this? */
			gprs_llc_prim_call_up_cb(llc_prim_tx);
			break;
		case OSMO_GPRS_LLC_SAPI_SMS:
			/* FIXME */
		case OSMO_GPRS_LLC_SAPI_TOM2:
		case OSMO_GPRS_LLC_SAPI_TOM8:
			/* FIXME: send LL_DATA_IND/LL_UNITDATA_IND to TOM */
		default:
			LOGLLC(LOGL_NOTICE, "Unsupported SAPI %u\n", pdu_dec->sapi);
			rc = -EINVAL;
			break;
		}
	}
	return rc;
}
