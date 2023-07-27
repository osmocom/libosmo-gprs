/* GPRS LLC LL SAP as per 3GPP TS 44.064 7.2.2 */
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

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/gprs/llc/llc.h>
#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/llc/llc_private.h>

const struct value_string osmo_gprs_llc_ll_prim_type_names[] = {
	{ OSMO_GPRS_LLC_LL_RESET,		"RESET" },
	{ OSMO_GPRS_LLC_LL_ESTABLISH,		"ESTABLISH" },
	{ OSMO_GPRS_LLC_LL_RELEASE,		"RELEASE" },
	{ OSMO_GPRS_LLC_LL_XID,			"XID" },
	{ OSMO_GPRS_LLC_LL_DATA,		"DATA" },
	{ OSMO_GPRS_LLC_LL_UNITDATA,		"UNITDATA" },
	{ OSMO_GPRS_LLC_LL_STATUS,		"STATUS" },
	{ OSMO_GPRS_LLC_LL_ASSIGN,		"ASSIGN" },
	{ 0, NULL }
};

/********************************
 * Primitive allocation:
 ********************************/

static inline struct osmo_gprs_llc_prim *llc_prim_ll_alloc(enum osmo_gprs_llc_ll_prim_type type,
							   enum osmo_prim_operation operation,
							   unsigned int l3_len)
{
	return gprs_llc_prim_alloc(OSMO_GPRS_LLC_SAP_LL, type, operation, l3_len);
}

/* 7.2.2.2 LL-ESTABLISH.req (MS/SGSN) */
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_ll_establish_req(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi, uint8_t *l3_par, unsigned int l3_par_len)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_ll_alloc(OSMO_GPRS_LLC_LL_ESTABLISH, PRIM_OP_REQUEST, l3_par_len);
	llc_prim->ll.tlli = tlli;
	llc_prim->ll.sapi = ll_sapi;
	llc_prim->ll.l3_pdu = l3_par;
	llc_prim->ll.l3_pdu_len = l3_par_len;
	return llc_prim;
}

/* 7.2.2.2 LL-ESTABLISH.cnf (MS/SGSN) */
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_ll_establish_cnf(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi, uint8_t *l3_par, unsigned int l3_par_len)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_ll_alloc(OSMO_GPRS_LLC_LL_ESTABLISH, PRIM_OP_CONFIRM, l3_par_len);
	llc_prim->ll.tlli = tlli;
	llc_prim->ll.sapi = ll_sapi;
	llc_prim->ll.l3_pdu = l3_par;
	llc_prim->ll.l3_pdu_len = l3_par_len;
	return llc_prim;
}

/* 7.2.2.4 LL-XID.req (MS/SGSN) */
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_ll_xid_req(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi, uint8_t *l3_par, unsigned int l3_par_len)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_ll_alloc(OSMO_GPRS_LLC_LL_XID, PRIM_OP_REQUEST, l3_par_len);
	llc_prim->ll.tlli = tlli;
	llc_prim->ll.sapi = ll_sapi;
	llc_prim->ll.l3_pdu = l3_par;
	llc_prim->ll.l3_pdu_len = l3_par_len;
	return llc_prim;
}

/* 7.2.2.4 LL-XID.ind (MS/SGSN) */
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_ll_xid_ind(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi, uint8_t *l3_par, unsigned int l3_par_len)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_ll_alloc(OSMO_GPRS_LLC_LL_XID, PRIM_OP_INDICATION, l3_par_len);
	llc_prim->ll.tlli = tlli;
	llc_prim->ll.sapi = ll_sapi;
	llc_prim->ll.l3_pdu = l3_par;
	llc_prim->ll.l3_pdu_len = l3_par_len;
	return llc_prim;
}

/* 7.2.2.4 LL-XID.resp (MS/SGSN) */
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_ll_xid_resp(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi, uint8_t *l3_par, unsigned int l3_par_len)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_ll_alloc(OSMO_GPRS_LLC_LL_XID, PRIM_OP_RESPONSE, l3_par_len);
	llc_prim->ll.tlli = tlli;
	llc_prim->ll.sapi = ll_sapi;
	llc_prim->ll.l3_pdu = l3_par;
	llc_prim->ll.l3_pdu_len = l3_par_len;
	return llc_prim;
}

/* 7.2.2.4 LL-XID.cnf (MS/SGSN) */
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_ll_xid_cnf(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi, uint8_t *l3_par, unsigned int l3_par_len)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_ll_alloc(OSMO_GPRS_LLC_LL_XID, PRIM_OP_CONFIRM, l3_par_len);
	llc_prim->ll.tlli = tlli;
	llc_prim->ll.sapi = ll_sapi;
	llc_prim->ll.l3_pdu = l3_par;
	llc_prim->ll.l3_pdu_len = l3_par_len;
	return llc_prim;
}

/* 7.2.2.6 LL-UNITDATA.req (MS/SGSN):*/
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_ll_unitdata_req(
				uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi, uint8_t *l3_pdu, size_t l3_pdu_len)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_ll_alloc(OSMO_GPRS_LLC_LL_UNITDATA, PRIM_OP_REQUEST, l3_pdu_len);
	llc_prim->ll.tlli = tlli;
	llc_prim->ll.sapi = ll_sapi;
	llc_prim->ll.l3_pdu = l3_pdu;
	llc_prim->ll.l3_pdu_len = l3_pdu_len;
	return llc_prim;
}

/* 7.2.2.6 LL-UNITDATA.ind (MS/SGSN):*/
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_ll_unitdata_ind(
				uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi, uint8_t *l3_pdu, size_t l3_pdu_len)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_ll_alloc(OSMO_GPRS_LLC_LL_UNITDATA, PRIM_OP_INDICATION, l3_pdu_len);
	llc_prim->ll.tlli = tlli;
	llc_prim->ll.sapi = ll_sapi;
	llc_prim->ll.l3_pdu = l3_pdu;
	llc_prim->ll.l3_pdu_len = l3_pdu_len;
	return llc_prim;
}

/* LL-ASSIGN.ind (MS/SGSN): Osmocom specific, used to inform TLLI update LLC->SNDCP */
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_ll_assign_ind(uint32_t old_tlli, uint32_t new_tlli)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_ll_alloc(OSMO_GPRS_LLC_LL_ASSIGN, PRIM_OP_INDICATION, 0);
	llc_prim->ll.tlli = old_tlli;
	llc_prim->ll.sapi = OSMO_GPRS_LLC_SAPI_SNDCP3; /* any SNDCP SAPI is good */
	llc_prim->ll.assign_ind.tlli_new = new_tlli;
	return llc_prim;
}

/********************************
 * Handling to upper layers:
 ********************************/
/* Submit LL-XID.ind to upper layers (Figure 17) */
int gprs_llc_lle_submit_prim_ll_xid_ind(struct gprs_llc_lle *lle,
					const struct gprs_llc_xid_field *xid_field_request_l3)
{
	struct osmo_gprs_llc_prim *llc_prim_tx;
	llc_prim_tx = gprs_llc_prim_alloc_ll_xid_ind(lle->llme->tlli, lle->sapi, NULL, xid_field_request_l3->var.val_len);
	OSMO_ASSERT(llc_prim_tx);
	if (xid_field_request_l3) {
		llc_prim_tx->ll.l3_pdu_len = xid_field_request_l3->var.val_len;
		llc_prim_tx->ll.l3_pdu = msgb_put(llc_prim_tx->oph.msg, llc_prim_tx->ll.l3_pdu_len);
		if (llc_prim_tx->ll.l3_pdu_len > 0)
			memcpy(llc_prim_tx->ll.l3_pdu, xid_field_request_l3->var.val,
			       llc_prim_tx->ll.l3_pdu_len);
	}
	llc_prim_tx->ll.xid.n201_i = lle->params.n201_i;
	llc_prim_tx->ll.xid.n201_u = lle->params.n201_u;
	return gprs_llc_prim_call_up_cb(llc_prim_tx);
}

/* Submit LL-XID.cnf to upper layers */
int gprs_llc_lle_submit_prim_ll_xid_cnf(struct gprs_llc_lle *lle,
					const struct gprs_llc_xid_field *xid_field_response_l3,
					const struct gprs_llc_xid_field *xid_field_request_l3)
{
	struct osmo_gprs_llc_prim *llc_prim_tx;
	OSMO_ASSERT(xid_field_response_l3);
	llc_prim_tx = gprs_llc_prim_alloc_ll_xid_cnf(lle->llme->tlli, lle->sapi, NULL, xid_field_response_l3->var.val_len);
	OSMO_ASSERT(llc_prim_tx);
	llc_prim_tx->ll.l3_pdu_len = xid_field_response_l3->var.val_len;
	llc_prim_tx->ll.l3_pdu = msgb_put(llc_prim_tx->oph.msg, llc_prim_tx->ll.l3_pdu_len);
	if (llc_prim_tx->ll.l3_pdu_len > 0)
		memcpy(llc_prim_tx->ll.l3_pdu, xid_field_response_l3->var.val,
		       llc_prim_tx->ll.l3_pdu_len);
	llc_prim_tx->ll.xid.n201_i = lle->params.n201_i;
	llc_prim_tx->ll.xid.n201_u = lle->params.n201_u;

	/* TODO: do something with following. Is it actually needed? */
	(void)xid_field_request_l3;

	return gprs_llc_prim_call_up_cb(llc_prim_tx);
}

int gprs_llc_llme_submit_prim_ll_assign_ind(uint32_t old_tlli, uint32_t new_tlli)
{
	struct osmo_gprs_llc_prim *llc_prim_tx;
	llc_prim_tx = gprs_llc_prim_alloc_ll_assign_ind(old_tlli, new_tlli);
	OSMO_ASSERT(llc_prim_tx);

	return gprs_llc_prim_call_up_cb(llc_prim_tx);
}

/********************************
 * Handling from upper layers:
 ********************************/

/* 7.2.2.2 LL-ESTABLISH.req (MS/SGSN):*/
static int llc_prim_handle_ll_establish_req(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc = 0;
	struct gprs_llc_lle *lle;

	lle = gprs_llc_find_lle_by_tlli_sapi(llc_prim->ll.tlli, llc_prim->ll.sapi);
	if (!lle) {
		LOGLLC(LOGL_NOTICE, "Rx %s: Unknown TLLI 0x%08x SAPI 0x%02x\n",
		       osmo_gprs_llc_prim_name(llc_prim), llc_prim->ll.tlli,
		       llc_prim->ll.sapi);
		rc = -ENOKEY;
		goto ret_free;
	}

	rc = gprs_llc_lle_tx_sabm(lle, llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len);

ret_free:
	msgb_free(llc_prim->oph.msg);
	return rc;
}

 /* 7.2.2.4 LL-XID.req (MS/SGSN):*/
static int llc_prim_handle_ll_xid_req(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc = 0;
	struct gprs_llc_lle *lle;

	lle = gprs_llc_find_lle_by_tlli_sapi(llc_prim->ll.tlli, llc_prim->ll.sapi);
	if (!lle) {
		LOGLLC(LOGL_NOTICE, "Rx %s: Unknown TLLI 0x%08x SAPI 0x%02x\n",
		       osmo_gprs_llc_prim_name(llc_prim), llc_prim->ll.tlli,
		       llc_prim->ll.sapi);
		rc = -ENOKEY;
		goto ret_free;
	}

	rc = gprs_llc_lle_tx_xid_req(lle, llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len);

ret_free:
	msgb_free(llc_prim->oph.msg);
	return rc;
}

 /* 7.2.2.4 LL-XID.resp (MS/SGSN):*/
static int llc_prim_handle_ll_xid_resp(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc = 0;
	struct gprs_llc_lle *lle;

	lle = gprs_llc_find_lle_by_tlli_sapi(llc_prim->ll.tlli, llc_prim->ll.sapi);
	if (!lle) {
		LOGLLC(LOGL_NOTICE, "Rx %s: Unknown TLLI 0x%08x SAPI 0x%02x\n",
		       osmo_gprs_llc_prim_name(llc_prim), llc_prim->ll.tlli,
		       llc_prim->ll.sapi);
		rc = -ENOKEY;
		goto ret_free;
	}

	rc = gprs_llc_lle_tx_xid_resp(lle, llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len);

ret_free:
	msgb_free(llc_prim->oph.msg);
	return rc;
}

 /* 7.2.2.6 LL-UNITDATA.req (MS/SGSN):*/
static int llc_prim_handle_ll_unitdata_req(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc = 0;
	struct gprs_llc_lle *lle;

	lle = gprs_llc_find_lle_by_tlli_sapi(llc_prim->ll.tlli, llc_prim->ll.sapi);
	if (!lle) {
		struct gprs_llc_llme *llme;
		LOGLLC(LOGL_NOTICE, "Rx %s: unknown TLLI 0x%08x, creating LLME on the fly\n",
		       osmo_gprs_llc_prim_name(llc_prim), llc_prim->ll.tlli);
		llme = gprs_llc_llme_alloc(llc_prim->ll.tlli);
		lle = gprs_llc_llme_get_lle(llme, llc_prim->ll.sapi);
	}

	if (lle->llme->suspended && llc_prim->ll.sapi != OSMO_GPRS_LLC_SAPI_GMM) {
		LOGLLE(lle, LOGL_NOTICE, "Dropping frame to transmit, LLME is suspended\n");
		goto ret_free;
	}

	rc = gprs_llc_lle_tx_ui(lle, llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len,
				llc_prim->ll.unitdata_req.apply_gea,
				llc_prim->ll.unitdata_req.radio_prio);

ret_free:
	msgb_free(llc_prim->oph.msg);
	return rc;
}

/* LLC higher layers push LLC primitive down to LLC layer: */
int gprs_llc_prim_ll_upper_down(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_ESTABLISH, PRIM_OP_REQUEST):
		OSMO_ASSERT(g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_MS ||
			    g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = llc_prim_handle_ll_establish_req(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_XID, PRIM_OP_REQUEST):
		OSMO_ASSERT(g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_MS ||
			    g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = llc_prim_handle_ll_xid_req(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_XID, PRIM_OP_RESPONSE):
		OSMO_ASSERT(g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_MS ||
			    g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = llc_prim_handle_ll_xid_resp(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_UNITDATA, PRIM_OP_REQUEST):
		OSMO_ASSERT(g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_MS ||
			    g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = llc_prim_handle_ll_unitdata_req(llc_prim);
		break;
	/* TODO: others */
	default:
		rc = gprs_llc_prim_handle_unsupported(llc_prim);
	}
	return rc;
}
