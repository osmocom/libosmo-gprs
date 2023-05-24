/* GPRS Radio Resource SAP as per:
 * 3GPP TS 44.060 4.3
 * 3GPP TS 24.007 9.3
 * 3GPP TS 44.064 7.2.3
 */
/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/rlcmac_prim.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/tbf_ul_ass_fsm.h>

#define RLCMAC_MSGB_HEADROOM 0

const struct value_string osmo_gprs_rlcmac_prim_sap_names[] = {
	{ OSMO_GPRS_RLCMAC_SAP_GRR,	"GRR" },
	{ OSMO_GPRS_RLCMAC_SAP_GMMRR,	"GMMRR" },
	{ OSMO_GPRS_RLCMAC_SAP_L1CTL,	"L1CTL" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_rlcmac_grr_prim_type_names[] = {
	{ OSMO_GPRS_RLCMAC_GRR_DATA,		"DATA" },
	{ OSMO_GPRS_RLCMAC_GRR_UNITDATA,	"UNITDATA" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_rlcmac_gmmrr_prim_type_names[] = {
	{ OSMO_GPRS_RLCMAC_GMMRR_ASSIGN,	"ASSIGN" },
	{ OSMO_GPRS_RLCMAC_GMMRR_PAGE,		"PAGE" },
	{ OSMO_GPRS_RLCMAC_GMMRR_LLC_TRANSMITTED, "LLC_TRANSMITTED" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_rlcmac_l1ctl_prim_type_names[] = {
	{ OSMO_GPRS_RLCMAC_L1CTL_RACH,		"RACH" },
	{ OSMO_GPRS_RLCMAC_L1CTL_CCCH_DATA,	"CCCH_DATA" },
	{ OSMO_GPRS_RLCMAC_L1CTL_PDCH_DATA,	"PDCH_DATA" },
	{ OSMO_GPRS_RLCMAC_L1CTL_PDCH_RTS,	"PDCH_RTS" },
	{ OSMO_GPRS_RLCMAC_L1CTL_CFG_UL_TBF,	"CFG_UL_TBF" },
	{ OSMO_GPRS_RLCMAC_L1CTL_CFG_DL_TBF,	"CFG_DL_TBF" },
	{ 0, NULL }
};

const char *osmo_gprs_rlcmac_prim_name(const struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	static char name_buf[256];
	const char *sap = osmo_gprs_rlcmac_prim_sap_name(rlcmac_prim->oph.sap);
	const char *op = get_value_string(osmo_prim_op_names, rlcmac_prim->oph.operation);
	const char *type;

	switch (rlcmac_prim->oph.sap) {
	case OSMO_GPRS_RLCMAC_SAP_GRR:
		type = osmo_gprs_rlcmac_grr_prim_type_name(rlcmac_prim->oph.primitive);
		break;
	case OSMO_GPRS_RLCMAC_SAP_GMMRR:
		type = osmo_gprs_rlcmac_gmmrr_prim_type_name(rlcmac_prim->oph.primitive);
		break;
	case OSMO_GPRS_RLCMAC_SAP_L1CTL:
		type = osmo_gprs_rlcmac_l1ctl_prim_type_name(rlcmac_prim->oph.primitive);
		break;
	default:
		type = "unsupported-rlcmac-sap";
	}

	snprintf(name_buf, sizeof(name_buf), "%s-%s.%s", sap, type, op);
	return name_buf;
}

static int rlcmac_up_cb_dummy(struct osmo_gprs_rlcmac_prim *rlcmac_prim, void *user_data)
{
	LOGRLCMAC(LOGL_INFO, "rlcmac_up_cb_dummy(%s)\n", osmo_gprs_rlcmac_prim_name(rlcmac_prim));
	return 0;
}

static int rlcmac_down_cb_dummy(struct osmo_gprs_rlcmac_prim *rlcmac_prim, void *user_data)
{
	LOGRLCMAC(LOGL_INFO, "rlcmac_down_cb_dummy(%s)\n", osmo_gprs_rlcmac_prim_name(rlcmac_prim));
	return 0;
}

/* Set callback used by LLC layer to push primitives to higher layers in protocol stack */
void osmo_gprs_rlcmac_prim_set_up_cb(osmo_gprs_rlcmac_prim_up_cb up_cb, void *up_user_data)
{
	g_rlcmac_ctx->rlcmac_up_cb = up_cb;
	g_rlcmac_ctx->rlcmac_up_cb_user_data = up_user_data;
}

/* Set callback used by LLC layer to push primitives to lower layers in protocol stack */
void osmo_gprs_rlcmac_prim_set_down_cb(osmo_gprs_rlcmac_prim_down_cb down_cb, void *down_user_data)
{
	g_rlcmac_ctx->rlcmac_down_cb = down_cb;
	g_rlcmac_ctx->rlcmac_down_cb_user_data = down_user_data;
}

/********************************
 * Primitive allocation:
 ********************************/

/* allocate a msgb containing a struct osmo_gprs_rlcmac_prim + optional l3 data */
static struct msgb *gprs_rlcmac_prim_msgb_alloc(unsigned int l3_len)
{
	const int headroom = RLCMAC_MSGB_HEADROOM;
	const int size = headroom + sizeof(struct osmo_gprs_rlcmac_prim) + l3_len;
	struct msgb *msg = msgb_alloc_headroom(size, headroom, "rlcmac_prim");

	if (!msg)
		return NULL;

	msg->l1h = msgb_put(msg, sizeof(struct osmo_gprs_rlcmac_prim));

	return msg;
}

static struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc(enum osmo_gprs_rlcmac_prim_sap sap,
							    unsigned int type,
							    enum osmo_prim_operation operation,
							    unsigned int l3_len)
{
	struct msgb *msg = gprs_rlcmac_prim_msgb_alloc(l3_len);
	struct osmo_gprs_rlcmac_prim *rlcmac_prim = msgb_rlcmac_prim(msg);

	osmo_prim_init(&rlcmac_prim->oph, sap, type, operation, msg);
	return rlcmac_prim;
}

static inline
struct osmo_gprs_rlcmac_prim *rlcmac_prim_grr_alloc(enum osmo_gprs_rlcmac_grr_prim_type type,
						    enum osmo_prim_operation operation,
						    unsigned int l3_len)
{
	return gprs_rlcmac_prim_alloc(OSMO_GPRS_RLCMAC_SAP_GRR, type, operation, l3_len);
}

static inline
struct osmo_gprs_rlcmac_prim *rlcmac_prim_gmmrr_alloc(enum osmo_gprs_rlcmac_gmmrr_prim_type type,
						    enum osmo_prim_operation operation,
						    unsigned int l3_len)
{
	return gprs_rlcmac_prim_alloc(OSMO_GPRS_RLCMAC_SAP_GMMRR, type, operation, l3_len);
}

static inline
struct osmo_gprs_rlcmac_prim *rlcmac_prim_l1ctl_alloc(enum osmo_gprs_rlcmac_l1ctl_prim_type type,
						    enum osmo_prim_operation operation,
						    unsigned int l3_len)
{
	return gprs_rlcmac_prim_alloc(OSMO_GPRS_RLCMAC_SAP_L1CTL, type, operation, l3_len);
}

/* 3GPP TS 44.064 7.2.3.2 GRR-UNITDATA.ind (MS):*/
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_grr_unitdata_ind(
					uint32_t tlli, uint8_t *ll_pdu,
					size_t ll_pdu_len)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_grr_alloc(OSMO_GPRS_RLCMAC_GRR_UNITDATA, PRIM_OP_INDICATION, ll_pdu_len);
	rlcmac_prim->grr.tlli = tlli;
	rlcmac_prim->grr.ll_pdu = ll_pdu;
	rlcmac_prim->grr.ll_pdu_len = ll_pdu_len;
	return rlcmac_prim;
}

/* 3GPP TS 44.064 7.2.3.2 GRR-UL-UNITDATA.req (MS):*/
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(
				uint32_t tlli, uint8_t *ll_pdu, size_t ll_pdu_len)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_grr_alloc(OSMO_GPRS_RLCMAC_GRR_UNITDATA, PRIM_OP_REQUEST, ll_pdu_len);
	rlcmac_prim->grr.tlli = tlli;
	rlcmac_prim->grr.ll_pdu = ll_pdu;
	rlcmac_prim->grr.ll_pdu_len = ll_pdu_len;
	return rlcmac_prim;
}

/* 3GPP TS 24.007 9.3.2.1 GMMRR-ASSIGN-REQ:*/
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_gmmrr_assign_req(uint32_t old_tlli, uint32_t new_tlli)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_gmmrr_alloc(OSMO_GPRS_RLCMAC_GMMRR_ASSIGN, PRIM_OP_REQUEST, 0);
	rlcmac_prim->gmmrr.tlli = old_tlli;
	rlcmac_prim->gmmrr.assign_req.new_tlli = new_tlli;
	return rlcmac_prim;
}

/* 3GPP TS 24.007 9.3.2.2 GMMRR-PAGE-IND:*/
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_gmmrr_page_ind(uint32_t tlli)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_gmmrr_alloc(OSMO_GPRS_RLCMAC_GMMRR_PAGE, PRIM_OP_INDICATION, 0);
	rlcmac_prim->gmmrr.tlli = tlli;
	return rlcmac_prim;
}

/* TS 24.008 4.7.2.1.1: indication towards GMM that an LLC frame other than LLC
 * NULL frame has been transmitted on the radio interface */
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_gmmrr_llc_transmitted_ind(uint32_t tlli)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_gmmrr_alloc(OSMO_GPRS_RLCMAC_GMMRR_LLC_TRANSMITTED, PRIM_OP_INDICATION, 0);
	rlcmac_prim->gmmrr.tlli = tlli;
	return rlcmac_prim;
}

/* L1CTL-RACH.req (8bit) */
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_rach8_req(uint8_t ra)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_l1ctl_alloc(OSMO_GPRS_RLCMAC_L1CTL_RACH, PRIM_OP_REQUEST, 0);
	rlcmac_prim->l1ctl.rach_req.is_11bit = false;
	rlcmac_prim->l1ctl.rach_req.ra = ra;
	return rlcmac_prim;
}

/* L1CTL-RACH.req (11bit) */
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_rach11_req(uint16_t ra11, uint8_t synch_seq)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_l1ctl_alloc(OSMO_GPRS_RLCMAC_L1CTL_RACH, PRIM_OP_REQUEST, 0);
	rlcmac_prim->l1ctl.rach_req.is_11bit = true;
	rlcmac_prim->l1ctl.rach_req.ra11 = ra11;
	rlcmac_prim->l1ctl.rach_req.synch_seq = synch_seq;
	return rlcmac_prim;
}

/* L1CTL-CCCH_DATA.ind */
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(uint32_t fn, uint8_t *data)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_l1ctl_alloc(OSMO_GPRS_RLCMAC_L1CTL_CCCH_DATA, PRIM_OP_INDICATION, 0);
	rlcmac_prim->l1ctl.ccch_data_ind.fn = fn;
	rlcmac_prim->l1ctl.ccch_data_ind.data = data;
	return rlcmac_prim;
}

/* L1CTL-PDCH_DATA.req */
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_pdch_data_req(uint8_t ts_nr, uint32_t fn,
									uint8_t *data, uint8_t data_len)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_l1ctl_alloc(OSMO_GPRS_RLCMAC_L1CTL_PDCH_DATA, PRIM_OP_REQUEST, data_len);
	rlcmac_prim->l1ctl.pdch_data_req.fn = fn;
	rlcmac_prim->l1ctl.pdch_data_req.ts_nr = ts_nr;
	rlcmac_prim->l1ctl.pdch_data_req.data_len = data_len;
	rlcmac_prim->l1ctl.pdch_data_req.data = data;
	return rlcmac_prim;
}

/* L1CTL-PDCH_DATA.ind */
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_data_ind(uint8_t ts_nr, uint32_t fn,
				uint8_t rx_lev, uint16_t ber10k, int16_t ci_cb, uint8_t *data, uint8_t data_len)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_l1ctl_alloc(OSMO_GPRS_RLCMAC_L1CTL_PDCH_DATA, PRIM_OP_INDICATION, data_len);
	rlcmac_prim->l1ctl.pdch_data_ind.fn = fn;
	rlcmac_prim->l1ctl.pdch_data_ind.ts_nr = ts_nr;
	rlcmac_prim->l1ctl.pdch_data_ind.rx_lev = rx_lev;
	rlcmac_prim->l1ctl.pdch_data_ind.ber10k = ber10k;
	rlcmac_prim->l1ctl.pdch_data_ind.ci_cb = ci_cb;
	rlcmac_prim->l1ctl.pdch_data_ind.data_len = data_len;
	rlcmac_prim->l1ctl.pdch_data_ind.data = data;
	return rlcmac_prim;
}

/* L1CTL-PDCH_RTS.ind */
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(uint8_t ts_nr, uint32_t fn, uint8_t usf)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_l1ctl_alloc(OSMO_GPRS_RLCMAC_L1CTL_PDCH_RTS, PRIM_OP_INDICATION, 0);
	rlcmac_prim->l1ctl.pdch_rts_ind.fn = fn;
	rlcmac_prim->l1ctl.pdch_rts_ind.ts_nr = ts_nr;
	rlcmac_prim->l1ctl.pdch_rts_ind.usf = usf;
	return rlcmac_prim;
}

/* L1CTL-CFG_DL_TBF.req */
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_cfg_dl_tbf_req(uint8_t tbf_nr, uint8_t slotmask, uint8_t dl_tfi)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_l1ctl_alloc(OSMO_GPRS_RLCMAC_L1CTL_CFG_DL_TBF, PRIM_OP_REQUEST, 0);
	rlcmac_prim->l1ctl.cfg_dl_tbf_req.dl_tbf_nr = tbf_nr;
	rlcmac_prim->l1ctl.cfg_dl_tbf_req.dl_slotmask = slotmask;
	rlcmac_prim->l1ctl.cfg_dl_tbf_req.dl_tfi = dl_tfi;
	return rlcmac_prim;
}

/* L1CTL-CFG_UL_TBF.req */
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_cfg_ul_tbf_req(uint8_t ul_tbf_nr, uint8_t ul_slotmask)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_l1ctl_alloc(OSMO_GPRS_RLCMAC_L1CTL_CFG_UL_TBF, PRIM_OP_REQUEST, 0);
	rlcmac_prim->l1ctl.cfg_ul_tbf_req.ul_tbf_nr = ul_tbf_nr;
	rlcmac_prim->l1ctl.cfg_ul_tbf_req.ul_slotmask = ul_slotmask;
	return rlcmac_prim;
}

int gprs_rlcmac_prim_handle_unsupported(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	LOGRLCMAC(LOGL_ERROR, "Unsupported rlcmac_prim! %s\n", osmo_gprs_rlcmac_prim_name(rlcmac_prim));
	msgb_free(rlcmac_prim->oph.msg);
	return -ENOTSUP;
}

/********************************
 * Handling from/to upper layers:
 ********************************/

static int rlcmac_prim_handle_grr_data_req(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	int rc = gprs_rlcmac_prim_handle_unsupported(rlcmac_prim);
	return rc;
}

static int rlcmac_prim_handle_grr_unitdata_req(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	struct gprs_rlcmac_entity *gre;
	int rc;

	gre = gprs_rlcmac_find_entity_by_tlli(rlcmac_prim->grr.tlli);
	if (!gre) {
		LOGRLCMAC(LOGL_INFO, "TLLI=0x%08x not found, creating entity on the fly\n",
			  rlcmac_prim->grr.tlli);
		gre = gprs_rlcmac_entity_alloc(rlcmac_prim->grr.tlli);
	}
	OSMO_ASSERT(gre);

	rc = gprs_rlcmac_entity_llc_enqueue(gre,
					    rlcmac_prim->grr.ll_pdu,
					    rlcmac_prim->grr.ll_pdu_len,
					    rlcmac_prim->grr.unitdata_req.sapi,
					    rlcmac_prim->grr.unitdata_req.radio_prio);
	msgb_free(rlcmac_prim->oph.msg);
	return rc;
}

int gprs_rlcmac_prim_call_up_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	int rc;
	if (g_rlcmac_ctx->rlcmac_up_cb)
		rc = g_rlcmac_ctx->rlcmac_up_cb(rlcmac_prim, g_rlcmac_ctx->rlcmac_up_cb_user_data);
	else
		rc = rlcmac_up_cb_dummy(rlcmac_prim, g_rlcmac_ctx->rlcmac_up_cb_user_data);
	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(rlcmac_prim->oph.msg);
	else
		rc = 0;
	return rc;
}

static int gprs_rlcmac_prim_grr_upper_down(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	int rc;

	switch (OSMO_PRIM_HDR(&rlcmac_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_RLCMAC_GRR_DATA, PRIM_OP_REQUEST):
		rc = rlcmac_prim_handle_grr_data_req(rlcmac_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_RLCMAC_GRR_UNITDATA, PRIM_OP_REQUEST):
		rc = rlcmac_prim_handle_grr_unitdata_req(rlcmac_prim);
		break;
	default:
		rc = -ENOTSUP;
	}
	return rc;
}

static int rlcmac_prim_handle_gmmrr_assign_req(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	struct gprs_rlcmac_entity *gre;
	uint32_t old_tlli = rlcmac_prim->gmmrr.tlli;
	uint32_t new_tlli = rlcmac_prim->gmmrr.assign_req.new_tlli;
	int rc = 0;
	if (old_tlli == GPRS_RLCMAC_TLLI_UNASSIGNED) {
		/* Case "create" */
		if (new_tlli == GPRS_RLCMAC_TLLI_UNASSIGNED) {
			LOGRLCMAC(LOGL_ERROR, "GMMRR-ASSIGN.req: both old and new TLLIs are unassigned\n");
			rc = -EINVAL;
			goto free_ret;
		}
		if ((gre = gprs_rlcmac_find_entity_by_tlli(new_tlli))) {
			LOGRLCMAC(LOGL_ERROR, "GMMRR-ASSIGN.req: GRE with new TLLI=0x%08x already exists\n", new_tlli);
			rc = -EINVAL;
			goto free_ret;
		}
		LOGRLCMAC(LOGL_INFO, "GMMRR-ASSIGN.req: creating new entity TLLI=0x%08x\n", new_tlli);
		gre = gprs_rlcmac_entity_alloc(new_tlli);
		OSMO_ASSERT(gre);
	} else if (new_tlli == GPRS_RLCMAC_TLLI_UNASSIGNED) {
		/* Case "destroy" */
		gre = gprs_rlcmac_find_entity_by_tlli(old_tlli);
		if (!gre) {
			LOGRLCMAC(LOGL_ERROR, "GMMRR-ASSIGN.req: GRE with TLLI=0x%08x not found\n", old_tlli);
			rc = -ENOENT;
			goto free_ret;
		}
		gprs_rlcmac_entity_free(gre);
		gre = NULL;
		goto free_ret;
	} else {
		/* Case "update", both old_tlli and new_tlli are valid */
		gre = gprs_rlcmac_find_entity_by_tlli(old_tlli);
		if (!gre) {
			LOGRLCMAC(LOGL_ERROR, "GMMRR-ASSIGN.req: GRE with TLLI=0x%08x not found\n", old_tlli);
			rc = -ENOENT;
			goto free_ret;
		}
		LOGGRE(gre, LOGL_INFO, "Update TLLI 0x%08x -> 0x%08x\n", old_tlli, new_tlli);
		gre->tlli = new_tlli;
	}

	/* cache/update knowledge about this GMME's PTMSI and IMSI. It will be
	 * needed later on to match paging requests: */
	gre->ptmsi = rlcmac_prim->gmmrr.assign_req.ptmsi;
	OSMO_STRLCPY_ARRAY(gre->imsi, rlcmac_prim->gmmrr.assign_req.imsi);

free_ret:
	msgb_free(rlcmac_prim->oph.msg);
	return rc;
}

static int gprs_rlcmac_prim_gmmrr_upper_down(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	int rc;

	switch (OSMO_PRIM_HDR(&rlcmac_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_RLCMAC_GMMRR_ASSIGN, PRIM_OP_REQUEST):
		rc = rlcmac_prim_handle_gmmrr_assign_req(rlcmac_prim);
		break;
	default:
		rc = -ENOTSUP;
	}
	return rc;
}

/* RLC/MAC higher layers (RLCMAC) push GRR/GMMRR primitive down to RLC/MAC layer: */
int osmo_gprs_rlcmac_prim_upper_down(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	int rc;

	LOGRLCMAC(LOGL_INFO, "Rx from upper layers: %s\n", osmo_gprs_rlcmac_prim_name(rlcmac_prim));

	switch (rlcmac_prim->oph.sap) {
	case OSMO_GPRS_RLCMAC_SAP_GRR:
		rc = gprs_rlcmac_prim_grr_upper_down(rlcmac_prim);
		break;
	case OSMO_GPRS_RLCMAC_SAP_GMMRR:
		rc = gprs_rlcmac_prim_gmmrr_upper_down(rlcmac_prim);
		break;
	default:
		rc = gprs_rlcmac_prim_handle_unsupported(rlcmac_prim);
	}
	return rc;
}

/********************************
 * Handling from/to lower layers:
 ********************************/

int gprs_rlcmac_prim_call_down_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	int rc;

	LOGRLCMAC(LOGL_DEBUG, "Tx to lower layers: %s\n", osmo_gprs_rlcmac_prim_name(rlcmac_prim));

	if (g_rlcmac_ctx->rlcmac_down_cb)
		rc = g_rlcmac_ctx->rlcmac_down_cb(rlcmac_prim, g_rlcmac_ctx->rlcmac_down_cb_user_data);
	else
		rc = rlcmac_down_cb_dummy(rlcmac_prim, g_rlcmac_ctx->rlcmac_down_cb_user_data);
	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(rlcmac_prim->oph.msg);
	else
		rc = 0;
	return rc;
}

static int rlcmac_prim_handle_l1ctl_pdch_rts_ind(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	int rc;
	struct gprs_rlcmac_rts_block_ind bi = {
		.ts = rlcmac_prim->l1ctl.pdch_rts_ind.ts_nr,
		.fn = rlcmac_prim->l1ctl.pdch_rts_ind.fn,
		.usf = rlcmac_prim->l1ctl.pdch_rts_ind.usf,
	};

	rc = gprs_rlcmac_rcv_rts_block(&bi);
	return rc;
}

static int rlcmac_prim_handle_l1ctl_pdch_data_ind(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	enum gprs_rlcmac_coding_scheme cs;

	/* ignore empty DATA.ind */
	if (OSMO_UNLIKELY(rlcmac_prim->l1ctl.pdch_data_ind.data_len == 0)) {
		LOGRLCMAC(LOGL_DEBUG, "Dropping DL data block with length 0\n");
		return 0;
	}

	cs = gprs_rlcmac_mcs_get_by_size_dl(rlcmac_prim->l1ctl.pdch_data_ind.data_len);
	if (cs == GPRS_RLCMAC_CS_UNKNOWN) {
		LOGRLCMAC(LOGL_ERROR, "Dropping DL data block with invalid length %u: %s\n",
			  rlcmac_prim->l1ctl.pdch_data_ind.data_len,
			  osmo_hexdump(rlcmac_prim->l1ctl.pdch_data_ind.data,
				       rlcmac_prim->l1ctl.pdch_data_ind.data_len));
		return -EINVAL;
	}

	/* TODO: handle PTCCH/D (Packet Timing Control CHannel) blocks */
	if ((rlcmac_prim->l1ctl.pdch_data_ind.fn % 104) == 12) {
		LOGRLCMAC(LOGL_DEBUG, "Dropping PTCCH/D block (not implemented)\n");
		return 0;
	}

	if (gprs_rlcmac_mcs_is_gprs(cs))
		return gprs_rlcmac_handle_gprs_dl_block(rlcmac_prim, cs);

	if (gprs_rlcmac_mcs_is_edge(cs)) {
		LOGRLCMAC(LOGL_NOTICE, "RX EGPRS DL data block NOT SUPPORTED\n");
		return -ENOTSUP;
	}

	/* Should never be reached. */
	OSMO_ASSERT(0);
	return -EINVAL;
}

static int rlcmac_prim_handle_l1ctl_ccch_data_ind(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	/* TODO: check if it's IMM_ASS: */
	int rc;

	switch (rlcmac_prim->l1ctl.ccch_data_ind.data[2]) {
	case GSM48_MT_RR_IMM_ASS:
		rc = gprs_rlcmac_handle_ccch_imm_ass((struct gsm48_imm_ass *)rlcmac_prim->l1ctl.ccch_data_ind.data,
						     rlcmac_prim->l1ctl.ccch_data_ind.fn);
		break;
	case GSM48_MT_RR_SYSINFO_13:
		rc = gprs_rlcmac_handle_bcch_si13((struct gsm48_system_information_type_13 *)rlcmac_prim->l1ctl.ccch_data_ind.data);
		break;
	default:
		rc = -ENOTSUP;
	}
	return rc;
}

static int gprs_rlcmac_prim_l1ctl_lower_up(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	int rc;

	switch (OSMO_PRIM_HDR(&rlcmac_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_RLCMAC_L1CTL_PDCH_RTS, PRIM_OP_INDICATION):
		rc = rlcmac_prim_handle_l1ctl_pdch_rts_ind(rlcmac_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_RLCMAC_L1CTL_PDCH_DATA, PRIM_OP_INDICATION):
		rc = rlcmac_prim_handle_l1ctl_pdch_data_ind(rlcmac_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_RLCMAC_L1CTL_CCCH_DATA, PRIM_OP_INDICATION):
		rc = rlcmac_prim_handle_l1ctl_ccch_data_ind(rlcmac_prim);
		break;
	default:
		rc = -ENOTSUP;
	}
	return rc;
}

int osmo_gprs_rlcmac_prim_lower_up(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	OSMO_ASSERT(g_rlcmac_ctx);
	OSMO_ASSERT(rlcmac_prim);
	struct msgb *msg = rlcmac_prim->oph.msg;
	int rc;

	LOGRLCMAC(LOGL_DEBUG, "Rx from lower layers: %s\n", osmo_gprs_rlcmac_prim_name(rlcmac_prim));

	switch (rlcmac_prim->oph.sap) {
	case OSMO_GPRS_RLCMAC_SAP_L1CTL:
		rc = gprs_rlcmac_prim_l1ctl_lower_up(rlcmac_prim);
		break;
	default:
		rc = -EINVAL;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);
	else
		rc = 0;
	return rc;
}
