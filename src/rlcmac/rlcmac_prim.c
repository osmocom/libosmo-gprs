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

#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/rlcmac_prim.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/rlcmac/gre.h>

#define RLCMAC_MSGB_HEADROOM 0

const struct value_string osmo_gprs_rlcmac_prim_sap_names[] = {
	{ OSMO_GPRS_RLCMAC_SAP_GRR,	"GRR" },
	{ OSMO_GPRS_RLCMAC_SAP_GMMRR,	"GMMRR" },
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
	g_ctx->rlcmac_up_cb = up_cb;
	g_ctx->rlcmac_up_cb_user_data = up_user_data;
}

/* Set callback used by LLC layer to push primitives to lower layers in protocol stack */
void osmo_gprs_rlcmac_prim_set_down_cb(osmo_gprs_rlcmac_prim_down_cb down_cb, void *down_user_data)
{
	g_ctx->rlcmac_down_cb = down_cb;
	g_ctx->rlcmac_down_cb_user_data = down_user_data;
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
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_gmmrr_assign_req(uint32_t new_tlli)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_gmmrr_alloc(OSMO_GPRS_RLCMAC_GMMRR_ASSIGN, PRIM_OP_REQUEST, 0);
	rlcmac_prim->gmmrr.assign_req.new_tlli = new_tlli;
	return rlcmac_prim;
}

/* 3GPP TS 24.007 9.3.2.2 GMMRR-PAGE-IND:*/
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_gmmrr_page_ind(uint32_t tlli)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	rlcmac_prim = rlcmac_prim_gmmrr_alloc(OSMO_GPRS_RLCMAC_GMMRR_PAGE, PRIM_OP_INDICATION, 0);
	rlcmac_prim->gmmrr.page_ind.tlli = tlli;
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
	return rc;
}

int gprs_rlcmac_prim_call_up_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	int rc;
	if (g_ctx->rlcmac_up_cb)
		rc = g_ctx->rlcmac_up_cb(rlcmac_prim, g_ctx->rlcmac_up_cb_user_data);
	else
		rc = rlcmac_up_cb_dummy(rlcmac_prim, g_ctx->rlcmac_up_cb_user_data);
	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(rlcmac_prim->oph.msg);
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
	int rc = gprs_rlcmac_prim_handle_unsupported(rlcmac_prim);
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
	if (g_ctx->rlcmac_down_cb)
		rc = g_ctx->rlcmac_down_cb(rlcmac_prim, g_ctx->rlcmac_down_cb_user_data);
	else
		rc = rlcmac_down_cb_dummy(rlcmac_prim, g_ctx->rlcmac_down_cb_user_data);
	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(rlcmac_prim->oph.msg);
	return rc;
}

int osmo_gprs_rlcmac_prim_lower_up(struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	OSMO_ASSERT(g_ctx);
	OSMO_ASSERT(rlcmac_prim);
	struct msgb *msg = rlcmac_prim->oph.msg;
	int rc;

	LOGRLCMAC(LOGL_INFO, "Rx from lower layers: %s\n", osmo_gprs_rlcmac_prim_name(rlcmac_prim));

	switch (rlcmac_prim->oph.sap) {
	// TODO
	//case OSMO_GPRS_LLC_SAP_GRR:
	//	OSMO_ASSERT(g_ctx->location == OSMO_GPRS_LLC_LOCATION_MS);
	//	rc = gprs_rlcmac_prim_lower_up_grr(rlcmac_prim);
	default:
		rc = -EINVAL;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);
	return rc;
}
