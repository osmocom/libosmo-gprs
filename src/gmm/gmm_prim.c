/* GMM service primitive implementation as per 3GPP TS 44.065 */
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

#include <osmocom/gprs/gmm/gmm.h>
#include <osmocom/gprs/gmm/gmm_prim.h>
#include <osmocom/gprs/gmm/gmm_private.h>
#include <osmocom/gprs/gmm/gmm_pdu.h>

#define GMM_MSGB_HEADROOM 0

const struct value_string osmo_gprs_gmm_prim_sap_names[] = {
	{ OSMO_GPRS_GMM_SAP_GMMREG,	"GMMREG" },
	{ OSMO_GPRS_GMM_SAP_GMMRR,	"GMRR" },
	{ OSMO_GPRS_GMM_SAP_GMMAS,	"GMMAS" },
	{ OSMO_GPRS_GMM_SAP_LLGMM,	"LLGMM" },
	{ OSMO_GPRS_GMM_SAP_GMMSM,	"GMMSM" },
	{ OSMO_GPRS_GMM_SAP_GMMSMS,	"GMMSMS" },
	{ OSMO_GPRS_GMM_SAP_GMMRABM,	"GMMRABM" },
	{ OSMO_GPRS_GMM_SAP_GMMSS,	"GMMSS" },
	{ OSMO_GPRS_GMM_SAP_GMMSS2,	"GMMSS2" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_gmm_gmmreg_prim_type_names[] = {
	{ OSMO_GPRS_GMM_GMMREG_ATTACH, "ATTACH" },
	{ OSMO_GPRS_GMM_GMMREG_DETACH, "DETACH" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_gmm_gmmrr_prim_type_names[] = {
	{ OSMO_GPRS_GMM_GMMRR_ASSIGN,	"ASSIGN" },
	{ OSMO_GPRS_GMM_GMMRR_PAGE,	"PAGE" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_gmm_gmmsm_prim_type_names[] = {
	{ OSMO_GPRS_GMM_GMMSM_ESTABLISH, "ESTABLISH" },
	{ OSMO_GPRS_GMM_GMMSM_RELEASE,	"RELEASE" },
	{ OSMO_GPRS_GMM_GMMSM_UNITDATA, "UNITDATA" },
	{ 0, NULL }
};

const char *osmo_gprs_gmm_prim_name(const struct osmo_gprs_gmm_prim *gmm_prim)
{
	static char name_buf[256];
	const char *sap = osmo_gprs_gmm_prim_sap_name(gmm_prim->oph.sap);
	const char *op = get_value_string(osmo_prim_op_names, gmm_prim->oph.operation);
	const char *type;

	switch (gmm_prim->oph.sap) {
	case OSMO_GPRS_GMM_SAP_GMMREG:
		type = osmo_gprs_gmm_gmmreg_prim_type_name(gmm_prim->oph.primitive);
		break;
	case OSMO_GPRS_GMM_SAP_GMMRR:
		type = osmo_gprs_gmm_gmmrr_prim_type_name(gmm_prim->oph.primitive);
		break;
	case OSMO_GPRS_GMM_SAP_GMMSM:
		type = osmo_gprs_gmm_gmmsm_prim_type_name(gmm_prim->oph.primitive);
		break;
	default:
		type = "unsupported-gmm-sap";
	}

	snprintf(name_buf, sizeof(name_buf), "%s-%s.%s", sap, type, op);
	return name_buf;
}

static int gmm_up_cb_dummy(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	LOGGMM(LOGL_INFO, "%s(%s)\n", __func__, osmo_gprs_gmm_prim_name(gmm_prim));
	return 0;
}

static int gmm_down_cb_dummy(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	LOGGMM(LOGL_INFO, "%s(%s)\n", __func__, osmo_gprs_gmm_prim_name(gmm_prim));
	return 0;
}

static int gmm_llc_down_cb_dummy(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
{
	LOGGMM(LOGL_INFO, "%s(%s)\n", __func__, osmo_gprs_llc_prim_name(llc_prim));
	return 0;
}

/* Set callback used by GMM layer to push primitives to higher layers in protocol stack */
void osmo_gprs_gmm_prim_set_up_cb(osmo_gprs_gmm_prim_up_cb up_cb, void *up_user_data)
{
	g_ctx->gmm_up_cb = up_cb;
	g_ctx->gmm_up_cb_user_data = up_user_data;
}

/* Set callback used by GMM layer to push primitives to lower layers in protocol stack */
void osmo_gprs_gmm_prim_set_down_cb(osmo_gprs_gmm_prim_down_cb down_cb, void *down_user_data)
{
	g_ctx->gmm_down_cb = down_cb;
	g_ctx->gmm_down_cb_user_data = down_user_data;
}

/* Set callback used by GMM layer to push primitives to LLC lower layer in protocol stack */
void osmo_gprs_gmm_prim_set_llc_down_cb(osmo_gprs_gmm_prim_llc_down_cb llc_down_cb, void *llc_down_user_data)
{
	g_ctx->gmm_llc_down_cb = llc_down_cb;
	g_ctx->gmm_llc_down_cb_user_data = llc_down_user_data;
}

/********************************
 * Primitive allocation:
 ********************************/

/* allocate a msgb containing a struct osmo_gprs_gmm_prim + optional l3 data */
static struct msgb *gprs_gmm_prim_msgb_alloc(unsigned int npdu_len)
{
	const int headroom = GMM_MSGB_HEADROOM;
	const int size = headroom + sizeof(struct osmo_gprs_gmm_prim) + npdu_len;
	struct msgb *msg = msgb_alloc_headroom(size, headroom, "gmm_prim");

	if (!msg)
		return NULL;

	msg->l1h = msgb_put(msg, sizeof(struct osmo_gprs_gmm_prim));

	return msg;
}

struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc(unsigned int sap, unsigned int type,
						   enum osmo_prim_operation operation,
						   unsigned int extra_size)
{
	struct msgb *msg = gprs_gmm_prim_msgb_alloc(extra_size);
	struct osmo_gprs_gmm_prim *gmm_prim = msgb_gmm_prim(msg);

	osmo_prim_init(&gmm_prim->oph, sap, type, operation, msg);
	return gmm_prim;
}

/*** GMMREG ***/

static inline struct osmo_gprs_gmm_prim *gmm_prim_gmmreg_alloc(enum osmo_gprs_gmm_gmmreg_prim_type type,
							   enum osmo_prim_operation operation,
							   unsigned int extra_size)
{
	return gprs_gmm_prim_alloc(OSMO_GPRS_GMM_SAP_GMMREG, type, operation, extra_size);
}

/* TS 24.007 6.6.1.1 GMMREG-ATTACH.request */
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmreg_attach_req(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmreg_alloc(OSMO_GPRS_GMM_GMMREG_ATTACH, PRIM_OP_REQUEST, 0);
	return gmm_prim;
}


/* 6.6.1.2 GMMREG-ATTACH.cnf */
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmreg_attach_cnf(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmreg_alloc(OSMO_GPRS_GMM_GMMREG_ATTACH, PRIM_OP_CONFIRM, 0);
	gmm_prim->gmmreg.attach_cnf.accepted = true;
	/* TODO: gmm_prim->gmmreg.attach_cnf.acc.* */
	return gmm_prim;
}
/* TODO: 6.6.1.3 GMMREG-ATTACH.rej */

/* TS 24.007 6.6.1.4 GMMREG-DETACH.request */
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmreg_detach_req(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmreg_alloc(OSMO_GPRS_GMM_GMMREG_DETACH, PRIM_OP_REQUEST, 0);
	return gmm_prim;
}

/* TS 24.007 6.6.1.5 GMMREG-DETACH.cnf */
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmreg_detach_cnf(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmreg_alloc(OSMO_GPRS_GMM_GMMREG_DETACH, PRIM_OP_CONFIRM, 0);
	return gmm_prim;
}

/* TS 24.007 6.6.1.6 GMMREG-DETACH.cnf */
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmreg_detach_ind(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmreg_alloc(OSMO_GPRS_GMM_GMMREG_DETACH, PRIM_OP_INDICATION, 0);
	return gmm_prim;
}

/*** GMMRR ***/

static inline struct osmo_gprs_gmm_prim *gmm_prim_gmmrr_alloc(enum osmo_gprs_gmm_gmmrr_prim_type type,
							      enum osmo_prim_operation operation,
							      unsigned int extra_size)
{
	return gprs_gmm_prim_alloc(OSMO_GPRS_GMM_SAP_GMMRR, type, operation, extra_size);
}

/* 3GPP TS 24.007 9.3.2.1 GMMRR-ASSIGN-REQ:*/
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmrr_assign_req(uint32_t new_tlli)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmrr_alloc(OSMO_GPRS_GMM_GMMRR_ASSIGN, PRIM_OP_REQUEST, 0);
	gmm_prim->gmmrr.assign_req.new_tlli = new_tlli;
	return gmm_prim;
}

/* 3GPP TS 24.007 9.3.2.2 GMMRR-PAGE-IND:*/
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmrr_page_ind(uint32_t tlli)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmrr_alloc(OSMO_GPRS_GMM_GMMRR_PAGE, PRIM_OP_INDICATION, 0);
	gmm_prim->gmmrr.page_ind.tlli = tlli;
	return gmm_prim;
}

/*** GMMSM ***/

static inline struct osmo_gprs_gmm_prim *gmm_prim_gmmsm_alloc(enum osmo_gprs_gmm_gmmrr_prim_type type,
							      enum osmo_prim_operation operation,
							      unsigned int extra_size)
{
	return gprs_gmm_prim_alloc(OSMO_GPRS_GMM_SAP_GMMSM, type, operation, extra_size);
}

/* 3GPP TS 24.007 9.5.1.1 GMMSM-ESTABLISH-REQ:*/
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmsm_establish_req(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmrr_alloc(OSMO_GPRS_GMM_GMMSM_ESTABLISH, PRIM_OP_REQUEST, 0);
	return gmm_prim;
}

/* 3GPP TS 24.007 9.5.1.2 GMMSM-ESTABLISH-CNF:*/
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmsm_establish_cnf(uint8_t cause)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmrr_alloc(OSMO_GPRS_GMM_GMMSM_ESTABLISH, PRIM_OP_CONFIRM, 0);
	gmm_prim->gmmsm.establish_cnf.cause = cause;
	return gmm_prim;
}

/* 3GPP TS 24.007 9.5.1.4 GMMSM-RELEASE-IND:*/
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmrr_release_ind(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmrr_alloc(OSMO_GPRS_GMM_GMMSM_RELEASE, PRIM_OP_INDICATION, 0);
	return gmm_prim;
}

/* 3GPP TS 24.007 9.5.1.5 GMMRSM-UNITDATA-REQ:*/
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmsm_unitdata_req(uint8_t *smpdu, unsigned int smpdu_len)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmrr_alloc(OSMO_GPRS_GMM_GMMSM_UNITDATA, PRIM_OP_REQUEST, 0);
	gmm_prim->gmmsm.unitdata_req.smpdu = smpdu;
	gmm_prim->gmmsm.unitdata_req.smpdu_len = smpdu_len;
	return gmm_prim;
}

/* 3GPP TS 24.007 9.5.1.6 GMMRSM-UNITDATA-IND:*/
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmsm_unitdata_ind(uint8_t *smpdu, unsigned int smpdu_len)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmrr_alloc(OSMO_GPRS_GMM_GMMSM_UNITDATA, PRIM_OP_INDICATION, 0);
	gmm_prim->gmmsm.unitdata_ind.smpdu = smpdu;
	gmm_prim->gmmsm.unitdata_ind.smpdu_len = smpdu_len;
	return gmm_prim;
}

static int gprs_gmm_prim_handle_unsupported(struct osmo_gprs_gmm_prim *gmm_prim)
{
	LOGGMM(LOGL_ERROR, "Unsupported gmm_prim! %s\n", osmo_gprs_gmm_prim_name(gmm_prim));
	msgb_free(gmm_prim->oph.msg);
	return -ENOTSUP;
}

static int gprs_gmm_prim_handle_llc_unsupported(struct osmo_gprs_llc_prim *llc_prim)
{
	LOGGMM(LOGL_ERROR, "Unsupported llc_prim! %s\n", osmo_gprs_llc_prim_name(llc_prim));
	msgb_free(llc_prim->oph.msg);
	return -ENOTSUP;
}

/********************************
 * Handling from/to upper layers:
 ********************************/

int gprs_gmm_prim_call_up_cb(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;
	if (g_ctx->gmm_up_cb)
		rc = g_ctx->gmm_up_cb(gmm_prim, g_ctx->gmm_up_cb_user_data);
	else
		rc = gmm_up_cb_dummy(gmm_prim, g_ctx->gmm_up_cb_user_data);
	msgb_free(gmm_prim->oph.msg);
	return rc;
}

/* TS 24.007 6.6.1.1 GMMREG-Attach.request:*/
static int gprs_gmm_prim_handle_gmmreg_attach_req(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;
	struct gprs_gmm_entity *gmme;

	gmme = llist_first_entry_or_null(&g_ctx->gmme_list, struct gprs_gmm_entity, list);
	if (!gmme) {
		gmme = gprs_gmm_gmme_alloc();
		OSMO_ASSERT(gmme);
	}
	gmme->ptmsi = gmm_prim->gmmreg.attach_req.ptmsi;
	if (gmm_prim->gmmreg.attach_req.imsi[0] != '\0')
		OSMO_STRLCPY_ARRAY(gmme->imsi, gmm_prim->gmmreg.attach_req.imsi);
	if (gmm_prim->gmmreg.attach_req.imei[0] != '\0')
		OSMO_STRLCPY_ARRAY(gmme->imei, gmm_prim->gmmreg.attach_req.imei);
	if (gmm_prim->gmmreg.attach_req.imeisv[0] != '\0')
		OSMO_STRLCPY_ARRAY(gmme->imeisv, gmm_prim->gmmreg.attach_req.imeisv);

	rc = gprs_gmm_tx_att_req(gmme,
				 gmm_prim->gmmreg.attach_req.attach_type,
				 gmm_prim->gmmreg.attach_req.attach_with_imsi);

	if (rc < 0)
		return rc;

	rc = osmo_fsm_inst_dispatch(gmme->ms_fsm.fi, GPRS_GMM_MS_EV_ATTACH_REQUESTED, NULL);

	return rc;
}

/* TS 24.007 6.6.1.4 GMMREG-Detach.request:*/
static int gprs_gmm_prim_handle_gmmreg_detach_req(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;

	rc = gprs_gmm_prim_handle_unsupported(gmm_prim);

	return rc;
}

static int gprs_gmm_prim_handle_gmmreg(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;

	switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_GMM_GMMREG_ATTACH, PRIM_OP_REQUEST):
		rc = gprs_gmm_prim_handle_gmmreg_attach_req(gmm_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_GMM_GMMREG_DETACH, PRIM_OP_REQUEST):
		rc = gprs_gmm_prim_handle_gmmreg_detach_req(gmm_prim);
		break;
	default:
		rc = gprs_gmm_prim_handle_unsupported(gmm_prim);
	}
	return rc;
}

/* TS 24.007 9.5.1.1 GMMSM-Establish.request:*/
static int gprs_gmm_prim_handle_gmmsm_establish_req(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;

	rc = gprs_gmm_prim_handle_unsupported(gmm_prim);

	return rc;
}

/* TS 24.007 9.5.1.5 GMMSM-Unitdata.request:*/
static int gprs_gmm_prim_handle_gmmsm_unitdata_req(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;

	rc = gprs_gmm_prim_handle_unsupported(gmm_prim);

	return rc;
}

static int gprs_gmm_prim_handle_gmmsm(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;

	switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_ESTABLISH, PRIM_OP_REQUEST):
		rc = gprs_gmm_prim_handle_gmmsm_establish_req(gmm_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_UNITDATA, PRIM_OP_REQUEST):
		rc = gprs_gmm_prim_handle_gmmsm_unitdata_req(gmm_prim);
		break;
	default:
		rc = gprs_gmm_prim_handle_unsupported(gmm_prim);
		rc = 1;
	}
	return rc;
}

/* GMM higher layers push GMM primitive down to GMM layer: */
int osmo_gprs_gmm_prim_upper_down(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;

	LOGGMM(LOGL_INFO, "Rx from upper layers: %s\n", osmo_gprs_gmm_prim_name(gmm_prim));


	switch (gmm_prim->oph.sap) {
	case OSMO_GPRS_GMM_SAP_GMMREG:
		rc = gprs_gmm_prim_handle_gmmreg(gmm_prim);
		break;
	case OSMO_GPRS_GMM_SAP_GMMSM:
		rc = gprs_gmm_prim_handle_gmmsm(gmm_prim);
		break;
	default:
		rc = gprs_gmm_prim_handle_unsupported(gmm_prim);
		rc = 1;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(gmm_prim->oph.msg);
	else
		rc = 0;
	return rc;
}

/********************************
 * Handling from/to lower layers:
 ********************************/

int gprs_gmm_prim_call_down_cb(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;
	if (g_ctx->gmm_down_cb)
		rc = g_ctx->gmm_down_cb(gmm_prim, g_ctx->gmm_down_cb_user_data);
	else
		rc = gmm_down_cb_dummy(gmm_prim, g_ctx->gmm_down_cb_user_data);
	msgb_free(gmm_prim->oph.msg);
	return rc;
}

static int gprs_gmm_prim_handle_gmmrr(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc = 0;
	switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_GMM_GMMRR_PAGE, PRIM_OP_INDICATION):
		rc = gprs_gmm_prim_handle_unsupported(gmm_prim);
		rc = 1;
		break;
	default:
		rc = gprs_gmm_prim_handle_unsupported(gmm_prim);
		rc = 1;
	}
	return rc;
}

/* GMM lower layers (LLC) push GMM primitive up to GMM layer: */
int osmo_gprs_gmm_prim_lower_up(struct osmo_gprs_gmm_prim *gmm_prim)
{
	OSMO_ASSERT(g_ctx);
	OSMO_ASSERT(gmm_prim);
	struct msgb *msg = gmm_prim->oph.msg;
	int rc;

	LOGGMM(LOGL_INFO, "Rx from lower layers: %s\n", osmo_gprs_gmm_prim_name(gmm_prim));

	switch (gmm_prim->oph.sap) {
	case OSMO_GPRS_GMM_SAP_GMMRR:
		rc = gprs_gmm_prim_handle_gmmrr(gmm_prim);
		break;
	default:
		rc = gprs_gmm_prim_handle_unsupported(gmm_prim);
		rc = 1;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);
	else
		rc = 0;
	return rc;
}

int gprs_gmm_prim_call_llc_down_cb(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	if (g_ctx->gmm_llc_down_cb)
		rc = g_ctx->gmm_llc_down_cb(llc_prim, g_ctx->gmm_llc_down_cb_user_data);
	else
		rc = gmm_llc_down_cb_dummy(llc_prim, g_ctx->gmm_llc_down_cb_user_data);
	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(llc_prim->oph.msg);
	else
		rc = 0;
	return rc;
}

static int gprs_gmm_prim_handle_llgmm(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc = 0;
	switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_PAGE, PRIM_OP_INDICATION):
		rc = gprs_gmm_prim_handle_llc_unsupported(llc_prim);
		rc = 1;
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_PSHO, PRIM_OP_INDICATION):
		rc = gprs_gmm_prim_handle_llc_unsupported(llc_prim);
		rc = 1;
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_PSHO, PRIM_OP_CONFIRM):
		rc = gprs_gmm_prim_handle_llc_unsupported(llc_prim);
		rc = 1;
		break;
	}
	return rc;
}

static int gprs_gmm_prim_handle_ll_unitdata_ind(struct osmo_gprs_llc_prim *llc_prim)
{
	struct gprs_gmm_entity *gmme;
	int rc = 0;
	gmme = gprs_gmm_find_gmme_by_tlli(llc_prim->ll.tlli);
	if (!gmme) {
		LOGGMM(LOGL_NOTICE, "Rx %s: Unknown TLLI 0x%08x\n",
		       osmo_gprs_llc_prim_name(llc_prim), llc_prim->ll.tlli);
		return -ENOENT;
	}
	rc = gprs_gmm_rx(gmme,
			 (struct gsm48_hdr *)llc_prim->ll.l3_pdu,
			 llc_prim->ll.l3_pdu_len);

	return rc;
}

static int gprs_gmm_prim_handle_ll(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;

	switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_RESET, PRIM_OP_INDICATION):
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_ESTABLISH, PRIM_OP_INDICATION):
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_ESTABLISH, PRIM_OP_CONFIRM):
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_RELEASE, PRIM_OP_INDICATION):
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_RELEASE, PRIM_OP_CONFIRM):
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_DATA, PRIM_OP_INDICATION):
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_DATA, PRIM_OP_CONFIRM):
		rc = gprs_gmm_prim_handle_llc_unsupported(llc_prim);
		rc = 1;
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_UNITDATA, PRIM_OP_INDICATION):
		rc = gprs_gmm_prim_handle_ll_unitdata_ind(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_UNITDATA, PRIM_OP_CONFIRM):
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_STATUS, PRIM_OP_INDICATION):
	default:
		rc = gprs_gmm_prim_handle_llc_unsupported(llc_prim);
		rc = 1;
		break;
	}

	return rc;
}

/* GMM lower layers (LLC) push GMM primitive up to GMM layer: */
int osmo_gprs_gmm_prim_llc_lower_up(struct osmo_gprs_llc_prim *llc_prim)
{
	OSMO_ASSERT(g_ctx);
	OSMO_ASSERT(llc_prim);
	struct msgb *msg = llc_prim->oph.msg;
	int rc;

	LOGGMM(LOGL_INFO, "Rx from lower layers: %s\n", osmo_gprs_llc_prim_name(llc_prim));

	switch (llc_prim->oph.sap) {
	case OSMO_GPRS_LLC_SAP_LLGM:
		rc = gprs_gmm_prim_handle_llgmm(llc_prim);
		break;
	case OSMO_GPRS_LLC_SAP_LL:
		rc = gprs_gmm_prim_handle_ll(llc_prim);
		break;
	default:
		rc = gprs_gmm_prim_handle_llc_unsupported(llc_prim);
		rc = 1;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);
	else
		rc = 0;
	return rc;
}
