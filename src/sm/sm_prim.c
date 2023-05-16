/* SM service primitive implementation as per 3GPP TS 44.065 */
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
#include <osmocom/gsm/gsm48.h>

#include <osmocom/gprs/sm/sm.h>
#include <osmocom/gprs/sm/sm_prim.h>
#include <osmocom/gprs/sm/sm_private.h>
#include <osmocom/gprs/gmm/gmm_prim.h>
#include <osmocom/gprs/sndcp/sndcp_prim.h>

#define SM_MSGB_HEADROOM 0

const struct value_string osmo_gprs_sm_prim_sap_names[] = {
	{ OSMO_GPRS_SM_SAP_SMREG,	"SMREG" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_sm_smreg_prim_type_names[] = {
	{ OSMO_GPRS_SM_SMREG_PDP_ACTIVATE,	"PDP_ACTIVATE" },
	{ OSMO_GPRS_SM_SMREG_PDP_DEACTIVATE,	"PDP_DEACTIVATE" },
	{ OSMO_GPRS_SM_SMREG_PDP_MODIFY,	"PDP_MODIFY"},
	{ OSMO_GPRS_SM_SMREG_PDP_ACTIVATE_SEC,	"PDP_ACTIVATE_SEC" },
	{ OSMO_GPRS_SM_SMREG_MBMS_ACTIVATE,	"MBMS_ACTIVATE" },
	{ 0, NULL }
};

const char *osmo_gprs_sm_prim_name(const struct osmo_gprs_sm_prim *sm_prim)
{
	static char name_buf[256];
	const char *sap = osmo_gprs_sm_prim_sap_name(sm_prim->oph.sap);
	const char *op = get_value_string(osmo_prim_op_names, sm_prim->oph.operation);
	const char *type;

	switch (sm_prim->oph.sap) {
	case OSMO_GPRS_SM_SAP_SMREG:
		type = osmo_gprs_sm_smreg_prim_type_name(sm_prim->oph.primitive);
		break;
	default:
		type = "unsupported-sm-sap";
	}

	snprintf(name_buf, sizeof(name_buf), "%s-%s.%s", sap, type, op);
	return name_buf;
}

static int sm_up_cb_dummy(struct osmo_gprs_sm_prim *sm_prim, void *user_data)
{
	LOGSM(LOGL_INFO, "%s(%s)\n", __func__, osmo_gprs_sm_prim_name(sm_prim));
	return 0;
}

static int sm_sndcp_up_cb_dummy(struct osmo_gprs_sndcp_prim *sndcp_prim, void *user_data)
{
	LOGSM(LOGL_INFO, "%s(%s)\n", __func__, osmo_gprs_sndcp_prim_name(sndcp_prim));
	return 0;
}

static int sm_down_cb_dummy(struct osmo_gprs_sm_prim *sm_prim, void *user_data)
{
	LOGSM(LOGL_INFO, "%s(%s)\n", __func__, osmo_gprs_sm_prim_name(sm_prim));
	return 0;
}

static int sm_gmm_down_cb_dummy(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	LOGSM(LOGL_INFO, "%s(%s)\n", __func__, osmo_gprs_gmm_prim_name(gmm_prim));
	return 0;
}

/* Set callback used by SM layer to push primitives to higher layers in protocol stack */
void osmo_gprs_sm_prim_set_up_cb(osmo_gprs_sm_prim_up_cb up_cb, void *up_user_data)
{
	g_sm_ctx->sm_up_cb = up_cb;
	g_sm_ctx->sm_up_cb_user_data = up_user_data;
}

/* Set callback used by SM layer to push primitives to SNDCP higher layer in protocol stack */
void osmo_gprs_sm_prim_set_sndcp_up_cb(osmo_gprs_sm_prim_sndcp_up_cb sndcp_up_cb, void *sndcp_up_user_data)
{
	g_sm_ctx->sm_sndcp_up_cb = sndcp_up_cb;
	g_sm_ctx->sm_sndcp_up_cb_user_data = sndcp_up_user_data;
}

/* Set callback used by SM layer to push primitives to lower layers in protocol stack */
void osmo_gprs_sm_prim_set_down_cb(osmo_gprs_sm_prim_down_cb down_cb, void *down_user_data)
{
	g_sm_ctx->sm_down_cb = down_cb;
	g_sm_ctx->sm_down_cb_user_data = down_user_data;
}

/* Set callback used by SM layer to push primitives to GMM lower layer in protocol stack */
void osmo_gprs_sm_prim_set_gmm_down_cb(osmo_gprs_sm_prim_gmm_down_cb gmm_down_cb, void *gmm_down_user_data)
{
	g_sm_ctx->sm_gmm_down_cb = gmm_down_cb;
	g_sm_ctx->sm_gmm_down_cb_user_data = gmm_down_user_data;
}

/********************************
 * Primitive allocation:
 ********************************/

/* allocate a msgb containing a struct osmo_gprs_sm_prim + optional l3 data */
static struct msgb *gprs_sm_prim_msgb_alloc(unsigned int npdu_len)
{
	const int headroom = SM_MSGB_HEADROOM;
	const int size = headroom + sizeof(struct osmo_gprs_sm_prim) + npdu_len;
	struct msgb *msg = msgb_alloc_headroom(size, headroom, "sm_prim");

	if (!msg)
		return NULL;

	msg->l1h = msgb_put(msg, sizeof(struct osmo_gprs_sm_prim));

	return msg;
}

struct osmo_gprs_sm_prim *gprs_sm_prim_alloc(unsigned int sap, unsigned int type,
						   enum osmo_prim_operation operation,
						   unsigned int extra_size)
{
	struct msgb *msg = gprs_sm_prim_msgb_alloc(extra_size);
	struct osmo_gprs_sm_prim *sm_prim = msgb_sm_prim(msg);

	osmo_prim_init(&sm_prim->oph, sap, type, operation, msg);
	return sm_prim;
}

/*** SMREG ***/

static inline struct osmo_gprs_sm_prim *sm_prim_smreg_alloc(enum osmo_gprs_sm_smreg_prim_type type,
							   enum osmo_prim_operation operation,
							   unsigned int extra_size)
{
	return gprs_sm_prim_alloc(OSMO_GPRS_SM_SAP_SMREG, type, operation, extra_size);
}

/* TS 24.007 6.5.1.1 SMREG-PDP-ACTIVATE-REQ */
struct osmo_gprs_sm_prim *osmo_gprs_sm_prim_alloc_smreg_pdp_act_req(void)
{
	struct osmo_gprs_sm_prim *sm_prim;
	sm_prim = sm_prim_smreg_alloc(OSMO_GPRS_SM_SMREG_PDP_ACTIVATE, PRIM_OP_REQUEST, 0);
	return sm_prim;
}


/* TS 24.007 6.5.1.2 SMREG-PDP-ACTIVATE-CNF */
struct osmo_gprs_sm_prim *gprs_sm_prim_alloc_smreg_pdp_act_cnf(void)
{
	struct osmo_gprs_sm_prim *sm_prim;
	sm_prim = sm_prim_smreg_alloc(OSMO_GPRS_SM_SMREG_PDP_ACTIVATE, PRIM_OP_CONFIRM, 0);
	sm_prim->smreg.pdp_act_cnf.accepted = true;
	/* TODO: sm_prim->smreg.pdp_act_cnf.acc.* */
	return sm_prim;
}
/* TODO: TS 24.007 6.5.1.3  SMREG-PDP-ACTIVATE-REJ */

/* TS 24.007 6.5.1.4 SMREG-PDP-ACTIVATE-IND */
struct osmo_gprs_sm_prim *gprs_sm_prim_alloc_smreg_pdp_act_ind(void)
{
	struct osmo_gprs_sm_prim *sm_prim;
	sm_prim = sm_prim_smreg_alloc(OSMO_GPRS_SM_SMREG_PDP_ACTIVATE, PRIM_OP_INDICATION, 0);
	return sm_prim;
}

static int gprs_sm_prim_handle_unsupported(struct osmo_gprs_sm_prim *sm_prim)
{
	LOGSM(LOGL_ERROR, "Unsupported sm_prim! %s\n", osmo_gprs_sm_prim_name(sm_prim));
	msgb_free(sm_prim->oph.msg);
	return -ENOTSUP;
}

static int gprs_sm_prim_handle_gmm_unsupported(struct osmo_gprs_gmm_prim *gmm_prim)
{
	LOGSM(LOGL_ERROR, "Unsupported gmm_prim! %s\n", osmo_gprs_gmm_prim_name(gmm_prim));
	msgb_free(gmm_prim->oph.msg);
	return -ENOTSUP;
}

static int gprs_sm_prim_handle_sndcp_unsupported(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	LOGSM(LOGL_ERROR, "Unsupported sndcp_prim! %s\n", osmo_gprs_sndcp_prim_name(sndcp_prim));
	msgb_free(sndcp_prim->oph.msg);
	return -ENOTSUP;
}

/********************************
 * Handling from/to upper layers:
 ********************************/

int gprs_sm_prim_call_up_cb(struct osmo_gprs_sm_prim *sm_prim)
{
	int rc;
	if (g_sm_ctx->sm_up_cb)
		rc = g_sm_ctx->sm_up_cb(sm_prim, g_sm_ctx->sm_up_cb_user_data);
	else
		rc = sm_up_cb_dummy(sm_prim, g_sm_ctx->sm_up_cb_user_data);
	msgb_free(sm_prim->oph.msg);
	return rc;
}

/* TS 24.007 6.6.1.1 SMREG-Attach.request:*/
static int gprs_sm_prim_handle_smreg_pdp_act_req(struct osmo_gprs_sm_prim *sm_prim)
{
	int rc = 0;
	struct gprs_sm_ms *ms;
	struct gprs_sm_entity *sme = NULL;
	struct osmo_gprs_sm_smreg_prim *smreg = &sm_prim->smreg;

	OSMO_ASSERT(smreg->pdp_act_req.qos_len <= sizeof(sme->qos));
	OSMO_ASSERT(smreg->pdp_act_req.pco_len <= sizeof(sme->pco));

	ms = gprs_sm_find_ms_by_id(smreg->ms_id);
	if (!ms) {
		ms = gprs_sm_ms_alloc(smreg->ms_id);
		OSMO_ASSERT(ms);
	} else {
		sme = gprs_sm_ms_get_pdp_ctx(ms, smreg->pdp_act_req.nsapi);
		if (sme) {
			LOGSME(sme, LOGL_ERROR, "Rx SMREG-PDP-ACT.req for already existing PDP context\n");
			return -EINVAL;
		}
	}

	sme = gprs_sm_entity_alloc(ms, smreg->pdp_act_req.nsapi);
	OSMO_ASSERT(sme);

	if (smreg->pdp_act_req.llc_sapi != OSMO_GPRS_SM_LLC_SAPI_UNASSIGNED)
		sme->llc_sapi = smreg->pdp_act_req.llc_sapi;
	else
		sme->llc_sapi = OSMO_GPRS_SM_LLC_SAPI_SAPI3; /* default */

	sme->pdp_addr_ietf_type = smreg->pdp_act_req.pdp_addr_ietf_type;
	memcpy(&sme->pdp_addr_v4, &smreg->pdp_act_req.pdp_addr_v4, sizeof(sme->pdp_addr_v4));
	memcpy(&sme->pdp_addr_v6, &smreg->pdp_act_req.pdp_addr_v6, sizeof(sme->pdp_addr_v6));

	OSMO_STRLCPY_ARRAY(sme->apn, smreg->pdp_act_req.apn);

	sme->qos_len = smreg->pdp_act_req.qos_len;
	if (sme->qos_len > 0)
		memcpy(&sme->qos, &smreg->pdp_act_req.qos, sme->qos_len);

	sme->pco_len = smreg->pdp_act_req.pco_len;
	if (sme->pco_len > 0)
		memcpy(&sme->pco, &smreg->pdp_act_req.pco, sme->pco_len);

	/* Info required to establish GMM: */
	ms->gmm.ptmsi = sm_prim->smreg.pdp_act_req.gmm.ptmsi;
	if (sm_prim->smreg.pdp_act_req.gmm.imsi[0] != '\0')
		OSMO_STRLCPY_ARRAY(ms->gmm.imsi, sm_prim->smreg.pdp_act_req.gmm.imsi);
	if (sm_prim->smreg.pdp_act_req.gmm.imei[0] != '\0')
		OSMO_STRLCPY_ARRAY(ms->gmm.imei, sm_prim->smreg.pdp_act_req.gmm.imei);
	if (sm_prim->smreg.pdp_act_req.gmm.imeisv[0] != '\0')
		OSMO_STRLCPY_ARRAY(ms->gmm.imeisv, sm_prim->smreg.pdp_act_req.gmm.imeisv);
	memcpy(&ms->gmm.ra, &sm_prim->smreg.pdp_act_req.gmm.old_rai, sizeof(ms->gmm.ra));

	rc = osmo_fsm_inst_dispatch(sme->ms_fsm.fi, GPRS_SM_MS_EV_TX_ACT_PDP_CTX_REQ, NULL);

	return rc;
}

static int gprs_sm_prim_handle_smreg(struct osmo_gprs_sm_prim *sm_prim)
{
	int rc;

	switch (OSMO_PRIM_HDR(&sm_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_SM_SMREG_PDP_ACTIVATE, PRIM_OP_REQUEST):
		rc = gprs_sm_prim_handle_smreg_pdp_act_req(sm_prim);
		break;
	default:
		rc = gprs_sm_prim_handle_unsupported(sm_prim);
	}
	return rc;
}

/* SM higher layers push SM primitive down to SM layer: */
int osmo_gprs_sm_prim_upper_down(struct osmo_gprs_sm_prim *sm_prim)
{
	int rc;

	LOGSM(LOGL_INFO, "Rx from upper layers: %s\n", osmo_gprs_sm_prim_name(sm_prim));


	switch (sm_prim->oph.sap) {
	case OSMO_GPRS_SM_SAP_SMREG:
		rc = gprs_sm_prim_handle_smreg(sm_prim);
		break;
	default:
		rc = gprs_sm_prim_handle_unsupported(sm_prim);
		rc = 1;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(sm_prim->oph.msg);
	else
		rc = 0;
	return rc;
}

/* SM layer pushes SNDCP primitive up to higher layers (SNSM): */
int gprs_sm_prim_call_sndcp_up_cb(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;
	if (g_sm_ctx->sm_sndcp_up_cb)
		rc = g_sm_ctx->sm_sndcp_up_cb(sndcp_prim, g_sm_ctx->sm_sndcp_up_cb_user_data);
	else
		rc = sm_sndcp_up_cb_dummy(sndcp_prim, g_sm_ctx->sm_sndcp_up_cb_user_data);
	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(sndcp_prim->oph.msg);
	else
		rc = 0;
	return rc;
}

/* TS 24.007 6.6.1.1 SMREG-Attach.request:*/
static int gprs_sm_prim_handle_snsm_act_resp(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;
	struct gprs_sm_ms *ms;
	struct gprs_sm_entity *sme;

	ms = gprs_sm_find_ms_by_tlli(sndcp_prim->snsm.tlli);
	if (!ms) {
		LOGSM(LOGL_ERROR, "Rx %s: Unable to find MS with TLLI=0x%08x\n",
		      osmo_gprs_sndcp_prim_name(sndcp_prim), sndcp_prim->snsm.tlli);
		return -ENOENT;
	}

	sme = gprs_sm_ms_get_pdp_ctx(ms, sndcp_prim->snsm.activate_rsp.nsapi);
	if (!sme) {
		LOGMS(ms, LOGL_ERROR, "Rx %s: Unable to find NSAPI=%u\n",
		      osmo_gprs_sndcp_prim_name(sndcp_prim),
		      sndcp_prim->snsm.activate_rsp.nsapi);
		return -ENOENT;
	}

	rc = osmo_fsm_inst_dispatch(sme->ms_fsm.fi, GPRS_SM_MS_EV_NSAPI_ACTIVATED, NULL);
	return rc;
}

/* SNDCP higher layers push SNDCP primitive (SNSM) down to SM layer: */
static int gprs_sm_prim_handle_sndcp_snsm(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;

	switch (OSMO_PRIM_HDR(&sndcp_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_ACTIVATE, PRIM_OP_RESPONSE):
		rc = gprs_sm_prim_handle_snsm_act_resp(sndcp_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_DEACTIVATE, PRIM_OP_RESPONSE):
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_MODIFY, PRIM_OP_RESPONSE):
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_STATUS, PRIM_OP_REQUEST):
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_SEQUENCE, PRIM_OP_RESPONSE):
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_STOP_ASSIGN, PRIM_OP_RESPONSE):
	default:
		rc = gprs_sm_prim_handle_sndcp_unsupported(sndcp_prim);
	}
	return rc;
}

/* SM higher layers push SM primitive down to SM layer: */
int osmo_gprs_sm_prim_sndcp_upper_down(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;

	LOGSM(LOGL_INFO, "Rx from SNDCP layer: %s\n", osmo_gprs_sndcp_prim_name(sndcp_prim));


	switch (sndcp_prim->oph.sap) {
	case OSMO_GPRS_SNDCP_SAP_SNSM:
		rc = gprs_sm_prim_handle_sndcp_snsm(sndcp_prim);
		break;
	default:
		rc = gprs_sm_prim_handle_sndcp_unsupported(sndcp_prim);
		rc = 1;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(sndcp_prim->oph.msg);
	else
		rc = 0;
	return rc;
}

/********************************
 * Handling from/to lower layers:
 ********************************/

int gprs_sm_prim_call_down_cb(struct osmo_gprs_sm_prim *sm_prim)
{
	int rc;
	if (g_sm_ctx->sm_down_cb)
		rc = g_sm_ctx->sm_down_cb(sm_prim, g_sm_ctx->sm_down_cb_user_data);
	else
		rc = sm_down_cb_dummy(sm_prim, g_sm_ctx->sm_down_cb_user_data);
	msgb_free(sm_prim->oph.msg);
	return rc;
}

/* SM lower layers (GMM) push SM primitive up to SM layer: */
int osmo_gprs_sm_prim_lower_up(struct osmo_gprs_sm_prim *sm_prim)
{
	OSMO_ASSERT(g_sm_ctx);
	OSMO_ASSERT(sm_prim);
	struct msgb *msg = sm_prim->oph.msg;
	int rc;

	LOGSM(LOGL_INFO, "Rx from lower layers: %s\n", osmo_gprs_sm_prim_name(sm_prim));

	switch (sm_prim->oph.sap) {
	default:
		rc = gprs_sm_prim_handle_unsupported(sm_prim);
		rc = 1;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);
	else
		rc = 0;
	return rc;
}

int gprs_sm_prim_call_gmm_down_cb(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;
	if (g_sm_ctx->sm_gmm_down_cb)
		rc = g_sm_ctx->sm_gmm_down_cb(gmm_prim, g_sm_ctx->sm_gmm_down_cb_user_data);
	else
		rc = sm_gmm_down_cb_dummy(gmm_prim, g_sm_ctx->sm_gmm_down_cb_user_data);
	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(gmm_prim->oph.msg);
	else
		rc = 0;
	return rc;
}

/* TS 24.007 9.5.1.2 GMMSM-ESTABLISH-CNF */
static int gprs_sm_prim_handle_gmmsm_establish_cnf(struct osmo_gprs_gmm_prim *gmm_prim)
{
	struct osmo_gprs_gmm_gmmsm_prim *gmmsm = &gmm_prim->gmmsm;
	struct gprs_sm_entity *sme;
	int rc;

	sme = gprs_sm_find_sme_by_sess_id(gmmsm->sess_id);
	if (!sme) {
		LOGSM(LOGL_ERROR, "Rx GMMSM-ESTABLISH.cnf for non existing SM Entity\n");
		return -EINVAL;
	}
	if (gmmsm->establish_cnf.accepted) {
		/* Update allocated PTMSI: */
		if (gmm_prim->gmmsm.establish_cnf.acc.allocated_ptmsi != GSM_RESERVED_TMSI)
			sme->ms->gmm.ptmsi = gmm_prim->gmmsm.establish_cnf.acc.allocated_ptmsi;
		/* Set allocated TLLI: */
		sme->ms->gmm.tlli = gmm_prim->gmmsm.establish_cnf.acc.allocated_tlli;
		/* Set the current RAI: */
		memcpy(&sme->ms->gmm.ra, &gmm_prim->gmmsm.establish_cnf.acc.rai, sizeof(sme->ms->gmm.ra));
		rc = osmo_fsm_inst_dispatch(sme->ms_fsm.fi, GPRS_SM_MS_EV_RX_GMM_ESTABLISH_CNF, NULL);
	} else {
		rc = osmo_fsm_inst_dispatch(sme->ms_fsm.fi, GPRS_SM_MS_EV_RX_GMM_ESTABLISH_REJ, NULL);
	}

	return rc;
}

/* TS 24.007 9.5.1.6 GMMSM-UNITDATA-IND */
static int gprs_sm_prim_handle_gmmsm_unitdata_ind(struct osmo_gprs_gmm_prim *gmm_prim)
{
	struct osmo_gprs_gmm_gmmsm_prim *gmmsm = &gmm_prim->gmmsm;
	struct gprs_sm_entity *sme;
	int rc;

	sme = gprs_sm_find_sme_by_sess_id(gmmsm->sess_id);
	if (!sme) {
		LOGSM(LOGL_ERROR, "Rx GMMSM-UNITDATA.ind for non existing SM Entity\n");
		return -EINVAL;
	}

	rc = gprs_sm_rx(sme,
			(struct gsm48_hdr *)gmm_prim->gmmsm.unitdata_ind.smpdu,
			gmm_prim->gmmsm.unitdata_ind.smpdu_len);

	return rc;
}

static int gprs_sm_prim_handle_gmmsm(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc = 0;
	switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_ESTABLISH, PRIM_OP_CONFIRM):
		rc = gprs_sm_prim_handle_gmmsm_establish_cnf(gmm_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_UNITDATA, PRIM_OP_INDICATION):
		rc = gprs_sm_prim_handle_gmmsm_unitdata_ind(gmm_prim);
		break;
	default:
		rc = gprs_sm_prim_handle_gmm_unsupported(gmm_prim);
		rc = 1;
		break;
	}
	return rc;
}

/* SM lower layers (GMM) push SM primitive up to SM layer: */
int osmo_gprs_sm_prim_gmm_lower_up(struct osmo_gprs_gmm_prim *gmm_prim)
{
	OSMO_ASSERT(g_sm_ctx);
	OSMO_ASSERT(gmm_prim);
	struct msgb *msg = gmm_prim->oph.msg;
	int rc;

	LOGSM(LOGL_INFO, "Rx from lower layers: %s\n", osmo_gprs_gmm_prim_name(gmm_prim));

	switch (gmm_prim->oph.sap) {
	case OSMO_GPRS_GMM_SAP_GMMSM:
		rc = gprs_sm_prim_handle_gmmsm(gmm_prim);
		break;
	default:
		rc = gprs_sm_prim_handle_gmm_unsupported(gmm_prim);
		rc = 1;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);
	else
		rc = 0;
	return rc;
}
