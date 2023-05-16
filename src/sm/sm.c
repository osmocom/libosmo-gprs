/* GPRS SM as per 3GPP TS 24.008, TS 24.007 */
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
#include <arpa/inet.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/gprs/sndcp/sndcp_prim.h>

#include <osmocom/gprs/sm/sm.h>
#include <osmocom/gprs/sm/sm_prim.h>
#include <osmocom/gprs/sm/sm_private.h>
#include <osmocom/gprs/sm/sm_ms_fsm.h>
#include <osmocom/gprs/sm/sm_pdu.h>

struct gprs_sm_ctx *g_sm_ctx;

/* TS 24.008 */
static struct osmo_tdef T_defs_sm[] = {
	{ .T=3380, .default_val=30, .desc = "" },
	{ 0 } /* empty item at the end */
};

static void gprs_sm_ctx_free(void)
{
	struct gprs_sm_ms *ms;

	while ((ms = llist_first_entry_or_null(&g_sm_ctx->ms_list, struct gprs_sm_ms, list)))
		gprs_sm_ms_free(ms);

	talloc_free(g_sm_ctx);
}

int osmo_gprs_sm_init(enum osmo_gprs_sm_location location)
{
	bool first_init = true;
	int rc;
	OSMO_ASSERT(location == OSMO_GPRS_SM_LOCATION_MS || location == OSMO_GPRS_SM_LOCATION_NETWORK)

	if (g_sm_ctx) {
		first_init = false;
		gprs_sm_ctx_free();
	}

	g_sm_ctx = talloc_zero(NULL, struct gprs_sm_ctx);
	g_sm_ctx->location = location;
	g_sm_ctx->T_defs = T_defs_sm;
	INIT_LLIST_HEAD(&g_sm_ctx->ms_list);

	osmo_tdefs_reset(g_sm_ctx->T_defs);

	if (first_init) {
		rc = gprs_sm_ms_fsm_init();
		if (rc != 0) {
			TALLOC_FREE(g_sm_ctx);
			return rc;
		}
	}
	return 0;
}

struct gprs_sm_ms *gprs_sm_ms_alloc(uint32_t ms_id)
{
	struct gprs_sm_ms *ms;

	ms = talloc_zero(g_sm_ctx, struct gprs_sm_ms);
	if (!ms)
		return NULL;

	ms->ms_id = ms_id;

	llist_add(&ms->list, &g_sm_ctx->ms_list);

	return ms;
}

void gprs_sm_ms_free(struct gprs_sm_ms *ms)
{
	unsigned int i;
	if (!ms)
		return;

	LOGMS(ms, LOGL_DEBUG, "free()\n");

	for (i = 0; i < ARRAY_SIZE(ms->pdp); i++)
		gprs_sm_entity_free(ms->pdp[i]);

	llist_del(&ms->list);
	talloc_free(ms);
}

struct gprs_sm_ms *gprs_sm_find_ms_by_id(uint32_t ms_id)
{
	struct gprs_sm_ms *ms;

	llist_for_each_entry(ms, &g_sm_ctx->ms_list, list) {
		if (ms->ms_id == ms_id)
			return ms;
	}
	return NULL;
}

struct gprs_sm_ms *gprs_sm_find_ms_by_tlli(uint32_t tlli)
{
	struct gprs_sm_ms *ms;

	llist_for_each_entry(ms, &g_sm_ctx->ms_list, list) {
		if (ms->gmm.tlli == tlli)
			return ms;
	}
	return NULL;
}

struct gprs_sm_entity *gprs_sm_entity_alloc(struct gprs_sm_ms *ms, uint32_t nsapi)
{
	struct gprs_sm_entity *sme;
	sme = talloc_zero(g_sm_ctx, struct gprs_sm_entity);
	if (!sme)
		return NULL;

	sme->ms = ms;
	sme->sess_id = g_sm_ctx->next_sess_id++;
	sme->nsapi = nsapi;

	if (gprs_sm_ms_fsm_ctx_init(&sme->ms_fsm, sme) < 0) {
		talloc_free(sme);
		return NULL;
	}

	OSMO_ASSERT(sme->ms->pdp[sme->nsapi] == NULL);
	sme->ms->pdp[sme->nsapi] = sme;
	return sme;
}

void gprs_sm_entity_free(struct gprs_sm_entity *sme)
{
	if (!sme)
		return;

	gprs_sm_ms_fsm_ctx_release(&sme->ms_fsm);

	sme->ms->pdp[sme->nsapi] = NULL;
	talloc_free(sme);
}

struct gprs_sm_entity *gprs_sm_find_sme_by_sess_id(uint32_t sess_id)
{
	struct gprs_sm_ms *ms;
	unsigned int i;

	llist_for_each_entry(ms, &g_sm_ctx->ms_list, list) {
		for (i = 0; i < ARRAY_SIZE(ms->pdp); i++) {
			if (!ms->pdp[i])
				continue;
			if (ms->pdp[i]->sess_id != sess_id)
				continue;
			return ms->pdp[i];
		}
	}
	return NULL;
}

int gprs_sm_submit_gmmsm_assign_req(const struct gprs_sm_entity *sme)
{
	struct gprs_sm_ms *ms = sme->ms;
	struct osmo_gprs_gmm_prim *gmm_prim_tx;
	int rc;

	gmm_prim_tx = osmo_gprs_gmm_prim_alloc_gmmsm_establish_req(sme->sess_id);
	gmm_prim_tx->gmmsm.establish_req.attach_type = OSMO_GPRS_GMM_ATTACH_TYPE_GPRS;
	gmm_prim_tx->gmmsm.establish_req.attach_with_imsi = (ms->gmm.ptmsi == GSM_RESERVED_TMSI);
	gmm_prim_tx->gmmsm.establish_req.ptmsi = ms->gmm.ptmsi;
	OSMO_STRLCPY_ARRAY(gmm_prim_tx->gmmsm.establish_req.imsi, ms->gmm.imsi);
	OSMO_STRLCPY_ARRAY(gmm_prim_tx->gmmsm.establish_req.imei, ms->gmm.imei);
	OSMO_STRLCPY_ARRAY(gmm_prim_tx->gmmsm.establish_req.imeisv, ms->gmm.imeisv);
	memcpy(&gmm_prim_tx->gmmsm.establish_req.old_rai, &ms->gmm.ra, sizeof(ms->gmm.ra));

	rc = gprs_sm_prim_call_gmm_down_cb(gmm_prim_tx);
	return rc;
}

int gprs_sm_submit_smreg_pdp_act_cnf(const struct gprs_sm_entity *sme, enum gsm48_gsm_cause cause)
{
	struct osmo_gprs_sm_prim *sm_prim_tx;
	int rc;

	sm_prim_tx = gprs_sm_prim_alloc_smreg_pdp_act_cnf();
	sm_prim_tx->smreg.ms_id = sme->ms->ms_id;
	sm_prim_tx->smreg.pdp_act_cnf.accepted = (cause == 0);
	sm_prim_tx->smreg.pdp_act_cnf.nsapi = sme->nsapi;
	sm_prim_tx->smreg.pdp_act_cnf.pco_len = sme->pco_len;
	if (sme->pco_len)
		memcpy(sm_prim_tx->smreg.pdp_act_cnf.pco, &sme->pco, sme->pco_len);

	if (sm_prim_tx->smreg.pdp_act_cnf.accepted) {
		sm_prim_tx->smreg.pdp_act_cnf.acc.pdp_addr_ietf_type = sme->pdp_addr_ietf_type;
		memcpy(&sm_prim_tx->smreg.pdp_act_cnf.acc.pdp_addr_v4, &sme->pdp_addr_v4, sizeof(sme->pdp_addr_v4));
		memcpy(&sm_prim_tx->smreg.pdp_act_cnf.acc.pdp_addr_v6, &sme->pdp_addr_v6, sizeof(sme->pdp_addr_v6));
		sm_prim_tx->smreg.pdp_act_cnf.acc.radio_prio = sme->radio_prio;
		sm_prim_tx->smreg.pdp_act_cnf.acc.qos_len = sme->qos_len;
		if (sme->qos_len)
			memcpy(sm_prim_tx->smreg.pdp_act_cnf.acc.qos, &sme->qos, sme->qos_len);
		sm_prim_tx->smreg.pdp_act_cnf.acc.gmm.allocated_ptmsi = sme->ms->gmm.ptmsi;
		sm_prim_tx->smreg.pdp_act_cnf.acc.gmm.allocated_tlli = sme->ms->gmm.tlli;
		memcpy(&sm_prim_tx->smreg.pdp_act_cnf.acc.gmm.rai, &sme->ms->gmm.ra, sizeof(sme->ms->gmm.ra));
	} else {
		sm_prim_tx->smreg.pdp_act_cnf.rej.cause = cause;
	}

	rc = gprs_sm_prim_call_up_cb(sm_prim_tx);
	return rc;
}


int gprs_sm_submit_snsm_act_ind(const struct gprs_sm_entity *sme)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim_tx;
	int rc;

	sndcp_prim_tx = osmo_gprs_sndcp_prim_alloc_snsm_activate_ind(
				sme->ms->gmm.tlli,
				sme->nsapi,
				sme->llc_sapi);
	//sndcp_prim_tx->snsm.activat_ind.qos_params = ; /* TODO */
	//sndcp_prim_tx->snsm.activat_ind.radio_prio = 0; /* TODO */

	rc = gprs_sm_prim_call_sndcp_up_cb(sndcp_prim_tx);
	return rc;
}

/* Tx SM Activate PDP context request, 9.5.1 */
int gprs_sm_tx_act_pdp_ctx_req(struct gprs_sm_entity *sme)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	int rc;
	struct msgb *msg;

	LOGSME(sme, LOGL_INFO, "Tx SM Activate PDP Context Request\n");
	gmm_prim = osmo_gprs_gmm_prim_alloc_gmmsm_unitdata_req(
			sme->ms->ms_id, NULL, GPRS_SM_ALLOC_SIZE);
	msg = gmm_prim->oph.msg;
	msg->l3h = msg->tail;
	rc = gprs_sm_build_act_pdp_ctx_req(sme, msg);
	if (rc < 0) {
		msgb_free(msg);
		return -EBADMSG;
	}
	gmm_prim->gmmsm.unitdata_req.smpdu = msg->l3h;
	gmm_prim->gmmsm.unitdata_req.smpdu_len = msgb_l3len(msg);

	rc = gprs_sm_prim_call_gmm_down_cb(gmm_prim);

	return rc;
}

/* 3GPP TS 24.008 § 9.5.2: Activate PDP Context Accept */
static int gprs_sm_rx_act_pdp_ack(struct gprs_sm_entity *sme,
				    struct gsm48_hdr *gh,
				    unsigned int len)
{
	struct tlv_parsed tp;
	int rc;
	uint8_t *ofs = (uint8_t *)gh;
	uint8_t qos_len;

	ofs += sizeof(*gh);
	//uint8_t transaction_id = gsm48_hdr_trans_id(gh);

	LOGSME(sme, LOGL_INFO, "Rx SM Activate PDP Context Accept\n");

	if (len < (ofs + 2) - (uint8_t *)gh)
		goto tooshort;
	sme->llc_sapi = *ofs++;
	qos_len = *ofs++;

	if (qos_len > ARRAY_SIZE(sme->qos)) {
		LOGSME(sme, LOGL_ERROR,
		       "Rx SM Activate PDP Context Accept: QoS size too big! %u\n", qos_len);
		goto rejected;
	}

	if (len < (ofs + qos_len) - (uint8_t *)gh)
		goto tooshort;
	memcpy(sme->qos, ofs, qos_len);

	ofs += qos_len;

	if (len < (ofs + 1) - (uint8_t *)gh)
		goto tooshort;

	sme->radio_prio = *ofs++;

	if (len > ofs - (uint8_t *)gh) {
		rc = gprs_sm_tlv_parse(&tp, ofs, len - (ofs - (uint8_t *)gh));
		if (rc < 0) {
			LOGSME(sme, LOGL_ERROR, "Rx SM Activate PDP Context Accept: failed to parse TLVs %d\n", rc);
			goto rejected;
		}

		if (TLVP_PRESENT(&tp, GSM48_IE_GSM_PDP_ADDR)) {
			rc = gprs_sm_pdp_addr_dec(
					(const struct gprs_sm_pdp_addr *)TLVP_VAL(&tp, GSM48_IE_GSM_PDP_ADDR),
					TLVP_LEN(&tp, GSM48_IE_GSM_PDP_ADDR),
					&sme->pdp_addr_ietf_type,
					&sme->pdp_addr_v4, &sme->pdp_addr_v6);
			if (rc < 0)
				goto rejected;
		}

		if (TLVP_PRESENT(&tp, GSM48_IE_GSM_PROTO_CONF_OPT)) {
			if (TLVP_LEN(&tp, GSM48_IE_GSM_PROTO_CONF_OPT) > ARRAY_SIZE(sme->pco)) {
				LOGSME(sme, LOGL_ERROR,
				       "Rx SM Activate PDP Context Accept: PCO size too big! %u\n",
				       TLVP_LEN(&tp, GSM48_IE_GSM_PROTO_CONF_OPT));
				goto rejected;
			}
			sme->pco_len = TLVP_LEN(&tp, GSM48_IE_GSM_PROTO_CONF_OPT);
			if (sme->pco_len)
				memcpy(sme->pco, TLVP_VAL(&tp, GSM48_IE_GSM_PROTO_CONF_OPT), sme->pco_len);
		}
	}

	rc = osmo_fsm_inst_dispatch(sme->ms_fsm.fi, GPRS_SM_MS_EV_RX_ACT_PDP_CTX_ACC, NULL);
	if (rc < 0)
		goto rejected;
	return rc;

tooshort:
	LOGSME(sme, LOGL_ERROR, "Rx GMM message too short! len=%u\n", len);
rejected:
	return -EINVAL; /* TODO: what to do on error? */
}

/* 3GPP TS 24.008 § 9.5.3: Activate PDP Context rej */
static int gprs_sm_rx_act_pdp_rej(struct gprs_sm_entity *sme,
				    struct gsm48_hdr *gh,
				    unsigned int len)
{
	struct tlv_parsed tp;
	int rc;
	enum gsm48_gsm_cause cause;
	uint8_t *ofs = (uint8_t *)gh;

	ofs += sizeof(*gh);
	//uint8_t transaction_id = gsm48_hdr_trans_id(gh);

	LOGSME(sme, LOGL_INFO, "Rx SM Activate PDP Context Reject\n");

	if (len < (ofs + 1) - (uint8_t *)gh)
		goto tooshort;
	cause = *ofs++;

	if (len > ofs - (uint8_t *)gh) {
		rc = gprs_sm_tlv_parse(&tp, ofs, len - (ofs - (uint8_t *)gh));
		if (rc < 0) {
			LOGSME(sme, LOGL_ERROR, "Rx SM Activate PDP Context Reject: failed to parse TLVs %d\n", rc);
			goto rejected;
		}

		if (TLVP_PRESENT(&tp, GSM48_IE_GSM_PROTO_CONF_OPT)) {
			if (TLVP_LEN(&tp, GSM48_IE_GSM_PROTO_CONF_OPT) > ARRAY_SIZE(sme->pco)) {
				LOGSME(sme, LOGL_ERROR,
				       "Rx SM Activate PDP Context Reject: PCO size too big! %u\n",
				       TLVP_LEN(&tp, GSM48_IE_GSM_PROTO_CONF_OPT));
				goto rejected;
			}
			sme->pco_len = TLVP_LEN(&tp, GSM48_IE_GSM_PROTO_CONF_OPT);
			if (sme->pco_len)
				memcpy(sme->pco, TLVP_VAL(&tp, GSM48_IE_GSM_PROTO_CONF_OPT), sme->pco_len);
		}
	}

	rc = osmo_fsm_inst_dispatch(sme->ms_fsm.fi, GPRS_SM_MS_EV_RX_ACT_PDP_CTX_REJ, &cause);
	if (rc < 0)
		goto rejected;
	return rc;

tooshort:
	LOGSME(sme, LOGL_ERROR, "Rx GMM message too short! len=%u\n", len);
rejected:
	return -EINVAL; /* TODO: what to do on error? */
}

/* Rx Session Management PDU */
int gprs_sm_rx(struct gprs_sm_entity *sme, struct gsm48_hdr *gh, unsigned int len)
{
	int rc = 0;
	if (len < sizeof(struct gsm48_hdr)) {
		LOGSME(sme, LOGL_ERROR, "Rx GMM message too short! len=%u\n", len);
		return -EINVAL;
	}

	switch (gh->msg_type) {
	case GSM48_MT_GSM_ACT_PDP_ACK:
		rc = gprs_sm_rx_act_pdp_ack(sme, gh, len);
		break;
	case GSM48_MT_GSM_ACT_PDP_REJ:
		rc = gprs_sm_rx_act_pdp_rej(sme, gh, len);
		break;
	default:
		LOGSME(sme, LOGL_ERROR,
			"Rx SM message not implemented! type=%u len=%u\n",
			gh->msg_type, len);
		rc = -EINVAL;
	}

	return rc;
}
