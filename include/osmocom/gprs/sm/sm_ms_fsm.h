#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/gprs/sm/sm_prim.h>

struct gprs_sm_entity;

/* 3GPP TS 24.008 § 6.1.2.1 Session management states in the MS */
enum gprs_sm_ms_fsm_states {
	GPRS_SM_MS_ST_PDP_INACTIVE,		/* 6.1.2.1.1 */
	GPRS_SM_MS_ST_PDP_ACTIVE_PENDING,	/* 6.1.2.1.2 */
	GPRS_SM_MS_ST_PDP_ACTIVE,		/* 6.1.2.1.4 */
	GPRS_SM_MS_ST_PDP_MODIFY_PENDING,	/* 6.1.2.1.5 */
	GPRS_SM_MS_ST_PDP_INACTIVE_PENDING,	/* 6.1.2.1.3 */
	//GPRS_SM_MS_ST_MBMS_ACTIVE_PENDING,	/*  6.1.2.1.6 */
	//GPRS_SM_MS_ST_MBMS_ACTIVE,		/* 6.1.2.1.7 */
};

enum gprs_sm_ms_fsm_events {
	GPRS_SM_MS_EV_RX_GMM_ESTABLISH_CNF,
	GPRS_SM_MS_EV_RX_GMM_ESTABLISH_REJ,
	GPRS_SM_MS_EV_TX_ACT_PDP_CTX_REQ,
	GPRS_SM_MS_EV_RX_ACT_PDP_CTX_REJ, /* data: enum gsm48_gsm_cause *cause */
	GPRS_SM_MS_EV_RX_ACT_PDP_CTX_ACC,
	GPRS_SM_MS_EV_TX_DEACT_PDP_CTX_REQ,
	GPRS_SM_MS_EV_RX_DEACT_PDP_CTX_REQ,
	GPRS_SM_MS_EV_RX_DEACT_PDP_CTX_ACC,
	GPRS_SM_MS_EV_TX_MOD_PDP_CTX_REQ,
	GPRS_SM_MS_EV_RX_MOD_PDP_CTX_REJ,
	GPRS_SM_MS_EV_RX_MOD_PDP_CTX_ACC,
};

struct gprs_sm_ms_fsm_ctx {
	struct osmo_fsm_inst *fi;
	struct gprs_sm_entity *sme;
	/* TS 24.008 6.1.3.1.5 retrans counter for T3380: */
	uint8_t act_pdp_ctx_attempts;
};

int gprs_sm_ms_fsm_init(void);
void gprs_sm_ms_fsm_set_log_cat(int logcat);

int gprs_sm_ms_fsm_ctx_init(struct gprs_sm_ms_fsm_ctx *ctx, struct gprs_sm_entity *sme);
void gprs_sm_ms_fsm_ctx_release(struct gprs_sm_ms_fsm_ctx *ctx);
