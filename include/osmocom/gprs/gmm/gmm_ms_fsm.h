#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/gprs/gmm/gmm_prim.h>

struct gprs_gmm_entity;

/* 3GPP TS 24.008 § 4.1.3.1 GMM states in the MS */
enum gprs_gmm_ms_fsm_states {
	GPRS_GMM_MS_ST_NULL,			/* 4.1.3.1.1.1 */
	GPRS_GMM_MS_ST_DEREGISTERED,		/* 4.1.3.1.1.2 */
	GPRS_GMM_MS_ST_REGISTERED_INITIATED,	/* 4.1.3.1.1.3 */
	GPRS_GMM_MS_ST_REGISTERED,		/* 4.1.3.1.1.4 */
	GPRS_GMM_MS_ST_DEREGISTERED_INITIATED,	/* 4.1.3.1.1.5 */
	GPRS_GMM_MS_ST_RAU_INITIATED,		/* 4.1.3.1.1.6 */
	GPRS_GMM_MS_ST_SR_INITIATED,		/* 4.1.3.1.1.7 (Iu only) */
	//GPRS_GMM_MS_ST_DEREGISTERED_NORMAL,	/* 4.1.3.1.2.1 */
	//GPRS_GMM_MS_ST_DEREGISTERED_LIMITED,	/* 4.1.3.1.2.2 */
	//GPRS_GMM_MS_ST_DEREGISTERED_ATTACH_NEEDED, /* 4.1.3.1.2.3 */
	//GPRS_GMM_MS_ST_DEREGISTERED_ATTEMTPING_ATTACH, /* 4.1.3.1.2.4 */
	//GPRS_GMM_MS_ST_DEREGISTERED_NO_IMSI, /* 4.1.3.1.2.5 */
	//GPRS_GMM_MS_ST_DEREGISTERED_NO_CELL_AVAIL, /* 4.1.3.1.2.6 */
	//GPRS_GMM_MS_ST_DEREGISTERED_PLMN_SEARCH, /* 4.1.3.1.2.7 */
	//GPRS_GMM_MS_ST_DEREGISTERED_SUSPENDED,	/* 4.1.3.1.2.8 (Gb only) */
};

enum gprs_gmm_ms_fsm_events {
	GPRS_GMM_MS_EV_ENABLE_GPRS_MODE,
	GPRS_GMM_MS_EV_DISABLE_GPRS_MODE,
	GPRS_GMM_MS_EV_ATTACH_REQUESTED,
	GPRS_GMM_MS_EV_ATTACH_REJECTED,
	GPRS_GMM_MS_EV_ATTACH_ACCEPTED,
	GPRS_GMM_MS_EV_DETACH_REQUESTED, /* also network initiated. data: ptr to enum osmo_gprs_gmm_detach_ms_type */
	GPRS_GMM_MS_EV_DETACH_REQUESTED_POWEROFF,
	GPRS_GMM_MS_EV_DETACH_ACCEPTED,
	GPRS_GMM_MS_EV_SR_REQUESTED, /* (Iu only) */
	GPRS_GMM_MS_EV_SR_REJECTED, /* (Iu only) */
	GPRS_GMM_MS_EV_SR_ACCEPTED, /* (Iu only) */
	GPRS_GMM_MS_EV_RAU_REQUESTED,
	GPRS_GMM_MS_EV_RAU_REJECTED,
	GPRS_GMM_MS_EV_RAU_ACCEPTED,
	GPRS_GMM_MS_EV_LOW_LVL_FAIL,
};

struct gprs_gmm_ms_fsm_ctx {
	struct osmo_fsm_inst *fi;
	struct gprs_gmm_entity *gmme;
	/* Type of last initiated detach: */
	enum osmo_gprs_gmm_detach_ms_type detach_type;
};

int gprs_gmm_ms_fsm_init(void);
void gprs_gmm_ms_fsm_set_log_cat(int logcat);

int gprs_gmm_ms_fsm_ctx_init(struct gprs_gmm_ms_fsm_ctx *ctx, struct gprs_gmm_entity *gmme);
