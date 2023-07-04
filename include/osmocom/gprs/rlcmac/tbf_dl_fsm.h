/* Uplink TBF, 3GPP TS 44.060 */
#pragma once

#include <osmocom/core/fsm.h>

#include <osmocom/gprs/rlcmac/rlcmac_private.h>

struct gprs_rlcmac_dl_tbf;

enum gprs_rlcmac_tbf_dl_fsm_states {
	GPRS_RLCMAC_TBF_DL_ST_NEW = 0,	/* new created TBF */
	GPRS_RLCMAC_TBF_DL_ST_FLOW,	/* RLC/MAC flow, resource needed */
	GPRS_RLCMAC_TBF_DL_ST_FINISHED,	/* flow finished, wait for release */
};

struct gprs_rlcmac_tbf_dl_fsm_ctx {
	struct osmo_fsm_inst *fi;
	union { /* back pointer. union used to easily access superclass from ctx */
		struct gprs_rlcmac_tbf *tbf;
		struct gprs_rlcmac_dl_tbf *dl_tbf;
	};
};

enum tbf_dl_fsm_event {
	GPRS_RLCMAC_TBF_DL_EV_LAST_DL_DATA_RECVD,
	GPRS_RLCMAC_TBF_DL_EV_DL_ASS_COMPL,
};

int gprs_rlcmac_tbf_dl_fsm_init(void);
void gprs_rlcmac_tbf_dl_fsm_set_log_cat(int logcat);

int gprs_rlcmac_tbf_dl_fsm_constructor(struct gprs_rlcmac_dl_tbf *dl_tbf);
void gprs_rlcmac_tbf_dl_fsm_destructor(struct gprs_rlcmac_dl_tbf *dl_tbf);

enum gprs_rlcmac_tbf_dl_fsm_states gprs_rlcmac_tbf_dl_state(const struct gprs_rlcmac_dl_tbf *dl_tbf);
