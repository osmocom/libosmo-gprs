/* Uplink TBF, 3GPP TS 44.060 */
#pragma once

#include <osmocom/core/fsm.h>

#include <osmocom/gprs/rlcmac/rlcmac_private.h>

struct gprs_rlcmac_ul_tbf;

enum gprs_rlcmac_tbf_ul_fsm_states {
	GPRS_RLCMAC_TBF_UL_ST_NEW = 0,	/* new created TBF */
	GPRS_RLCMAC_TBF_UL_ST_WAIT_ASSIGN,	/* wait for Immediate Assignment */
	GPRS_RLCMAC_TBF_UL_ST_FLOW,	/* RLC/MAC flow, resource needed */
	GPRS_RLCMAC_TBF_UL_ST_FINISHED,	/* flow finished, wait for release */
};

struct gprs_rlcmac_tbf_ul_fsm_ctx {
	struct osmo_fsm_inst *fi;
	union { /* back pointer. union used to easily access superclass from ctx */
		struct gprs_rlcmac_tbf *tbf;
		struct gprs_rlcmac_ul_tbf *ul_tbf;
	};
};

enum tbf_ul_fsm_event {
	GPRS_RLCMAC_TBF_UL_EV_UL_ASS_START,
	GPRS_RLCMAC_TBF_UL_EV_UL_ASS_COMPL,
	GPRS_RLCMAC_TBF_UL_EV_LAST_UL_DATA_SENT,
	GPRS_RLCMAC_TBF_UL_EV_FOOBAR,
};

int gprs_rlcmac_tbf_ul_fsm_init(void);
void gprs_rlcmac_tbf_ul_fsm_set_log_cat(int logcat);

int gprs_rlcmac_tbf_ul_fsm_constructor(struct gprs_rlcmac_ul_tbf *ul_tbf);
void gprs_rlcmac_tbf_ul_fsm_destructor(struct gprs_rlcmac_ul_tbf *ul_tbf);

enum gprs_rlcmac_tbf_ul_fsm_states gprs_rlcmac_tbf_ul_state(const struct gprs_rlcmac_ul_tbf *ul_tbf);
