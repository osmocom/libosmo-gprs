/* DL TBF Assignment FSM, 3GPP TS 44.060 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/rlcmac/rlcmac_dec.h>

enum gprs_rlcmac_tbf_dl_ass_fsm_states {
	GPRS_RLCMAC_TBF_DL_ASS_ST_IDLE = 0,	/* new created TBF */
	GPRS_RLCMAC_TBF_DL_ASS_ST_WAIT_TBF_STARTING_TIME,	/* wait for Immediate Assignment */
	GPRS_RLCMAC_TBF_DL_ASS_ST_COMPL, /* Completed, will update TBF and return to IDLE state */
};

struct gprs_rlcmac_tbf_dl_ass_fsm_ctx {
	struct osmo_fsm_inst *fi;
	struct gprs_rlcmac_entity *gre; /* backpointer */
	struct gprs_rlcmac_dl_tbf_allocation alloc;
	union {
		IA_RestOctets_t iaro; /* CCCH Imm Ass rest octets */
		RlcMacDownlink_t dl_block; /* PACCH pkt dl ass */
	};
	bool tbf_starting_time_exists;
	uint32_t tbf_starting_time;
	uint8_t ts_nr;
};

enum tbf_dl_ass_fsm_event {
	GPRS_RLCMAC_TBF_DL_ASS_EV_RX_CCCH_IMM_ASS, /* Start Downlink/Uplink assignment from CCCH Imm Ass (data: strcut tbf_start_ev_rx_ccch_imm_ass_ctx) */
	GPRS_RLCMAC_TBF_DL_ASS_EV_RX_PACCH_PKT_ASS, /* Start Downlink/Uplink assignment from Pkt Dl/Ul Ass (data: strcut tbf_start_ev_rx_pacch_pkt_ass_ctx) */
	GPRS_RLCMAC_TBF_DL_ASS_EV_TBF_STARTING_TIME, /* TBF Starting Time reached */
};

struct tbf_start_ev_rx_ccch_imm_ass_ctx {
	uint8_t ts_nr;
	uint32_t fn;
	const struct gsm48_imm_ass *ia;
	const IA_RestOctets_t *iaro;
};

struct tbf_start_ev_rx_pacch_pkt_ass_ctx {
	uint8_t ts_nr;
	uint32_t fn;
	const RlcMacDownlink_t *dl_block; /* decoded Pkt{Ul,Dl}Ass */
};
int gprs_rlcmac_tbf_dl_ass_fsm_init(void);
void gprs_rlcmac_tbf_dl_ass_fsm_set_log_cat(int logcat);

int gprs_rlcmac_tbf_dl_ass_fsm_constructor(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx, struct gprs_rlcmac_entity *gre);
void gprs_rlcmac_tbf_dl_ass_fsm_destructor(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx);

int gprs_rlcmac_tbf_start_from_ccch(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx, const struct tbf_start_ev_rx_ccch_imm_ass_ctx *d);
int gprs_rlcmac_tbf_start_from_pacch(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx, const struct tbf_start_ev_rx_pacch_pkt_ass_ctx *d);

bool gprs_rlcmac_tbf_start_pending(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx);
void gprs_rlcmac_tbf_start_fn_tick(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx, uint32_t fn, uint8_t ts_nr);
enum gprs_rlcmac_tbf_dl_ass_fsm_states gprs_rlcmac_tbf_start_state(const struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx);
