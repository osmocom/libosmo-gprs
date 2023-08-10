/* UL TBF Assignment FSM, 3GPP TS 44.060 */
#pragma once

#include <stdint.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>

struct gprs_rlcmac_ul_tbf;
struct gprs_rlcmac_rts_block_ind;

enum gprs_rlcmac_tbf_ul_ass_type {
	GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE,
	GPRS_RLCMAC_TBF_UL_ASS_TYPE_2PHASE,
};

enum gprs_rlcmac_tbf_ul_ass_fsm_states {
	GPRS_RLCMAC_TBF_UL_ASS_ST_IDLE = 0,	/* new created TBF */
	GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_CCCH_IMM_ASS,	/* wait for Immediate Assignment */
	GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME1,	/* Wait for Tbf Starting Time (1phase) */
	GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ,	/* wait PDCH sched (USF) */
	GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_PKT_UL_ASS,	/* Wait for PCU to send the new assignment */
	GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME2,	/* Wait for Tbf Starting Time (2phase) */
	GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL, /* Completed, will update TBF and return to IDLE state */
};

struct gprs_rlcmac_tbf_ul_ass_fsm_ctx {
	struct osmo_fsm_inst *fi;
	union { /* back pointer. union used to easily access superclass from ctx */
		struct gprs_rlcmac_tbf *tbf;
		struct gprs_rlcmac_ul_tbf *ul_tbf;
	};
	const struct gprs_rlcmac_dl_tbf *dl_tbf; /* Not null if assignment was started by a DL TBF ACK/NACK */
	enum gprs_rlcmac_tbf_ul_ass_type ass_type;
	uint8_t rach_req_ra;
	struct gprs_rlcmac_ul_tbf_allocation phase1_alloc;
	struct gprs_rlcmac_ul_tbf_allocation phase2_alloc;
	bool tbf_starting_time_exists;
	uint32_t tbf_starting_time;
	bool sba; /* Single Block Allocation was received from the network */
	/* Number of packet resource request transmitted (T3168) */
	unsigned int pkt_res_req_proc_attempts;
};

enum tbf_ul_ass_fsm_event {
	GPRS_RLCMAC_TBF_UL_ASS_EV_START,	/* Start Uplink assignment (data: enum gprs_rlcmac_tbf_ul_ass_type) */
	GPRS_RLCMAC_TBF_UL_ASS_EV_START_DIRECT_2PHASE, /* Start Uplink assignment directly into 2phase from an older UL TBF */
	GPRS_RLCMAC_TBF_UL_ASS_EV_START_FROM_DL_TBF, /* Uplink assignment requested by DL TBF ACK/NACK, wait to receive Pkt Ul Ass on its PACCH */
	GPRS_RLCMAC_TBF_UL_ASS_EV_RX_CCCH_IMM_ASS, /* (data: struct tbf_ul_ass_ev_rx_ccch_imm_ass_ctx *) */
	GPRS_RLCMAC_TBF_UL_ASS_EV_TBF_STARTING_TIME, /* Scheduler ticking reaches TBF Starting Time */
	GPRS_RLCMAC_TBF_UL_ASS_EV_CREATE_RLCMAC_MSG, /* Generate RLC/MAC block (data: struct tbf_ul_ass_ev_create_rlcmac_msg_ctx) */
	GPRS_RLCMAC_TBF_UL_ASS_EV_RX_PKT_UL_ASS, /* (data: struct tbf_ul_ass_ev_create_rlcmac_msg_ctx) */
};

struct tbf_ul_ass_ev_rx_ccch_imm_ass_ctx {
	uint8_t ts_nr;
	uint32_t fn;
	const struct gsm48_imm_ass *ia;
	const IA_RestOctets_t *iaro;
};

struct tbf_ul_ass_ev_rx_pkt_ul_ass_ctx {
	uint8_t ts_nr;
	uint32_t fn;
	const RlcMacDownlink_t *dl_block; /* decoded PktUlAss */
};

struct tbf_ul_ass_ev_create_rlcmac_msg_ctx {
	uint8_t ts; /* TS where the created UL ctrl block is to be sent */
	uint32_t fn; /* FN where the created UL ctrl block is to be sent */
	struct msgb *msg; /* to be filled by FSM during event processing */
};

int gprs_rlcmac_tbf_ul_ass_fsm_init(void);
void gprs_rlcmac_tbf_ul_ass_fsm_set_log_cat(int logcat);

int gprs_rlcmac_tbf_ul_ass_fsm_constructor(struct gprs_rlcmac_ul_tbf *ul_tbf);
void gprs_rlcmac_tbf_ul_ass_fsm_destructor(struct gprs_rlcmac_ul_tbf *ul_tbf);

int gprs_rlcmac_tbf_ul_ass_start(struct gprs_rlcmac_ul_tbf *ul_tbf, enum gprs_rlcmac_tbf_ul_ass_type type);
int gprs_rlcmac_tbf_ul_ass_start_from_releasing_ul_tbf(struct gprs_rlcmac_ul_tbf *ul_tbf, struct gprs_rlcmac_ul_tbf *old_ul_tbf);
int gprs_rlcmac_tbf_ul_ass_start_from_dl_tbf_ack_nack(struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_dl_tbf *dl_tbf);

bool gprs_rlcmac_tbf_ul_ass_pending(struct gprs_rlcmac_ul_tbf *ul_tbf);
bool gprs_rlcmac_tbf_ul_ass_match_rach_req(struct gprs_rlcmac_ul_tbf *ul_tbf, uint8_t ra);
bool gprs_rlcmac_tbf_ul_ass_waiting_tbf_starting_time(const struct gprs_rlcmac_ul_tbf *ul_tbf);
void gprs_rlcmac_tbf_ul_ass_fn_tick(const struct gprs_rlcmac_ul_tbf *ul_tbf, uint32_t fn, uint8_t ts_nr);
bool gprs_rlcmac_tbf_ul_ass_rts(const struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi);
struct msgb *gprs_rlcmac_tbf_ul_ass_create_rlcmac_msg(const struct gprs_rlcmac_ul_tbf *ul_tbf,
						      const struct gprs_rlcmac_rts_block_ind *bi);

enum gprs_rlcmac_tbf_ul_ass_fsm_states gprs_rlcmac_tbf_ul_ass_state(const struct gprs_rlcmac_ul_tbf *ul_tbf);
