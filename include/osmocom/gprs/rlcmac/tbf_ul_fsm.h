/* Uplink TBF, 3GPP TS 44.060 */
#pragma once

#include <osmocom/core/fsm.h>

#include <osmocom/gprs/rlcmac/rlcmac_private.h>

struct gprs_rlcmac_ul_tbf;

enum gprs_rlcmac_tbf_ul_fsm_states {
	GPRS_RLCMAC_TBF_UL_ST_NEW = 0,	/* new created TBF */
	GPRS_RLCMAC_TBF_UL_ST_WAIT_ASSIGN,	/* wait for Immediate Assignment */
	GPRS_RLCMAC_TBF_UL_ST_FLOW,	/* RLC/MAC flow, resource needed */
	GPRS_RLCMAC_TBF_UL_ST_FINISHED,	/* All data transmitted (CV=0), only retransmits and waiting for ACKs */
	GPRS_RLCMAC_TBF_UL_ST_RELEASING, /* Network sent UL ACK w/ FinalAck=1 and polled for response */
};

struct gprs_rlcmac_tbf_ul_fsm_ctx {
	struct osmo_fsm_inst *fi;
	union { /* back pointer. union used to easily access superclass from ctx */
		struct gprs_rlcmac_tbf *tbf;
		struct gprs_rlcmac_ul_tbf *ul_tbf;
	};
	/* Number of packet access procedure timeouts (T3164, T3166) */
	unsigned int pkt_acc_proc_attempts;
	/* 9.3.3.3.2: The block with CV=0 shall not be retransmitted more than four times. */
	unsigned int last_data_block_retrans_attempts;
	/* Whether the Received Packet UL ACK/NACK w/ FinalAck=1 had 'TBF Est' field to '1'.
	 * Used during ST_RELEASING to find out if a new UL TBF can be recreated
	 * when ansering the final UL ACK. */
	bool rx_final_pkt_ul_ack_nack_has_tbf_est;
};

enum tbf_ul_fsm_event {
	GPRS_RLCMAC_TBF_UL_EV_UL_ASS_START,
	GPRS_RLCMAC_TBF_UL_EV_UL_ASS_COMPL,
	GPRS_RLCMAC_TBF_UL_EV_UL_ASS_REJ,
	GPRS_RLCMAC_TBF_UL_EV_FIRST_UL_DATA_SENT,
	GPRS_RLCMAC_TBF_UL_EV_N3104_MAX,
	GPRS_RLCMAC_TBF_UL_EV_RX_UL_ACK_NACK, /* data: struct tbf_ul_ass_ev_rx_ul_ack_nack* */
	GPRS_RLCMAC_TBF_UL_EV_LAST_UL_DATA_SENT,
};

struct tbf_ul_ass_ev_rx_ul_ack_nack {
	bool final_ack;
	bool tbf_est;
};

int gprs_rlcmac_tbf_ul_fsm_init(void);
void gprs_rlcmac_tbf_ul_fsm_set_log_cat(int logcat);

int gprs_rlcmac_tbf_ul_fsm_constructor(struct gprs_rlcmac_ul_tbf *ul_tbf);
void gprs_rlcmac_tbf_ul_fsm_destructor(struct gprs_rlcmac_ul_tbf *ul_tbf);

enum gprs_rlcmac_tbf_ul_fsm_states gprs_rlcmac_tbf_ul_state(const struct gprs_rlcmac_ul_tbf *ul_tbf);
