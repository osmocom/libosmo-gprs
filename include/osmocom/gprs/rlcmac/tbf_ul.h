/* Uplink TBF, 3GPP TS 44.060 */
#pragma once

#include <inttypes.h>

#include <osmocom/core/msgb.h>

#include <osmocom/gprs/rlcmac/tbf.h>
#include <osmocom/gprs/rlcmac/tbf_ul_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_ul_ass_fsm.h>
#include <osmocom/gprs/rlcmac/coding_scheme.h>
#include <osmocom/gprs/rlcmac/sched.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>

struct gprs_rlcmac_rlc_window;
struct gprs_rlcmac_rlc_ul_window;

struct gprs_rlcmac_ul_tbf {
	struct gprs_rlcmac_tbf tbf;
	struct gprs_rlcmac_tbf_ul_fsm_ctx state_fsm;
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx ul_ass_fsm;

	/* Current TS/TFI/USF allocated by the PCU: */
	struct gprs_rlcmac_ul_tbf_allocation cur_alloc;

	/* Currently selected LLC frame to be scheduled/transmitted */
	struct msgb *llc_tx_msg;
	int32_t last_ul_drained_fn;
	/* count all transmitted data blocks */
	unsigned int n3104;

	/* Holds state of all generated in-transit RLC blocks */
	struct gprs_rlcmac_rlc_block_store *blkst;

	/* Uplink RLC Window, holds ACK state */
	union { /* easy access to parent and child */
		struct gprs_rlcmac_rlc_window *w;
		struct gprs_rlcmac_rlc_ul_window *ulw;
	};

	/* (M)CS used to transmit uplink blocks, assigned by PCU: */
	enum gprs_rlcmac_coding_scheme tx_cs;

	/* Whether the UL TBF entered the countdown procedure (TS 44.060 9.3.1)*/
	struct {
		bool active;
		uint8_t cv;
		struct gprs_rlcmac_llc_queue *llc_queue;
	} countdown_proc;

	struct osmo_timer_list t3180;
};

struct gprs_rlcmac_ul_tbf *gprs_rlcmac_ul_tbf_alloc(struct gprs_rlcmac_entity *gre);
void gprs_rlcmac_ul_tbf_free(struct gprs_rlcmac_ul_tbf *ul_tbf);

int gprs_rlcmac_ul_tbf_submit_configure_req(const struct gprs_rlcmac_ul_tbf *ul_tbf,
					    const struct gprs_rlcmac_ul_tbf_allocation *alloc,
					    bool starting_time_present, uint32_t starting_time_fn);

void gprs_rlcmac_ul_tbf_countdown_proc_update_cv(struct gprs_rlcmac_ul_tbf *ul_tbf);

bool gprs_rlcmac_ul_tbf_in_contention_resolution(const struct gprs_rlcmac_ul_tbf *ul_tbf);
unsigned int gprs_rlcmac_ul_tbf_n3104_max(const struct gprs_rlcmac_ul_tbf *ul_tbf);
bool gprs_rlcmac_ul_tbf_have_data(const struct gprs_rlcmac_ul_tbf *ul_tbf);
bool gprs_rlcmac_ul_tbf_can_request_new_ul_tbf(const struct gprs_rlcmac_ul_tbf *ul_tbf);
bool gprs_rlcmac_ul_tbf_data_rts(const struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi);
bool gprs_rlcmac_ul_tbf_dummy_rts(const struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi);

struct msgb *gprs_rlcmac_ul_tbf_data_create(struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi);
struct msgb *gprs_rlcmac_ul_tbf_dummy_create(struct gprs_rlcmac_ul_tbf *ul_tbf);

int gprs_rlcmac_ul_tbf_handle_pkt_ul_ack_nack(struct gprs_rlcmac_ul_tbf *ul_tbf,
					      const struct gprs_rlcmac_dl_block_ind *dlbi);
int gprs_rlcmac_ul_tbf_handle_pkt_ul_ass(struct gprs_rlcmac_ul_tbf *ul_tbf,
					 const struct gprs_rlcmac_dl_block_ind *dlbi);

static inline struct gprs_rlcmac_tbf *ul_tbf_as_tbf(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	return &ul_tbf->tbf;
}

static inline const struct gprs_rlcmac_tbf *ul_tbf_as_tbf_const(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	return &ul_tbf->tbf;
}

static inline struct gprs_rlcmac_ul_tbf *tbf_as_ul_tbf(struct gprs_rlcmac_tbf *tbf)
{
	OSMO_ASSERT(tbf->direction == GPRS_RLCMAC_TBF_DIR_UL);
	return (struct gprs_rlcmac_ul_tbf *)tbf;
}

static inline const struct gprs_rlcmac_ul_tbf *tbf_as_ul_tbf_const(struct gprs_rlcmac_tbf *tbf)
{
	OSMO_ASSERT(tbf->direction == GPRS_RLCMAC_TBF_DIR_UL);
	return (const struct gprs_rlcmac_ul_tbf *)tbf;
}

#define LOGPTBFUL(ul_tbf, lvl, fmt, args...) \
	LOGP(g_rlcmac_log_cat[OSMO_GPRS_RLCMAC_LOGC_TBFUL], lvl, "TBF(UL:NR-%" PRIu8 ":TLLI-%08x) " fmt, \
	(ul_tbf)->tbf.nr, (ul_tbf)->tbf.gre->tlli, \
	## args)
