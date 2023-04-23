/* TBF as per 3GPP TS 44.064 */
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

#include <talloc.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/fsm.h>

#include <osmocom/gprs/rlcmac/tbf_ul_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/rlc_window_ul.h>
#include <osmocom/gprs/rlcmac/gre.h>

#define X(s) (1 << (s))

static const struct value_string tbf_ul_fsm_event_names[] = {
	{ GPRS_RLCMAC_TBF_UL_EV_UL_ASS_START,			"UL_ASS_START" },
	{ GPRS_RLCMAC_TBF_UL_EV_UL_ASS_COMPL,			"UL_ASS_COMPL" },
	{ GPRS_RLCMAC_TBF_UL_EV_FIRST_UL_DATA_SENT,		"FIRST_UL_DATA_SENT" },
	{ GPRS_RLCMAC_TBF_UL_EV_N3104_MAX,			"N3104_MAX" },
	{ GPRS_RLCMAC_TBF_UL_EV_RX_UL_ACK_NACK,			"RX_UL_ACK_NACK" },
	{ GPRS_RLCMAC_TBF_UL_EV_LAST_UL_DATA_SENT,		"LAST_UL_DATA_SENT" },
	{ 0, NULL }
};

static const struct osmo_tdef_state_timeout tbf_ul_fsm_timeouts[32] = {
	[GPRS_RLCMAC_TBF_UL_ST_NEW] = { },
	[GPRS_RLCMAC_TBF_UL_ST_WAIT_ASSIGN] = { },
	[GPRS_RLCMAC_TBF_UL_ST_FLOW] = { .T = 3164 },
	[GPRS_RLCMAC_TBF_UL_ST_FINISHED] = { .keep_timer = true }, /* keep FLOW state's T3164 / T3166 */
};

/* Transition to a state, using the T timer defined in tbf_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
 #define tbf_ul_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_ul_fsm_timeouts, \
				     g_rlcmac_ctx->T_defs, \
				     -1)

static uint8_t ul_tbf_ul_slotmask(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	uint8_t i;
	uint8_t ul_slotmask = 0;

	for (i = 0; i < 8; i++) {
		if (ul_tbf->cur_alloc.ts[i].allocated)
			ul_slotmask |= (1 << i);
	}

	return ul_slotmask;
}

static int configure_ul_tbf(struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx, bool release)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	uint8_t ul_slotmask;

	ul_slotmask = release ? 0 : ul_tbf_ul_slotmask(ctx->ul_tbf);

	LOGPFSML(ctx->fi, LOGL_INFO, "Send L1CTL-CF_UL_TBF.req ul_tbf_nr=%u ul_slotmask=0x%02x %s\n",
		 ctx->tbf->nr, ul_slotmask, release ? "(release)" : "(reconf)");
	rlcmac_prim = gprs_rlcmac_prim_alloc_l1ctl_cfg_ul_tbf_req(ctx->tbf->nr, ul_slotmask);
	return gprs_rlcmac_prim_call_down_cb(rlcmac_prim);
}

static void reinit_pkt_acces_procedure(struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx)
{
	int rc;
	/* TS 44.060 sub-clause 7.1.4. Reinitiate the packet access procedure:
		* Move to NEW state, start Ass and wait for GPRS_RLCMAC_TBF_UL_ASS_EV_START */
	tbf_ul_fsm_state_chg(ctx->fi, GPRS_RLCMAC_TBF_UL_ST_NEW);
	/* We always use 1phase for now... */
	rc = gprs_rlcmac_tbf_ul_ass_start(ctx->ul_tbf, GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE);
	if (rc < 0)
		gprs_rlcmac_ul_tbf_free(ctx->ul_tbf);
}

/* 9.3.3.3.2: Upon each retransmission of the last block with CV=0, the mobile station shall restart timer T3182 for the TBF.
* Slight impl deviation from spec: If tbf is still in contention resolution, keep using T3166, otherwise start T3182
*/
static void arm_T3182_if_needed(struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx)
{
	struct osmo_fsm_inst *fi = ctx->fi;
	unsigned long val_sec;

	if (gprs_rlcmac_ul_tbf_in_contention_resolution(ctx->ul_tbf)) {
		OSMO_ASSERT(fi->T == 3166);
		OSMO_ASSERT(osmo_timer_pending(&fi->timer));
	} else {
		OSMO_ASSERT(!osmo_timer_pending(&fi->timer) ||
			    (osmo_timer_pending(&fi->timer) && fi->T == 3182));
		LOGPFSML(ctx->fi, LOGL_INFO, "Last UL block sent (CV=0), start T3182\n");
		fi->T = 3182;
		val_sec = osmo_tdef_get(g_rlcmac_ctx->T_defs, fi->T, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&fi->timer, val_sec, 0);
	}
}

/* This one is triggered when packet access procedure fails, which can happen
 * either in WAIT_IMM_ASS (ImmAss timeout), FLOW (T3164) or FINISHED (T3164, T3166) */
static void st_new_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_fsm_ctx *)fi->priv;

	memset(&ctx->ul_tbf->cur_alloc, 0, sizeof(ctx->ul_tbf->cur_alloc));
	ctx->ul_tbf->n3104 = 0;

	/* Mark everything we transmitted so far as NACKed: */
	gprs_rlcmac_rlc_ul_window_mark_for_resend(ctx->ul_tbf->ulw);
	/* Make sure the lower layers realize this tbf_nr has no longer any assigned resource: */
	configure_ul_tbf(ctx, true);
}

static void st_new(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_fsm_ctx *)fi->priv;
	switch (event) {
	case GPRS_RLCMAC_TBF_UL_EV_UL_ASS_START:
		tbf_ul_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ST_WAIT_ASSIGN);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_assign(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_fsm_ctx *)fi->priv;
	switch (event) {
	case GPRS_RLCMAC_TBF_UL_EV_UL_ASS_COMPL:
		/* Configure UL TBF on the lower MAC side: */
		configure_ul_tbf(ctx, false);
		tbf_ul_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ST_FLOW);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_flow(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_fsm_ctx *)fi->priv;
	unsigned long val_sec;

	switch (event) {
	case GPRS_RLCMAC_TBF_UL_EV_FIRST_UL_DATA_SENT:
		LOGPFSML(ctx->fi, LOGL_INFO, "First UL block sent, stop T3164\n");
		OSMO_ASSERT(fi->T == 3164);
		osmo_timer_del(&fi->timer);
		if (ctx->ul_tbf->ul_ass_fsm.ass_type == GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE) {
			LOGPFSML(ctx->fi, LOGL_INFO, "First UL block sent (1 phase access), start T3166\n");
			fi->T = 3166;
			val_sec = osmo_tdef_get(g_rlcmac_ctx->T_defs, fi->T, OSMO_TDEF_S, -1);
			osmo_timer_schedule(&fi->timer, val_sec, 0);
		}
		break;
	case GPRS_RLCMAC_TBF_UL_EV_N3104_MAX:
		reinit_pkt_acces_procedure(ctx);
		break;
	case GPRS_RLCMAC_TBF_UL_EV_RX_UL_ACK_NACK:
		if (gprs_rlcmac_ul_tbf_in_contention_resolution(ctx->ul_tbf)) {
			LOGPFSML(ctx->fi, LOGL_INFO, "Contention resolution succeeded, stop T3166\n");
			OSMO_ASSERT(ctx->ul_tbf->ul_ass_fsm.ass_type == GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE);
			OSMO_ASSERT(fi->T == 3166);
			osmo_timer_del(&fi->timer);
			fi->T = 0;
		}
		/* It's impossible we receive a correct final_ack here, since we didn't
		 * sent last data (FSM would be in FINISHED state then) */
		break;
	case GPRS_RLCMAC_TBF_UL_EV_LAST_UL_DATA_SENT:
		arm_T3182_if_needed(ctx);
		tbf_ul_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ST_FINISHED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_finished(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_fsm_ctx *)fi->priv;
	struct tbf_ul_ass_ev_rx_ul_ack_nack *ctx_ul_ack_nack;
	switch (event) {
	case GPRS_RLCMAC_TBF_UL_EV_N3104_MAX:
		reinit_pkt_acces_procedure(ctx);
		break;
	case GPRS_RLCMAC_TBF_UL_EV_RX_UL_ACK_NACK:
		ctx_ul_ack_nack = (struct tbf_ul_ass_ev_rx_ul_ack_nack *)data;
		if (gprs_rlcmac_ul_tbf_in_contention_resolution(ctx->ul_tbf)) {
			LOGPFSML(ctx->fi, LOGL_INFO, "Contention resolution succeeded, stop T3166\n");
			OSMO_ASSERT(ctx->ul_tbf->ul_ass_fsm.ass_type == GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE);
			OSMO_ASSERT(fi->T == 3166);
			osmo_timer_del(&fi->timer);
			fi->T = 0;
		} else if (fi->T == 3182 && osmo_timer_pending(&fi->timer))  {
			/* 9.3.3.3.2 "Upon reception of a PACKET UPLINK ACK/NACK message for this TBF
			 * the mobile station shall stop timer T3182 for the TBF".
			 * In our case we only use T3128 once we are out of contention resolution (T3166)
			 */
			LOGPFSML(ctx->fi, LOGL_DEBUG, "Rx Pkt UL ACK/NACK, stop T3182\n");
			osmo_timer_del(&fi->timer);
			fi->T = 0;
		}
		if (ctx_ul_ack_nack->final_ack) {
			LOGPFSML(ctx->fi, LOGL_DEBUG, "Final ACK received\n");
			ctx->rx_final_pkt_ul_ack_nack_has_tbf_est = ctx_ul_ack_nack->tbf_est;
			tbf_ul_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ST_RELEASING);
		}
		break;
	case GPRS_RLCMAC_TBF_UL_EV_LAST_UL_DATA_SENT:
		/* If LAST_UL_DATA_SENT is received in this state, it means the
		 * UL TBF is retransmitting the block.
		 * 9.3.3.3.2: The block with CV=0 shall not be retransmitted more than four times.
		 */
		ctx->last_data_block_retrans_attempts++;
		LOGPFSML(ctx->fi, LOGL_INFO, "Data block with CV=0 retransmit attempts=%u\n", ctx->last_data_block_retrans_attempts);
		arm_T3182_if_needed(ctx);
		if (ctx->last_data_block_retrans_attempts == 4) {
			LOGPFSML(ctx->fi, LOGL_NOTICE, "TBF establishment failure (Data block with CV=0 retransmit attempts=%u)\n",
				 ctx->last_data_block_retrans_attempts);
			gprs_rlcmac_ul_tbf_free(ctx->ul_tbf);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Waiting for scheduler to transmit PKT CTRL ACK for the already received UL ACK/NACK FinalAck=1 */
static void st_releasing(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_fsm_ctx *)fi->priv;
	switch (event) {
	default:
		OSMO_ASSERT(0);
	}
}

static struct osmo_fsm_state tbf_ul_fsm_states[] = {
	[GPRS_RLCMAC_TBF_UL_ST_NEW] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_EV_UL_ASS_START),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ST_WAIT_ASSIGN) |
			X(GPRS_RLCMAC_TBF_UL_ST_FLOW),
		.name = "NEW",
		.onenter = st_new_on_enter,
		.action = st_new,
	},
	[GPRS_RLCMAC_TBF_UL_ST_WAIT_ASSIGN] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_EV_UL_ASS_COMPL),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ST_FLOW),
		.name = "ASSIGN",
		.action = st_wait_assign,
	},
	[GPRS_RLCMAC_TBF_UL_ST_FLOW] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_EV_FIRST_UL_DATA_SENT) |
			X(GPRS_RLCMAC_TBF_UL_EV_N3104_MAX) |
			X(GPRS_RLCMAC_TBF_UL_EV_RX_UL_ACK_NACK) |
			X(GPRS_RLCMAC_TBF_UL_EV_LAST_UL_DATA_SENT),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ST_NEW) |
			X(GPRS_RLCMAC_TBF_UL_ST_FINISHED),
		.name = "FLOW",
		.action = st_flow,
	},
	[GPRS_RLCMAC_TBF_UL_ST_FINISHED] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_EV_N3104_MAX) |
			X(GPRS_RLCMAC_TBF_UL_EV_RX_UL_ACK_NACK) |
			X(GPRS_RLCMAC_TBF_UL_EV_LAST_UL_DATA_SENT),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ST_NEW) |
			X(GPRS_RLCMAC_TBF_UL_ST_RELEASING),
		.name = "FINISHED",
		.action = st_finished,
	},
	[GPRS_RLCMAC_TBF_UL_ST_RELEASING] = {
		.in_event_mask = 0,
		.out_state_mask = 0,
		.name = "RELEASING",
		.action = st_releasing,
	},
};

static int tbf_ul_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_fsm_ctx *)fi->priv;

	switch (fi->T) {
	case 3164:
		ctx->pkt_acc_proc_attempts++;
		LOGPFSML(ctx->fi, LOGL_INFO, "T3164 timeout attempts=%u\n", ctx->pkt_acc_proc_attempts);
		OSMO_ASSERT(fi->state == GPRS_RLCMAC_TBF_UL_ST_FLOW);
		if (ctx->pkt_acc_proc_attempts == 4) {
			/* TS 44.060 7.1.4 "... the packet access procedure has already been attempted four time ..."
			 * mobile station shall notify higher layers (TBF establishment failure) */
			/* TODO: find out how to notify higher layers */
			LOGPFSML(ctx->fi, LOGL_NOTICE, "TBF establishment failure (T3164 timeout attempts=%u)\n", ctx->pkt_acc_proc_attempts);
			gprs_rlcmac_ul_tbf_free(ctx->ul_tbf);
			return 0;
		}
		reinit_pkt_acces_procedure(ctx);
		break;
	case 3166:
		ctx->pkt_acc_proc_attempts++;
		LOGPFSML(ctx->fi, LOGL_INFO, "T3166 timeout attempts=%u\n", ctx->pkt_acc_proc_attempts);
		OSMO_ASSERT(fi->state == GPRS_RLCMAC_TBF_UL_ST_FLOW ||
			    fi->state == GPRS_RLCMAC_TBF_UL_ST_FINISHED);
		if (ctx->pkt_acc_proc_attempts == 4) {
			/* TS 44.060 7.1.4 "... expiry of timers T3166 ... the
			 * mobile station shall remain in packet idle mode and
			 * notify higher layer (TBF establishment failure)" */
			/* TODO: find out how to notify higher layers */
			LOGPFSML(ctx->fi, LOGL_NOTICE, "TBF establishment failure (T3166 timeout attempts=%u)\n", ctx->pkt_acc_proc_attempts);
			gprs_rlcmac_ul_tbf_free(ctx->ul_tbf);
			return 0;
		}
		reinit_pkt_acces_procedure(ctx);
		break;
	case 3182:
		gprs_rlcmac_ul_tbf_free(ctx->ul_tbf);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm tbf_ul_fsm = {
	.name = "UL_TBF",
	.states = tbf_ul_fsm_states,
	.num_states = ARRAY_SIZE(tbf_ul_fsm_states),
	.timer_cb = tbf_ul_fsm_timer_cb,
	.log_subsys = DLGLOBAL, /* updated dynamically through gprs_rlcmac_tbf_ul_fsm_set_log_cat() */
	.event_names = tbf_ul_fsm_event_names,
};

int gprs_rlcmac_tbf_ul_fsm_init(void)
{
	return osmo_fsm_register(&tbf_ul_fsm);
}

void gprs_rlcmac_tbf_ul_fsm_set_log_cat(int logcat)
{
	tbf_ul_fsm.log_subsys = logcat;
}

int gprs_rlcmac_tbf_ul_fsm_constructor(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx = &ul_tbf->state_fsm;
	ctx->ul_tbf = ul_tbf;
	ctx->fi = osmo_fsm_inst_alloc(&tbf_ul_fsm, ul_tbf, ctx, LOGL_INFO, NULL);
	if (!ctx->fi)
		return -ENODATA;

	return 0;
}

void gprs_rlcmac_tbf_ul_fsm_destructor(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx = &ul_tbf->state_fsm;

	/* Make sure the lower layers realize this tbf_nr has no longer any assigned resource: */
	configure_ul_tbf(ctx, true);

	osmo_fsm_inst_free(ctx->fi);
	ctx->fi = NULL;
}

enum gprs_rlcmac_tbf_ul_fsm_states gprs_rlcmac_tbf_ul_state(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	const struct gprs_rlcmac_tbf_ul_fsm_ctx *ctx = &ul_tbf->state_fsm;
	return ctx->fi->state;
}
