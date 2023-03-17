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

#include <errno.h>
#include <talloc.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/bitvec.h>

#include <osmocom/gprs/rlcmac/types.h>
#include <osmocom/gprs/rlcmac/tbf_dl_ass_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/sched.h>
#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/rlcmac_enc.h>
#include <osmocom/gprs/rlcmac/pdch_ul_controller.h>

#define X(s) (1 << (s))

static const struct value_string tbf_dl_ass_fsm_event_names[] = {
	{ GPRS_RLCMAC_TBF_DL_ASS_EV_RX_CCCH_IMM_ASS,	"RX_CCCH_IMM_ASS" },
	{ GPRS_RLCMAC_TBF_DL_ASS_EV_RX_PACCH_PKT_ASS,	"RX_PACCH_PKT_ASS" },
	{ GPRS_RLCMAC_TBF_DL_ASS_EV_TBF_STARTING_TIME,	"TBF_STARTING_TIME" },
	{ 0, NULL }
};

static const struct osmo_tdef_state_timeout tbf_dl_ass_fsm_timeouts[32] = {
	[GPRS_RLCMAC_TBF_DL_ASS_ST_IDLE] = { },
	[GPRS_RLCMAC_TBF_DL_ASS_ST_WAIT_TBF_STARTING_TIME] = { },
	[GPRS_RLCMAC_TBF_DL_ASS_ST_COMPL] = { },
};

/* Transition to a state, using the T timer defined in tbf_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
 #define tbf_dl_ass_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_dl_ass_fsm_timeouts, \
				     g_ctx->T_defs, \
				     -1)

static int handle_imm_ass(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx, const struct tbf_start_ev_rx_ccch_imm_ass_ctx *d)
{
	const Packet_Downlink_ImmAssignment_t *pkdlass;

	switch (d->iaro->UnionType) {
	case 1: /* d->iaro->u.lh.* (IA_RestOctetsLH_t) */
		switch (d->iaro->u.lh.lh0x.UnionType) {
		case 1: /* d->iaro->u.ll.lh0x.MultiBlock_PktDlAss.* (IA_MultiBlock_PktDlAss_t) */
			return -ENOTSUP; /* TODO */
		}
	case 3: /* d->iaro->u.hh.* (IA_RestOctetsHH_t) */
		switch (d->iaro->u.hh.UnionType) {
		case 0: /* d->iaro->u.hh.u.UplinkDownlinkAssignment.* (IA_PacketAssignment_UL_DL_t) */
			switch (d->iaro->u.hh.u.UplinkDownlinkAssignment.UnionType) {
			case 1: /* d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Downlink_ImmAssignment.* (Packet_Downlink_ImmAssignment_t) */
				pkdlass = &d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Downlink_ImmAssignment;
				ctx->alloc.dl_tfi = pkdlass->TFI_ASSIGNMENT;

				ctx->tbf_starting_time_exists = pkdlass->Exist_TBF_STARTING_TIME;
				if (ctx->tbf_starting_time_exists)
					ctx->tbf_starting_time = TBF_StartingTime_to_fn(&pkdlass->TBF_STARTING_TIME, d->fn);

				ctx->alloc.num_ts = 1;
				ctx->alloc.ts[d->ts_nr].allocated = true;
				LOGPFSML(ctx->fi, LOGL_INFO, "Got PCH IMM_ASS (DL_TBF): DL_TFI=%u TS=%u\n",
					pkdlass->TFI_ASSIGNMENT, d->ts_nr);
				return 0;
			}
		}
		break;
	}

	OSMO_ASSERT(0);
	return -EFAULT;
}

static int handle_pkt_dl_ass(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx, const struct tbf_start_ev_rx_pacch_pkt_ass_ctx *d)
{

	const Packet_Downlink_Assignment_t *dlass = &d->dl_block->u.Packet_Downlink_Assignment;

	if (dlass->Exist_DOWNLINK_TFI_ASSIGNMENT)
		ctx->alloc.dl_tfi = dlass->DOWNLINK_TFI_ASSIGNMENT;
	else
		ctx->alloc.dl_tfi = 0xff;

	ctx->tbf_starting_time_exists = dlass->Exist_TBF_Starting_Time;
	if (ctx->tbf_starting_time_exists)
		ctx->tbf_starting_time = TBF_Starting_Frame_Number_to_fn(&dlass->TBF_Starting_Time, d->fn);

	ctx->alloc.num_ts = 0;
	for (unsigned int i = 0; i < ARRAY_SIZE(ctx->alloc.ts); i++) {
		ctx->alloc.ts[i].allocated = (dlass->TIMESLOT_ALLOCATION >> (7 - i)) & 0x01;
		if (ctx->alloc.ts[i].allocated)
			ctx->alloc.num_ts++;
	}
	return 0;
}

static void st_idle_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *)fi->priv;

	/* Reset state: */
	ctx->tbf_starting_time_exists = false;
	ctx->tbf_starting_time = 0;
	ctx->ts_nr = 0;
	memset(&ctx->alloc, 0, sizeof(ctx->alloc));
}

static void st_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *)fi->priv;
	struct tbf_start_ev_rx_ccch_imm_ass_ctx *ev_ccch_imm_ass;
	struct tbf_start_ev_rx_pacch_pkt_ass_ctx *ev_pacch_pkt_ass;

	switch (event) {
	case GPRS_RLCMAC_TBF_DL_ASS_EV_RX_CCCH_IMM_ASS:
		ev_ccch_imm_ass = (struct tbf_start_ev_rx_ccch_imm_ass_ctx *)data;
		if (handle_imm_ass(ctx, ev_ccch_imm_ass) < 0)
			return;
		memcpy(&ctx->iaro, ev_ccch_imm_ass->iaro, sizeof(ctx->iaro));
		if (ctx->tbf_starting_time_exists &&
		    fn_cmp(ctx->tbf_starting_time, ev_ccch_imm_ass->fn) > 0)
			tbf_dl_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ASS_ST_WAIT_TBF_STARTING_TIME);
		else
			tbf_dl_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ASS_ST_COMPL);
		break;
	case GPRS_RLCMAC_TBF_DL_ASS_EV_RX_PACCH_PKT_ASS:
		ev_pacch_pkt_ass = (struct tbf_start_ev_rx_pacch_pkt_ass_ctx *)data;
		if (handle_pkt_dl_ass(ctx, ev_pacch_pkt_ass) < 0)
			return;
		memcpy(&ctx->dl_block, ev_pacch_pkt_ass->dl_block, sizeof(ctx->dl_block));
		if (ctx->tbf_starting_time_exists &&
		    fn_cmp(ctx->tbf_starting_time, ev_pacch_pkt_ass->fn) > 0)
			tbf_dl_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ASS_ST_WAIT_TBF_STARTING_TIME);
		else
			tbf_dl_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ASS_ST_COMPL);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_tbf_starting_time(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *)fi->priv;
	const struct tbf_start_ev_rx_ccch_imm_ass_ctx *ev_ccch_imm_ass;
	struct tbf_start_ev_rx_pacch_pkt_ass_ctx *ev_pacch_pkt_ass;

	switch (event) {
	case GPRS_RLCMAC_TBF_DL_ASS_EV_RX_CCCH_IMM_ASS:
		ev_ccch_imm_ass = (struct tbf_start_ev_rx_ccch_imm_ass_ctx *)data;
		if (handle_imm_ass(ctx, ev_ccch_imm_ass) < 0)
			return;
		memcpy(&ctx->iaro, ev_ccch_imm_ass->iaro, sizeof(ctx->iaro));
		if (ctx->tbf_starting_time_exists &&
		    fn_cmp(ctx->tbf_starting_time, ev_ccch_imm_ass->fn) > 0)
			tbf_dl_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ASS_ST_WAIT_TBF_STARTING_TIME);
		else
			tbf_dl_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ASS_ST_COMPL);
		break;
	case GPRS_RLCMAC_TBF_DL_ASS_EV_RX_PACCH_PKT_ASS:
		ev_pacch_pkt_ass = (struct tbf_start_ev_rx_pacch_pkt_ass_ctx *)data;
		if (handle_pkt_dl_ass(ctx, ev_pacch_pkt_ass) < 0)
			return;
		memcpy(&ctx->dl_block, ev_pacch_pkt_ass->dl_block, sizeof(ctx->dl_block));
		if (ctx->tbf_starting_time_exists &&
		    fn_cmp(ctx->tbf_starting_time, ev_pacch_pkt_ass->fn) > 0)
			tbf_dl_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ASS_ST_WAIT_TBF_STARTING_TIME);
		else
			tbf_dl_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ASS_ST_COMPL);
		break;
	case GPRS_RLCMAC_TBF_DL_ASS_EV_TBF_STARTING_TIME:
		tbf_dl_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ASS_ST_COMPL);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_compl_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *)fi->priv;
	struct gprs_rlcmac_dl_tbf *dl_tbf;

	dl_tbf = gprs_rlcmac_dl_tbf_alloc(ctx->gre);

	/* Update TBF with allocated content: */
	memcpy(&dl_tbf->cur_alloc, &ctx->alloc, sizeof(ctx->alloc));

	/* Replace old DL TBF with new one. 8.1.1.1.3: "the mobile station shall
	 * release all ongoing downlink TBFs not addressed by this message and
	 * shall act on the message. All ongoing uplink TBFs shall be maintained;"
	 */
	gprs_rlcmac_dl_tbf_free(ctx->gre->dl_tbf);
	ctx->gre->dl_tbf = dl_tbf;

	/* Inform the main TBF state about the assignment completed: */
	osmo_fsm_inst_dispatch(dl_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_DL_ASS_COMPL, NULL);
	/* Go back to IDLE state. */
	tbf_dl_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ASS_ST_IDLE);
}

static struct osmo_fsm_state tbf_dl_ass_fsm_states[] = {
	[GPRS_RLCMAC_TBF_DL_ASS_ST_IDLE] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_DL_ASS_EV_RX_CCCH_IMM_ASS) |
			X(GPRS_RLCMAC_TBF_DL_ASS_EV_RX_PACCH_PKT_ASS),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_DL_ASS_ST_WAIT_TBF_STARTING_TIME) |
			X(GPRS_RLCMAC_TBF_DL_ASS_ST_COMPL),
		.name = "IDLE",
		.onenter = st_idle_on_enter,
		.action = st_idle,
	},
	[GPRS_RLCMAC_TBF_DL_ASS_ST_WAIT_TBF_STARTING_TIME] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_DL_ASS_EV_RX_CCCH_IMM_ASS) |
			X(GPRS_RLCMAC_TBF_DL_ASS_EV_RX_PACCH_PKT_ASS) |
			X(GPRS_RLCMAC_TBF_DL_ASS_EV_TBF_STARTING_TIME),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_DL_ASS_ST_WAIT_TBF_STARTING_TIME) |
			X(GPRS_RLCMAC_TBF_DL_ASS_ST_COMPL),
		.name = "WAIT_TBF_STARTING_TIME",
		.action = st_wait_tbf_starting_time,
	},
	[GPRS_RLCMAC_TBF_DL_ASS_ST_COMPL] = {
		.in_event_mask = 0,
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_DL_ASS_ST_IDLE),
		.name = "COMPLETED",
		.onenter = st_compl_on_enter,
	},
};


static int tbf_dl_ass_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	//struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *)fi->priv;
	switch (fi->T) {
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm tbf_dl_ass_fsm = {
	.name = "DL_TBF_ASS",
	.states = tbf_dl_ass_fsm_states,
	.num_states = ARRAY_SIZE(tbf_dl_ass_fsm_states),
	.timer_cb = tbf_dl_ass_fsm_timer_cb,
	.log_subsys = DLGLOBAL, /* updated dynamically through gprs_rlcmac_tbf_dl_ass_fsm_set_log_cat() */
	.event_names = tbf_dl_ass_fsm_event_names,
};

int gprs_rlcmac_tbf_dl_ass_fsm_init(void)
{
	return osmo_fsm_register(&tbf_dl_ass_fsm);
}

void gprs_rlcmac_tbf_dl_ass_fsm_set_log_cat(int logcat)
{
	tbf_dl_ass_fsm.log_subsys = logcat;
}

int gprs_rlcmac_tbf_dl_ass_fsm_constructor(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx, struct gprs_rlcmac_entity *gre)
{
	ctx->gre = gre;
	ctx->fi = osmo_fsm_inst_alloc(&tbf_dl_ass_fsm, gre, ctx, LOGL_INFO, NULL);
	if (!ctx->fi)
		return -ENODATA;

	return 0;
}

void gprs_rlcmac_tbf_dl_ass_fsm_destructor(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx)
{
	osmo_fsm_inst_free(ctx->fi);
	ctx->fi = NULL;
}

/* A DL TBF assaigned was received over CCCH. */
int gprs_rlcmac_tbf_start_from_ccch(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx, const struct tbf_start_ev_rx_ccch_imm_ass_ctx *d)
{
	int rc;
	rc = osmo_fsm_inst_dispatch(ctx->fi,
				    GPRS_RLCMAC_TBF_DL_ASS_EV_RX_CCCH_IMM_ASS,
				    (void *)d);
	return rc;
}

/* A DL TBF assaigned was received over PACCH (of an UL TBF or previous DL TBF). */
int gprs_rlcmac_tbf_start_from_pacch(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx, const struct tbf_start_ev_rx_pacch_pkt_ass_ctx *d)
{
	int rc;
	rc = osmo_fsm_inst_dispatch(ctx->fi,
				    GPRS_RLCMAC_TBF_DL_ASS_EV_RX_PACCH_PKT_ASS,
				    (void *)d);
	return rc;
}

bool gprs_rlcmac_tbf_start_pending(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx)
{
	return ctx->fi->state == GPRS_RLCMAC_TBF_DL_ASS_ST_WAIT_TBF_STARTING_TIME;
}

/* The scheduled ticks the new FN, which may trigger changes internally if TBF Starting Time is reached */
void gprs_rlcmac_tbf_start_fn_tick(struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx, uint32_t fn, uint8_t ts_nr)
{
	OSMO_ASSERT(gprs_rlcmac_tbf_start_pending(ctx));
	if (fn != ctx->tbf_starting_time ||
	    ts_nr != ctx->ts_nr)
		return;

	osmo_fsm_inst_dispatch(ctx->fi, GPRS_RLCMAC_TBF_DL_ASS_EV_TBF_STARTING_TIME, NULL);
}

enum gprs_rlcmac_tbf_dl_ass_fsm_states gprs_rlcmac_tbf_start_state(const struct gprs_rlcmac_tbf_dl_ass_fsm_ctx *ctx)
{
	return ctx->fi->state;
}
