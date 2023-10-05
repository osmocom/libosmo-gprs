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
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsm0502.h>

#include <osmocom/gprs/rlcmac/types.h>
#include <osmocom/gprs/rlcmac/tbf_ul_ass_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/sched.h>
#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/rlcmac_enc.h>
#include <osmocom/gprs/rlcmac/rlcmac_dec.h>
#include <osmocom/gprs/rlcmac/pdch_ul_controller.h>

#define X(s) (1 << (s))

static const struct value_string tbf_ul_ass_fsm_event_names[] = {
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_START,		"START" },
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_START_DIRECT_2PHASE, "START_DIRECT_2PHASE" },
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_START_FROM_DL_TBF,	"START_FROM_DL_TBF" },
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_RX_CCCH_IMM_ASS,	"RX_CCCH_IMM_ASS" },
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_TBF_STARTING_TIME,	"TBF_STARTING_TIME" },
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_CREATE_RLCMAC_MSG,	"CREATE_RLCMAC_MSG" },
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_RX_PKT_UL_ASS,	"RX_PKT_UL_ASS" },
	{ 0, NULL }
};

static const struct osmo_tdef_state_timeout tbf_ul_ass_fsm_timeouts[32] = {
	[GPRS_RLCMAC_TBF_UL_ASS_ST_IDLE] = { },
	[GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_CCCH_IMM_ASS] = { },
	[GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME1] = { },
	[GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ] = { },
	[GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_PKT_UL_ASS] = { .T = 3168 },
	[GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME2] = { },
	[GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL] = { },
};

/* Transition to a state, using the T timer defined in tbf_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
 #define tbf_ul_ass_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_ul_ass_fsm_timeouts, \
				     g_rlcmac_ctx->T_defs, \
				     -1)

static struct msgb *create_pkt_resource_req(const struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx,
					    struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *d)
{
	struct msgb *msg;
	struct bitvec bv;
	RlcMacUplink_t ul_block;
	int rc;

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "pkt_res_req");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer. */
	bv = (struct bitvec){
		.data = msgb_put(msg, GSM_MACBLOCK_LEN),
		.data_len = GSM_MACBLOCK_LEN,
	};
	bitvec_unhex(&bv, GPRS_RLCMAC_DUMMY_VEC);

	gprs_rlcmac_enc_prepare_pkt_resource_req(&ul_block, ctx->ul_tbf, GPRS_RLCMAC_ACCESS_TYPE_2PHASE_ACC_REQ);
	rc = osmo_gprs_rlcmac_encode_uplink(&bv, &ul_block);
	if (rc < 0) {
		LOGPTBFUL(ctx->ul_tbf, LOGL_ERROR, "Encoding of Packet Resource Req failed (%d)\n", rc);
		goto free_ret;
	}

	return msg;

free_ret:
	msgb_free(msg);
	return NULL;
}

static int submit_packet_access_req(const struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;

	switch (ctx->ass_type) {
	case GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE:
		/* 3GPP TS 44.018, table 9.1.8.1: cause 011110xx or 01111x0x or 01111xx0 */
		LOGPFSML(ctx->fi, LOGL_INFO, "Requesting one-phase packet access using CCCH\n");
		rlcmac_prim = gprs_rlcmac_prim_alloc_l1ctl_rach8_req(0x78);
		break;
	case GPRS_RLCMAC_TBF_UL_ASS_TYPE_2PHASE:
		/* 3GPP TS 44.018, table 9.1.8.1: cause 011110xx */
		LOGPFSML(ctx->fi, LOGL_INFO, "Requesting two-phase packet access using CCCH\n");
		rlcmac_prim = gprs_rlcmac_prim_alloc_l1ctl_rach8_req(0x70);
		break;
	default:
		/* TODO: EGPRS specific modes (11-bit RACH) */
		return -ENOTSUP;
	}

	return gprs_rlcmac_prim_call_down_cb(rlcmac_prim);
}

static int handle_imm_ass(struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx, const struct tbf_ul_ass_ev_rx_ccch_imm_ass_ctx *d)
{
	/* reset previous state: */
	memset(&ctx->phase1_alloc, 0, sizeof(ctx->phase1_alloc));
	ctx->sba = false;
	ctx->tbf_starting_time_exists = false;
	ctx->tbf_starting_time = 0;

	/* TS 44.018 10.5.2.16 IA Rest Octets */
	switch (d->iaro->UnionType) {
	case 1: /* d->iaro->u.lh.* (IA_RestOctetsLH_t) */
		switch (d->iaro->u.lh.lh0x.UnionType) {
		case 0: /* d->iaro->u.ll.lh0x.EGPRS_PktUlAss.* (IA_EGPRS_PktUlAss_t) */
			return -ENOTSUP; /* TODO */
		}
	case 3: /* d->iaro->u.hh.* (IA_RestOctetsHH_t) */
		switch (d->iaro->u.hh.UnionType) {
		case 0: /* d->iaro->u.hh.u.UplinkDownlinkAssignment.* (IA_PacketAssignment_UL_DL_t) */
			switch (d->iaro->u.hh.u.UplinkDownlinkAssignment.UnionType) {
			case 0: /* d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.* (Packet_Uplink_ImmAssignment_t) */
				switch (d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.UnionType) {
				case 0: /* d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.SingleBlockAllocation.* (GPRS_SingleBlockAllocation_t) */
					/* TODO: 2phase access support: Schedule transmit of PKT_RES_REQ on FN=(GPRS_SingleBlockAllocation_t).TBF_STARTING_TIME */
					if (ctx->ass_type == GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE) {
						LOGPFSML(ctx->fi, LOGL_INFO, "MS requested 1-Phase-Access, but Network forces 2-Phase-Access\n");
						ctx->ass_type = GPRS_RLCMAC_TBF_UL_ASS_TYPE_2PHASE;
					}
					ctx->sba = true;
					ctx->tbf_starting_time_exists = true;
					ctx->tbf_starting_time = TBF_StartingTime_to_fn(&d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.SingleBlockAllocation.TBF_STARTING_TIME,
											d->fn);
					ctx->phase1_alloc.ts[d->ts_nr].allocated = true;
					ctx->phase1_alloc.num_ts = 1;
					LOGPFSML(ctx->fi, LOGL_INFO, "ImmAss SingleBlock (2phase access) cur_tn=%u cur_fn=%u start_fn=%u\n", d->ts_nr, d->fn, ctx->tbf_starting_time);
					return 0;
				case 1: /* d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.* (GPRS_DynamicOrFixedAllocation_t) */
					ctx->phase1_alloc.ul_tfi = d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.TFI_ASSIGNMENT;
					ctx->ul_tbf->tx_cs = d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.CHANNEL_CODING_COMMAND + 1;
					ctx->tbf_starting_time_exists = d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.Exist_TBF_STARTING_TIME;
					if (ctx->tbf_starting_time_exists)
						ctx->tbf_starting_time = TBF_StartingTime_to_fn(&d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.TBF_STARTING_TIME,
												d->fn);
					LOGPFSML(ctx->fi, LOGL_INFO, "ImmAss TFI=%u initCS=%s cur_tn=%u cur_fn=%u start_fn=%u\n",
						 ctx->phase1_alloc.ul_tfi, gprs_rlcmac_mcs_name(ctx->ul_tbf->tx_cs), d->ts_nr, d->fn, ctx->tbf_starting_time);
					switch (d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.UnionType) {
					case 0: /* d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.Allocation.DynamicAllocation (DynamicAllocation_t) */
						ctx->phase1_alloc.ts[d->ts_nr].allocated = true;
						ctx->phase1_alloc.ts[d->ts_nr].usf = d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.Allocation.DynamicAllocation.USF;
						ctx->phase1_alloc.num_ts = 1;
						LOGPFSML(ctx->fi, LOGL_INFO, "ImmAss DynamicAlloc (1phase access) ts_nr=%u usf=%u\n", d->ts_nr, ctx->phase1_alloc.ts[d->ts_nr].usf);
						return 0;
					case 1: /* d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.Allocation.FixedAllocationDummy (guint8) */
						return -ENOTSUP;
					}
					break;
				}
				break;
			}
			break;
		}
		break;
	}

	OSMO_ASSERT(0);
	return -EFAULT;
}

static int handle_pkt_ul_ass(struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx, const struct tbf_ul_ass_ev_rx_pkt_ul_ass_ctx *d)
{

	const Packet_Uplink_Assignment_t *ulass = &d->dl_block->u.Packet_Uplink_Assignment;
	uint8_t tn;
	const Timeslot_Allocation_t *ts_alloc;
	const Timeslot_Allocation_Power_Ctrl_Param_t *ts_alloc_pwr_ctl;

	/* reset previous state: */
	memset(&ctx->phase2_alloc, 0, sizeof(ctx->phase2_alloc));
	ctx->sba = false;
	ctx->tbf_starting_time_exists = false;
	ctx->tbf_starting_time = 0;

	switch (ulass->UnionType) {
	case 0: /* ulass->u.PUA_GPRS_Struct.* (PUA_GPRS_t) */
		ctx->ul_tbf->tx_cs = ulass->u.PUA_GPRS_Struct.CHANNEL_CODING_COMMAND + 1;
		switch (ulass->u.PUA_GPRS_Struct.UnionType) {
		case 1: /* Dynamic Allocation (Dynamic_Allocation_t) */
			if (ulass->u.PUA_GPRS_Struct.u.Dynamic_Allocation.Exist_UPLINK_TFI_ASSIGNMENT)
				ctx->phase2_alloc.ul_tfi = ulass->u.PUA_GPRS_Struct.u.Dynamic_Allocation.UPLINK_TFI_ASSIGNMENT;
			/* TODO: P0, PR_MODE, USF_GRANULARITY, RLC_DATA_BLOCKS_GRANTED */
			ctx->tbf_starting_time_exists = ulass->u.PUA_GPRS_Struct.u.Dynamic_Allocation.Exist_TBF_Starting_Time;
			if (ctx->tbf_starting_time_exists)
				ctx->tbf_starting_time = TBF_Starting_Frame_Number_to_fn(&ulass->u.PUA_GPRS_Struct.u.Dynamic_Allocation.TBF_Starting_Time,
											 d->fn);
			switch (ulass->u.PUA_GPRS_Struct.u.Dynamic_Allocation.UnionType) {
			case 0: /* Timeslot_Allocation_t */
				ts_alloc = &ulass->u.PUA_GPRS_Struct.u.Dynamic_Allocation.u.Timeslot_Allocation[0];
				ctx->phase2_alloc.num_ts = 0;
				for (tn = 0; tn < 8; tn++) {
					ctx->phase2_alloc.ts[tn].allocated = ts_alloc[tn].Exist;
					if (ts_alloc[tn].Exist) {
						ctx->phase2_alloc.num_ts++;
						ctx->phase2_alloc.ts[tn].usf = ts_alloc[tn].USF_TN;
					}
				}
				break;
			case 1: /* Timeslot_Allocation_Power_Ctrl_Param_t */
				/* TODO: ALPHA, GAMMA */
				ts_alloc_pwr_ctl = &ulass->u.PUA_GPRS_Struct.u.Dynamic_Allocation.u.Timeslot_Allocation_Power_Ctrl_Param;
				ctx->phase2_alloc.num_ts = 0;
				for (tn = 0; tn < 8; tn++) {
					ctx->phase2_alloc.ts[tn].allocated = ts_alloc_pwr_ctl->Slot[tn].Exist;
					if (ts_alloc_pwr_ctl->Slot[tn].Exist) {
						ctx->phase2_alloc.num_ts++;
						ctx->phase2_alloc.ts[tn].usf = ts_alloc_pwr_ctl->Slot[tn].USF_TN;
					}
				}
				break;
			}
			break;
		case 2: /* Single Block Allocation */
			LOGPFSML(ctx->fi, LOGL_NOTICE, "Rx Pkt Ul Ass GPRS Single Block Allocation not supported!\n");
			return -ENOTSUP;
		case 0: /* Fixed Allocation */
			LOGPFSML(ctx->fi, LOGL_NOTICE, "Rx Pkt Ul Ass GPRS Fixed Allocation not supported!\n");
			return -ENOTSUP;
		}
		return 0;
	case 1: /* ulass->u.PUA_EGPRS_Struct.* (PUA_EGPRS_t) */
		LOGPFSML(ctx->fi, LOGL_NOTICE, "Rx Pkt Ul Ass EGPRS not supported!\n");
		return -ENOTSUP;
	}

	OSMO_ASSERT(0);
	return -EFAULT;
}

static void st_idle_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;

	/* Reset state: */
	ctx->dl_tbf = NULL;
	memset(&ctx->phase1_alloc, 0, sizeof(ctx->phase1_alloc));
	memset(&ctx->phase2_alloc, 0, sizeof(ctx->phase2_alloc));
	ctx->sba = false;
	ctx->tbf_starting_time_exists = false;
	ctx->tbf_starting_time = 0;
}

static void st_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;
	int rc;

	switch (event) {
	case GPRS_RLCMAC_TBF_UL_ASS_EV_START:
		/* Inform the main TBF state about the assignment starting: */
		osmo_fsm_inst_dispatch(ctx->ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_UL_ASS_START, NULL);
		ctx->ass_type = *(enum gprs_rlcmac_tbf_ul_ass_type *)data;
		rc = submit_packet_access_req(ctx);
		if (rc < 0) {
			osmo_fsm_inst_dispatch(ctx->ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_UL_ASS_REJ, NULL);
			break;
		}
		tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_CCCH_IMM_ASS);
		break;
	case GPRS_RLCMAC_TBF_UL_ASS_EV_START_DIRECT_2PHASE:
		osmo_fsm_inst_dispatch(ctx->ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_UL_ASS_START, NULL);
		ctx->ass_type = GPRS_RLCMAC_TBF_UL_ASS_TYPE_2PHASE;
		tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ);
		break;
	case GPRS_RLCMAC_TBF_UL_ASS_EV_START_FROM_DL_TBF:
		osmo_fsm_inst_dispatch(ctx->ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_UL_ASS_START, NULL);
		ctx->ass_type = GPRS_RLCMAC_TBF_UL_ASS_TYPE_2PHASE;
		tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_PKT_UL_ASS);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_ccch_imm_ass(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;
	const struct tbf_ul_ass_ev_rx_ccch_imm_ass_ctx *ev_rx_ccch_imm_ass_ctx;

	switch (event) {
	case GPRS_RLCMAC_TBF_UL_ASS_EV_RX_CCCH_IMM_ASS:
		ev_rx_ccch_imm_ass_ctx = data;
		if (handle_imm_ass(ctx, ev_rx_ccch_imm_ass_ctx) < 0)
			return;
		if (ctx->tbf_starting_time_exists &&
		    gsm0502_fncmp(ctx->tbf_starting_time, ev_rx_ccch_imm_ass_ctx->fn) > 0) {
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME1);
			return;
		}
		if (ctx->ass_type == GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE)
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL);
		else
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_tbf_starting_time1_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;

	/* Configure lower layers to submit an RTS tick starting at tbf_starting_time
	 * and scheduler will send event  GPRS_RLCMAC_TBF_UL_ASS_EV_TBF_STARTING_TIME to us. */
	gprs_rlcmac_ul_tbf_submit_configure_req(ctx->ul_tbf, &ctx->phase1_alloc,
						ctx->tbf_starting_time_exists, ctx->tbf_starting_time);
}

static void st_wait_tbf_starting_time1(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;
	const struct tbf_ul_ass_ev_rx_ccch_imm_ass_ctx *ev_rx_ccch_imm_ass_ctx;

	switch (event) {
	case GPRS_RLCMAC_TBF_UL_ASS_EV_RX_CCCH_IMM_ASS:
		ev_rx_ccch_imm_ass_ctx = data;
		if (handle_imm_ass(ctx, ev_rx_ccch_imm_ass_ctx) < 0)
			return;
		if (ctx->tbf_starting_time_exists &&
		    gsm0502_fncmp(ctx->tbf_starting_time, ev_rx_ccch_imm_ass_ctx->fn) > 0) {
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME1);
			return;
		}
		if (ctx->ass_type == GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE)
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL);
		else
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ);
		break;
	case GPRS_RLCMAC_TBF_UL_ASS_EV_TBF_STARTING_TIME:
		if (ctx->ass_type == GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE)
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL);
		else
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_sched_pkt_res_req(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;
	struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *data_ctx;
	switch (event) {
	case GPRS_RLCMAC_TBF_UL_ASS_EV_CREATE_RLCMAC_MSG:
		data_ctx = (struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *)data;
		data_ctx->msg = create_pkt_resource_req(ctx, data_ctx);
		if (!data_ctx->msg)
			return;
		tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_PKT_UL_ASS);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_pkt_ul_ass(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;
	struct tbf_ul_ass_ev_rx_pkt_ul_ass_ctx *d;
	int rc;

	switch (event) {
	case GPRS_RLCMAC_TBF_UL_ASS_EV_RX_PKT_UL_ASS:
		d = data;
		rc = handle_pkt_ul_ass(ctx, d);
		if (rc < 0)
			LOGPFSML(fi, LOGL_ERROR, "Rx Pkt Ul Ass: failed to parse!\n");
		// TODO: what to do if Pkt_ul_ass is "reject"? need to check spec, depending on cause.
		/* If RRBP contains valid data, schedule a response (PKT CONTROL ACK or PKT RESOURCE REQ). */
		if (d->dl_block->SP) {
			uint32_t poll_fn = rrbp2fn(d->fn, d->dl_block->RRBP);
			uint32_t next_blk = fn_next_block(fn_next_block(poll_fn));
			gprs_rlcmac_pdch_ulc_reserve(g_rlcmac_ctx->sched.ulc[d->ts_nr], poll_fn,
						GPRS_RLCMAC_PDCH_ULC_POLL_UL_ASS,
						ul_tbf_as_tbf(ctx->ul_tbf));
			/* We need to wait at least until sending the PKT CTRL
			 * ACK (in the old CTRL TS) before completing the
			 * assignment and using the new TS assignment. */
			if (!ctx->tbf_starting_time_exists || gsm0502_fncmp(ctx->tbf_starting_time, next_blk) < 0) {
				ctx->tbf_starting_time_exists = true;
				ctx->tbf_starting_time = next_blk;
			}
		}

		if (ctx->tbf_starting_time_exists &&
		    gsm0502_fncmp(ctx->tbf_starting_time, d->fn) > 0) {
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME2);
		} else {
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_tbf_starting_time2_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;

	/* Configure lower layers to submit an RTS tick starting at tbf_starting_time
	 * and scheduler will send event GPRS_RLCMAC_TBF_UL_ASS_EV_TBF_STARTING_TIME to us. */
	gprs_rlcmac_ul_tbf_submit_configure_req(ctx->ul_tbf, &ctx->phase2_alloc,
						ctx->tbf_starting_time_exists, ctx->tbf_starting_time);
}

static void st_wait_tbf_starting_time2(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;
	struct tbf_ul_ass_ev_rx_pkt_ul_ass_ctx *d;
	struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *data_ctx;
	int rc;

	switch (event) {
	case GPRS_RLCMAC_TBF_UL_ASS_EV_RX_PKT_UL_ASS:
		d = data;
		rc = handle_pkt_ul_ass(ctx, d);
		if (rc < 0)
			LOGPFSML(fi, LOGL_ERROR, "Rx Pkt Ul Ass: failed to parse!\n");
		// TODO: what to do if Pkt_ul_ass is "reject"? need to check spec, depending on cause.
		/* If RRBP contains valid data, schedule a response (PKT CONTROL ACK or PKT RESOURCE REQ). */
		if (d->dl_block->SP) {
			uint32_t poll_fn = rrbp2fn(d->fn, d->dl_block->RRBP);
			uint32_t next_blk = fn_next_block(poll_fn);
			/* FIXME: double fn_next_block() here is to delay
			* release of old TS late enough so that the PKT CTRL ACK
			* is transmitted. This is wrong since we basically lose
			* the first TS in the new TBF, but otherwise lower layers
			* may free the lchan while last burst of the last block is
			* still not transmitted... IMHO lower layers need to be
			* fixed to delay closing the lchan until all the
			* blocks/bursts enqueued are transmitted... */
			next_blk = fn_next_block(next_blk);
			gprs_rlcmac_pdch_ulc_reserve(g_rlcmac_ctx->sched.ulc[d->ts_nr], poll_fn,
						GPRS_RLCMAC_PDCH_ULC_POLL_UL_ASS,
						ul_tbf_as_tbf(ctx->ul_tbf));
			/* We need to wait at least until sending the PKT CTRL
			 * ACK (in the old CTRL TS) before completing the
			 * assignment and using the new TS assignment. */
			if (!ctx->tbf_starting_time_exists || gsm0502_fncmp(ctx->tbf_starting_time, next_blk) < 0) {
				ctx->tbf_starting_time_exists = true;
				ctx->tbf_starting_time = next_blk;
			}
		}

		if (ctx->tbf_starting_time_exists &&
		    gsm0502_fncmp(ctx->tbf_starting_time, d->fn) > 0) {
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME2);
		} else {
			tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL);
		}
		break;
	case GPRS_RLCMAC_TBF_UL_ASS_EV_TBF_STARTING_TIME:
		tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL);
		break;
	case GPRS_RLCMAC_TBF_UL_ASS_EV_CREATE_RLCMAC_MSG:
		data_ctx = (struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *)data;
		LOGPFSML(fi, LOGL_INFO, "TS=%u FN=%u Tx Pkt Ctrl Ack\n", data_ctx->ts, data_ctx->fn);
		data_ctx->msg = gprs_rlcmac_gre_create_pkt_ctrl_ack(ul_tbf_as_tbf(ctx->ul_tbf)->gre);
		if (!data_ctx->msg)
			return;
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_compl_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;

	/* Update TBF with allocated content: */
	if (ctx->ass_type == GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE)
		memcpy(&ctx->ul_tbf->cur_alloc, &ctx->phase1_alloc, sizeof(ctx->phase1_alloc));
	else
		memcpy(&ctx->ul_tbf->cur_alloc, &ctx->phase2_alloc, sizeof(ctx->phase2_alloc));
	/* Inform the main TBF state about the assignment completed: */
	osmo_fsm_inst_dispatch(ctx->ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_UL_ASS_COMPL, NULL);
	/* Go back to IDLE state. */
	tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_IDLE);
}

static struct osmo_fsm_state tbf_ul_ass_fsm_states[] = {
	[GPRS_RLCMAC_TBF_UL_ASS_ST_IDLE] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_START) |
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_START_DIRECT_2PHASE) |
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_START_FROM_DL_TBF),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_CCCH_IMM_ASS) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_PKT_UL_ASS),
		.name = "IDLE",
		.onenter = st_idle_on_enter,
		.action = st_idle,
	},
	[GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_CCCH_IMM_ASS] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_RX_CCCH_IMM_ASS),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME1) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL),
		.name = "WAIT_CCCH_IMM_ASS",
		.action = st_wait_ccch_imm_ass,
	},
	[GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME1] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_RX_CCCH_IMM_ASS) |
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_TBF_STARTING_TIME),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME1) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL),
		.name = "WAIT_TBF_STARTING_TIME1",
		.onenter = st_wait_tbf_starting_time1_on_enter,
		.action = st_wait_tbf_starting_time1,
	},
	[GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_CREATE_RLCMAC_MSG),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_PKT_UL_ASS),
		.name = "SCHED_PKT_RES_REQ",
		.action = st_sched_pkt_res_req,
	},
	[GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_PKT_UL_ASS] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_RX_PKT_UL_ASS),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME2) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL),
		.name = "WAIT_PKT_UL_ASS",
		.action = st_wait_pkt_ul_ass,
	},
	[GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME2] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_RX_PKT_UL_ASS) |
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_TBF_STARTING_TIME) |
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_CREATE_RLCMAC_MSG),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME2) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL),
		.name = "WAIT_TBF_STARTING_TIME2",
		.onenter = st_wait_tbf_starting_time2_on_enter,
		.action = st_wait_tbf_starting_time2,
	},
	[GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL] = {
		.in_event_mask = 0,
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_IDLE),
		.name = "COMPLETED",
		.onenter = st_compl_on_enter,
	},
};


static int tbf_ul_ass_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;
	switch (fi->T) {
	case 3168:
		/* If the UL TBF assignment was started from DL TBF it is not
		really possible reattempting because we haven't yet any phase1
		allocation. Hence simply destroy the TBF and let next DL TBF DL
		ACK/NACK re-request an UL TBF assignment: */
		if (ctx->dl_tbf) {
			LOGPFSML(ctx->fi, LOGL_NOTICE,
				 "UL TBF establishment failure (T3168 timeout attempts=%u, ass from DL TBF)\n",
				 ctx->pkt_res_req_proc_attempts);
			gprs_rlcmac_ul_tbf_free(ctx->ul_tbf);
			return 0;
		}
		/* TS 44.060 7.1.3.3: "the mobile station shall then reinitiate the packet access
		 * procedure unless the packet access procedure has already been attempted four
		 * times. In that case, TBF failure has occurred and an RLC/MAC error should be
		 * reported to the higher layer for each of the TBFs for which resources were
		 * requested". */
		ctx->pkt_res_req_proc_attempts++;
		LOGPFSML(ctx->fi, LOGL_INFO, "T3168 timeout attempts=%u\n", ctx->pkt_res_req_proc_attempts);
		OSMO_ASSERT(fi->state == GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_PKT_UL_ASS);
		if (ctx->pkt_res_req_proc_attempts == 4) {
			LOGPFSML(ctx->fi, LOGL_NOTICE, "TBF establishment failure (T3168 timeout attempts=%u)\n",
				 ctx->pkt_res_req_proc_attempts);
			gprs_rlcmac_ul_tbf_free(ctx->ul_tbf);
			return 0;
		}
		tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm tbf_ul_ass_fsm = {
	.name = "UL_TBF_ASS",
	.states = tbf_ul_ass_fsm_states,
	.num_states = ARRAY_SIZE(tbf_ul_ass_fsm_states),
	.timer_cb = tbf_ul_ass_fsm_timer_cb,
	.log_subsys = DLGLOBAL, /* updated dynamically through gprs_rlcmac_tbf_ul_ass_fsm_set_log_cat() */
	.event_names = tbf_ul_ass_fsm_event_names,
};

int gprs_rlcmac_tbf_ul_ass_fsm_init(void)
{
	return osmo_fsm_register(&tbf_ul_ass_fsm);
}

void gprs_rlcmac_tbf_ul_ass_fsm_set_log_cat(int logcat)
{
	tbf_ul_ass_fsm.log_subsys = logcat;
}

int gprs_rlcmac_tbf_ul_ass_fsm_constructor(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = &ul_tbf->ul_ass_fsm;
	ctx->ul_tbf = ul_tbf;
	ctx->fi = osmo_fsm_inst_alloc(&tbf_ul_ass_fsm, ul_tbf, ctx, LOGL_INFO, NULL);
	if (!ctx->fi)
		return -ENODATA;

	return 0;
}

void gprs_rlcmac_tbf_ul_ass_fsm_destructor(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = &ul_tbf->ul_ass_fsm;
	osmo_fsm_inst_free(ctx->fi);
	ctx->fi = NULL;
}

int gprs_rlcmac_tbf_ul_ass_start(struct gprs_rlcmac_ul_tbf *ul_tbf, enum gprs_rlcmac_tbf_ul_ass_type type)
{
	int rc;
	rc = osmo_fsm_inst_dispatch(ul_tbf->ul_ass_fsm.fi,
				    GPRS_RLCMAC_TBF_UL_ASS_EV_START,
				    &type);
	return rc;
}

/* A releasing TBF being polled is used to fill in 1phase access internally and
* switch the FSM to trigger the 2hpase directly (tx Pkt Res Req) */
int gprs_rlcmac_tbf_ul_ass_start_from_releasing_ul_tbf(struct gprs_rlcmac_ul_tbf *ul_tbf, struct gprs_rlcmac_ul_tbf *old_ul_tbf)
{
	int rc;
	memcpy(&ul_tbf->ul_ass_fsm.phase1_alloc, &old_ul_tbf->cur_alloc,
	       sizeof(ul_tbf->ul_ass_fsm.phase1_alloc));
	rc = osmo_fsm_inst_dispatch(ul_tbf->ul_ass_fsm.fi,
				    GPRS_RLCMAC_TBF_UL_ASS_EV_START_DIRECT_2PHASE,
				    NULL);
	return rc;
}

/* A DL-TBF requested a UL TBF over DL ACK/NACK, wait to receive Pkt Ul Ass for
 * it, aka switch the FSM to trigger the 2hpase directly (tx Pkt Res Req) */
int gprs_rlcmac_tbf_ul_ass_start_from_dl_tbf_ack_nack(struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_dl_tbf *dl_tbf, uint8_t tn)
{
	int rc;
	ul_tbf->ul_ass_fsm.dl_tbf = dl_tbf;

	/* The TS where the PKT UL ASS is to be received is the one where the DL
	 * ACK/NACK was sent in the DL TBF (control TS): */
	ul_tbf->ul_ass_fsm.phase1_alloc.num_ts = 1;
	ul_tbf->ul_ass_fsm.phase1_alloc.ts[tn].allocated = true;
	ul_tbf->ul_ass_fsm.phase1_alloc.ts[tn].usf = 0xff;

	rc = osmo_fsm_inst_dispatch(ul_tbf->ul_ass_fsm.fi,
				    GPRS_RLCMAC_TBF_UL_ASS_EV_START_FROM_DL_TBF,
				    NULL);
	return rc;
}

bool gprs_rlcmac_tbf_ul_ass_pending(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	return ul_tbf->ul_ass_fsm.fi->state != GPRS_RLCMAC_TBF_UL_ASS_ST_IDLE;
}

bool gprs_rlcmac_tbf_ul_ass_wait_ccch_imm_ass(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	return ul_tbf->ul_ass_fsm.fi->state == GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_CCCH_IMM_ASS;
}

bool gprs_rlcmac_tbf_ul_ass_waiting_tbf_starting_time(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	return ul_tbf->ul_ass_fsm.fi->state == GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME1 ||
	       ul_tbf->ul_ass_fsm.fi->state == GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME2;
}

/* The scheduled ticks the new FN, which may trigger changes internally if TBF Starting Time is reached */
void gprs_rlcmac_tbf_ul_ass_fn_tick(const struct gprs_rlcmac_ul_tbf *ul_tbf, uint32_t fn, uint8_t ts_nr)
{
	int res;

	OSMO_ASSERT(ul_tbf->ul_ass_fsm.tbf_starting_time_exists);
	switch (ul_tbf->ul_ass_fsm.fi->state) {
	case GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME1:
		OSMO_ASSERT(ul_tbf->ul_ass_fsm.phase1_alloc.num_ts > 0);
		if (!ul_tbf->ul_ass_fsm.phase1_alloc.ts[ts_nr].allocated)
			return;
		break;
	case GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_TBF_STARTING_TIME2:
		OSMO_ASSERT(ul_tbf->ul_ass_fsm.phase2_alloc.num_ts > 0);
		if (!ul_tbf->ul_ass_fsm.phase2_alloc.ts[ts_nr].allocated)
			return;
		break;
	default:
		OSMO_ASSERT(0);
	}
	res = gsm0502_fncmp(fn, ul_tbf->ul_ass_fsm.tbf_starting_time);
	if (res < 0) {/* fn BEFORE tbf_starting_time */
		LOGPTBFUL(ul_tbf, LOGL_DEBUG, "TS=%" PRIu8 " FN=%u Waiting for tbf_starting_time=%u\n",
			  ts_nr, fn, ul_tbf->ul_ass_fsm.tbf_starting_time);
		return;
	}
	if (res > 0) /* fn AFTER tbf_starting time */
		LOGPTBFUL(ul_tbf, LOGL_ERROR, "TS=%" PRIu8 " FN=%u Received late tick for tbf_starting_time=%u!\n",
			  ts_nr, fn, ul_tbf->ul_ass_fsm.tbf_starting_time);
	/* fn == tbf_starting time */
	LOGPTBFUL(ul_tbf, LOGL_INFO, "TS=%" PRIu8 " FN=%u TBF_STARTING_TIME reached\n", fn, ts_nr);
	osmo_fsm_inst_dispatch(ul_tbf->ul_ass_fsm.fi, GPRS_RLCMAC_TBF_UL_ASS_EV_TBF_STARTING_TIME, NULL);
}

enum gprs_rlcmac_tbf_ul_ass_fsm_states gprs_rlcmac_tbf_ul_ass_state(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	const struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = &ul_tbf->ul_ass_fsm;
	return ctx->fi->state;
}

bool gprs_rlcmac_tbf_ul_ass_rts(const struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi)
{
	const struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = &ul_tbf->ul_ass_fsm;

	switch (ctx->fi->state) {
	case GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ:
		if (!ctx->phase1_alloc.ts[bi->ts].allocated)
			return false;
		if (ctx->sba)
			return (!ctx->tbf_starting_time_exists || ctx->tbf_starting_time == bi->fn);
		/* No SBA, check assigned USF: */
		return ctx->phase1_alloc.ts[bi->ts].usf == bi->usf;
	default:
		return false;
	};
}

struct msgb *gprs_rlcmac_tbf_ul_ass_create_rlcmac_msg(const struct gprs_rlcmac_ul_tbf *ul_tbf,
						      const struct gprs_rlcmac_rts_block_ind *bi)
{
	int rc;
	struct tbf_ul_ass_ev_create_rlcmac_msg_ctx data_ctx = {
		.ts = bi->ts,
		.fn = bi->fn,
		.msg = NULL,
	};

	rc = osmo_fsm_inst_dispatch(ul_tbf->ul_ass_fsm.fi,
				    GPRS_RLCMAC_TBF_UL_ASS_EV_CREATE_RLCMAC_MSG,
				    &data_ctx);
	if (rc != 0 || !data_ctx.msg)
		return NULL;
	return data_ctx.msg;
}
