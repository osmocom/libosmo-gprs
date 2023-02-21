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
#include <osmocom/gprs/rlcmac/tbf_ul_ass_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/sched.h>
#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/rlcmac_enc.h>

#define X(s) (1 << (s))

static const struct value_string tbf_ul_ass_fsm_event_names[] = {
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_START,		"START" },
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_START_DIRECT_2PHASE, "START_DIRECT_2PHASE" },
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_RX_CCCH_IMM_ASS,	"RX_CCCH_IMM_ASS" },
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_CREATE_RLCMAC_MSG,	"CREATE_RLCMAC_MSG" },
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_RX_PKT_UL_ASS,	"RX_PKT_UL_ASS" },
	{ GPRS_RLCMAC_TBF_UL_ASS_EV_FOOBAR,		"FOOBAR" },
	{ 0, NULL }
};

static const struct osmo_tdef_state_timeout tbf_ul_ass_fsm_timeouts[32] = {
	[GPRS_RLCMAC_TBF_UL_ASS_ST_IDLE] = { },
	[GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_CCCH_IMM_ASS] = { },
	[GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ] = { },
	[GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_PKT_UL_ASS] = { .T = 3168 },
	[GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_CTRL_ACK] = { },
	[GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL] = { },
};

/* Transition to a state, using the T timer defined in tbf_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
 #define tbf_ul_ass_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_ul_ass_fsm_timeouts, \
				     g_ctx->T_defs, \
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

/* Generate a 8-bit CHANNEL REQUEST message as per 3GPP TS 44.018, 9.1.8 */
static uint8_t gen_chan_req(bool single_block)
{
	uint8_t rnd = (uint8_t)rand();

	if (single_block) /* 01110xxx */
		return 0x70 | (rnd & 0x07);

	/* 011110xx or 01111x0x or 01111xx0 */
	if ((rnd & 0x07) == 0x07)
		return 0x78;
	return 0x78 | (rnd & 0x07);
}

static int submit_rach_req(struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	ctx->rach_req_ra = gen_chan_req(ctx->ass_type == GPRS_RLCMAC_TBF_UL_ASS_TYPE_2PHASE);

	LOGPFSML(ctx->fi, LOGL_INFO, "Send RACH.req ra=0x%02x\n", ctx->rach_req_ra);
	rlcmac_prim = gprs_rlcmac_prim_alloc_l1ctl_rach8_req(ctx->rach_req_ra);
	return gprs_rlcmac_prim_call_down_cb(rlcmac_prim);
}

static int handle_imm_ass(struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx, const struct tbf_ul_ass_ev_rx_ccch_imm_ass_ctx *d)
{
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
					LOGPFSML(ctx->fi, LOGL_ERROR, "ImmAss SingleBlock (2phase access) not yet supported!\n");
					return -ENOTSUP;
				case 1: /* d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.* (GPRS_DynamicOrFixedAllocation_t) */
					ctx->ul_tbf->tx_cs = d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.CHANNEL_CODING_COMMAND + 1;
					LOGPFSML(ctx->fi, LOGL_INFO, "ImmAss initial CS=%s\n", gprs_rlcmac_mcs_name(ctx->ul_tbf->tx_cs));
					switch (d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.UnionType) {
					case 0: /* d->iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.Allocation.DynamicAllocation (DynamicAllocation_t) */
						/* TODO: 2phase access support: Schedule transmit of PKT_RES_REQ on FN=(GPRS_SingleBlockAllocation_t).TBF_STARTING_TIME */
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

static void st_idle_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;

	/* Reset state: */
	memset(&ctx->phase1_alloc, 0, sizeof(ctx->phase1_alloc));
	memset(&ctx->phase2_alloc, 0, sizeof(ctx->phase2_alloc));
	memset(&ctx->sched_pkt_ctrl_ack, 0, sizeof(ctx->sched_pkt_ctrl_ack));
}

static void st_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;
	switch (event) {
	case GPRS_RLCMAC_TBF_UL_ASS_EV_START:
		/* Inform the main TBF state about the assignment starting: */
		osmo_fsm_inst_dispatch(ctx->ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_UL_ASS_START, NULL);
		ctx->ass_type = *(enum gprs_rlcmac_tbf_ul_ass_type *)data;
		submit_rach_req(ctx);
		tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_CCCH_IMM_ASS);
		break;
	case GPRS_RLCMAC_TBF_UL_ASS_EV_START_DIRECT_2PHASE:
		osmo_fsm_inst_dispatch(ctx->ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_UL_ASS_START, NULL);
		ctx->ass_type = GPRS_RLCMAC_TBF_UL_ASS_TYPE_2PHASE;
		tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ);
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
	//struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;
	switch (event) {
	case GPRS_RLCMAC_TBF_UL_ASS_EV_RX_PKT_UL_ASS:
		// TODO: fill ctx->phase2_alloc with contents from pkt_ul_ass
		// TODO: what to do if Pkt_ul_ass is "reject"? need to check spec, depending on cause.
		tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_CTRL_ACK);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_sched_pkt_ctrl_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_ul_ass_fsm_ctx *)fi->priv;
	struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *data_ctx;

	switch (event) {
	case GPRS_RLCMAC_TBF_UL_ASS_EV_CREATE_RLCMAC_MSG:
		data_ctx = (struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *)data;
		LOGPFSML(fi, LOGL_ERROR, "TODO: create PKT CTRL ACK...\n");
		//data_ctx->msg = create_packet_ctrl_ack(ctx, data_ctx);
		data_ctx->msg = NULL;
		if (!data_ctx->msg)
			return;
		tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL);
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
		memcpy(&ctx->ul_tbf->cur_alloc, &ctx->phase2_alloc, sizeof(ctx->phase1_alloc));
	/* Inform the main TBF state about the assignment completed: */
	osmo_fsm_inst_dispatch(ctx->ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_UL_ASS_COMPL, NULL);
	/* Go back to IDLE state. */
	tbf_ul_ass_fsm_state_chg(fi, GPRS_RLCMAC_TBF_UL_ASS_ST_IDLE);
}

static struct osmo_fsm_state tbf_ul_ass_fsm_states[] = {
	[GPRS_RLCMAC_TBF_UL_ASS_ST_IDLE] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_START) |
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_START_DIRECT_2PHASE),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_CCCH_IMM_ASS) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ),
		.name = "IDLE",
		.onenter = st_idle_on_enter,
		.action = st_idle,
	},
	[GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_CCCH_IMM_ASS] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_RX_CCCH_IMM_ASS),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_RES_REQ) |
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL),
		.name = "WAIT_CCCH_IMM_ASS",
		.action = st_wait_ccch_imm_ass,
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
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_CTRL_ACK),
		.name = "WAIT_PKT_UL_ASS",
		.action = st_wait_pkt_ul_ass,
	},
	[GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_CTRL_ACK] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_EV_CREATE_RLCMAC_MSG),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_UL_ASS_ST_COMPL),
		.name = "SCHED_PKT_CTRL_ACK",
		.action = st_sched_pkt_ctrl_ack,
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

bool gprs_rlcmac_tbf_ul_ass_pending(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	return ul_tbf->ul_ass_fsm.fi->state != GPRS_RLCMAC_TBF_UL_ASS_ST_IDLE;
}

bool gprs_rlcmac_tbf_ul_ass_match_rach_req(struct gprs_rlcmac_ul_tbf *ul_tbf, uint8_t ra)
{
	return ul_tbf->ul_ass_fsm.fi->state == GPRS_RLCMAC_TBF_UL_ASS_ST_WAIT_CCCH_IMM_ASS &&
		ul_tbf->ul_ass_fsm.rach_req_ra == ra;
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
		return (ctx->phase1_alloc.ts[bi->ts].allocated &&
			ctx->phase1_alloc.ts[bi->ts].usf == bi->usf);
	case GPRS_RLCMAC_TBF_UL_ASS_ST_SCHED_PKT_CTRL_ACK:
		return (ctx->sched_pkt_ctrl_ack.ts == bi->ts &&
			ctx->sched_pkt_ctrl_ack.fn == bi->fn);
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
