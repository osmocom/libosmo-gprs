/* SM states in the MS, 3GPP TS 24.008 § 6.1.2.1 */
/*
 * (C) 2023 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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
 */
#include <errno.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/utils.h>

#include <osmocom/gprs/sm/sm_ms_fsm.h>
#include <osmocom/gprs/sm/sm.h>
#include <osmocom/gprs/sm/sm_private.h>

#define X(s) (1 << (s))

#define TIMER_DELAY_FREE 0

static const struct osmo_tdef_state_timeout sm_ms_fsm_timeouts[32] = {
	[GPRS_SM_MS_ST_PDP_INACTIVE] = {},
	[GPRS_SM_MS_ST_PDP_ACTIVE_PENDING] = { .T = 3380 },
	[GPRS_SM_MS_ST_PDP_ACTIVE] = {},
	[GPRS_SM_MS_ST_PDP_MODIFY_PENDING] = {},
	[GPRS_SM_MS_ST_PDP_INACTIVE_PENDING] = {},
};

#define sm_ms_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, sm_ms_fsm_timeouts, g_sm_ctx->T_defs, -1)

static void st_sm_ms_pdp_inactive_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	/* PDP became inactive, there's no use in keeping it.
	 * Schedule asynchronous release of PDP. It will automatically be
	 * aborted as a consequence of changing state if user decides to
	 * automatically activate the PDP ctx in this same code path as an
	 * answer to a primitive submitted to it. */
	fi->T = TIMER_DELAY_FREE;
	osmo_timer_schedule(&fi->timer, 0, 0);
}

static void st_sm_ms_pdp_inactive(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_SM_MS_EV_TX_ACT_PDP_CTX_REQ:
		sm_ms_fsm_state_chg(fi, GPRS_SM_MS_ST_PDP_ACTIVE_PENDING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_sm_ms_pdp_active_pending_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gprs_sm_ms_fsm_ctx *ctx = (struct gprs_sm_ms_fsm_ctx *)fi->priv;

	gprs_sm_submit_gmmsm_assign_req(ctx->sme);
}

static void st_sm_ms_pdp_active_pending(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_sm_ms_fsm_ctx *ctx = (struct gprs_sm_ms_fsm_ctx *)fi->priv;

	switch (event) {
	case GPRS_SM_MS_EV_RX_GMM_ESTABLISH_CNF:
		gprs_sm_tx_act_pdp_ctx_req(ctx->sme);
		break;
	case GPRS_SM_MS_EV_RX_GMM_ESTABLISH_REJ:
		sm_ms_fsm_state_chg(fi, GPRS_SM_MS_ST_PDP_INACTIVE);
		break;
	case GPRS_SM_MS_EV_RX_ACT_PDP_CTX_REJ:
		sm_ms_fsm_state_chg(fi, GPRS_SM_MS_ST_PDP_INACTIVE);
		gprs_sm_submit_smreg_pdp_act_cnf(ctx->sme, *((enum gsm48_gsm_cause *)data));
		break;
	case GPRS_SM_MS_EV_RX_ACT_PDP_CTX_ACC:
		gprs_sm_submit_snsm_act_ind(ctx->sme);
		/* Submitting SMREG-PDP-ACT-CNF is delayed until ,
		 * SNSM-ACTIVATE-RSP (GPRS_SM_MS_EV_NSAPI_ACTIVATED) is received
		 * from SNDCP, see TS 24.007 C.6 */
		break;
	case GPRS_SM_MS_EV_NSAPI_ACTIVATED:
		/* see TS 24.007 C.6 */
		sm_ms_fsm_state_chg(fi, GPRS_SM_MS_ST_PDP_ACTIVE);
		gprs_sm_submit_smreg_pdp_act_cnf(ctx->sme, (enum gsm48_gsm_cause)0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_sm_ms_pdp_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_SM_MS_EV_RX_DEACT_PDP_CTX_REQ:
		/* TODO: Tx PDP DEACT ACC */
		sm_ms_fsm_state_chg(fi, GPRS_SM_MS_ST_PDP_INACTIVE);
		break;
	case GPRS_SM_MS_EV_TX_DEACT_PDP_CTX_REQ:
		sm_ms_fsm_state_chg(fi, GPRS_SM_MS_ST_PDP_INACTIVE_PENDING);
		break;
	case GPRS_SM_MS_EV_TX_MOD_PDP_CTX_REQ:
		sm_ms_fsm_state_chg(fi, GPRS_SM_MS_ST_PDP_MODIFY_PENDING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_sm_ms_pdp_modify_pending(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_SM_MS_EV_RX_DEACT_PDP_CTX_REQ:
		/* TODO: Tx PDP DEACT ACC */
		sm_ms_fsm_state_chg(fi, GPRS_SM_MS_ST_PDP_INACTIVE);
		break;
	case GPRS_SM_MS_EV_RX_MOD_PDP_CTX_REJ:
		sm_ms_fsm_state_chg(fi, GPRS_SM_MS_ST_PDP_INACTIVE_PENDING);
		break;
	case GPRS_SM_MS_EV_RX_MOD_PDP_CTX_ACC:
		sm_ms_fsm_state_chg(fi, GPRS_SM_MS_ST_PDP_ACTIVE);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_sm_ms_pdp_inactive_pending(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_SM_MS_EV_RX_DEACT_PDP_CTX_ACC:
		sm_ms_fsm_state_chg(fi, GPRS_SM_MS_ST_PDP_INACTIVE);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int sm_ms_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct gprs_sm_ms_fsm_ctx *ctx = (struct gprs_sm_ms_fsm_ctx *)fi->priv;

	switch (fi->T) {
	case TIMER_DELAY_FREE:
		gprs_sm_entity_free(ctx->sme);
		break;
	case 3380:
		ctx->act_pdp_ctx_attempts++;
		LOGPFSML(ctx->fi, LOGL_INFO, "T3380 timeout attempts=%u\n", ctx->act_pdp_ctx_attempts);
		OSMO_ASSERT(fi->state == GPRS_SM_MS_ST_PDP_ACTIVE_PENDING);
		if (ctx->act_pdp_ctx_attempts == 4) {
			enum gsm48_gsm_cause cause = GSM_CAUSE_SERV_OPT_TEMP_OOO;
			/* TS 24.008 6.1.3.1.5:
			 * "On the first expiry of the timer T3380, the MS shall resend the ACTIVATE PDP
			 * CONTEXT REQUEST and shall reset and restart timer T3380. This retransmission is
			 * repeated four times, i.e. on the fifth expiry of timer T3380, the MS shall release
			 * all resources possibly allocated for this invocation and shall abort the procedure"
			 */
			LOGPFSML(ctx->fi, LOGL_NOTICE, "TBF establishment failure (T3380 timeout attempts=%u)\n",
				 ctx->act_pdp_ctx_attempts);

			osmo_fsm_inst_dispatch(ctx->fi, GPRS_SM_MS_EV_RX_ACT_PDP_CTX_REJ, &cause);
			return 0;
		}
		/* reinit tx of Act Pdp Ctx Req and rearm timer by re-entering state: */
		sm_ms_fsm_state_chg(ctx->fi, GPRS_SM_MS_ST_PDP_ACTIVE_PENDING);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm_state sm_ms_fsm_states[] = {
	[GPRS_SM_MS_ST_PDP_INACTIVE] = {
		.in_event_mask =
			X(GPRS_SM_MS_EV_TX_ACT_PDP_CTX_REQ),
		.out_state_mask =
			X(GPRS_SM_MS_ST_PDP_ACTIVE_PENDING),
		.name = "INACTIVE",
		.onenter = st_sm_ms_pdp_inactive_on_enter,
		.action = st_sm_ms_pdp_inactive,
	},
	[GPRS_SM_MS_ST_PDP_ACTIVE_PENDING] = {
		.in_event_mask =
			X(GPRS_SM_MS_EV_RX_GMM_ESTABLISH_CNF) |
			X(GPRS_SM_MS_EV_RX_GMM_ESTABLISH_REJ) |
			X(GPRS_SM_MS_EV_RX_ACT_PDP_CTX_REJ) |
			X(GPRS_SM_MS_EV_RX_ACT_PDP_CTX_ACC) |
			X(GPRS_SM_MS_EV_NSAPI_ACTIVATED),
		.out_state_mask =
			X(GPRS_SM_MS_ST_PDP_INACTIVE) |
			X(GPRS_SM_MS_ST_PDP_ACTIVE_PENDING) |
			X(GPRS_SM_MS_ST_PDP_ACTIVE),
		.name = "PDP_ACTIVE_PENDING",
		.onenter = st_sm_ms_pdp_active_pending_on_enter,
		.action = st_sm_ms_pdp_active_pending,
	},
	[GPRS_SM_MS_ST_PDP_ACTIVE] = {
		.in_event_mask =
			X(GPRS_SM_MS_EV_RX_DEACT_PDP_CTX_REQ) |
			X(GPRS_SM_MS_EV_TX_DEACT_PDP_CTX_REQ)|
			X(GPRS_SM_MS_EV_TX_MOD_PDP_CTX_REQ),
		.out_state_mask =
			X(GPRS_SM_MS_ST_PDP_INACTIVE) |
			X(GPRS_SM_MS_ST_PDP_INACTIVE_PENDING) |
			X(GPRS_SM_MS_ST_PDP_MODIFY_PENDING),
		.name = "PDP_ACTIVE",
		.action = st_sm_ms_pdp_active,
	},
	[GPRS_SM_MS_ST_PDP_MODIFY_PENDING] = {
		.in_event_mask =
			X(GPRS_SM_MS_EV_RX_DEACT_PDP_CTX_REQ) |
			X(GPRS_SM_MS_EV_RX_MOD_PDP_CTX_REJ) |
			X(GPRS_SM_MS_EV_RX_MOD_PDP_CTX_ACC),
		.out_state_mask =
			X(GPRS_SM_MS_ST_PDP_INACTIVE) |
			X(GPRS_SM_MS_ST_PDP_ACTIVE) |
			X(GPRS_SM_MS_ST_PDP_INACTIVE_PENDING),
		.name = "PDP_MODIFY_PENDING",
		.action = st_sm_ms_pdp_modify_pending,
	},
	[GPRS_SM_MS_ST_PDP_INACTIVE_PENDING] = {
		.in_event_mask =
			X(GPRS_SM_MS_EV_RX_DEACT_PDP_CTX_ACC),
		.out_state_mask =
			X(GPRS_SM_MS_ST_PDP_INACTIVE),
		.name = "PDP_INACTIVE_PENDING",
		.action = st_sm_ms_pdp_inactive_pending,
	},
};

const struct value_string sm_ms_fsm_event_names[] = {
	{ GPRS_SM_MS_EV_RX_GMM_ESTABLISH_CNF,	"RX GMM_ESTABLISH_CNF" },
	{ GPRS_SM_MS_EV_RX_GMM_ESTABLISH_REJ,	"RX GMM_ESTABLISH_REJ" },
	{ GPRS_SM_MS_EV_TX_ACT_PDP_CTX_REQ,	"TX_ACT_PDP_CTX_REQ" },
	{ GPRS_SM_MS_EV_RX_ACT_PDP_CTX_REJ,	"RX_ACT_PDP_CTX_REJ" },
	{ GPRS_SM_MS_EV_RX_ACT_PDP_CTX_ACC,	"RX_ACT_PDP_CTX_ACC" },
	{ GPRS_SM_MS_EV_NSAPI_ACTIVATED,	"NSAPI_ACTIVATED" },
	{ GPRS_SM_MS_EV_TX_DEACT_PDP_CTX_REQ,	"TX_DEACT_PDP_CTX_REQ" },
	{ GPRS_SM_MS_EV_RX_DEACT_PDP_CTX_REQ,	"RX_DEACT_PDP_CTX_REQ" },
	{ GPRS_SM_MS_EV_RX_DEACT_PDP_CTX_ACC,	"RX_DEACT_PDP_CTX_ACC" },
	{ GPRS_SM_MS_EV_TX_MOD_PDP_CTX_REQ,	"TX_MOD_PDP_CTX_REQ" },
	{ GPRS_SM_MS_EV_RX_MOD_PDP_CTX_REJ,	"RX_MOD_PDP_CTX_REJ" },
	{ GPRS_SM_MS_EV_RX_MOD_PDP_CTX_ACC,	"RX_MOD_PDP_CTX_ACC" },
	{ 0, NULL }
};

struct osmo_fsm sm_ms_fsm = {
	.name = "SM_MS",
	.states = sm_ms_fsm_states,
	.num_states = ARRAY_SIZE(sm_ms_fsm_states),
	.timer_cb = sm_ms_fsm_timer_cb,
	.event_names = sm_ms_fsm_event_names,
	.log_subsys = DLGLOBAL, /* updated dynamically through gprs_sm_ms_fsm_set_log_cat() */
	.timer_cb = sm_ms_fsm_timer_cb,
};

int gprs_sm_ms_fsm_init(void)
{
	return osmo_fsm_register(&sm_ms_fsm);
}

void gprs_sm_ms_fsm_set_log_cat(int logcat)
{
	sm_ms_fsm.log_subsys = logcat;
}

int gprs_sm_ms_fsm_ctx_init(struct gprs_sm_ms_fsm_ctx *ctx, struct gprs_sm_entity *sme)
{
	ctx->sme = sme;
	ctx->fi = osmo_fsm_inst_alloc(&sm_ms_fsm, sme, ctx, LOGL_INFO, NULL);
	if (!ctx->fi)
		return -ENODATA;

	return 0;
}

void gprs_sm_ms_fsm_ctx_release(struct gprs_sm_ms_fsm_ctx *ctx)
{
	osmo_fsm_inst_free(ctx->fi);
}
