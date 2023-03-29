/* GMM states in the MS, 3GPP TS 24.008 § 4.1.3.1 */
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
#include <osmocom/core/tdef.h>

#include <osmocom/gprs/gmm/gmm_ms_fsm.h>
#include <osmocom/gprs/gmm/gmm.h>
#include <osmocom/gprs/gmm/gmm_private.h>

#define X(s) (1 << (s))

static const struct osmo_tdef_state_timeout gmm_ms_fsm_timeouts[32] = {};

#define gmm_ms_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, gmm_ms_fsm_timeouts, g_ctx->T_defs, -1)

static void st_gmm_ms_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_GMM_MS_EV_ENABLE_GPRS_MODE:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_DEREGISTERED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_gmm_ms_deregistered(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_GMM_MS_EV_DISABLE_GPRS_MODE:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_NULL);
		break;
	case GPRS_GMM_MS_EV_ATTACH_REQUESTED:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_REGISTERED_INITIATED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_gmm_ms_registered_initiated(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_GMM_MS_EV_ATTACH_REJECTED:
	case GPRS_GMM_MS_EV_LOW_LVL_FAIL:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_DEREGISTERED);
		break;
	case GPRS_GMM_MS_EV_ATTACH_ACCEPTED:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_REGISTERED);
		break;
	case GPRS_GMM_MS_EV_DETACH_REQUESTED:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_DEREGISTERED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_gmm_ms_registered(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_gmm_ms_fsm_ctx *ctx = (struct gprs_gmm_ms_fsm_ctx *)fi->priv;
	switch (event) {
	case GPRS_GMM_MS_EV_SR_REQUESTED:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_REGISTERED);
		break;
	case GPRS_GMM_MS_EV_RAU_REQUESTED:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_RAU_INITIATED);
		break;
	case GPRS_GMM_MS_EV_DETACH_REQUESTED:
		ctx->detach_type = *((enum osmo_gprs_gmm_detach_ms_type *)data);
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_DEREGISTERED_INITIATED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_gmm_ms_deregistered_initiated(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_GMM_MS_EV_DETACH_ACCEPTED:
	case GPRS_GMM_MS_EV_LOW_LVL_FAIL:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_DEREGISTERED);
		break;
	case GPRS_GMM_MS_EV_RAU_ACCEPTED:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_REGISTERED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_gmm_ms_rau_initiated(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_GMM_MS_EV_RAU_REJECTED:
		// causes #13, #15, #25
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_REGISTERED);
		// else
		//mm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_DEREGISTERED_INITIATED);
		break;
	case GPRS_GMM_MS_EV_RAU_ACCEPTED:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_REGISTERED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_gmm_ms_sr_initiated(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_GMM_MS_EV_SR_REJECTED:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_REGISTERED);
		break;
	case GPRS_GMM_MS_EV_SR_ACCEPTED:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_REGISTERED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

void gmm_ms_fsm_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case GPRS_GMM_MS_EV_DETACH_REQUESTED_POWEROFF:
		gmm_ms_fsm_state_chg(fi, GPRS_GMM_MS_ST_DEREGISTERED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static struct osmo_fsm_state gmm_ms_fsm_states[] = {
	[GPRS_GMM_MS_ST_NULL] = {
		.in_event_mask =
			X(GPRS_GMM_MS_EV_ENABLE_GPRS_MODE),
		.out_state_mask =
			X(GPRS_GMM_MS_ST_DEREGISTERED),
		.name = "Null",
		.action = st_gmm_ms_null,
	},
	[GPRS_GMM_MS_ST_DEREGISTERED] = {
		.in_event_mask =
			X(GPRS_GMM_MS_EV_DISABLE_GPRS_MODE) |
			X(GPRS_GMM_MS_EV_ATTACH_REQUESTED),
		.out_state_mask =
			X(GPRS_GMM_MS_ST_NULL) |
			X(GPRS_GMM_MS_ST_REGISTERED_INITIATED)|
			X(GPRS_GMM_MS_ST_DEREGISTERED),
		.name = "Deregistered",
		.action = st_gmm_ms_deregistered,
	},
	[GPRS_GMM_MS_ST_REGISTERED_INITIATED] = {
		.in_event_mask =
			X(GPRS_GMM_MS_EV_ATTACH_REJECTED) |
			X(GPRS_GMM_MS_EV_LOW_LVL_FAIL) |
			X(GPRS_GMM_MS_EV_ATTACH_ACCEPTED) |
			X(GPRS_GMM_MS_EV_DETACH_REQUESTED),
		.out_state_mask =
			X(GPRS_GMM_MS_ST_DEREGISTERED) |
			X(GPRS_GMM_MS_ST_REGISTERED),
		.name = "RegisteredInitiated",
		.action = st_gmm_ms_registered_initiated,
	},
	[GPRS_GMM_MS_ST_REGISTERED] = {
		.in_event_mask =
			X(GPRS_GMM_MS_EV_SR_REQUESTED) |
			X(GPRS_GMM_MS_EV_RAU_REQUESTED) |
			X(GPRS_GMM_MS_EV_DETACH_REQUESTED),
		.out_state_mask =
			X(GPRS_GMM_MS_ST_REGISTERED) |
			X(GPRS_GMM_MS_ST_RAU_INITIATED) |
			X(GPRS_GMM_MS_ST_DEREGISTERED_INITIATED) |
			X(GPRS_GMM_MS_ST_DEREGISTERED),
		.name = "Registered",
		.action = st_gmm_ms_registered,
	},
	[GPRS_GMM_MS_ST_DEREGISTERED_INITIATED] = {
		.in_event_mask =
			X(GPRS_GMM_MS_EV_DETACH_ACCEPTED) |
			X(GPRS_GMM_MS_EV_LOW_LVL_FAIL) |
			X(GPRS_GMM_MS_EV_RAU_ACCEPTED),
		.out_state_mask =
			X(GPRS_GMM_MS_ST_REGISTERED) |
			X(GPRS_GMM_MS_ST_DEREGISTERED),
		.name = "DeregisteredInitiated",
		.action = st_gmm_ms_deregistered_initiated,
	},
	[GPRS_GMM_MS_ST_RAU_INITIATED] = {
		.in_event_mask =
			X(GPRS_GMM_MS_EV_RAU_REJECTED) |
			X(GPRS_GMM_MS_EV_RAU_ACCEPTED),
		.out_state_mask =
			X(GPRS_GMM_MS_ST_REGISTERED) |
			X(GPRS_GMM_MS_ST_DEREGISTERED_INITIATED) |
			X(GPRS_GMM_MS_ST_DEREGISTERED),
		.name = "RAUInitidated",
		.action = st_gmm_ms_rau_initiated,
	},
	[GPRS_GMM_MS_ST_SR_INITIATED] = {
		.in_event_mask =
			X(GPRS_GMM_MS_EV_SR_REJECTED) |
			X(GPRS_GMM_MS_EV_SR_ACCEPTED),
		.out_state_mask =
			X(GPRS_GMM_MS_ST_REGISTERED) |
			X(GPRS_GMM_MS_ST_DEREGISTERED),
		.name = "SRInitiated",
		.action = st_gmm_ms_sr_initiated,
	},
};

const struct value_string gmm_ms_fsm_event_names[] = {
	{ GPRS_GMM_MS_EV_ENABLE_GPRS_MODE,	"ENABLE_GPRS_MODE" },
	{ GPRS_GMM_MS_EV_DISABLE_GPRS_MODE,	"DIOSABLE_GPRS_MODE" },
	{ GPRS_GMM_MS_EV_ATTACH_REQUESTED,	"ATTACH_REQUESTED" },
	{ GPRS_GMM_MS_EV_ATTACH_REJECTED,	"ATTACH_REJECTED" },
	{ GPRS_GMM_MS_EV_ATTACH_ACCEPTED,	"ATTACH_ACCEPTED" },
	{ GPRS_GMM_MS_EV_DETACH_REQUESTED,	"DETACH_REQUESTED" },
	{ GPRS_GMM_MS_EV_DETACH_REQUESTED_POWEROFF, "DETACH_REQUESTED_POWEROFF" },
	{ GPRS_GMM_MS_EV_DETACH_ACCEPTED,	"DETACH_ACCEPTED" },
	{ GPRS_GMM_MS_EV_SR_REQUESTED,		"SR_REQUESTED" },
	{ GPRS_GMM_MS_EV_SR_REJECTED,		"SR_REJECTED" },
	{ GPRS_GMM_MS_EV_SR_ACCEPTED,		"SR_ACCEPTED" },
	{ GPRS_GMM_MS_EV_RAU_REQUESTED,		"RAU_REQUESTED" },
	{ GPRS_GMM_MS_EV_RAU_REJECTED,		"RAU_REJECTED" },
	{ GPRS_GMM_MS_EV_RAU_ACCEPTED,		"RAU_ACCEPTED" },
	{ GPRS_GMM_MS_EV_LOW_LVL_FAIL,		"LOW_LVL_FAIL" },
	{ 0, NULL }
};

int gmm_ms_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	return 0;
}

struct osmo_fsm gmm_ms_fsm = {
	.name = "GMM_MS",
	.states = gmm_ms_fsm_states,
	.num_states = ARRAY_SIZE(gmm_ms_fsm_states),
	.event_names = gmm_ms_fsm_event_names,
	.allstate_event_mask = X(GPRS_GMM_MS_EV_DETACH_REQUESTED_POWEROFF),
	.allstate_action = gmm_ms_fsm_allstate_action,
	.log_subsys = DLGLOBAL, /* updated dynamically through gprs_gmm_ms_fsm_set_log_cat() */
	.timer_cb = gmm_ms_fsm_timer_cb,
};

int gprs_gmm_ms_fsm_init(void)
{
	return osmo_fsm_register(&gmm_ms_fsm);
}

void gprs_gmm_ms_fsm_set_log_cat(int logcat)
{
	gmm_ms_fsm.log_subsys = logcat;
}

int gprs_gmm_ms_fsm_ctx_init(struct gprs_gmm_ms_fsm_ctx *ctx, struct gprs_gmm_entity *gmme)
{
	ctx->gmme = gmme;
	ctx->fi = osmo_fsm_inst_alloc(&gmm_ms_fsm, gmme, ctx, LOGL_INFO, NULL);
	if (!ctx->fi)
		return -ENODATA;

	/* Transition to state GMM-DEREGISTERED right away if GPRS is enabled: */
	if (g_ctx->gprs_enabled)
		osmo_fsm_inst_dispatch(ctx->fi, GPRS_GMM_MS_EV_ENABLE_GPRS_MODE, NULL);

	return 0;
}

void gprs_gmm_ms_fsm_ctx_release(struct gprs_gmm_ms_fsm_ctx *ctx)
{
	osmo_fsm_inst_free(ctx->fi);
}
