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

#include <osmocom/gprs/rlcmac/tbf_dl_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/gre.h>

#define X(s) (1 << (s))

static const struct value_string tbf_dl_fsm_event_names[] = {
	{ GPRS_RLCMAC_TBF_DL_EV_LAST_DL_DATA_RECVD,	"LAST_DL_DATA_RECVD" },
	{ GPRS_RLCMAC_TBF_DL_EV_DL_ASS_COMPL,		"DL_ASS_COMPL" },
	{ 0, NULL }
};

static const struct osmo_tdef_state_timeout tbf_dl_fsm_timeouts[32] = {
	[GPRS_RLCMAC_TBF_DL_ST_NEW] = { },
	[GPRS_RLCMAC_TBF_DL_ST_FLOW] = { },
	[GPRS_RLCMAC_TBF_DL_ST_FINISHED] = { },
};

/* Transition to a state, using the T timer defined in tbf_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
 #define tbf_dl_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_dl_fsm_timeouts, \
				     g_rlcmac_ctx->T_defs, \
				     -1)

static void st_new(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gprs_rlcmac_tbf_dl_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_dl_fsm_ctx *)fi->priv;
	switch (event) {
	case GPRS_RLCMAC_TBF_DL_EV_DL_ASS_COMPL:
		/* Configure DL TBF on the lower MAC side: */
		gprs_rlcmac_dl_tbf_configure_l1ctl(ctx->dl_tbf);
		tbf_dl_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ST_FLOW);
		/* FIXME: This should ideally be done after TbfStartTime has elapsed: */
		gprs_rlcmac_dl_tbf_t3190_start(ctx->dl_tbf);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_flow(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct gprs_rlcmac_tbf_dl_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_dl_fsm_ctx *)fi->priv;
	switch (event) {
	case GPRS_RLCMAC_TBF_DL_EV_LAST_DL_DATA_RECVD:
		tbf_dl_fsm_state_chg(fi, GPRS_RLCMAC_TBF_DL_ST_FINISHED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_finished(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* Wait to be freed by T3190/T3192. */

	//struct gprs_rlcmac_tbf_dl_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_dl_fsm_ctx *)fi->priv;
	switch (event) {
	case GPRS_RLCMAC_TBF_DL_EV_LAST_DL_DATA_RECVD:
		/* ignore, PCU is retransmitting last DL block (FBI=1) before we ACKed it */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static struct osmo_fsm_state tbf_dl_fsm_states[] = {
	[GPRS_RLCMAC_TBF_DL_ST_NEW] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_DL_EV_DL_ASS_COMPL),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_DL_ST_FLOW),
		.name = "NEW",
		.action = st_new,
	},
	[GPRS_RLCMAC_TBF_DL_ST_FLOW] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_DL_EV_LAST_DL_DATA_RECVD),
		.out_state_mask =
			X(GPRS_RLCMAC_TBF_DL_ST_FINISHED),
		.name = "FLOW",
		.action = st_flow,
	},
	[GPRS_RLCMAC_TBF_DL_ST_FINISHED] = {
		.in_event_mask =
			X(GPRS_RLCMAC_TBF_DL_EV_LAST_DL_DATA_RECVD),
		.out_state_mask = 0,
		.name = "FINISHED",
		.action = st_finished,
	},
};

static int tbf_dl_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	//struct gprs_rlcmac_tbf_dl_fsm_ctx *ctx = (struct gprs_rlcmac_tbf_dl_fsm_ctx *)fi->priv;
	switch (fi->T) {
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm tbf_dl_fsm = {
	.name = "DL_TBF",
	.states = tbf_dl_fsm_states,
	.num_states = ARRAY_SIZE(tbf_dl_fsm_states),
	.timer_cb = tbf_dl_fsm_timer_cb,
	.log_subsys = DLGLOBAL, /* updated dynamically through gprs_rlcmac_tbf_dl_fsm_set_log_cat() */
	.event_names = tbf_dl_fsm_event_names,
};

int gprs_rlcmac_tbf_dl_fsm_init(void)
{
	return osmo_fsm_register(&tbf_dl_fsm);
}

void gprs_rlcmac_tbf_dl_fsm_set_log_cat(int logcat)
{
	tbf_dl_fsm.log_subsys = logcat;
}

int gprs_rlcmac_tbf_dl_fsm_constructor(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	struct gprs_rlcmac_tbf_dl_fsm_ctx *ctx = &dl_tbf->state_fsm;
	ctx->dl_tbf = dl_tbf;
	ctx->fi = osmo_fsm_inst_alloc(&tbf_dl_fsm, dl_tbf, ctx, LOGL_INFO, NULL);
	if (!ctx->fi)
		return -ENODATA;

	return 0;
}

void gprs_rlcmac_tbf_dl_fsm_destructor(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	struct gprs_rlcmac_tbf_dl_fsm_ctx *ctx = &dl_tbf->state_fsm;
	osmo_fsm_inst_free(ctx->fi);
	ctx->fi = NULL;
}

enum gprs_rlcmac_tbf_dl_fsm_states gprs_rlcmac_tbf_dl_state(const struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	const struct gprs_rlcmac_tbf_dl_fsm_ctx *ctx = &dl_tbf->state_fsm;
	return ctx->fi->state;
}
