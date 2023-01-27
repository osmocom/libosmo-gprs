/* RLC/MAC scheduler, 3GPP TS 44.060 */
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

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/rlcmac/sched.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/tbf_ul_ass_fsm.h>

struct tbf_sched_ctrl_candidates {
	struct gprs_rlcmac_ul_tbf *ul_ass;
};

static void get_ctrl_msg_tbf_candidates(const struct gprs_rlcmac_rts_block_ind *bi,
					struct tbf_sched_ctrl_candidates *tbfs)
{

	struct gprs_rlcmac_entity *gre;
	struct gprs_rlcmac_ul_tbf *ul_tbf;

	/* Iterate over UL TBFs: */
	llist_for_each_entry(gre, &g_ctx->gre_list, entry) {
		if (!gre->ul_tbf)
			continue;
		ul_tbf = gre->ul_tbf;
		if (gprs_rlcmac_tbf_ul_ass_rts(ul_tbf, bi))
			tbfs->ul_ass = ul_tbf;
	}

	/* TODO: Iterate over DL TBFs: */
}

static struct gprs_rlcmac_ul_tbf *find_requested_ul_tbf_for_data(const struct gprs_rlcmac_rts_block_ind *bi)
{
	struct gprs_rlcmac_entity *gre;
	llist_for_each_entry(gre, &g_ctx->gre_list, entry) {
		if (!gre->ul_tbf)
			continue;
		if (gprs_rlcmac_ul_tbf_data_rts(gre->ul_tbf, bi))
			return gre->ul_tbf;
	}
	return NULL;
}

static struct gprs_rlcmac_ul_tbf *find_requested_ul_tbf_for_dummy(const struct gprs_rlcmac_rts_block_ind *bi)
{
	struct gprs_rlcmac_entity *gre;
	llist_for_each_entry(gre, &g_ctx->gre_list, entry) {
		if (!gre->ul_tbf)
			continue;
		if (gprs_rlcmac_ul_tbf_dummy_rts(gre->ul_tbf, bi))
			return gre->ul_tbf;
	}
	return NULL;
}

static struct msgb *sched_select_ctrl_msg(const struct gprs_rlcmac_rts_block_ind *bi,
					     struct tbf_sched_ctrl_candidates *tbfs)
{
	struct msgb *msg = NULL;
	if (tbfs->ul_ass)
		msg = gprs_rlcmac_tbf_ul_ass_create_rlcmac_msg(tbfs->ul_ass, bi);
	return msg;
}

static struct msgb *sched_select_ul_data_msg(const struct gprs_rlcmac_rts_block_ind *bi)
{
	struct gprs_rlcmac_ul_tbf *ul_tbf;

	ul_tbf = find_requested_ul_tbf_for_data(bi);
	if (!ul_tbf) {
		LOGRLCMAC(LOGL_DEBUG, "(ts=%u,fn=%u,usf=%u) No Uplink TBF available to transmit RLC/MAC Ul Data Block\n",
			  bi->ts, bi->fn, bi->usf);
		return NULL;
	}
	return gprs_rlcmac_ul_tbf_data_create(ul_tbf, bi);
}

static struct msgb *sched_select_ul_dummy_ctrl_blk(const struct gprs_rlcmac_rts_block_ind *bi)
{
	struct gprs_rlcmac_ul_tbf *ul_tbf;

	ul_tbf = find_requested_ul_tbf_for_dummy(bi);
	if (!ul_tbf) {
		LOGRLCMAC(LOGL_DEBUG, "(ts=%u,fn=%u,usf=%u) No Uplink TBF available to transmit RLC/MAC Ul Dummy Ctrl Block\n",
			  bi->ts, bi->fn, bi->usf);
		return NULL;
	}

	return gprs_rlcmac_ul_tbf_dummy_create(ul_tbf);
}

int gprs_rlcmac_rcv_rts_block(struct gprs_rlcmac_rts_block_ind *bi)
{
	struct msgb *msg = NULL;
	struct tbf_sched_ctrl_candidates tbf_cand = {0};

	get_ctrl_msg_tbf_candidates(bi, &tbf_cand);

	if ((msg = sched_select_ctrl_msg(bi, &tbf_cand)))
		goto tx_msg;

	if ((msg = sched_select_ul_data_msg(bi)))
		goto tx_msg;

	/* Prio 3: send dummy control message (or nothing depending on EXT_UTBF_NODATA) */
	if ((msg = sched_select_ul_dummy_ctrl_blk(bi)))
		goto tx_msg;

	/* Nothing to transmit */
	return 0;
tx_msg:
	/* TODO: transmit msg to lower layer (L1CTL?) */
	return 0;
}
