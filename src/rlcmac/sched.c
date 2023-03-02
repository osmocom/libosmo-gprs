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
#include <osmocom/gsm/gsm0502.h>

#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/rlcmac/sched.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/tbf_ul_ass_fsm.h>
#include <osmocom/gprs/rlcmac/types_private.h>
#include <osmocom/gprs/rlcmac/pdch_ul_controller.h>

struct tbf_sched_ctrl_candidates {
	struct gprs_rlcmac_dl_tbf *poll_dl_ack_final_ack; /* 8.1.2.2 1) */
	struct gprs_rlcmac_dl_tbf *poll_dl_ack; /* 8.1.2.2 7) */
	struct gprs_rlcmac_ul_tbf *poll_ul_ack_new_ul_tbf; /* 9.3.2.4.2  (answer with PKT RES REQ) */
	struct gprs_rlcmac_ul_tbf *poll_ul_ack; /* 11.2.2 (answer with PKT CTRL ACK) */
	struct gprs_rlcmac_ul_tbf *ul_ass;
};

static inline bool fn_valid(uint32_t fn)
{
	uint32_t f = fn % 13;
	return f == 0 || f == 4 || f == 8;
}

uint32_t rrbp2fn(uint32_t cur_fn, uint8_t rrbp)
{
	uint32_t poll_fn;
	static const uint8_t rrbp_list[] = {
		13, /* GPRS_RLCMAC_RRBP_N_plus_13 */
		17, /* GPRS_RLCMAC_RRBP_N_plus_17_18 */
		21, /* GPRS_RLCMAC_RRBP_N_plus_21_22 */
		26, /* GPRS_RLCMAC_RRBP_N_plus_26 */
	};

	OSMO_ASSERT(rrbp < ARRAY_SIZE(rrbp_list));

	poll_fn = GSM_TDMA_FN_SUM(cur_fn, rrbp_list[rrbp]);
	if (!fn_valid(poll_fn)) {
		/* 17 -> 18, 21 -> 22: */
		GSM_TDMA_FN_INC(poll_fn);
		OSMO_ASSERT(fn_valid(poll_fn));
	}
	return poll_fn;
}

static void get_ctrl_msg_tbf_candidates(const struct gprs_rlcmac_rts_block_ind *bi,
					struct tbf_sched_ctrl_candidates *tbfs)
{

	struct gprs_rlcmac_entity *gre;
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_pdch_ulc_node *node;

	node = gprs_rlcmac_pdch_ulc_get_node(g_ctx->sched.ulc[bi->ts], bi->fn);
	if (node) {
		switch (node->reason) {
		case GPRS_RLCMAC_PDCH_ULC_POLL_UL_ASS:
			/* TODO */
			break;
		case GPRS_RLCMAC_PDCH_ULC_POLL_DL_ASS:
			/* TODO */
			break;
		case GPRS_RLCMAC_PDCH_ULC_POLL_UL_ACK:
			/* TS 44.060: 9.3.2.4.2 If the PACKET UPLINK ACK/NACK message
			* has the Final Ack Indicator bit set to '1' and the following
			* conditions are fulfilled: TBF Est field is set to '1'; the
			* mobile station has new data to transmit; the mobile station
			* has no other ongoing downlink TBFs, the mobile station shall
			* release the uplink TBF and may request the establishment of a
			* new TBF using one of the following procedures.
			* If Control Ack Type parameter in System Information indicates
			* acknowledgement is RLC/MAC control block, the mobile station
			* shall transmit the PACKET RESOURCE REQUEST message and start
			* timer T3168 for the TBF request. The mobile station shall use
			* the same procedures as are used for TBF establishment using two
			* phase access described in sub-clause 7.1.3 starting from the
			* point where the mobile station transmits the PACKET RESOURCE
			* REQUEST message. */
			ul_tbf = tbf_as_ul_tbf(node->tbf);
			if (gprs_rlcmac_ul_tbf_can_request_new_ul_tbf(ul_tbf))
				tbfs->poll_ul_ack_new_ul_tbf = ul_tbf;
			else
				tbfs->poll_ul_ack = ul_tbf;
			break;
		case GPRS_RLCMAC_PDCH_ULC_POLL_DL_ACK:
			dl_tbf = tbf_as_dl_tbf(node->tbf);
			/* 8.1.2.2 Polling for Packet Downlink Ack/Nack */
			if (gprs_rlcmac_tbf_dl_state(dl_tbf) == GPRS_RLCMAC_TBF_DL_ST_FINISHED)
				tbfs->poll_dl_ack_final_ack = dl_tbf;
			else
				tbfs->poll_dl_ack = dl_tbf;
			break;
		case GPRS_RLCMAC_PDCH_ULC_POLL_CELL_CHG_CONTINUE:
			/* TODO */
			break;
		}
		gprs_rlcmac_pdch_ulc_release_node(g_ctx->sched.ulc[bi->ts], node);
	}

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
	struct gprs_rlcmac_entity *gre;
	int rc;

	/* 8.1.2.2 1) (EGPRS) PACKET DOWNLINK ACK/NACK w/ FinalAckInd=1 */
	if (tbfs->poll_dl_ack_final_ack) {
		LOGRLCMAC(LOGL_DEBUG, "(ts=%u,fn=%u,usf=%u) Tx DL ACK/NACK FinalAck=1\n",
			  bi->ts, bi->fn, bi->usf);
		msg = gprs_rlcmac_dl_tbf_create_pkt_dl_ack_nack(tbfs->poll_dl_ack_final_ack);
		if (msg)
			return msg;
	}

	/* 8.1.2.2 5) Any other RLC/MAC control message, other than a (EGPRS) PACKET DOWNLINK ACK/NACK */
	if (tbfs->poll_ul_ack_new_ul_tbf) {
		LOGRLCMAC(LOGL_DEBUG, "(ts=%u,fn=%u,usf=%u) Tx Pkt Resource Request (UL ACK/NACK poll)\n",
			  bi->ts, bi->fn, bi->usf);
		gre = tbfs->poll_ul_ack_new_ul_tbf->tbf.gre;
		OSMO_ASSERT(gre->ul_tbf == tbfs->poll_ul_ack_new_ul_tbf);
		gre->ul_tbf = gprs_rlcmac_ul_tbf_alloc(gre);
		if (!gre->ul_tbf) {
			gprs_rlcmac_ul_tbf_free(tbfs->poll_ul_ack_new_ul_tbf);
			return NULL;
		}
		/* Prepare new UL TBF from old UL TBF: */
		rc = gprs_rlcmac_tbf_ul_ass_start_from_releasing_ul_tbf(gre->ul_tbf, tbfs->poll_ul_ack_new_ul_tbf);
		gprs_rlcmac_ul_tbf_free(tbfs->poll_ul_ack_new_ul_tbf); /* always free */
		if (rc < 0) {
			gprs_rlcmac_ul_tbf_free(gre->ul_tbf);
			return NULL;
		}
		/* New UL TBF is ready to send the Pkt Res Req: */
		OSMO_ASSERT(gprs_rlcmac_tbf_ul_ass_rts(gre->ul_tbf, bi));
		msg = gprs_rlcmac_tbf_ul_ass_create_rlcmac_msg(gre->ul_tbf, bi);
		if (msg)
			return msg;
	}
	if (tbfs->poll_ul_ack) {
		LOGRLCMAC(LOGL_DEBUG, "(ts=%u,fn=%u,usf=%u) Tx Pkt Control Ack (UL ACK/NACK poll)\n",
			  bi->ts, bi->fn, bi->usf);
		msg = gprs_rlcmac_ul_tbf_create_pkt_ctrl_ack(tbfs->poll_ul_ack);
		/* Last UL message, freeing */
		gprs_rlcmac_ul_tbf_free(tbfs->poll_ul_ack);
		return msg;
	}
	if (tbfs->ul_ass) {
		msg = gprs_rlcmac_tbf_ul_ass_create_rlcmac_msg(tbfs->ul_ass, bi);
		if (msg)
			return msg;
	}

	/* 8.1.2.2 7) A (EGPRS) PACKET DOWNLINK ACK/NACK message not containing a Final Ack Indicator or a
	 * Channel Request Description IE */
	if (tbfs->poll_dl_ack) {
		LOGRLCMAC(LOGL_DEBUG, "(ts=%u,fn=%u,usf=%u) Tx DL ACK/NACK\n",
			  bi->ts, bi->fn, bi->usf);
		msg = gprs_rlcmac_dl_tbf_create_pkt_dl_ack_nack(tbfs->poll_dl_ack);
		if (msg)
			return msg;
	}

	return NULL;
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
	struct osmo_gprs_rlcmac_prim *rlcmac_prim_tx;
	int rc = 0;

	get_ctrl_msg_tbf_candidates(bi, &tbf_cand);

	if ((msg = sched_select_ctrl_msg(bi, &tbf_cand)))
		goto tx_msg;

	if ((msg = sched_select_ul_data_msg(bi)))
		goto tx_msg;

	/* Lowest prio: send dummy control message (or nothing depending on EXT_UTBF_NODATA) */
	if ((msg = sched_select_ul_dummy_ctrl_blk(bi)))
		goto tx_msg;

	/* Nothing to transmit */
	goto ret_rc;

tx_msg:
	rlcmac_prim_tx = gprs_rlcmac_prim_alloc_l1ctl_pdch_data_req(bi->ts, bi->fn, msgb_data(msg), 0);
	rlcmac_prim_tx->l1ctl.pdch_data_req.data_len = msgb_length(msg);
	rc = gprs_rlcmac_prim_call_down_cb(rlcmac_prim_tx);
	msgb_free(msg);

ret_rc:
	gprs_rlcmac_pdch_ulc_expire_fn(g_ctx->sched.ulc[bi->ts], bi->fn);
	return rc;
}
