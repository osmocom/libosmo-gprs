/* Uplink TBF as per 3GPP TS 44.064 */
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

#include <osmocom/core/bitvec.h>

#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/rlcmac_dec.h>
#include <osmocom/gprs/rlcmac/rlcmac_enc.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/coding_scheme.h>
#include <osmocom/gprs/rlcmac/rlc_window_ul.h>
#include <osmocom/gprs/rlcmac/rlc.h>

struct gprs_rlcmac_ul_tbf *gprs_rlcmac_ul_tbf_alloc(struct gprs_rlcmac_entity *gre)
{
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	int rc;

	ul_tbf = talloc_zero(gre, struct gprs_rlcmac_ul_tbf);
	if (!ul_tbf)
		return NULL;

	gprs_rlcmac_tbf_constructor(ul_tbf_as_tbf(ul_tbf), GPRS_RLCMAC_TBF_DIR_UL, gre);

	rc = gprs_rlcmac_tbf_ul_fsm_constructor(ul_tbf);
	if (rc < 0)
		goto err_tbf_destruct;

	rc = gprs_rlcmac_tbf_ul_ass_fsm_constructor(ul_tbf);
	if (rc < 0)
		goto err_state_fsm_destruct;

	ul_tbf->tbf.nr = g_rlcmac_ctx->next_ul_tbf_nr++;
	ul_tbf->tx_cs = GPRS_RLCMAC_CS_1;

	ul_tbf->ulw = gprs_rlcmac_rlc_ul_window_alloc(ul_tbf);
	OSMO_ASSERT(ul_tbf->ulw);

	ul_tbf->blkst = gprs_rlcmac_rlc_block_store_alloc(ul_tbf);
	OSMO_ASSERT(ul_tbf->blkst);

	return ul_tbf;

err_state_fsm_destruct:
	gprs_rlcmac_tbf_destructor(ul_tbf_as_tbf(ul_tbf));
err_tbf_destruct:
	gprs_rlcmac_tbf_destructor(ul_tbf_as_tbf(ul_tbf));
	talloc_free(ul_tbf);
	return NULL;
}

void gprs_rlcmac_ul_tbf_free(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	if (!ul_tbf)
		return;

	if (ul_tbf->tbf.gre->ul_tbf == ul_tbf)
		ul_tbf->tbf.gre->ul_tbf = NULL;

	talloc_free(ul_tbf->llc_tx_msg);

	gprs_rlcmac_rlc_block_store_free(ul_tbf->blkst);
	ul_tbf->blkst = NULL;

	gprs_rlcmac_rlc_ul_window_free(ul_tbf->ulw);
	ul_tbf->ulw = NULL;

	gprs_rlcmac_tbf_ul_ass_fsm_destructor(ul_tbf);
	gprs_rlcmac_tbf_ul_fsm_destructor(ul_tbf);

	gprs_rlcmac_tbf_destructor(ul_tbf_as_tbf(ul_tbf));
	talloc_free(ul_tbf);
}

/* whether the UL TBF is in Contention Resolution state (false = already succeeded)*/
bool gprs_rlcmac_ul_tbf_in_contention_resolution(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	struct osmo_fsm_inst *fi = ul_tbf->state_fsm.fi;
	switch (fi->state) {
	case GPRS_RLCMAC_TBF_UL_ST_NEW:
	case GPRS_RLCMAC_TBF_UL_ST_WAIT_ASSIGN:
		return true;
	case GPRS_RLCMAC_TBF_UL_ST_FLOW:
	case GPRS_RLCMAC_TBF_UL_ST_FINISHED:
		/* TS 44.60 7.1.3.3: For 2hase access, contention resolution is
		 * successful once we get out of GPRS_RLCMAC_TBF_UL_ST_WAIT_ASSIGN
		 * (when we receive a Pkt Ul Ass, see TS 44.60 7.1.3.3) */
		if (ul_tbf->ul_ass_fsm.ass_type == GPRS_RLCMAC_TBF_UL_ASS_TYPE_2PHASE)
			return false;
		/* 1phase access: Check if we didn't yet send any data, or whether
		 * either T3164 or T3166 are active: */
		if (ul_tbf->ul_ass_fsm.ass_type == GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE)
			return (ul_tbf->n3104 == 0) ||
			       (osmo_timer_pending(&fi->timer) && (fi->T == 3164 || fi->T == 3166));
		return false;
	default:
		return false;
	}
}

unsigned int gprs_rlcmac_ul_tbf_n3104_max(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	/* 3GPP TS 44.060 13.3:
	 * N3104_MAX = 3 * (BS_CV_MAX + 3) * number of uplink timeslots assigned */
	/* If we didn't receive SI13 yet, use maximum value bs_cv_max in range 0..15 */
	uint8_t bs_cv_max = g_rlcmac_ctx->si13_available ?
				g_rlcmac_ctx->si13ro.u.PBCCH_Not_present.GPRS_Cell_Options.BS_CV_MAX :
				15;
	return 3 * (bs_cv_max + 3) * ul_tbf->cur_alloc.num_ts;
}

/* Whether the existing UL TBF can directly request a new UL TBF instead of goig to packet idle mode. */
bool gprs_rlcmac_ul_tbf_can_request_new_ul_tbf(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	/* 9.3.2.4.2: "If the PACKET UPLINK ACK/NACK message has the Final Ack Indicator
	* bit set to '1' and the following conditions are fulfilled: TBF Est field is set
	* to '1'; the mobile station has new data to transmit; the mobile station has no
	* other ongoing downlink TBFs, the mobile station shall release the uplink TBF and
	* may request the establishment of a new TBF"
	*/

	/* "PACKET UPLINK ACK/NACK message has the Final Ack Indicator" means GPRS_RLCMAC_TBF_UL_ST_RELEASING: */
	if (gprs_rlcmac_tbf_ul_state(ul_tbf) != GPRS_RLCMAC_TBF_UL_ST_RELEASING)
		return false;

	/* "TBF Est field is set to '1'"" */
	if (!ul_tbf->state_fsm.rx_final_pkt_ul_ack_nack_has_tbf_est)
		return false;

	/* the mobile station has new data to transmit */
	if (!gprs_rlcmac_ul_tbf_have_data(ul_tbf))
		return false;

	/* "the mobile station has no other ongoing downlink TBFs */
	if (ul_tbf->tbf.gre->dl_tbf)
		return false;

	return true;

}

/* Used by the scheduler to find out whether an Uplink Dummy Control Block can be transmitted. If
 * true, it will potentially call gprs_rlcmac_ul_tbf_dummy_create() to generate a new dummy message to transmit. */
bool gprs_rlcmac_ul_tbf_dummy_rts(const struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi)
{
	if (!ul_tbf->cur_alloc.ts[bi->ts].allocated)
		return false;
	if (ul_tbf->cur_alloc.ts[bi->ts].usf != bi->usf)
		return false;
	return true;
}

/* Used by the scheduler to find out whether there's data to be transmitted at the requested time. If
 * true, it will potentially call gprs_rlcmac_ul_tbf_data_create() to generate a new data message to transmit. */
bool gprs_rlcmac_ul_tbf_data_rts(const struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi)
{
	enum gprs_rlcmac_tbf_ul_fsm_states st;

	if (!gprs_rlcmac_ul_tbf_dummy_rts(ul_tbf, bi))
		return false;

	st = gprs_rlcmac_tbf_ul_state(ul_tbf);
	return (st == GPRS_RLCMAC_TBF_UL_ST_FLOW ||
		st == GPRS_RLCMAC_TBF_UL_ST_FINISHED);
}

static int gprs_rlcmac_ul_tbf_update_window(struct gprs_rlcmac_ul_tbf *ul_tbf,
					    unsigned first_bsn, struct bitvec *rbb)
{
	unsigned dist;
	uint16_t lost = 0, received = 0;
	char show_v_b[RLC_MAX_SNS + 1];
	char show_rbb[RLC_MAX_SNS + 1];
	dist = gprs_rlcmac_rlc_ul_window_distance(ul_tbf->ulw);
	unsigned num_blocks = rbb->cur_bit > dist
				? dist : rbb->cur_bit;
	unsigned behind_last_bsn = gprs_rlcmac_rlc_window_mod_sns_bsn(ul_tbf->w, first_bsn + num_blocks);

	gprs_rlcmac_extract_rbb(rbb, show_rbb);
	/* show received array in debug */
	LOGPTBFUL(ul_tbf, LOGL_DEBUG,
		  "ack:  (BSN=%d)\"%s\"(BSN=%d)  R=ACK I=NACK\n",
		  first_bsn, show_rbb,
		  gprs_rlcmac_rlc_window_mod_sns_bsn(ul_tbf->w, behind_last_bsn - 1));

	gprs_rlcmac_rlc_ul_window_update(ul_tbf->ulw, rbb, first_bsn, &lost, &received);

	/* raise V(A), if possible */
	gprs_rlcmac_rlc_ul_window_raise(ul_tbf->ulw,
					gprs_rlcmac_rlc_ul_window_move_window(ul_tbf->ulw));

	/* show receive state array in debug (V(A)..V(S)-1) */
	gprs_rlcmac_rlc_ul_window_show_state(ul_tbf->ulw, show_v_b);
	LOGPTBFUL(ul_tbf, LOGL_DEBUG,
		  "V(B): (V(A)=%d)\"%s\"(V(S)-1=%d)  A=Acked N=Nacked U=Unacked X=Resend-Unacked I=Invalid\n",
		  gprs_rlcmac_rlc_ul_window_v_a(ul_tbf->ulw), show_v_b,
		  gprs_rlcmac_rlc_ul_window_v_s_mod(ul_tbf->ulw, -1));
	return 0;
}

int gprs_rlcmac_ul_tbf_handle_pkt_ul_ack_nack(struct gprs_rlcmac_ul_tbf *ul_tbf,
					      const RlcMacDownlink_t *dl_block)
{
	const Packet_Uplink_Ack_Nack_t *ack = &dl_block->u.Packet_Uplink_Ack_Nack;
	const PU_AckNack_GPRS_t *gprs = &ack->u.PU_AckNack_GPRS_Struct;
	const Ack_Nack_Description_t *ack_desc = &gprs->Ack_Nack_Description;
	int bsn_begin, bsn_end;
	int num_blocks;
	uint8_t bits_data[GPRS_RLCMAC_GPRS_WS/8];
	char show_bits[GPRS_RLCMAC_GPRS_WS + 1];
	struct bitvec bits = {
		.data = bits_data,
		.data_len = sizeof(bits_data),
		.cur_bit = 0,
	};
	int rc;
	struct tbf_ul_ass_ev_rx_ul_ack_nack ev_ack = {
		.final_ack = ack_desc->FINAL_ACK_INDICATION,
		.tbf_est = (gprs->Exist_AdditionsR99 && gprs->AdditionsR99.TBF_EST),
	};

	num_blocks = gprs_rlcmac_decode_gprs_acknack_bits(
		ack_desc, &bits, &bsn_begin, &bsn_end, ul_tbf->ulw);

	LOGPTBFUL(ul_tbf, LOGL_DEBUG,
		"Got GPRS UL ACK bitmap: SSN: %d, BSN %d to %d - 1 (%d blocks), \"%s\"\n",
		ack_desc->STARTING_SEQUENCE_NUMBER,
		bsn_begin, bsn_end, num_blocks,
		(gprs_rlcmac_extract_rbb(&bits, show_bits), show_bits));

	rc = gprs_rlcmac_ul_tbf_update_window(ul_tbf, bsn_begin, &bits);

	osmo_fsm_inst_dispatch(ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_RX_UL_ACK_NACK, &ev_ack);

	if (ack_desc->FINAL_ACK_INDICATION) {
		gprs_rlcmac_rlc_ul_window_reset(ul_tbf->ulw);
	} else if (gprs_rlcmac_tbf_ul_state(ul_tbf) == GPRS_RLCMAC_TBF_UL_ST_FINISHED &&
		   gprs_rlcmac_rlc_ul_window_window_empty(ul_tbf->ulw)) {
		LOGPTBFUL(ul_tbf, LOGL_NOTICE,
			  "Received acknowledge of all blocks, but without final ack indication (don't worry)\n");
	}

	return rc;
}

int gprs_rlcmac_ul_tbf_handle_pkt_ul_ass(struct gprs_rlcmac_ul_tbf *ul_tbf,
					 const struct osmo_gprs_rlcmac_prim *rlcmac_prim,
					 const RlcMacDownlink_t *dl_block)
{
	int rc;
	struct tbf_ul_ass_ev_rx_pkt_ul_ass_ctx d = {
		.ts_nr = rlcmac_prim->l1ctl.pdch_data_ind.ts_nr,
		.fn = rlcmac_prim->l1ctl.pdch_data_ind.fn,
		.dl_block = dl_block,
	};

	rc = osmo_fsm_inst_dispatch(ul_tbf->ul_ass_fsm.fi, GPRS_RLCMAC_TBF_UL_ASS_EV_RX_PKT_UL_ASS, &d);
	return rc;
}

struct msgb *gprs_rlcmac_ul_tbf_dummy_create(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	struct msgb *msg;
	struct bitvec bv;
	RlcMacUplink_t ul_block;
	int rc;

	OSMO_ASSERT(ul_tbf);

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "pkt_ul_dummy_ctrl_blk");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer. */
	bv = (struct bitvec){
		.data = msgb_put(msg, GSM_MACBLOCK_LEN),
		.data_len = GSM_MACBLOCK_LEN,
	};
	bitvec_unhex(&bv, GPRS_RLCMAC_DUMMY_VEC);

	gprs_rlcmac_enc_prepare_pkt_ul_dummy_block(&ul_block, ul_tbf->tbf.gre->tlli);
	rc = osmo_gprs_rlcmac_encode_uplink(&bv, &ul_block);
	if (rc < 0) {
		LOGPTBFUL(ul_tbf, LOGL_ERROR, "Encoding of Packet Uplink Dummy Control Block failed (%d)\n", rc);
		goto free_ret;
	}

	return msg;

free_ret:
	msgb_free(msg);
	return NULL;
}

bool gprs_rlcmac_ul_tbf_have_data(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	return (ul_tbf->llc_tx_msg && msgb_length(ul_tbf->llc_tx_msg) > 0) ||
	       gprs_rlcmac_entity_have_tx_data_queued(ul_tbf->tbf.gre);
}

bool gprs_rlcmac_ul_tbf_shall_keep_open(const struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi)
{
	/* TODO: In here a VTY timer can be defined which specifies an amount of
	 * time during which the MS stays in CV=15 while waiting for more data from
	 * upper layers. This way we avoid entering last CV modes and keep the TBF
	 * open (sending Uplink Dummy Ctrl Block if necessary).
	 * Amount of time elapsed in this condition can be valculated based on
	 * bi->fn - ul_tbf->last_ul_drained_fn;
	 */
	return false;
}

void gprs_rlcmac_ul_tbf_schedule_next_llc_frame(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim_tx;

	if (ul_tbf->llc_tx_msg && msgb_length(ul_tbf->llc_tx_msg))
		return;

	msgb_free(ul_tbf->llc_tx_msg);
	/* dequeue next LLC frame, if any */
	ul_tbf->llc_tx_msg = gprs_rlcmac_llc_queue_dequeue(ul_tbf->tbf.gre->llc_queue);
	if (!ul_tbf->llc_tx_msg)
		return;

	LOGPTBFUL(ul_tbf, LOGL_DEBUG, "Dequeue next LLC (len=%d)\n", msgb_length(ul_tbf->llc_tx_msg));

	ul_tbf->last_ul_drained_fn = -1;

	/* TS 24.008 section 4.7.2.1.1: "The READY timer is started in the MS
	 * when the GMM entity receives an indication from lower layers that an LLC frame
	 * other than LLC NULL frame has been transmitted on the radio interface".
	 * hence, signal here to GMM the event.
	 */
	rlcmac_prim_tx = gprs_rlcmac_prim_alloc_gmmrr_llc_transmitted_ind(ul_tbf->tbf.gre->tlli);
	gprs_rlcmac_prim_call_up_cb(rlcmac_prim_tx);
}

static int create_new_bsn(struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi, enum gprs_rlcmac_coding_scheme cs)
{
	struct gprs_rlcmac_llc_queue *llc_queue = ul_tbf->tbf.gre->llc_queue;
	const uint16_t bsn = gprs_rlcmac_rlc_ul_window_v_s(ul_tbf->ulw);
	struct gprs_rlcmac_rlc_block *blk;
	struct gprs_rlcmac_rlc_block_info *rdbi;
	uint8_t *data;
	int num_chunks = 0;
	int write_offset = 0;
	enum gpr_rlcmac_append_result ar;

	if (!ul_tbf->llc_tx_msg || msgb_length(ul_tbf->llc_tx_msg) == 0)
		gprs_rlcmac_ul_tbf_schedule_next_llc_frame(ul_tbf);
	OSMO_ASSERT(ul_tbf->llc_tx_msg);

	OSMO_ASSERT(gprs_rlcmac_mcs_is_valid(cs));

	/* length of usable data block (single data unit w/o header) */
	const uint8_t block_data_len = gprs_rlcmac_mcs_max_data_block_bytes(cs);

	/* now we still have untransmitted LLC data, so we fill mac block */
	blk = gprs_rlcmac_rlc_block_store_get_block(ul_tbf->blkst, bsn);
	data = gprs_rlcmac_rlc_block_prepare(blk, block_data_len);
	blk->cs_last = cs;
	blk->cs_current_trans = cs;

	/* Initialise the variable related to UL SPB */
	blk->spb_status.block_status_ul = GPRS_RLCMAC_EGPRS_RESEG_UL_DEFAULT;
	blk->cs_init = cs;

	blk->len = block_data_len;

	rdbi = &(blk->block_info);
	memset(rdbi, 0, sizeof(*rdbi));
	rdbi->data_len = block_data_len;

	rdbi->ti = gprs_rlcmac_ul_tbf_in_contention_resolution(ul_tbf);
	rdbi->cv = 15; /* Final Block Indicator, set late, if true */
	rdbi->bsn = bsn; /* Block Sequence Number */
	rdbi->e = 1; /* Extension bit, maybe set later (1: no extension) */

	if (rdbi->ti) {
		/* Append TLLI: */
		if (gprs_rlcmac_mcs_is_gprs(cs))
			/* The TLLI is encoded in big endian for GPRS (see TS 44.060, figure 10.2.2.1, note) */
			osmo_store32be(ul_tbf->tbf.gre->tlli, (uint32_t *)&data[0]);
		else
			/* The TLLI is encoded in little endian for EGPRS (see TS 44.060, figure 10.3a.2.1, note 2) */
			osmo_store32le(ul_tbf->tbf.gre->tlli, (uint32_t *)&data[0]);
		write_offset += sizeof(uint32_t);
	}

	do {
		bool is_final;
		int payload_written = 0;

		if (msgb_length(ul_tbf->llc_tx_msg) == 0) {
			/* The data just drained, store the current fn */
			if (ul_tbf->last_ul_drained_fn < 0)
				ul_tbf->last_ul_drained_fn = bi->fn;

			int space = block_data_len - write_offset;

			if (num_chunks != 0) {
				/* Nothing to send, and we already put some data in
				 * rlcmac data block, we are done */
				LOGPTBFUL(ul_tbf, LOGL_DEBUG,
					  "LLC queue completely drained and there's "
					  "still %d free bytes in rlcmac data block\n", space);

				/* We may need to update fbi in header here
				 * since ul_tbf->last_ul_drained_fn was updated above
				 * Specially important when X2031 is 0. */
				is_final = gprs_rlcmac_llc_queue_size(llc_queue) == 0 &&
					   !gprs_rlcmac_ul_tbf_shall_keep_open(ul_tbf, bi);
				if (is_final)
					rdbi->cv = 0;

				if (gprs_rlcmac_mcs_is_edge(cs)) {
					/* in EGPRS there's no M bit, so we need
					 * to flag padding with LI=127 */
					gprs_rlcmac_rlc_data_to_ul_append_egprs_li_padding(
						rdbi, &write_offset, &num_chunks, data);
				}
				break;
			}
		}

		is_final = gprs_rlcmac_llc_queue_size(llc_queue) == 0 &&
			   !gprs_rlcmac_ul_tbf_shall_keep_open(ul_tbf, bi);

		ar = gprs_rlcmac_enc_append_ul_data(rdbi, cs, ul_tbf->llc_tx_msg,
						    &write_offset, &num_chunks, data,
						    is_final, &payload_written);

		if (ar == GPRS_RLCMAC_AR_NEED_MORE_BLOCKS)
			break;

		LOGPTBFUL(ul_tbf, LOGL_DEBUG, "Complete UL frame, len=%d\n", msgb_length(ul_tbf->llc_tx_msg));
		msgb_free(ul_tbf->llc_tx_msg);
		ul_tbf->llc_tx_msg = NULL;

		/* dequeue next LLC frame, if any */
		gprs_rlcmac_ul_tbf_schedule_next_llc_frame(ul_tbf);
	} while (ar == GPRS_RLCMAC_AR_COMPLETED_SPACE_LEFT);

	LOGPTBFUL(ul_tbf, LOGL_DEBUG, "data block (BSN %d, %s): %s\n",
		  bsn, gprs_rlcmac_mcs_name(blk->cs_last),
		  osmo_hexdump(blk->buf, block_data_len));
	/* raise send state and set ack state array */
	gprs_rlcmac_rlc_v_b_mark_unacked(&ul_tbf->ulw->v_b, bsn);
	gprs_rlcmac_rlc_ul_window_increment_send(ul_tbf->ulw);

	return bsn;
}

static bool restart_bsn_cycle(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	/* If V(S) == V(A) and finished state, we would have received
	 * acknowledgement of all transmitted block.  In this case we would
	 * have transmitted the final block, and received ack from MS. But in
	 * this case we did not receive the final ack indication from MS.  This
	 * should never happen if MS works correctly.
	 */
	if (gprs_rlcmac_rlc_ul_window_window_empty(ul_tbf->ulw)) {
		LOGPTBFUL(ul_tbf, LOGL_DEBUG, "MS acked all blocks\n");
		return false;
	}

	/* cycle through all unacked blocks */
	int resend = gprs_rlcmac_rlc_ul_window_mark_for_resend(ul_tbf->ulw);

	/* At this point there should be at least one unacked block
	 * to be resent. If not, this is an software error. */
	if (resend == 0) {
		LOGPTBFUL(ul_tbf, LOGL_ERROR,
			  "FIXME: Software error: There are no unacknowledged blocks, but V(A) != V(S). PLEASE FIX!\n");
		return false;
	}

	return true;
}

static int take_next_bsn(struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi,
			int previous_bsn, bool *may_combine)
{
	int bsn;
	int data_len2;
	int force_data_len = -1;
	enum gprs_rlcmac_coding_scheme tx_cs;
	struct gprs_rlcmac_rlc_block *blk;

	/* search for a nacked or resend marked bsn */
	bsn = gprs_rlcmac_rlc_ul_window_resend_needed(ul_tbf->ulw);

	if (previous_bsn >= 0) {
		struct gprs_rlcmac_rlc_block *pevious_blk = gprs_rlcmac_rlc_block_store_get_block(ul_tbf->blkst, previous_bsn);
		tx_cs = pevious_blk->cs_current_trans;
		if (!gprs_rlcmac_mcs_is_edge(tx_cs))
			return -1;
		force_data_len = pevious_blk->len;
	} else {
		tx_cs = ul_tbf->tx_cs;
	}

	if (bsn >= 0) {
		/* resend an unacked bsn or resend bsn. */
		if (previous_bsn == bsn)
			return -1;

		if (previous_bsn >= 0 &&
		    gprs_rlcmac_rlc_window_mod_sns_bsn(ul_tbf->w, bsn - previous_bsn) > RLC_EGPRS_MAX_BSN_DELTA)
			return -1;

		blk = gprs_rlcmac_rlc_block_store_get_block(ul_tbf->blkst, bsn);
		if (ul_tbf->tbf.is_egprs) {
			/* Table 8.1.1.2 and Table 8.1.1.1 of 44.060 */
			blk->cs_current_trans = gprs_rlcmac_get_retx_mcs(blk->cs_init, tx_cs,
									 g_rlcmac_ctx->cfg.egprs_arq_type == GPRS_RLCMAC_EGPRS_ARQ1);

			LOGPTBFUL(ul_tbf, LOGL_DEBUG,
				  "initial_cs_dl(%s) last_mcs(%s) demanded_mcs(%s) cs_trans(%s) arq_type(%d) bsn(%d)\n",
				  gprs_rlcmac_mcs_name(blk->cs_init),
				  gprs_rlcmac_mcs_name(blk->cs_last),
				  gprs_rlcmac_mcs_name(tx_cs),
				  gprs_rlcmac_mcs_name(blk->cs_current_trans),
				  g_rlcmac_ctx->cfg.egprs_arq_type, bsn);

			/* TODO: Need to remove this check when MCS-8 -> MCS-6
			 * transistion is handled.
			 * Refer commit be881c028fc4da00c4046ecd9296727975c206a3
			 */
			if (blk->cs_init == GPRS_RLCMAC_MCS_8)
				blk->cs_current_trans = GPRS_RLCMAC_MCS_8;
		} else {
			/* gprs */
			blk->cs_current_trans = blk->cs_last;
		}

		data_len2 = blk->len;
		if (force_data_len > 0 && force_data_len != data_len2)
			return -1;
		LOGPTBFUL(ul_tbf, LOGL_DEBUG, "Resending BSN %d\n", bsn);
		/* re-send block with negative acknowlegement */
		gprs_rlcmac_rlc_v_b_mark_unacked(&ul_tbf->ulw->v_b, bsn);
	} else if (gprs_rlcmac_tbf_ul_state(ul_tbf) == GPRS_RLCMAC_TBF_UL_ST_FINISHED) {
		/* If the TBF is in finished, we already sent all packages at least once.
		 * If any packages could have been sent (because of unacked) it should have
		 * been catched up by the upper if(bsn >= 0) */
		LOGPTBFUL(ul_tbf, LOGL_DEBUG, "Restarting at BSN %d, because all blocks have been transmitted.\n",
			  gprs_rlcmac_rlc_ul_window_v_a(ul_tbf->ulw));
		if (restart_bsn_cycle(ul_tbf))
			return take_next_bsn(ul_tbf, bi, previous_bsn, may_combine);
	} else if (gprs_rlcmac_rlc_ul_window_window_stalled(ul_tbf->ulw)) {
		/* There are no more packages to send, but the window is stalled.
		 * Restart the bsn_cycle to resend all unacked messages */
		LOGPTBFUL(ul_tbf, LOGL_NOTICE, "Restarting at BSN %d, because the window is stalled.\n",
			  gprs_rlcmac_rlc_ul_window_v_a(ul_tbf->ulw));
		if (restart_bsn_cycle(ul_tbf))
			return take_next_bsn(ul_tbf, bi, previous_bsn, may_combine);
	} else if (gprs_rlcmac_ul_tbf_have_data(ul_tbf)) {
		/* The window has space left, generate new bsn */
		LOGPTBFUL(ul_tbf, LOGL_DEBUG, "Sending new block at BSN %d, CS=%s%s\n",
			  gprs_rlcmac_rlc_ul_window_v_s(ul_tbf->ulw), gprs_rlcmac_mcs_name(tx_cs),
			  force_data_len != -1 ? " (forced)" : "");

		bsn = create_new_bsn(ul_tbf, bi, tx_cs);
	} else if (g_rlcmac_ctx->cfg.ul_tbf_preemptive_retransmission &&
		   !gprs_rlcmac_rlc_ul_window_window_empty(ul_tbf->ulw)) {
		/* The window contains unacked packages, but not acked.
		 * Mark unacked bsns as RESEND */
		LOGPTBFUL(ul_tbf, LOGL_DEBUG, "Restarting at BSN %d, because all blocks have been transmitted (FLOW).\n",
			  gprs_rlcmac_rlc_ul_window_v_a(ul_tbf->ulw));
		if (restart_bsn_cycle(ul_tbf))
			return take_next_bsn(ul_tbf, bi, previous_bsn, may_combine);
	}

	if (bsn < 0) {
		/* we just send final block again */
		LOGPTBFUL(ul_tbf, LOGL_DEBUG, "Nothing else to send, Re-transmit final block!\n");
		bsn = gprs_rlcmac_rlc_ul_window_v_s_mod(ul_tbf->ulw, -1);
	}

	blk = gprs_rlcmac_rlc_block_store_get_block(ul_tbf->blkst, bsn);
	*may_combine = gprs_rlcmac_num_data_blocks(gprs_rlcmac_mcs_header_type(blk->cs_current_trans)) > 1;

	return bsn;
}

/*
 * This function returns the pointer to data which needs
 * to be copied. Also updates the status of the block related to
 * Split block handling in the RLC/MAC block.
 */
static enum gprs_rlcmac_rlc_egprs_ul_reseg_bsn_state egprs_ul_get_data(const struct gprs_rlcmac_ul_tbf *ul_tbf, int bsn, uint8_t **block_data)
{
	struct gprs_rlcmac_rlc_block *blk = gprs_rlcmac_rlc_block_store_get_block(ul_tbf->blkst, bsn);
	enum gprs_rlcmac_rlc_egprs_ul_reseg_bsn_state *block_status_ul = &blk->spb_status.block_status_ul;

	enum gprs_rlcmac_coding_scheme cs_init = blk->cs_init;
	enum gprs_rlcmac_coding_scheme cs_current_trans = blk->cs_current_trans;

	enum gprs_rlcmac_header_type ht_cs_init = gprs_rlcmac_mcs_header_type(blk->cs_init);
	enum gprs_rlcmac_header_type ht_cs_current_trans = gprs_rlcmac_mcs_header_type(blk->cs_current_trans);

	*block_data = &blk->buf[0];

	/*
	 * Table 10.3a.0.1 of 44.060
	 * MCS6,9: second segment starts at 74/2 = 37
	 * MCS5,7: second segment starts at 56/2 = 28
	 * MCS8: second segment starts at 31
	 * MCS4: second segment starts at 44/2 = 22
	 */
	if (ht_cs_current_trans == GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_3) {
		if (*block_status_ul == GPRS_RLCMAC_EGPRS_RESEG_FIRST_SEG_SENT) {
			switch (cs_init) {
			case GPRS_RLCMAC_MCS_6:
			case GPRS_RLCMAC_MCS_9:
				*block_data = &blk->buf[37];
				break;
			case GPRS_RLCMAC_MCS_7:
			case GPRS_RLCMAC_MCS_5:
				*block_data = &blk->buf[28];
				break;
			case GPRS_RLCMAC_MCS_8:
				*block_data = &blk->buf[31];
				break;
			case GPRS_RLCMAC_MCS_4:
				*block_data = &blk->buf[22];
				break;
			default:
				LOGPTBFUL(ul_tbf, LOGL_ERROR,
					  "FIXME: Software error: hit invalid condition. "
					  "headerType(%d) blockstatus(%d) cs(%s) PLEASE FIX!\n",
					  ht_cs_current_trans,
					  *block_status_ul, gprs_rlcmac_mcs_name(cs_init));
				break;

			}
			return GPRS_RLCMAC_EGPRS_RESEG_SECOND_SEG_SENT;
		} else if ((ht_cs_init == GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_1) ||
			   (ht_cs_init == GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_2)) {
			return GPRS_RLCMAC_EGPRS_RESEG_FIRST_SEG_SENT;
		} else if ((cs_init == GPRS_RLCMAC_MCS_4) &&
			   (cs_current_trans == GPRS_RLCMAC_MCS_1)) {
			return GPRS_RLCMAC_EGPRS_RESEG_FIRST_SEG_SENT;
		}
	}
	return GPRS_RLCMAC_EGPRS_RESEG_UL_DEFAULT;
}

/*
 * This function returns the spb value to be sent OTA
 * for RLC/MAC block.
 */
static enum gprs_rlcmac_rlc_egprs_ul_spb get_egprs_ul_spb(const struct gprs_rlcmac_ul_tbf *ul_tbf, int bsn)
{
	struct gprs_rlcmac_rlc_block *blk = gprs_rlcmac_rlc_block_store_get_block(ul_tbf->blkst, bsn);
	enum gprs_rlcmac_rlc_egprs_ul_reseg_bsn_state block_status_ul = blk->spb_status.block_status_ul;

	enum gprs_rlcmac_coding_scheme cs_init = blk->cs_init;
	enum gprs_rlcmac_coding_scheme cs_current_trans = blk->cs_current_trans;

	enum gprs_rlcmac_header_type ht_cs_init = gprs_rlcmac_mcs_header_type(blk->cs_init);
	enum gprs_rlcmac_header_type ht_cs_current_trans = gprs_rlcmac_mcs_header_type(blk->cs_current_trans);

	/* Table 10.4.8b.1 of 44.060 */
	if (ht_cs_current_trans == GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_3) {
		/*
		 * if we are sending the second segment the spb should be 3
		 * otherwise it should be 2
		 */
		if (block_status_ul == GPRS_RLCMAC_EGPRS_RESEG_FIRST_SEG_SENT) {
			return GPRS_RLCMAC_EGPRS_UL_SPB_SEC_SEG;
		} else if ((ht_cs_init == GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_1) ||
			   (ht_cs_init == GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_2)) {
			return GPRS_RLCMAC_EGPRS_UL_SPB_FIRST_SEG_6NOPAD;
		} else if ((cs_init == GPRS_RLCMAC_MCS_4) &&
			   (cs_current_trans == GPRS_RLCMAC_MCS_1)) {
			return GPRS_RLCMAC_EGPRS_UL_SPB_FIRST_SEG_10PAD;
		}
	}
	/* Non SPB cases 0 is reurned */
	return GPRS_RLCMAC_EGPRS_UL_SPB_NO_RETX;
}

static struct msgb *create_ul_acked_block(struct gprs_rlcmac_ul_tbf *ul_tbf,
					  const struct gprs_rlcmac_rts_block_ind *bi,
					  int index, int index2)
{
	uint8_t *msg_data;
	struct msgb *msg;
	unsigned msg_len;
	/* TODO: support MCS-7 - MCS-9, where data_block_idx can be 1 */
	uint8_t data_block_idx = 0;
	bool is_final = false;
	enum gprs_rlcmac_coding_scheme cs_init, cs;
	struct gprs_rlcmac_rlc_data_info rlc;
	int bsns[ARRAY_SIZE(rlc.block_info)];
	unsigned num_bsns;
	bool need_padding = false;
	enum gprs_rlcmac_rlc_egprs_ul_spb spb = GPRS_RLCMAC_EGPRS_UL_SPB_NO_RETX;
	unsigned int spb_status;
	struct gprs_rlcmac_rlc_block *blk;
	struct gprs_rlcmac_entity *gre = ul_tbf->tbf.gre;

	blk = gprs_rlcmac_rlc_block_store_get_block(ul_tbf->blkst, index);
	spb_status = blk->spb_status.block_status_ul;

	enum gprs_rlcmac_egprs_puncturing_values punct[2] = {
		GPRS_RLCMAC_EGPRS_PS_INVALID, GPRS_RLCMAC_EGPRS_PS_INVALID
	};
	osmo_static_assert(ARRAY_SIZE(rlc.block_info) == 2, rlc_block_info_size_is_two);

	/*
	 * TODO: This is an experimental work-around to put 2 BSN into
	 * MCS-7 to MCS-9 encoded messages. It just sends the same BSN
	 * twice in the block. The cs should be derived from the TBF's
	 * current CS such that both BSNs (that must be compatible) can
	 * be put into the data area, even if the resulting CS is higher than
	 * the current limit.
	 */
	cs = blk->cs_current_trans;
	cs_init = blk->cs_init;
	bsns[0] = index;
	num_bsns = 1;

	if (index2 >= 0) {
		bsns[num_bsns] = index2;
		num_bsns += 1;
	}

	/*
	 * if the initial mcs is 8 and retransmission mcs is either 6 or 3
	 * we have to include the padding of 6 octets in first segment
	 */
	if ((cs_init == GPRS_RLCMAC_MCS_8) &&
	    (cs == GPRS_RLCMAC_MCS_6 || cs == GPRS_RLCMAC_MCS_3)) {
		if (spb_status == GPRS_RLCMAC_EGPRS_RESEG_UL_DEFAULT ||
		    spb_status == GPRS_RLCMAC_EGPRS_RESEG_SECOND_SEG_SENT)
			need_padding  = true;
	} else if (num_bsns == 1) {
		/* TODO: remove the conditional when MCS-6 padding isn't
		 * failing to be decoded by MEs anymore */
		/* TODO: support of MCS-8 -> MCS-6 transition should be
		 * handled
		 * Refer commit be881c028fc4da00c4046ecd9296727975c206a3
		 * dated 2016-02-07 23:45:40 (UTC)
		 */
		if (cs != GPRS_RLCMAC_MCS_8)
			gprs_rlcmac_mcs_dec_to_single_block(&cs, &need_padding);
	}

	spb = get_egprs_ul_spb(ul_tbf, index);

	LOGPTBFUL(ul_tbf, LOGL_DEBUG, "need_padding %d spb_status %d spb %d (BSN1 %d BSN2 %d)\n",
		  need_padding, spb_status, spb, index, index2);

	gprs_rlcmac_rlc_data_info_init_ul(&rlc, cs, need_padding, spb);

	rlc.usf = 7; /* will be set at scheduler */
	rlc.pr = 0; /* FIXME: power reduction */
	rlc.tfi = ul_tbf->cur_alloc.ul_tfi; /* TFI */

	/* return data block(s) as message */
	msg_len = gprs_rlcmac_mcs_size_ul(cs);
	msg = msgb_alloc(msg_len, "rlcmac_ul_data");
	if (!msg)
		return NULL;

	msg_data = msgb_put(msg, msg_len);

	OSMO_ASSERT(rlc.num_data_blocks <= ARRAY_SIZE(rlc.block_info));
	OSMO_ASSERT(rlc.num_data_blocks > 0);

	LOGPTBFUL(ul_tbf, LOGL_DEBUG, "Copying %u RLC blocks, %u BSNs\n", rlc.num_data_blocks, num_bsns);

	/* Copy block(s) to RLC message: the num_data_blocks cannot be more than 2 - see assert above */
	for (data_block_idx = 0; data_block_idx < OSMO_MIN(rlc.num_data_blocks, 2); data_block_idx++) {
		int bsn;
		uint8_t *block_data;
		struct gprs_rlcmac_rlc_block_info *rdbi, *block_info;
		enum gprs_rlcmac_rlc_egprs_ul_reseg_bsn_state reseg_status;

		/* Check if there are more blocks than BSNs */
		if (data_block_idx < num_bsns)
			bsn = bsns[data_block_idx];
		else
			bsn = bsns[0];

		/* Get current puncturing scheme from block */
		blk = gprs_rlcmac_rlc_block_store_get_block(ul_tbf->blkst, bsn);

		blk->next_ps = gprs_rlcmac_get_punct_scheme(blk->next_ps, blk->cs_last, cs, spb);

		if (gprs_rlcmac_mcs_is_edge(cs)) {
			OSMO_ASSERT(blk->next_ps >= GPRS_RLCMAC_EGPRS_PS_1);
			OSMO_ASSERT(blk->next_ps <= GPRS_RLCMAC_EGPRS_PS_3);
		}

		punct[data_block_idx] = blk->next_ps;

		rdbi = &rlc.block_info[data_block_idx];
		block_info = &blk->block_info;

		/*
		 * get data and header from current block
		 * function returns the reseg status
		 */
		reseg_status = egprs_ul_get_data(ul_tbf, bsn, &block_data);
		blk->spb_status.block_status_dl = reseg_status;

		/*
		 * If it is first segment of the split block set the state of
		 * bsn to nacked. If it is the first segment dont update the
		 * next ps value of bsn. since next segment also needs same cps
		 */
		if (spb == GPRS_RLCMAC_EGPRS_UL_SPB_FIRST_SEG_10PAD ||
		    spb == GPRS_RLCMAC_EGPRS_UL_SPB_FIRST_SEG_6NOPAD)
			gprs_rlcmac_rlc_v_b_mark_nacked(&ul_tbf->ulw->v_b, bsn);
		else {
			/*
			 * TODO: Need to handle 2 same bsns
			 * in header type 1
			 */
			gprs_rlcmac_update_punct_scheme(&blk->next_ps, cs);
		}

		blk->cs_last = cs;
		rdbi->ti  = block_info->ti;
		rdbi->e   = block_info->e;
		rdbi->cv  = block_info->cv;
		rdbi->bsn = bsn;
		is_final = is_final || rdbi->cv == 0;

		LOGPTBFUL(ul_tbf, LOGL_DEBUG, "Copying data unit %d (BSN %d)\n",
			  data_block_idx, bsn);

		gprs_rlcmac_rlc_copy_from_aligned_buffer(&rlc, data_block_idx, msg_data, block_data);
	}

	/* Calculate CPS only for EGPRS case */
	if (gprs_rlcmac_mcs_is_edge(cs))
		rlc.cps = gprs_rlcmac_rlc_mcs_cps(cs, punct[0], punct[1], need_padding);

	gprs_rlcmac_rlc_write_ul_data_header(&rlc, msg_data);

	LOGPTBFUL(ul_tbf, LOGL_DEBUG, "msg block (BSN %d, %s%s): %s\n",
		  index, gprs_rlcmac_mcs_name(cs),
		  need_padding ? ", padded" : "",
		  msgb_hexdump(msg));

	if (ul_tbf->n3104 == 0)
		osmo_fsm_inst_dispatch(ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_FIRST_UL_DATA_SENT, NULL);
	if (is_final)
		osmo_fsm_inst_dispatch(ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_LAST_UL_DATA_SENT, NULL);
	/* Early return if ul_tbf was freed by FSM: */
	if (!gre->ul_tbf)
		return msg;

	ul_tbf->n3104++;
	if (gprs_rlcmac_ul_tbf_in_contention_resolution(ul_tbf)) {
		unsigned int n3104_max = gprs_rlcmac_ul_tbf_n3104_max(ul_tbf);
		if (ul_tbf->n3104 >= n3104_max) {
			LOGPTBFUL(ul_tbf, LOGL_NOTICE, "N3104_MAX (%u) reached\n", n3104_max);
			osmo_fsm_inst_dispatch(ul_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_N3104_MAX, NULL);
		} else {
			LOGPTBFUL(ul_tbf, LOGL_DEBUG, "N3104 inc (%u)\n", ul_tbf->n3104);
		}
	}
	return msg;
}

struct msgb *gprs_rlcmac_ul_tbf_data_create(struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi)
{
	int bsn;
	int bsn2 = -1;
	bool may_combine;

	bsn = take_next_bsn(ul_tbf, bi, -1, &may_combine);
	if (bsn < 0)
		return NULL;

	if (may_combine)
		bsn2 = take_next_bsn(ul_tbf, bi, bsn, &may_combine);

	return create_ul_acked_block(ul_tbf, bi, bsn, bsn2);
}
