/* Downlink TBF as per 3GPP TS 44.064 */
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
#include <osmocom/core/logging.h>

#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/rlc_window_dl.h>
#include <osmocom/gprs/rlcmac/rlcmac_dec.h>
#include <osmocom/gprs/rlcmac/rlcmac_enc.h>
#include <osmocom/gprs/rlcmac/pdch_ul_controller.h>

static void gprs_rlcmac_dl_tbf_t3190_timer_cb(void *data);

struct gprs_rlcmac_dl_tbf *gprs_rlcmac_dl_tbf_alloc(struct gprs_rlcmac_entity *gre)
{
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	int rc;

	dl_tbf = talloc_zero(gre, struct gprs_rlcmac_dl_tbf);
	if (!dl_tbf)
		return NULL;

	gprs_rlcmac_tbf_constructor(dl_tbf_as_tbf(dl_tbf), GPRS_RLCMAC_TBF_DIR_DL, gre);

	rc = gprs_rlcmac_tbf_dl_fsm_constructor(dl_tbf);
	if (rc < 0)
		goto err_tbf_destruct;

	dl_tbf->tbf.nr = g_rlcmac_ctx->next_dl_tbf_nr++;

	dl_tbf->dlw = gprs_rlcmac_rlc_dl_window_alloc(dl_tbf);
	OSMO_ASSERT(dl_tbf->dlw);


	dl_tbf->blkst = gprs_rlcmac_rlc_block_store_alloc(dl_tbf);
	OSMO_ASSERT(dl_tbf->blkst);

	osmo_timer_setup(&dl_tbf->t3190, gprs_rlcmac_dl_tbf_t3190_timer_cb, dl_tbf);

	return dl_tbf;

err_tbf_destruct:
	gprs_rlcmac_tbf_destructor(dl_tbf_as_tbf(dl_tbf));
	talloc_free(dl_tbf);
	return NULL;
}

void gprs_rlcmac_dl_tbf_free(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	struct gprs_rlcmac_tbf *tbf;
	struct gprs_rlcmac_entity *gre;

	if (!dl_tbf)
		return;

	tbf = dl_tbf_as_tbf(dl_tbf);
	gre = tbf->gre;

	osmo_timer_del(&dl_tbf->t3190);

	msgb_free(dl_tbf->llc_rx_msg);
	dl_tbf->llc_rx_msg = NULL;

	gprs_rlcmac_rlc_block_store_free(dl_tbf->blkst);
	dl_tbf->blkst = NULL;

	gprs_rlcmac_rlc_dl_window_free(dl_tbf->dlw);
	dl_tbf->dlw = NULL;

	gprs_rlcmac_tbf_dl_fsm_destructor(dl_tbf);

	gprs_rlcmac_tbf_destructor(tbf);
	talloc_free(dl_tbf);
	/* Inform the MS that the TBF pointer has been freed: */
	gprs_rlcmac_entity_dl_tbf_freed(gre, dl_tbf);
}

static void gprs_rlcmac_dl_tbf_t3190_timer_cb(void *data)
{
	struct gprs_rlcmac_dl_tbf *dl_tbf = data;

	LOGPTBFDL(dl_tbf, LOGL_NOTICE, "Timeout of T3190\n");

	gprs_rlcmac_dl_tbf_free(dl_tbf);
}

void gprs_rlcmac_dl_tbf_t3190_start(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	unsigned long val_sec;
	val_sec = osmo_tdef_get(g_rlcmac_ctx->T_defs, 3190, OSMO_TDEF_S, -1);
	osmo_timer_schedule(&dl_tbf->t3190, val_sec, 0);
}

static uint8_t dl_tbf_dl_slotmask(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	uint8_t dl_slotmask = 0;

	for (unsigned int i = 0; i < ARRAY_SIZE(dl_tbf->cur_alloc.ts); i++) {
		if (dl_tbf->cur_alloc.ts[i].allocated)
			dl_slotmask |= (1 << i);
	}

	return dl_slotmask;
}

int gprs_rlcmac_dl_tbf_configure_l1ctl(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	uint8_t dl_slotmask = dl_tbf_dl_slotmask(dl_tbf);

	 LOGPTBFDL(dl_tbf, LOGL_INFO, "Send L1CTL-CFG_DL_TBF.req dl_slotmask=0x%02x dl_tfi=%u\n",
		   dl_slotmask, dl_tbf->cur_alloc.dl_tfi);
	rlcmac_prim = gprs_rlcmac_prim_alloc_l1ctl_cfg_dl_tbf_req(dl_tbf->tbf.nr,
								  dl_slotmask,
								  dl_tbf->cur_alloc.dl_tfi);
	return gprs_rlcmac_prim_call_down_cb(rlcmac_prim);
}

struct msgb *gprs_rlcmac_dl_tbf_create_pkt_dl_ack_nack(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	struct msgb *msg;
	struct bitvec bv;
	RlcMacUplink_t ul_block;
	int rc;

	OSMO_ASSERT(dl_tbf);

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "pkt_dl_ack_nack");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer. */
	bv = (struct bitvec){
		.data = msgb_put(msg, GSM_MACBLOCK_LEN),
		.data_len = GSM_MACBLOCK_LEN,
	};
	bitvec_unhex(&bv, GPRS_RLCMAC_DUMMY_VEC);

	gprs_rlcmac_enc_prepare_pkt_downlink_ack_nack(&ul_block, dl_tbf);
	rc = osmo_gprs_rlcmac_encode_uplink(&bv, &ul_block);
	if (rc < 0) {
		LOGPTBFDL(dl_tbf, LOGL_ERROR, "Encoding of Packet Downlink ACK/NACK failed (%d)\n", rc);
		goto free_ret;
	}

	/* Stop T3190 if transmitting final Downlink Ack/Nack */
	if (gprs_rlcmac_tbf_dl_state(dl_tbf) == GPRS_RLCMAC_TBF_DL_ST_FINISHED)
		osmo_timer_del(&dl_tbf->t3190);

	return msg;

free_ret:
	msgb_free(msg);
	return NULL;
}

/*
 * Store received block data in LLC message(s) and forward to SGSN
 * if complete.
 */
static int gprs_rlcmac_dl_tbf_assemble_forward_llc(struct gprs_rlcmac_dl_tbf *dl_tbf,
						   const struct gprs_rlcmac_rlc_block *blk)
{
	const uint8_t *data = &blk->buf[0];
	uint8_t len = blk->len;
	const struct gprs_rlcmac_rlc_block_info *rdbi = &blk->block_info;
	enum gprs_rlcmac_coding_scheme cs = blk->cs_last;
	struct gprs_rlcmac_rlc_llc_chunk frames[16];
	int i, num_frames = 0;
	int rc = 0;

	LOGPTBFDL(dl_tbf, LOGL_DEBUG, "Assembling frames: (len=%d)\n", len);

	num_frames = gprs_rlcmac_rlc_data_from_dl_data(rdbi, cs, data,
						       &frames[0], ARRAY_SIZE(frames));

	/* create LLC frames */
	for (i = 0; i < num_frames; i++) {
		struct gprs_rlcmac_rlc_llc_chunk *frame = &frames[i];
		struct osmo_gprs_rlcmac_prim *rlcmac_prim;

		if (!dl_tbf->llc_rx_msg) {
			rlcmac_prim = gprs_rlcmac_prim_alloc_grr_unitdata_ind(dl_tbf->tbf.gre->tlli,
									      NULL,
									      GPRS_RLCMAC_LLC_PDU_MAX_LEN);
			dl_tbf->llc_rx_msg = rlcmac_prim->oph.msg;
			dl_tbf->llc_rx_msg->l3h = dl_tbf->llc_rx_msg->tail;
		} else {
			rlcmac_prim = msgb_rlcmac_prim(dl_tbf->llc_rx_msg);
		}

		if (frame->length) {
			LOGPTBFDL(dl_tbf, LOGL_DEBUG, "Frame %d "
				"starts at offset %d, "
				"length=%d, is_complete=%d\n",
				i + 1, frame->offset, frame->length,
				frame->is_complete);

			memcpy(msgb_put(dl_tbf->llc_rx_msg, frame->length),
			       data + frame->offset, frame->length);
		}

		if (frame->is_complete) {
			/* send frame to upper layers: */
			LOGPTBFDL(dl_tbf, LOGL_DEBUG, "complete UL frame len=%d\n", msgb_l3len(dl_tbf->llc_rx_msg));
			rlcmac_prim->grr.ll_pdu = msgb_l3(dl_tbf->llc_rx_msg);
			rlcmac_prim->grr.ll_pdu_len = msgb_l3len(dl_tbf->llc_rx_msg);

			/* ownserhsip of dl_tbf->llc_rx_msg transferred here: */
			rc = gprs_rlcmac_prim_call_up_cb(rlcmac_prim);
			dl_tbf->llc_rx_msg = NULL;
		}
	}

	return rc;
}

int gprs_rlcmac_dl_tbf_rcv_data_block(struct gprs_rlcmac_dl_tbf *dl_tbf,
				      const struct gprs_rlcmac_rlc_data_info *rlc,
				      uint8_t *data, uint32_t fn, uint8_t ts_nr)
{
	const struct gprs_rlcmac_rlc_block_info *rdbi;
	struct gprs_rlcmac_rlc_block *block;
	unsigned int block_idx;
	const uint16_t ws = gprs_rlcmac_rlc_window_ws(dl_tbf->w);

	LOGPTBFDL(dl_tbf, LOGL_DEBUG, "DL DATA TFI=%d received (V(Q)=%d .. V(R)=%d)\n",
		  rlc->tfi,
		  gprs_rlcmac_rlc_dl_window_v_q(dl_tbf->dlw),
		  gprs_rlcmac_rlc_dl_window_v_r(dl_tbf->dlw));

	/* Re-arm T3190: */
	gprs_rlcmac_dl_tbf_t3190_start(dl_tbf);

	/* Loop over num_blocks */
	for (block_idx = 0; block_idx < rlc->num_data_blocks; block_idx++) {
		uint8_t *rlc_data;
		rdbi = &rlc->block_info[block_idx];

		LOGPTBFDL(dl_tbf, LOGL_DEBUG,
			  "Got %s RLC data block: FBI=%u, BSN=%d, SPB=%d, S/P=%d RRBP=%u, E=%d, bitoffs=%d\n",
			  gprs_rlcmac_mcs_name(rlc->cs),
			  rdbi->cv == 0, rdbi->bsn, rdbi->spb,
			  rlc->es_p, rlc->rrbp, rdbi->e,
			  rlc->data_offs_bits[block_idx]);

		/* Check whether the block needs to be decoded */

		if (!gprs_rlcmac_rlc_dl_window_is_in_window(dl_tbf->dlw, rdbi->bsn)) {
			LOGPTBFDL(dl_tbf, LOGL_DEBUG, "BSN %d out of window %d..%d (it's normal)\n",
				  rdbi->bsn,
				  gprs_rlcmac_rlc_dl_window_v_q(dl_tbf->dlw),
				  gprs_rlcmac_rlc_window_mod_sns_bsn(dl_tbf->w, gprs_rlcmac_rlc_dl_window_v_q(dl_tbf->dlw) + ws - 1));
			continue;
		} else if (gprs_rlcmac_rlc_v_n_is_received(&dl_tbf->dlw->v_n, rdbi->bsn)) {
			LOGPTBFDL(dl_tbf, LOGL_DEBUG, "BSN %d already received\n", rdbi->bsn);
			continue;
		}

		/* Store block and meta info to BSN buffer */

		LOGPTBFDL(dl_tbf, LOGL_DEBUG, "BSN %d storing in window (%d..%d)\n",
			  rdbi->bsn, gprs_rlcmac_rlc_dl_window_v_q(dl_tbf->dlw),
			  gprs_rlcmac_rlc_window_mod_sns_bsn(dl_tbf->w, gprs_rlcmac_rlc_dl_window_v_q(dl_tbf->dlw) + ws - 1));
		block = gprs_rlcmac_rlc_block_store_get_block(dl_tbf->blkst, rdbi->bsn);
		OSMO_ASSERT(rdbi->data_len <= sizeof(block->buf));
		rlc_data = &(block->buf[0]);

		block->block_info = *rdbi;
		block->cs_last = rlc->cs;
		block->len = gprs_rlcmac_rlc_copy_to_aligned_buffer(rlc, block_idx,
								    data, rlc_data);

		LOGPTBFDL(dl_tbf, LOGL_DEBUG, "data_length=%d, data=%s\n",
			  block->len, osmo_hexdump(rlc_data, block->len));

		gprs_rlcmac_rlc_dl_window_receive_bsn(dl_tbf->dlw, rdbi->bsn);
	}

	/* Raise V(Q) if possible, and retrieve LLC frames from blocks.
	 * This is looped until there is a gap (non received block) or
	 * the window is empty.*/
	const uint16_t v_q_beg = gprs_rlcmac_rlc_dl_window_v_q(dl_tbf->dlw);
	const uint16_t count = gprs_rlcmac_rlc_dl_window_raise_v_q(dl_tbf->dlw);

	/* Retrieve LLC frames from blocks that are ready */
	for (uint16_t i = 0; i < count; ++i) {
		uint16_t index = gprs_rlcmac_rlc_window_mod_sns_bsn(dl_tbf->w, v_q_beg + i);
		gprs_rlcmac_dl_tbf_assemble_forward_llc(dl_tbf, gprs_rlcmac_rlc_block_store_get_block(dl_tbf->blkst, index));
	}

	/* Last frame in buffer: */
	uint16_t last = gprs_rlcmac_rlc_window_mod_sns_bsn(dl_tbf->w,
							   gprs_rlcmac_rlc_dl_window_v_r(dl_tbf->dlw) - 1);
	block = gprs_rlcmac_rlc_block_store_get_block(dl_tbf->blkst, last);
	rdbi = &block->block_info;

	/* Check if we already received all data TBF had to send: */
	if (//this->state_is(TBF_ST_FLOW) && /* still in flow state */
	    (gprs_rlcmac_rlc_dl_window_v_q(dl_tbf->dlw) == gprs_rlcmac_rlc_dl_window_v_r(dl_tbf->dlw)) && /* if complete */
	     block->len) { /* if there was ever a last block received */
		LOGPTBFDL(dl_tbf, LOGL_DEBUG,
			  "No gaps in received block, last block: BSN=%d FBI=%d\n",
			  rdbi->bsn, rdbi->cv == 0);
		if (rdbi->cv == 0) {
			LOGPTBFDL(dl_tbf, LOGL_DEBUG, "Finished with DL TBF\n");
			osmo_fsm_inst_dispatch(dl_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_DL_EV_LAST_DL_DATA_RECVD, NULL);
		}
	}

	/* If RRBP contains valid data, schedule a DL ACK/NACK. */
	if (rlc->es_p) {
		uint32_t poll_fn = rrbp2fn(fn, rlc->rrbp);
		gprs_rlcmac_pdch_ulc_reserve(g_rlcmac_ctx->sched.ulc[ts_nr], poll_fn,
					     GPRS_RLCMAC_PDCH_ULC_POLL_DL_ACK,
					     dl_tbf_as_tbf(dl_tbf));
	}

	return 0;
}
