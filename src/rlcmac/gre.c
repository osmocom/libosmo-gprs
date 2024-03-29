/* GPRS RLC/MAC Entity (one per MS) */
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

#include <stdbool.h>

#include <osmocom/core/bitvec.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/rlcmac_prim.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/tbf_dl_ass_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_ul_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/rlcmac_enc.h>


/* We have to defer going to CCCH a bit to leave space for last PKT CTRL ACK to be transmitted */
static void _defer_pkt_idle_timer_cb(void *data)
{
	gprs_rlcmac_submit_l1ctl_pdch_rel_req();
	/* Wait for L1CTL-CCCH_READY.ind before attempting new pkt-access-procedure if needed. */
}

struct gprs_rlcmac_entity *gprs_rlcmac_entity_alloc(uint32_t tlli)
{
	struct gprs_rlcmac_entity *gre;
	int rc;

	gre = talloc_zero(g_rlcmac_ctx, struct gprs_rlcmac_entity);
	if (!gre)
		return NULL;

	osmo_timer_setup(&gre->defer_pkt_idle_timer, _defer_pkt_idle_timer_cb, gre);

	gre->llc_queue = gprs_rlcmac_llc_queue_alloc(gre);
	if (!gre->llc_queue)
		goto err_free_gre;
	gprs_rlcmac_llc_queue_set_codel_params(gre->llc_queue,
					       g_rlcmac_ctx->cfg.codel.use,
					       g_rlcmac_ctx->cfg.codel.interval_msec);

	rc = gprs_rlcmac_tbf_dl_ass_fsm_constructor(&gre->dl_tbf_dl_ass_fsm, gre);
	if (rc < 0)
		goto err_free_gre;

	gre->tlli = tlli;
	gre->old_tlli = GPRS_RLCMAC_TLLI_UNASSIGNED;
	gre->ptmsi = GSM_RESERVED_TMSI;
	llist_add_tail(&gre->entry, &g_rlcmac_ctx->gre_list);

	return gre;

err_free_gre:
	talloc_free(gre);
	return NULL;
}

void gprs_rlcmac_entity_free(struct gprs_rlcmac_entity *gre)
{
	if (!gre)
		return;

	gre->freeing = true;

	osmo_timer_del(&gre->defer_pkt_idle_timer);

	gprs_rlcmac_tbf_dl_ass_fsm_destructor(&gre->dl_tbf_dl_ass_fsm);
	gprs_rlcmac_dl_tbf_free(gre->dl_tbf);
	gprs_rlcmac_ul_tbf_free(gre->ul_tbf);
	gprs_rlcmac_llc_queue_free(gre->llc_queue);
	llist_del(&gre->entry);
	talloc_free(gre);
}

/* Called by dl_tbf destructor to inform the DL TBF pointer has been freed.
 * Hence memory pointed by "dl_tbf" is already freed and shall not be accessed. */
void gprs_rlcmac_entity_dl_tbf_freed(struct gprs_rlcmac_entity *gre, const struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	OSMO_ASSERT(gre);
	OSMO_ASSERT(gre->dl_tbf);
	OSMO_ASSERT(dl_tbf);

	/* GRE is freeing (destructor being called) do nothing */
	if (gre->freeing)
		return;

	if (gre->dl_tbf != dl_tbf) {
		/* This may happen if we already have a new DL TBF allocated
		 * immediately prior to freeing the old one (PACCH assignment
		 * reusing resources of old one). Nothing to do, simply wait for
		 * new DL TBF to do its job.
		 */
		return;
	}

	gre->dl_tbf = NULL;

	/* Nothing to do, we are still in packet-transfer-mode using UL TBF. */
	if (gre->ul_tbf)
		return;

	/* we have no DL nor UL TBFs. Go back to PACKET-IDLE state, and start
	 * packet-access-procedure if we still have data to be transmitted.
	 */
	/* We have to defer going to CCCH a bit to leave space for last PKT CTRL ACK to be transmitted */
	osmo_timer_schedule(&gre->defer_pkt_idle_timer, 0, DEFER_SCHED_PDCH_REL_REQ_uS);
}

/* Called by ul_tbf destructor to inform the UL TBF pointer has been freed.
 * Hence memory pointed by "ul_tbf" is already freed and shall not be accessed. */
void gprs_rlcmac_entity_ul_tbf_freed(struct gprs_rlcmac_entity *gre, const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	OSMO_ASSERT(gre);
	OSMO_ASSERT(gre->ul_tbf);
	OSMO_ASSERT(ul_tbf);

	/* GRE is freeing (destructor being called) do nothing */
	if (gre->freeing)
		return;

	if (gre->ul_tbf != ul_tbf) {
		/* This may happen if we already have a new UL TBF allocated
		 * immediately prior to freeing the old one (PACCH assignment
		 * reusing resources of old one). Nothing to do, simply wait for
		 * new UL TBF to do its job.
		 */
		return;
	}

	gre->ul_tbf = NULL;

	/* Nothing to do, dl_tbf will eventually trigger request for UL TBF PACCH assignment. */
	if (gre->dl_tbf)
		return;

	/* we have no DL nor UL TBFs. Go back to PACKET-IDLE state, and start
	 * packet-access-procedure if we still have data to be transmitted.
	 */
	/* We have to defer going to CCCH a bit to leave space for last PKT CTRL ACK to be transmitted */
	osmo_timer_schedule(&gre->defer_pkt_idle_timer, 0, DEFER_SCHED_PDCH_REL_REQ_uS);
}

/* TS 44.060 5.3 In packet idle mode:
* - no temporary block flow (TBF) exists..
* - the mobile station monitors the relevant paging subchannels on CCCH. In packet
* idle mode, upper layers may require the transfer of a upper layer PDU, which
* implicitly triggers the establishment of a TBF and the transition to packet
* transfer mode. In packet idle mode, upper layers may require the establishment
* of an RR connection. When the mobile station enters dedicated mode (see 3GPP TS
* 44.018), it may leave the packet idle mode, if the mobile station limitations
* make it unable to handle the RR connection and the procedures in packet idle
* mode simultaneously.*/
bool gprs_rlcmac_entity_in_packet_idle_mode(const struct gprs_rlcmac_entity *gre)
{
	return !gre->ul_tbf && !gre->dl_tbf;
}

/* TS 44.060 5.4 "In packet transfer mode, the mobile station is allocated radio
* resources providing one or more TBFs. [...]
* When a transfer of upper layer PDUs
* terminates, in either downlink or uplink direction, the corresponding TBF is
* released. In packet transfer mode, when all TBFs have been released, in downlink
* and uplink direction, the mobile station returns to packet idle mode."
*/
bool gprs_rlcmac_entity_in_packet_transfer_mode(const struct gprs_rlcmac_entity *gre)
{
	return gre->ul_tbf || gre->dl_tbf;
}

/* Whether MS has data queued from upper layers waiting to be transmitted in the
 * Tx queue (an active UL TBF may still have some extra data) */
bool gprs_rlcmac_entity_have_tx_data_queued(const struct gprs_rlcmac_entity *gre)
{
	return gprs_rlcmac_llc_queue_size(gre->llc_queue) > 0;
}

/* Create a new UL TBF and start Packet access procedure to get an UL assignment if needed */
int gprs_rlcmac_entity_start_ul_tbf_pkt_acc_proc_if_needed(struct gprs_rlcmac_entity *gre)
{
	enum osmo_gprs_rlcmac_llc_sapi tx_sapi;
	enum gprs_rlcmac_tbf_ul_ass_type ul_ass_type;

	/* TS 44.060 5.3 "In packet idle mode, upper layers may require the
	* transfer of a upper layer PDU, which implicitly triggers the
	* establishment of a TBF and the transition to packet transfer mode." */
	if (!gprs_rlcmac_entity_in_packet_idle_mode(gre))
		return 0;

	if (!gprs_rlcmac_entity_have_tx_data_queued(gre))
		return 0;

	OSMO_ASSERT(!gre->ul_tbf);
	/* We have data in the queue but we have no ul_tbf. Allocate one and start UL Assignment. */
	gre->ul_tbf = gprs_rlcmac_ul_tbf_alloc(gre);
	if (!gre->ul_tbf)
		return -ENOMEM;

	tx_sapi = gprs_rlcmac_llc_queue_highest_radio_prio_pending(gre->llc_queue);
	/* 3GPP TS 44.018 3.5.2.1.2 "Initiation of the packet access procedure: channel request" */
	switch (tx_sapi) {
	case OSMO_GPRS_RLCMAC_LLC_SAPI_GMM:
		/* "If the purpose [...] is to send a Page Response, a Cell update (the mobile
		 * station was in GMM READY state before the cell reselection) or for any other
		 * GPRS Mobility Management or GPRS Session Management procedure, the mobile station
		 * shall request a one phase packet access" */
		ul_ass_type = GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE;
		break;
	default:
		/* "If the purpose [...] is to send user data and the requested RLC mode is
		 * acknowledged mode, the mobile station shall request either a one phase packet
		 * access or a single block packet access." */
		/* TODO: We always use 1phase for now... ideally we should decide
		 * based on amount of Tx data and configured MultiSlot Class? */
		ul_ass_type = GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE;
	}
	/* We always use 1phase for now... */
	return gprs_rlcmac_tbf_ul_ass_start(gre->ul_tbf, ul_ass_type);
}

int gprs_rlcmac_entity_llc_enqueue(struct gprs_rlcmac_entity *gre,
				   const uint8_t *ll_pdu, unsigned int ll_pdu_len,
				   enum osmo_gprs_rlcmac_llc_sapi sapi,
				   enum gprs_rlcmac_radio_priority radio_prio)
{
	int rc;
	LOGGRE(gre, LOGL_DEBUG, "Enqueueing LLC-PDU len=%u SAPI=%s radio_prio=%u\n",
	       ll_pdu_len, get_value_string(osmo_gprs_rlcmac_llc_sapi_names, sapi), radio_prio + 1);
	rc = gprs_rlcmac_llc_queue_enqueue(gre->llc_queue, ll_pdu, ll_pdu_len,
					   sapi, radio_prio);
	if (rc < 0) {
		LOGGRE(gre, LOGL_NOTICE, "Enqueueing LLC-PDU len=%u SAPI=%s radio_prio=%u failed!\n",
		       ll_pdu_len, get_value_string(osmo_gprs_rlcmac_llc_sapi_names, sapi), radio_prio + 1);
		return rc;
	}

	rc = gprs_rlcmac_entity_start_ul_tbf_pkt_acc_proc_if_needed(gre);
	return rc;
}

/* Calculate TS 44.060 Table 12.7.2 RLC_OCTET_COUNT. 0 = unable to count. */
uint16_t gprs_rlcmac_entity_calculate_new_ul_tbf_rlc_octet_count(const struct gprs_rlcmac_entity *gre)
{
	/* The RLC_OCTET_COUNT field indicates the number of RLC data octets,
	 * plus the number of RLC data block length octets, that the mobile
	 * station wishes to transfer. The value '0' indicates that the mobile
	 * station does not provide any information on the TBF size.
	 */
	uint32_t rlc_oct_cnt = 0;
	const struct gprs_rlcmac_llc_queue *q = gre->llc_queue;

	for (unsigned int i = 0; i < ARRAY_SIZE(q->pq); i++) {
		for (unsigned int j = 0; j < ARRAY_SIZE(q->pq[i]); j++) {
			struct msgb *msg;
			llist_for_each_entry(msg, &q->pq[i][j].queue, list) {
				rlc_oct_cnt += 1 + msgb_l2len(msg);
				if (rlc_oct_cnt >= UINT16_MAX)
					return UINT16_MAX;
			}
		}
	}
	return rlc_oct_cnt;
}

struct msgb *gprs_rlcmac_gre_create_pkt_ctrl_ack(const struct gprs_rlcmac_entity *gre)
{
	struct msgb *msg;
	struct bitvec bv;
	RlcMacUplink_t ul_block;
	int rc;

	OSMO_ASSERT(gre);

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "pkt_ctrl_ack");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer. */
	bv = (struct bitvec){
		.data = msgb_put(msg, GSM_MACBLOCK_LEN),
		.data_len = GSM_MACBLOCK_LEN,
	};
	bitvec_unhex(&bv, GPRS_RLCMAC_DUMMY_VEC);

	gprs_rlcmac_enc_prepare_pkt_ctrl_ack(&ul_block, gre->tlli);
	rc = osmo_gprs_rlcmac_encode_uplink(&bv, &ul_block);
	if (rc < 0) {
		LOGGRE(gre, LOGL_ERROR, "Encoding of Packet Control ACK failed (%d)\n", rc);
		goto free_ret;
	}
	LOGGRE(gre, LOGL_DEBUG, "Tx Packet Control Ack\n");

	return msg;

free_ret:
	msgb_free(msg);
	return NULL;
}
