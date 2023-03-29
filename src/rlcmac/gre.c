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

struct gprs_rlcmac_entity *gprs_rlcmac_entity_alloc(uint32_t tlli)
{
	struct gprs_rlcmac_entity *gre;
	int rc;

	gre = talloc_zero(g_ctx, struct gprs_rlcmac_entity);
	if (!gre)
		return NULL;

	gre->llc_queue = gprs_rlcmac_llc_queue_alloc(gre);
	if (!gre->llc_queue)
		goto err_free_gre;
	gprs_rlcmac_llc_queue_set_codel_params(gre->llc_queue,
					       g_ctx->cfg.codel.use,
					       g_ctx->cfg.codel.interval_msec);

	rc = gprs_rlcmac_tbf_dl_ass_fsm_constructor(&gre->dl_tbf_dl_ass_fsm, gre);
	if (rc < 0)
		goto err_free_gre;

	gre->tlli = tlli;
	llist_add_tail(&gre->entry, &g_ctx->gre_list);

	return gre;

err_free_gre:
	talloc_free(gre);
	return NULL;
}

void gprs_rlcmac_entity_free(struct gprs_rlcmac_entity *gre)
{
	if (!gre)
		return;

	gprs_rlcmac_tbf_dl_ass_fsm_destructor(&gre->dl_tbf_dl_ass_fsm);
	gprs_rlcmac_dl_tbf_free(gre->dl_tbf);
	gprs_rlcmac_ul_tbf_free(gre->ul_tbf);
	gprs_rlcmac_llc_queue_free(gre->llc_queue);
	llist_del(&gre->entry);
	talloc_free(gre);
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

int gprs_rlcmac_entity_llc_enqueue(struct gprs_rlcmac_entity *gre, uint8_t *ll_pdu, unsigned int ll_pdu_len,
				   enum osmo_gprs_rlcmac_llc_sapi sapi, uint8_t radio_prio)
{
	int rc;
	rc = gprs_rlcmac_llc_queue_enqueue(gre->llc_queue, ll_pdu, ll_pdu_len,
					   sapi, radio_prio);
	if (rc < 0)
		return rc;

	/* TS 44.060 5.3 "In packet idle mode, upper layers may require the
	* transfer of a upper layer PDU, which implicitly triggers the
	* establishment of a TBF and the transition to packet transfer mode." */
	if (gprs_rlcmac_entity_in_packet_idle_mode(gre)) {
		OSMO_ASSERT(!gre->ul_tbf);
		/* We have new data in the queue but we have no ul_tbf. Allocate one and start UL Assignment. */
		gre->ul_tbf = gprs_rlcmac_ul_tbf_alloc(gre);
		if (!gre->ul_tbf)
			return -ENOMEM;
		/* We always use 1phase for now... */
		rc = gprs_rlcmac_tbf_ul_ass_start(gre->ul_tbf, GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE);
	}

	return rc;
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
