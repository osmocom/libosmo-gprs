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

#include <osmocom/core/bitvec.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/gprs/rlcmac/tbf.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/rlcmac_enc.h>
#include <osmocom/gprs/rlcmac/pdch_ul_controller.h>

void gprs_rlcmac_tbf_constructor(struct gprs_rlcmac_tbf *tbf,
				 enum gprs_rlcmac_tbf_direction direction,
				 struct gprs_rlcmac_entity *gre)
{
	tbf->gre = gre;
	tbf->direction = direction;
}

void gprs_rlcmac_tbf_destructor(struct gprs_rlcmac_tbf *tbf)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(g_ctx->sched.ulc); i++)
		gprs_rlcmac_pdch_ulc_release_tbf(g_ctx->sched.ulc[i], tbf);
}

void gprs_rlcmac_tbf_free(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->direction == GPRS_RLCMAC_TBF_DIR_UL)
		gprs_rlcmac_ul_tbf_free(tbf_as_ul_tbf(tbf));
	/* else: TODO dl_tbf not yet implemented */
}

struct msgb *gprs_rlcmac_tbf_create_pkt_ctrl_ack(const struct gprs_rlcmac_tbf *tbf)
{
	struct msgb *msg;
	struct bitvec bv;
	RlcMacUplink_t ul_block;
	int rc;

	OSMO_ASSERT(tbf);

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "pkt_ctrl_ack");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer. */
	bv = (struct bitvec){
		.data = msgb_put(msg, GSM_MACBLOCK_LEN),
		.data_len = GSM_MACBLOCK_LEN,
	};
	bitvec_unhex(&bv, GPRS_RLCMAC_DUMMY_VEC);

	gprs_rlcmac_enc_prepare_pkt_ctrl_ack(&ul_block, tbf->gre->tlli);
	rc = osmo_gprs_rlcmac_encode_uplink(&bv, &ul_block);
	if (rc < 0) {
		LOGPTBF(tbf, LOGL_ERROR, "Encoding of Packet Control ACK failed (%d)\n", rc);
		goto free_ret;
	}
	LOGPTBF(tbf, LOGL_DEBUG, "Tx Packet Control Ack\n");

	return msg;

free_ret:
	msgb_free(msg);
	return NULL;
}
