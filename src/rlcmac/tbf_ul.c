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
#include <osmocom/gprs/rlcmac/rlcmac_enc.h>
#include <osmocom/gprs/rlcmac/gre.h>

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

	ul_tbf->tbf.nr = g_ctx->next_ul_tbf_nr++;

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

	gprs_rlcmac_tbf_ul_ass_fsm_destructor(ul_tbf);
	gprs_rlcmac_tbf_ul_fsm_destructor(ul_tbf);

	gprs_rlcmac_tbf_destructor(ul_tbf_as_tbf(ul_tbf));
	talloc_free(ul_tbf);
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
	return (st == GPRS_RLCMAC_TBF_UL_ST_FLOW);
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

struct msgb *gprs_rlcmac_ul_tbf_data_create(const struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_rts_block_ind *bi)
{
	LOGPTBFUL(ul_tbf, LOGL_ERROR, "(ts=%u,fn=%u,usf=%u) TODO: implement dequeue from LLC\n",
		  bi->ts, bi->fn, bi->usf);
	return NULL;
}
