/* RLC block management as per 3GPP TS 44.060 */
/*
 * (C) 2012 Ivan Klyuchnikov
 * (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/gprs/rlcmac/rlc.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>

void gprs_rlcmac_rlc_block_info_init(struct gprs_rlcmac_rlc_block_info *rdbi,
				     enum gprs_rlcmac_coding_scheme cs,
				     bool with_padding, unsigned int spb)
{
	unsigned int data_len = gprs_rlcmac_mcs_max_data_block_bytes(cs);
	if (with_padding)
		data_len -= gprs_rlcmac_mcs_opt_padding_bits(cs) / 8;

	rdbi->data_len = data_len;
	rdbi->bsn = 0;
	rdbi->ti  = 0;
	rdbi->e   = 1;
	rdbi->cv  = 15;
	rdbi->pi  = 0;
	rdbi->spb = spb;
}

static void gprs_rlcmac_rlc_data_header_init(struct gprs_rlcmac_rlc_data_info *rlc,
					     enum gprs_rlcmac_coding_scheme cs,
					     bool with_padding, unsigned int header_bits,
					     unsigned int spb)
{
	unsigned int i;
	unsigned int padding_bits = with_padding ? gprs_rlcmac_mcs_opt_padding_bits(cs) : 0;

	rlc->cs = cs;
	rlc->r = 0;
	rlc->si = 0;
	rlc->tfi = 0;
	rlc->cps = 0;
	rlc->rsb = 0;
	rlc->usf = 0;
	rlc->es_p = 0;
	rlc->rrbp = 0;
	rlc->pr = 0;
	rlc->num_data_blocks = gprs_rlcmac_num_data_blocks(gprs_rlcmac_mcs_header_type(cs));
	rlc->with_padding = with_padding;

	OSMO_ASSERT(rlc->num_data_blocks <= ARRAY_SIZE(rlc->block_info));

	for (i = 0; i < rlc->num_data_blocks; i++) {
		gprs_rlcmac_rlc_block_info_init(&rlc->block_info[i], cs, with_padding, spb);

		rlc->data_offs_bits[i] =
			header_bits + padding_bits +
			(i+1) * gprs_rlcmac_num_data_block_header_bits(gprs_rlcmac_mcs_header_type(cs)) +
			i * 8 * rlc->block_info[0].data_len;
	}
}

void gprs_rlcmac_rlc_data_info_init_ul(struct gprs_rlcmac_rlc_data_info *rlc,
				       enum gprs_rlcmac_coding_scheme cs,
				       bool with_padding, unsigned int spb)
{
	OSMO_ASSERT(gprs_rlcmac_mcs_is_valid(cs));
	return gprs_rlcmac_rlc_data_header_init(
			rlc, cs, with_padding,
			gprs_rlcmac_num_data_header_bits_UL(gprs_rlcmac_mcs_header_type(cs)), spb);
}

void gprs_rlcmac_rlc_data_info_init_dl(struct gprs_rlcmac_rlc_data_info *rlc,
				       enum gprs_rlcmac_coding_scheme cs,
				       bool with_padding)
{
	OSMO_ASSERT(gprs_rlcmac_mcs_is_valid(cs));
	/*
	 * last parameter is sent as 0 since common function used
	 * for both DL and UL
	 */
	return gprs_rlcmac_rlc_data_header_init(
			rlc, cs, with_padding,
			gprs_rlcmac_num_data_header_bits_DL(gprs_rlcmac_mcs_header_type(cs)), 0);
}

uint8_t *gprs_rlcmac_rlc_block_prepare(struct gprs_rlcmac_rlc_block *blk, size_t block_data_len)
{
	/* todo.. only set it once if it turns out to be a bottleneck */
	memset(blk->buf, 0x0, sizeof(blk->buf));
	memset(blk->buf, 0x2b, block_data_len);

	/* Initial value of puncturing scheme */
	blk->next_ps = GPRS_RLCMAC_EGPRS_PS_1;

	return blk->buf;
}

struct gprs_rlcmac_rlc_block_store *gprs_rlcmac_rlc_block_store_alloc(void *ctx)
{
	struct gprs_rlcmac_rlc_block_store *blkst;

	blkst = talloc_zero(ctx, struct gprs_rlcmac_rlc_block_store);
	if (!blkst)
		return NULL;

	return blkst;
}

void gprs_rlcmac_rlc_block_store_free(struct gprs_rlcmac_rlc_block_store *blkst)
{
	talloc_free(blkst);
}

struct gprs_rlcmac_rlc_block *gprs_rlcmac_rlc_block_store_get_block(struct gprs_rlcmac_rlc_block_store *blkst, int bsn)
{
	return &blkst->blocks[bsn & mod_sns_half()];
}

unsigned int gprs_rlcmac_rlc_mcs_cps(enum gprs_rlcmac_coding_scheme cs,
			      enum gprs_rlcmac_egprs_puncturing_values punct,
			      enum gprs_rlcmac_egprs_puncturing_values punct2,
			      bool with_padding)
{
	/* validate that punct and punct2 are as expected */
	switch (cs) {
	case GPRS_RLCMAC_MCS_9:
	case GPRS_RLCMAC_MCS_8:
	case GPRS_RLCMAC_MCS_7:
		if (punct2 == GPRS_RLCMAC_EGPRS_PS_INVALID) {
			LOGRLCMAC(LOGL_ERROR, "Invalid punct2 value for coding scheme %d: %d\n",
				  cs, punct2);
			return -1;
		}
		/* fall through */
	case GPRS_RLCMAC_MCS_6:
	case GPRS_RLCMAC_MCS_5:
	case GPRS_RLCMAC_MCS_4:
	case GPRS_RLCMAC_MCS_3:
	case GPRS_RLCMAC_MCS_2:
	case GPRS_RLCMAC_MCS_1:
		if (punct == GPRS_RLCMAC_EGPRS_PS_INVALID) {
			LOGRLCMAC(LOGL_ERROR, "Invalid punct value for coding scheme %d: %d\n",
				  cs, punct);
			return -1;
		}
		break;
	default:
		return -1;
	}

	/* See 3GPP TS 44.060 10.4.8a.3.1, 10.4.8a.2.1, 10.4.8a.1.1 */
	switch (cs) {
	case GPRS_RLCMAC_MCS_1:
		return 0b1011 +
			punct % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_2;
	case GPRS_RLCMAC_MCS_2:
		return 0b1001 +
			punct % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_2;
	case GPRS_RLCMAC_MCS_3:
		return (with_padding ? 0b0110 : 0b0011) +
			punct % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_3;
	case GPRS_RLCMAC_MCS_4:
		return 0b0000 +
			punct % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_3;
	case GPRS_RLCMAC_MCS_5:
		return  0b100 +
			punct % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_2;
	case GPRS_RLCMAC_MCS_6:
		return (with_padding ? 0b010 : 0b000) +
			punct % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_2;
	case GPRS_RLCMAC_MCS_7:
		return 0b10100 +
			3 * (punct % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_3) +
			punct2 % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_3;
	case GPRS_RLCMAC_MCS_8:
		return 0b01011 +
			3 * (punct % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_3) +
			punct2 % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_3;
	case GPRS_RLCMAC_MCS_9:
		return 0b00000 +
			4 * (punct % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_3) +
			punct2 % GPRS_RLCMAC_EGPRS_MAX_PS_NUM_3;
	default:
		break;
	}

	return -1;
}

enum gprs_rlcmac_egprs_puncturing_values
gprs_rlcmac_get_punct_scheme(enum gprs_rlcmac_egprs_puncturing_values punct,
			     enum gprs_rlcmac_coding_scheme cs,
			     enum gprs_rlcmac_coding_scheme cs_current,
			     enum gprs_rlcmac_rlc_egprs_ul_spb spb)
{

	/*
	 * 10.4.8b of TS 44.060
	 * If it is second segment of the block
	 * dont change the puncturing scheme
	 */
	if (spb == GPRS_RLCMAC_EGPRS_UL_SPB_SEC_SEG)
		return punct;

	/* TS  44.060 9.3.2.1.1 */
	if ((cs == GPRS_RLCMAC_MCS_9) &&
	(cs_current == GPRS_RLCMAC_MCS_6)) {
		if ((punct == GPRS_RLCMAC_EGPRS_PS_1) || (punct == GPRS_RLCMAC_EGPRS_PS_3))
			return GPRS_RLCMAC_EGPRS_PS_1;
		else if (punct == GPRS_RLCMAC_EGPRS_PS_2)
			return GPRS_RLCMAC_EGPRS_PS_2;
	} else if ((cs == GPRS_RLCMAC_MCS_6) &&
	(cs_current == GPRS_RLCMAC_MCS_9)) {
		if (punct == GPRS_RLCMAC_EGPRS_PS_1)
			return GPRS_RLCMAC_EGPRS_PS_3;
		else if (punct == GPRS_RLCMAC_EGPRS_PS_2)
			return GPRS_RLCMAC_EGPRS_PS_2;
	} else if ((cs == GPRS_RLCMAC_MCS_7) &&
	(cs_current == GPRS_RLCMAC_MCS_5))
		return GPRS_RLCMAC_EGPRS_PS_1;
	else if ((cs == GPRS_RLCMAC_MCS_5) &&
	(cs_current == GPRS_RLCMAC_MCS_7))
		return GPRS_RLCMAC_EGPRS_PS_2;
	else if (cs != cs_current)
		return GPRS_RLCMAC_EGPRS_PS_1;
	/* TS  44.060 9.3.2.1.1 ends here */
	/*
	 * Below else will handle fresh transmission, retransmission with no
	 * MCS change case
	 */
	else
		return punct;
	return GPRS_RLCMAC_EGPRS_PS_INVALID;
}

void gprs_rlcmac_update_punct_scheme(enum gprs_rlcmac_egprs_puncturing_values *punct, enum gprs_rlcmac_coding_scheme cs)
{
	switch (cs) {
	case GPRS_RLCMAC_MCS_1:
	case GPRS_RLCMAC_MCS_2:
	case GPRS_RLCMAC_MCS_5:
	case GPRS_RLCMAC_MCS_6:
		*punct = ((enum gprs_rlcmac_egprs_puncturing_values)((*punct + 1) %
			GPRS_RLCMAC_EGPRS_MAX_PS_NUM_2));
		break;
	case GPRS_RLCMAC_MCS_3:
	case GPRS_RLCMAC_MCS_4:
	case GPRS_RLCMAC_MCS_7:
	case GPRS_RLCMAC_MCS_8:
	case GPRS_RLCMAC_MCS_9:
		*punct = ((enum gprs_rlcmac_egprs_puncturing_values)((*punct + 1) %
			GPRS_RLCMAC_EGPRS_MAX_PS_NUM_3));
		break;
	default:
		break;
	}
}
