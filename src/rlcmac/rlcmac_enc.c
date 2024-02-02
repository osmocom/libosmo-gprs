/* RLC/MAC encoding helpers, 3GPP TS 44.060 */
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

#include <osmocom/core/endian.h>

#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/rlcmac_enc.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/rlc_window_dl.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>

int gprs_rlcmac_rlc_write_ul_data_header(const struct gprs_rlcmac_rlc_data_info *rlc, uint8_t *data)
{
	struct gprs_rlcmac_rlc_ul_data_header *gprs;

	switch (gprs_rlcmac_mcs_header_type(rlc->cs)) {
	case GPRS_RLCMAC_HEADER_GPRS_DATA:
		gprs = (struct gprs_rlcmac_rlc_ul_data_header *)data;

		gprs->r  = rlc->r;
		gprs->si = rlc->si;
		gprs->cv = rlc->block_info[0].cv;
		gprs->pt = 0;

		gprs->ti    = rlc->block_info[0].ti;
		gprs->tfi   = rlc->tfi;
		gprs->pi    = 0; /* TODO */
		gprs->spare = 0;

		gprs->e   = rlc->block_info[0].e;
		gprs->bsn = rlc->block_info[0].bsn;
		break;

	case GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_1:
	case GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_2:
	case GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_3:
		/* TODO: EGPRS. See osmo-pcu.git Encoding::rlc_write_dl_data_header() */
	default:
		LOGRLCMAC(LOGL_ERROR, "Encoding of uplink %s data blocks not yet supported.\n",
			  gprs_rlcmac_mcs_name(rlc->cs));
		return -ENOTSUP;
	};

	return 0;
}

enum gpr_rlcmac_append_result gprs_rlcmac_enc_append_ul_data(
				struct gprs_rlcmac_rlc_block_info *rdbi,
				enum gprs_rlcmac_coding_scheme cs,
				struct msgb *llc_msg, int *offset, int *num_chunks,
				uint8_t *data_block, int *count_payload)
{
	int chunk;
	int space;
	struct gprs_rlcmac_rlc_li_field *li;
	uint8_t *delimiter, *data, *e_pointer;
	const bool is_final = rdbi->cv == 0;

	data = data_block + *offset;
	delimiter = data_block + *num_chunks;
	e_pointer = (*num_chunks ? delimiter - 1 : NULL);

	chunk = msgb_length(llc_msg);
	space = rdbi->data_len - *offset;

	/* if chunk will exceed block limit */
	if (chunk > space) {
		LOGRLCMAC(LOGL_DEBUG, "-- Chunk with length %d "
			  "larger than space (%d) left in block: copy "
			  "only remaining space, and we are done\n",
			  chunk, space);
		if (e_pointer) {
			/* LLC frame not finished, so there is no extension octet */
			*e_pointer |= 0x02; /* set previous M bit = 1 */
		}
		/* fill only space */
		memcpy(data, msgb_data(llc_msg), space);
		msgb_pull(llc_msg, space);
		if (count_payload)
			*count_payload = space;
		/* return data block as message */
		*offset = rdbi->data_len;
		(*num_chunks)++;
		return GPRS_RLCMAC_AR_NEED_MORE_BLOCKS;
	}
	/* if FINAL chunk would fit precisely in space left */
	if (chunk == space && is_final) {
		LOGRLCMAC(LOGL_DEBUG, "-- Chunk with length %d "
			  "would exactly fit into space (%d): because "
			  "this is a final block, we don't add length "
			  "header, and we are done\n", chunk, space);
		/* block is filled, so there is no extension */
		if (e_pointer)
			*e_pointer |= 0x01;
		/* fill space */
		memcpy(data, msgb_data(llc_msg), space);
		msgb_pull(llc_msg, space);
		if (count_payload)
			*count_payload = space;
		*offset = rdbi->data_len;
		(*num_chunks)++;
		return GPRS_RLCMAC_AR_COMPLETED_BLOCK_FILLED;
	}
	/* if chunk would fit exactly in space left */
	if (chunk == space) {
		LOGRLCMAC(LOGL_DEBUG, "-- Chunk with length %d "
			  "would exactly fit into space (%d): add length "
			  "header with LI=0, to make frame extend to "
			  "next block, and we are done\n", chunk, space);
		/* make space for delimiter */
		if (delimiter != data)
			memmove(delimiter + 1, delimiter,
				data - delimiter);
		if (e_pointer) {
			*e_pointer &= 0xfe; /* set previous E bit = 0 */
			*e_pointer |= 0x02; /* set previous M bit = 1 */
		}
		data++;
		(*offset)++;
		space--;
		/* add LI with 0 length */
		li = (struct gprs_rlcmac_rlc_li_field *)delimiter;
		li->e = 1; /* not more extension */
		li->m = 0; /* shall be set to 0, in case of li = 0 */
		li->li = 0; /* chunk fills the complete space */
		rdbi->e = 0; /* 0: extensions present */
		// no need to set e_pointer nor increase delimiter
		/* fill only space, which is 1 octet less than chunk */
		memcpy(data, msgb_data(llc_msg), space);
		msgb_pull(llc_msg, space);
		if (count_payload)
			*count_payload = space;
		/* return data block as message */
		*offset = rdbi->data_len;
		(*num_chunks)++;
		return GPRS_RLCMAC_AR_NEED_MORE_BLOCKS;
	}

	LOGRLCMAC(LOGL_DEBUG, "-- Chunk with length %d is less "
		  "than remaining space (%d): add length header to "
		  "delimit LLC frame\n", chunk, space);
	/* the LLC frame chunk ends in this block */
	/* make space for delimiter */
	if (delimiter != data)
		memmove(delimiter + 1, delimiter, data - delimiter);
	if (e_pointer) {
		*e_pointer &= 0xfe; /* set previous E bit = 0 */
		*e_pointer |= 0x02; /* set previous M bit = 1 */
	}
	data++;
	(*offset)++;
	space--;
	/* add LI to delimit frame */
	li = (struct gprs_rlcmac_rlc_li_field *)delimiter;
	li->e = 1; /*  not more extension, maybe set later */
	li->m = 0; /* will be set later, if there is more LLC data */
	li->li = chunk; /* length of chunk */
	rdbi->e = 0; /* 0: extensions present */
	(*num_chunks)++;
	/* copy (rest of) LLC frame to space and reset later */
	memcpy(data, msgb_data(llc_msg), chunk);
	msgb_pull(llc_msg, chunk);
	if (count_payload)
		*count_payload = chunk;
	data += chunk;
	space -= chunk;
	(*offset) += chunk;
	/* if we have more data and we have space left */
	if (space > 0 && !is_final)
		return GPRS_RLCMAC_AR_COMPLETED_SPACE_LEFT;

	/* if we don't have more LLC frames */
	if (is_final) {
		LOGRLCMAC(LOGL_DEBUG, "-- Final block, so we done.\n");
		return GPRS_RLCMAC_AR_COMPLETED_BLOCK_FILLED;
	}
	/* we have no space left */
	LOGRLCMAC(LOGL_DEBUG, "-- No space left, so we are done.\n");
	return GPRS_RLCMAC_AR_COMPLETED_BLOCK_FILLED;
}

void gprs_rlcmac_rlc_data_to_ul_append_egprs_li_padding(const struct gprs_rlcmac_rlc_block_info *rdbi,
							int *offset, int *num_chunks, uint8_t *data_block)
{
	struct gprs_rlcmac_rlc_li_field_egprs *li;
	struct gprs_rlcmac_rlc_li_field_egprs *prev_li;
	uint8_t *delimiter, *data;

	LOGRLCMAC(LOGL_DEBUG, "Adding LI=127 to signal padding\n");

	data = data_block + *offset;
	delimiter = data_block + *num_chunks;
	prev_li = (struct gprs_rlcmac_rlc_li_field_egprs *)(*num_chunks ? delimiter - 1 : NULL);

	/* we don't have more LLC frames */
	/* We will have to add another chunk with filling octets */

	if (delimiter != data)
		memmove(delimiter + 1, delimiter, data - delimiter);

	/* set filling bytes extension */
	li = (struct gprs_rlcmac_rlc_li_field_egprs *)delimiter;
	li->e = 1;
	li->li = 127;

	/* tell previous extension header about the new one */
	if (prev_li)
		prev_li->e = 0;

	(*num_chunks)++;
	*offset = rdbi->data_len;
}

/**
 * Copy LSB bitstream RLC data block from byte aligned buffer.
 *
 * Note that the bitstream is encoded in LSB first order, so the two octets
 * 654321xx xxxxxx87 contain the octet 87654321 starting at bit position 3
 * (LSB has bit position 1). This is a different order than the one used by
 * CSN.1.
 *
 * \param data_block_idx  The block index, 0..1 for header type 1, 0 otherwise
 * \param src     A pointer to the start of the RLC block (incl. the header)
 * \param buffer  A data area of a least the size of the RLC block
 * \returns  the number of bytes copied
 */
unsigned int gprs_rlcmac_rlc_copy_from_aligned_buffer(const struct gprs_rlcmac_rlc_data_info *rlc,
						      unsigned int data_block_idx,
						      uint8_t *dst, const uint8_t *buffer)
{
	unsigned int hdr_bytes;
	unsigned int extra_bits;
	unsigned int i;

	uint8_t c, last_c;
	const uint8_t *src;
	const struct gprs_rlcmac_rlc_block_info *rdbi;

	OSMO_ASSERT(data_block_idx < rlc->num_data_blocks);
	rdbi = &rlc->block_info[data_block_idx];

	hdr_bytes = rlc->data_offs_bits[data_block_idx] / 8;
	extra_bits = (rlc->data_offs_bits[data_block_idx] % 8);

	if (extra_bits == 0) {
		/* It is aligned already */
		memmove(dst + hdr_bytes, buffer, rdbi->data_len);
		return rdbi->data_len;
	}

	src = buffer;
	dst = dst + hdr_bytes;
	last_c = *dst << (8 - extra_bits);

	for (i = 0; i < rdbi->data_len; i++) {
		c = src[i];
		*(dst++) = (last_c >> (8 - extra_bits)) | (c << extra_bits);
		last_c = c;
	}

	/* overwrite the lower extra_bits */
	*dst = (*dst & (0xff << extra_bits)) | (last_c >> (8 - extra_bits));

	return rdbi->data_len;
}

void gprs_rlcmac_enc_prepare_pkt_ul_dummy_block(RlcMacUplink_t *block, uint32_t tlli)
{
	Packet_Uplink_Dummy_Control_Block_t *dummy;

	memset(block, 0, sizeof(*block));

	dummy = &block->u.Packet_Uplink_Dummy_Control_Block;
	dummy->MESSAGE_TYPE = OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK;
	/* 10.4.7: RLC/MAC control block that does not include the optional octets of the RLC/MAC control header: */
	dummy->PayloadType = 0x1;
	dummy->R = 0; /* MS sent channel request message once */
	dummy->TLLI = tlli;
}

/* 11.2.16 Packet Resource Request */
void gprs_rlcmac_enc_prepare_pkt_resource_req(RlcMacUplink_t *block,
					      struct gprs_rlcmac_ul_tbf *ul_tbf,
					      enum gprs_rlcmac_access_type acc_type)
{
	Packet_Resource_Request_t *req;
	struct gprs_rlcmac_entity *gre = ul_tbf->tbf.gre;

	memset(block, 0, sizeof(*block));

	req = &block->u.Packet_Resource_Request;
	req->MESSAGE_TYPE = OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_RESOURCE_REQUEST;
	/* 10.4.7: RLC/MAC control block that does not include the optional octets of the RLC/MAC control header: */
	req->PayloadType = 0x1;
	req->R = 0; /* MS sent channel request message once */

	req->Exist_ACCESS_TYPE = 1;
	req->ACCESS_TYPE = acc_type;

	req->ID.UnionType = 1; /* Use TLLI */
	req->ID.u.TLLI = gre->tlli; /* Use TLLI */
	req->Exist_MS_Radio_Access_capability2 = 1;

	req->MS_Radio_Access_capability2.Count_MS_RA_capability_value = 1;
	/* TODO: fill Content_t: */
	/* req->MS_Radio_Access_capability2.MS_RA_capability_value[0].Content.* */

	/* 3GPP TS 24.008 Peak Throughput Class, range 1..9 */
	req->Channel_Request_Description.PEAK_THROUGHPUT_CLASS = 1;
	req->Channel_Request_Description.RADIO_PRIORITY = GPRS_RLCMAC_RADIO_PRIORITY_4;
	req->Channel_Request_Description.RLC_MODE = GPRS_RLCMAC_RLC_MODE_ACKNOWLEDGED;
	req->Channel_Request_Description.LLC_PDU_TYPE = GPRS_RLCMAC_LLC_PDU_TYPE_ACKNOWLEDGED;
	req->Channel_Request_Description.RLC_OCTET_COUNT = gprs_rlcmac_llc_queue_octets(gre->llc_queue);

	/* "this field contains the SI13_CHANGE_MARK value stored by the mobile station.
	 * If the mobile station does not have a valid PSI2 or SI13 change mark for the current cell,
	 * the mobile station shall omit this field." */
	req->Exist_CHANGE_MARK = 0;
	/* req->CHANGE_MARK; */

	/* TODO: binary representation of the C value as specified in 3GPP TS 45.008. */
	req->C_VALUE = 0;

	/* SIGN_VAR: "This field is not present for TBF establishment using two phase access or for
	 *	      a TBF in EGPRS mode" (see 3GPP TS 45.008) */
	if (acc_type != GPRS_RLCMAC_ACCESS_TYPE_2PHASE_ACC_REQ) {
		req->Exist_SIGN_VAR = 1;
		req->SIGN_VAR = 0; /* TODO: calculate */
	}

	/* For element definition see sub-clause 11.2.6 - Packet Downlink Ack/Nack.  */
	/* TODO: req->I_LEVEL_TN[8]; */

	req->Exist_AdditionsR99 = 0;
	/* TODO: no req->AdditionsR99 yet */
}

static void gprs_rlcmac_enc_prepare_pkt_ack_nack_desc_gprs(Ack_Nack_Description_t *ack_desc, const struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	struct bitvec bv = {
		.data = &ack_desc->RECEIVED_BLOCK_BITMAP[0],
		.data_len = sizeof(ack_desc->RECEIVED_BLOCK_BITMAP),
	};
	uint16_t ssn = gprs_rlcmac_rlc_dl_window_ssn(dl_tbf->dlw);
	bool final_ack = (gprs_rlcmac_tbf_dl_state(dl_tbf) == GPRS_RLCMAC_TBF_DL_ST_FINISHED);
	char rbb[65];

	gprs_rlcmac_rlc_dl_window_update_rbb(dl_tbf->dlw, rbb);
	rbb[64] = 0;
	LOGPTBFDL(dl_tbf, LOGL_DEBUG, "- SSN %" PRIu16 ", V(N): \"%s\" R=Received I=Invalid, FINAL_ACK=%u\n",
		  ssn, rbb, final_ack);

	ack_desc->FINAL_ACK_INDICATION = final_ack;
	ack_desc->STARTING_SEQUENCE_NUMBER = ssn;
	for (int i = 0; i < 64; i++) {
		/* Set bit at the appropriate position (see 3GPP TS 44.060 9.1.8.1) */
		bool is_ack = (rbb[i] == 'R');
		bitvec_set_bit(&bv, is_ack == 1 ? ONE : ZERO);
	}
}

/* Channel Quality Report struct, TS 44.060 Table 11.2.6. */
static void gprs_rlcmac_enc_prepare_channel_quality_report(Channel_Quality_Report_t *cqr, const struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	/* TODO: fill cqr from info stored probably in the gre object. */
}

void gprs_rlcmac_enc_prepare_pkt_downlink_ack_nack(RlcMacUplink_t *block, const struct gprs_rlcmac_dl_tbf *dl_tbf, bool chan_req)
{
	Packet_Downlink_Ack_Nack_t *ack = &block->u.Packet_Downlink_Ack_Nack;

	memset(block, 0, sizeof(*block));
	ack->MESSAGE_TYPE = OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_DOWNLINK_ACK_NACK;
	ack->PayloadType = GPRS_RLCMAC_PT_CONTROL_BLOCK;
	ack->R = 0; /* MS sent channel request message once */

	ack->DOWNLINK_TFI = dl_tbf->cur_alloc.dl_tfi;
	gprs_rlcmac_enc_prepare_pkt_ack_nack_desc_gprs(&ack->Ack_Nack_Description, dl_tbf);

	if (chan_req) {
		Channel_Request_Description_t *chan_req = &ack->Channel_Request_Description;
		ack->Exist_Channel_Request_Description = 1;
		chan_req->PEAK_THROUGHPUT_CLASS = 0; /* TODO */
		chan_req->RADIO_PRIORITY = gprs_rlcmac_llc_queue_highest_radio_prio_pending(dl_tbf->tbf.gre->llc_queue);
		chan_req->RLC_MODE = GPRS_RLCMAC_RLC_MODE_ACKNOWLEDGED;
		chan_req->LLC_PDU_TYPE = GPRS_RLCMAC_LLC_PDU_TYPE_ACKNOWLEDGED;
		chan_req->RLC_OCTET_COUNT = gprs_rlcmac_entity_calculate_new_ul_tbf_rlc_octet_count(dl_tbf->tbf.gre);
	} else {
		ack->Exist_Channel_Request_Description = 0;
	}

	gprs_rlcmac_enc_prepare_channel_quality_report(&ack->Channel_Quality_Report, dl_tbf);
}

void gprs_rlcmac_enc_prepare_pkt_ctrl_ack(RlcMacUplink_t *block, uint32_t tlli)
{
	Packet_Control_Acknowledgement_t *ctrl_ack = &block->u.Packet_Control_Acknowledgement;

	memset(block, 0, sizeof(*block));
	ctrl_ack->MESSAGE_TYPE = OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_CONTROL_ACK;
	ctrl_ack->PayloadType = GPRS_RLCMAC_PT_CONTROL_BLOCK;
	ctrl_ack->R = 0; /* MS sent channel request message once */

	ctrl_ack->TLLI = tlli;
	ctrl_ack->CTRL_ACK = 0; /* not clear what this should be set to. TS 44.060 Table 11.2.2.2 */
}
