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

#include <stdint.h>

#include <osmocom/core/logging.h>

#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/rlcmac/rlcmac_dec.h>
#include <osmocom/gprs/rlcmac/rlc.h>

#define LENGTH_TO_END 255
/*!
 * \returns num extensions fields (num frames == offset) on success,
 *          -errno otherwise.
 */
static int parse_extensions_egprs(const uint8_t *data, unsigned int data_len,
				  unsigned int *offs, bool is_last_block,
				  struct gprs_rlcmac_rlc_llc_chunk *chunks,
				  unsigned int chunks_size)
{
	const struct gprs_rlcmac_rlc_li_field_egprs *li;
	uint8_t e;
	unsigned int num_chunks = 0;

	e = 0;
	while (!e) {
		if (*offs > data_len) {
			LOGRLCMAC(LOGL_NOTICE, "DL DATA LI extended, but no more data\n");
			return -EINVAL;
		}

		/* get new E */
		li = (struct gprs_rlcmac_rlc_li_field_egprs *)&data[*offs];
		e = li->e;
		*offs += 1;

		if (!chunks)
			continue;

		if (num_chunks == chunks_size) {
			LOGRLCMAC(LOGL_NOTICE, "DL DATA LI extended, but no more chunks possible\n");
			return -ENOSPC;
		}
		if (li->li == 0 && num_chunks == 0) {
			/* TS 44.060, table 10.4.14a.1, row 2a */
			/* TS 44.060, table 10.4.14a.1, row 4 */
			chunks[num_chunks].length = 0;
			chunks[num_chunks].is_complete = true;
		} else if (li->li == 127 && li->e == 1) {
			/* TS 44.060, table 10.4.14a.1, row 3 & 5 */
			/* only filling bytes left */
			LOGRLCMAC(LOGL_DEBUG, "DL DATA LI contains only filling bytes with extension octet: LI=%d, E=%d, count=%d\n",
				  li->li, li->e, num_chunks);
			break;
		} else if (li->li > 0) {
			/* TS 44.060, table 10.4.14a.1, row 1 & 2b */
			chunks[num_chunks].length = li->li;
			chunks[num_chunks].is_complete = true;
		} else {
			LOGRLCMAC(LOGL_NOTICE, "DL DATA LI contains invalid extension octet: LI=%d, E=%d, count=%d\n",
				  li->li, li->e, num_chunks);
			return -EINVAL;
		}

		LOGRLCMAC(LOGL_DEBUG, "DL DATA LI contains extension octet: LI=%d, E=%d, count=%d\n",
			  li->li, li->e, num_chunks);
		num_chunks += 1;

		if (e == 1) {
			/* There is space after the last chunk, add a final one */
			if (num_chunks == chunks_size) {
				LOGRLCMAC(LOGL_NOTICE, "DL DATA LI possibly extended, but no more chunks possible\n");
				return -ENOSPC;
			}

			chunks[num_chunks].length = LENGTH_TO_END;
			chunks[num_chunks].is_complete = is_last_block;
			num_chunks += 1;
		}
	}

	return num_chunks;
}

static int parse_extensions_gprs(const uint8_t *data, unsigned int data_len,
				 unsigned int *offs, bool is_last_block,
				 struct gprs_rlcmac_rlc_llc_chunk *chunks,
				 unsigned int chunks_size)
{
	const struct gprs_rlcmac_rlc_li_field *li;
	uint8_t m, e;
	unsigned int num_chunks = 0;

	e = 0;
	while (!e) {
		if (*offs > data_len) {
			LOGRLCMAC(LOGL_NOTICE, "DL DATA LI extended, but no more data\n");
			return -EINVAL;
		}

		/* get new E */
		li = (const struct gprs_rlcmac_rlc_li_field *)&data[*offs];
		e = li->e;
		m = li->m;
		*offs += 1;

		if (li->li == 0) {
			/* TS 44.060, 10.4.14, par 6 */
			e = 1;
			m = 0;
		}

		/* TS 44.060, table 10.4.13.1 */
		if (m == 0 && e == 0) {
			LOGRLCMAC(LOGL_NOTICE, "DL DATA ignored, because M='0' and E='0'.\n");
			return 0;
		}

		if (!chunks)
			continue;

		if (num_chunks == chunks_size) {
			LOGRLCMAC(LOGL_NOTICE, "DL DATA LI extended, but no more chunks possible\n");
			return -ENOSPC;
		}

		if (li->li == 0)
			/* e is 1 here */
			chunks[num_chunks].length = LENGTH_TO_END;
		else
			chunks[num_chunks].length = li->li;

		chunks[num_chunks].is_complete = li->li || is_last_block;

		LOGRLCMAC(LOGL_DEBUG, "DL DATA LI contains extension octet: LI=%d, M=%d, E=%d, count=%d\n",
			  li->li, li->m, li->e, num_chunks);
		num_chunks += 1;

		if (e == 1 && m == 1) {
			if (num_chunks == chunks_size) {
				LOGRLCMAC(LOGL_NOTICE, "DL DATA LI extended, but no more chunks possible\n");
				return -ENOSPC;
			}
			/* TS 44.060, 10.4.13.1, row 4 */
			chunks[num_chunks].length = LENGTH_TO_END;
			chunks[num_chunks].is_complete = is_last_block;
			num_chunks += 1;
		}
	}

	return num_chunks;
}

int gprs_rlcmac_rlc_data_from_dl_data(const struct gprs_rlcmac_rlc_block_info *rdbi,
				      enum gprs_rlcmac_coding_scheme cs,
				      const uint8_t *data,
				      struct gprs_rlcmac_rlc_llc_chunk *chunks,
				      unsigned int chunks_size)
{
	uint8_t e;
	unsigned int data_len = rdbi->data_len;
	int num_chunks = 0, i;
	unsigned int offs = 0;
	bool is_last_block = (rdbi->cv == 0);

	if (!chunks)
		chunks_size = 0;

	e = rdbi->e;
	if (e) {
		if (chunks_size > 0) {
			/* Block without LI means it only contains data of one LLC PDU */
			chunks[num_chunks].offset = offs;
			chunks[num_chunks].length = LENGTH_TO_END;
			chunks[num_chunks].is_complete = is_last_block;
			num_chunks += 1;
		} else if (chunks) {
			LOGRLCMAC(LOGL_NOTICE, "No extension, but no more chunks possible\n");
			return -ENOSPC;
		}
	} else if (gprs_rlcmac_mcs_is_edge(cs)) {
		/* if E is not set (LI follows), EGPRS */
		num_chunks = parse_extensions_egprs(data, data_len, &offs,
			is_last_block,
			chunks, chunks_size);
	} else {
		/* if E is not set (LI follows), GPRS */
		num_chunks = parse_extensions_gprs(data, data_len, &offs,
			is_last_block,
			chunks, chunks_size);
	}

	if (num_chunks < 0)
		return num_chunks;

	if (chunks_size == 0)
		return num_chunks;

	/* LLC */
	for (i = 0; i < num_chunks; i++) {
		chunks[i].offset = offs;
		if (chunks[i].length == LENGTH_TO_END) {
			if (offs == data_len) {
				/* There is no place for an additional chunk,
				 * so drop it (this may happen with EGPRS since
				 * there is no M flag. */
				num_chunks -= 1;
				break;
			}
			chunks[i].length = data_len - offs;
		}
		offs += chunks[i].length;
		if (offs > data_len) {
			LOGRLCMAC(LOGL_NOTICE, "DL DATA out of block border, "
				  "chunk idx: %d, offset: %u, size: %d, data_len: %u\n",
				  i, offs, chunks[i].length, data_len);
			return -EINVAL;
		}
	}

	return num_chunks;
}

int gprs_rlcmac_rlc_parse_dl_data_header_gprs(struct gprs_rlcmac_rlc_data_info *rlc,
					      const uint8_t *data, enum gprs_rlcmac_coding_scheme cs)
{
	const struct gprs_rlcmac_rlc_dl_data_header *gprs = (const struct gprs_rlcmac_rlc_dl_data_header *)data;
	unsigned int cur_bit = 0;

	gprs_rlcmac_rlc_data_info_init_dl(rlc, cs, false);

	rlc->usf = gprs->usf;
	rlc->es_p = gprs->s_p;
	rlc->rrbp = gprs->rrbp;
	rlc->tfi = gprs->tfi;
	rlc->pr = gprs->pr;

	rlc->num_data_blocks = 1;
	rlc->block_info[0].cv  = gprs->fbi ? 0 : 0xff;
	rlc->block_info[0].pi  = 0;
	rlc->block_info[0].bsn = gprs->bsn;
	rlc->block_info[0].e   = gprs->e;
	rlc->block_info[0].ti  = 0;
	rlc->block_info[0].spb = 0;
	cur_bit += rlc->data_offs_bits[0];
	/* skip data area */
	cur_bit += gprs_rlcmac_mcs_max_data_block_bytes(cs) * 8;

	return cur_bit;
}

int gprs_rlcmac_rlc_parse_dl_data_header(struct gprs_rlcmac_rlc_data_info *rlc,
					 const uint8_t *data,
					 enum gprs_rlcmac_coding_scheme cs)
{
	unsigned int cur_bit = 0;

	switch (gprs_rlcmac_mcs_header_type(cs)) {
	case GPRS_RLCMAC_HEADER_GPRS_DATA:
		cur_bit = gprs_rlcmac_rlc_parse_dl_data_header_gprs(rlc, data, cs);
		break;
	case GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_3:
	case GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_2:
	case GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_1:
		/* TODO: EGPRS. See osmo-pcu.git rlc_parse_ul_data_header_egprs_type_*() */
	default:
		LOGRLCMAC(LOGL_ERROR, "Decoding of DL %s data blocks not yet supported.\n",
			gprs_rlcmac_mcs_name(cs));
		return -ENOTSUP;
	};

	return cur_bit;
}

/**
 * Copy LSB bitstream RLC data block to byte aligned buffer.
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
unsigned int gprs_rlcmac_rlc_copy_to_aligned_buffer(
	const struct gprs_rlcmac_rlc_data_info *rlc,
	unsigned int data_block_idx,
	const uint8_t *src, uint8_t *buffer)
{
	unsigned int hdr_bytes;
	unsigned int extra_bits;
	unsigned int i;

	uint8_t c, last_c;
	uint8_t *dst;
	const struct gprs_rlcmac_rlc_block_info *rdbi;

	OSMO_ASSERT(data_block_idx < rlc->num_data_blocks);
	rdbi = &rlc->block_info[data_block_idx];

	hdr_bytes = rlc->data_offs_bits[data_block_idx] >> 3;
	extra_bits = (rlc->data_offs_bits[data_block_idx] & 7);

	if (extra_bits == 0) {
		/* It is aligned already */
		memmove(buffer, src + hdr_bytes, rdbi->data_len);
		return rdbi->data_len;
	}

	dst = buffer;
	src = src + hdr_bytes;
	last_c = *(src++);

	for (i = 0; i < rdbi->data_len; i++) {
		c = src[i];
		*(dst++) = (last_c >> extra_bits) | (c << (8 - extra_bits));
		last_c = c;
	}

	return rdbi->data_len;
}
