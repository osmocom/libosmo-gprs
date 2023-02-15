#pragma once

/* RLCMAC decoding support functions */

#include <stdint.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/bitvec.h>

#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/rlc.h>
#include <osmocom/gprs/rlcmac/coding_scheme.h>

struct gprs_rlcmac_rlc_ul_window;

/****************
 * DATA BLOCKS:
 ****************/

/* represents (parts) LLC PDUs within one RLC Data block */
struct gprs_rlcmac_rlc_llc_chunk {
	uint8_t	offset;
	uint8_t	length;
	bool	is_complete; /* if this PDU ends in this block */
};

int gprs_rlcmac_rlc_data_from_dl_data(const struct gprs_rlcmac_rlc_block_info *rdbi,
				      enum gprs_rlcmac_coding_scheme cs,
				      const uint8_t *data,
				      struct gprs_rlcmac_rlc_llc_chunk *chunks,
				      unsigned int chunks_size);

int gprs_rlcmac_rlc_parse_dl_data_header(struct gprs_rlcmac_rlc_data_info *rlc,
					 const uint8_t *data,
					 enum gprs_rlcmac_coding_scheme cs);

unsigned int gprs_rlcmac_rlc_copy_to_aligned_buffer(const struct gprs_rlcmac_rlc_data_info *rlc,
						    unsigned int data_block_idx,
						    const uint8_t *src, uint8_t *buffer);


/****************
 * CONTROL BLOCKS:
 ****************/

void gprs_rlcmac_extract_rbb(const struct bitvec *rbb, char *show_rbb);
int gprs_rlcmac_decode_gprs_acknack_bits(const Ack_Nack_Description_t *desc,
					 struct bitvec *bits, int *bsn_begin, int *bsn_end,
					 struct gprs_rlcmac_rlc_ul_window *ulw);
