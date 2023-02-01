#pragma once

/* RLCMAC encoding support functions */

#include <stdint.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/types_private.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/rlc.h>

#define GPRS_RLCMAC_DUMMY_VEC "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"


/****************
 * DATA BLOCKS:
 ****************/

enum gpr_rlcmac_append_result {
	GPRS_RLCMAC_AR_NEED_MORE_BLOCKS,
	GPRS_RLCMAC_AR_COMPLETED_SPACE_LEFT,
	GPRS_RLCMAC_AR_COMPLETED_BLOCK_FILLED,
};

int gprs_rlcmac_rlc_write_ul_data_header(const struct gprs_rlcmac_rlc_data_info *rlc, uint8_t *data);

enum gpr_rlcmac_append_result gprs_rlcmac_enc_append_ul_data(
				struct gprs_rlcmac_rlc_block_info *rdbi,
				enum gprs_rlcmac_coding_scheme cs,
				struct msgb *llc_msg, int *offset, int *num_chunks,
				uint8_t *data_block, bool is_final, int *count_payload);

void gprs_rlcmac_rlc_data_to_ul_append_egprs_li_padding(const struct gprs_rlcmac_rlc_block_info *rdbi,
							int *offset, int *num_chunks, uint8_t *data_block);

unsigned int gprs_rlcmac_rlc_copy_from_aligned_buffer(const struct gprs_rlcmac_rlc_data_info *rlc,
						      unsigned int data_block_idx,
						      uint8_t *dst, const uint8_t *buffer);


/****************
 * CONTROL BLOCKS:
 ****************/

void gprs_rlcmac_enc_prepare_pkt_ul_dummy_block(RlcMacUplink_t *block, uint32_t tlli);

void gprs_rlcmac_enc_prepare_pkt_resource_req(RlcMacUplink_t *block, struct gprs_rlcmac_ul_tbf *ul_tbf, enum gprs_rlcmac_access_type acc_type);
