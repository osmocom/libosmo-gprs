#pragma once

/* RLCMAC encoding support functions */

#include <stdint.h>

#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/types_private.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>

#define GPRS_RLCMAC_DUMMY_VEC "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"

void gprs_rlcmac_enc_prepare_pkt_ul_dummy_block(RlcMacUplink_t *block, uint32_t tlli);

void gprs_rlcmac_enc_prepare_pkt_resource_req(RlcMacUplink_t *block, struct gprs_rlcmac_ul_tbf *ul_tbf, enum gprs_rlcmac_access_type acc_type);
