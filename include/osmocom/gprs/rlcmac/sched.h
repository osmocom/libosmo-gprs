/* RLC/MAC scheduler, 3GPP TS 44.060 */
#pragma once

#include <stdint.h>

struct gprs_rlcmac_rts_block_ind {
	uint8_t ts;
	uint32_t fn;
	uint8_t usf;
};

uint32_t rrbp2fn(uint32_t cur_fn, uint8_t rrbp);

int gprs_rlcmac_rcv_rts_block(struct gprs_rlcmac_rts_block_ind *bi);
