/* RLC/MAC scheduler, 3GPP TS 44.060 */
#pragma once

#include <stdint.h>
#include <osmocom/gsm/gsm_utils.h>

struct gprs_rlcmac_rts_block_ind {
	uint8_t ts;
	uint32_t fn;
	uint8_t usf;
};

uint32_t rrbp2fn(uint32_t cur_fn, uint8_t rrbp);

int gprs_rlcmac_rcv_rts_block(struct gprs_rlcmac_rts_block_ind *bi);

static inline bool fn_valid(uint32_t fn)
{
	uint32_t f = fn % 13;
	return f == 0 || f == 4 || f == 8;
}

static inline uint32_t fn2bn(uint32_t fn)
{
	return (fn % 52) / 4;
}

static inline uint32_t fn_next_block(uint32_t fn)
{
	uint32_t bn = fn2bn(fn) + 1;
	fn = fn - (fn % 52);
	fn += bn * 4 + bn / 3;
	return fn % GSM_MAX_FN;
}
