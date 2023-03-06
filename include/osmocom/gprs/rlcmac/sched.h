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

static inline bool fn_valid(uint32_t fn)
{
	uint32_t f = fn % 13;
	return f == 0 || f == 4 || f == 8;
}

#define GSM_MAX_FN_THRESH (GSM_MAX_FN >> 1)
/* 0: equal, -1: fn1 BEFORE fn2, 1: fn1 AFTER fn2 */
static inline int fn_cmp(uint32_t fn1, uint32_t fn2)
{
	if (fn1 == fn2)
		return 0;
	/* FN1 goes before FN2: */
	if ((fn1 < fn2 && (fn2 - fn1) < GSM_MAX_FN_THRESH) ||
	    (fn1 > fn2 && (fn1 - fn2) > GSM_MAX_FN_THRESH))
		return -1;
	/* FN1 goes after FN2: */
	return 1;
}
