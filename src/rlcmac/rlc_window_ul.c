/* Uplink RLC Window as per 3GPP TS 44.060 */
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

#include <stdint.h>
#include <stdbool.h>
#include <osmocom/core/bitvec.h>

#include <osmocom/gprs/rlcmac/rlc.h>
#include <osmocom/gprs/rlcmac/rlc_window_ul.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>

static inline bool gprs_rlcmac_rlc_v_b_is_state(const struct gprs_rlcmac_rlc_v_b *v_b,
						int bsn, enum gprs_rlcmac_rlc_ul_bsn_state type)
{
	return v_b->v_b[bsn & mod_sns_half()] == type;
}

static inline void gprs_rlcmac_rlc_v_b_mark(struct gprs_rlcmac_rlc_v_b *v_b,
					    int bsn, enum gprs_rlcmac_rlc_ul_bsn_state type)
{
	v_b->v_b[bsn & mod_sns_half()] = type;
}

void gprs_rlcmac_rlc_v_b_reset(struct gprs_rlcmac_rlc_v_b *v_b)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(v_b->v_b); i++)
		gprs_rlcmac_rlc_v_b_mark_invalid(v_b, i);
}

/* Check for an individual frame */
bool gprs_rlcmac_rlc_v_b_is_unacked(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn)
{
	return gprs_rlcmac_rlc_v_b_is_state(v_b, bsn, GPRS_RLCMAC_RLC_UL_BSN_UNACKED);
}

bool gprs_rlcmac_rlc_v_b_is_nacked(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn)
{
	return gprs_rlcmac_rlc_v_b_is_state(v_b, bsn, GPRS_RLCMAC_RLC_UL_BSN_NACKED);
}

bool gprs_rlcmac_rlc_v_b_is_acked(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn)
{
	return gprs_rlcmac_rlc_v_b_is_state(v_b, bsn, GPRS_RLCMAC_RLC_UL_BSN_ACKED);
}

bool gprs_rlcmac_rlc_v_b_is_resend(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn)
{
	return gprs_rlcmac_rlc_v_b_is_state(v_b, bsn, GPRS_RLCMAC_RLC_UL_BSN_RESEND);
}

bool gprs_rlcmac_rlc_v_b_is_invalid(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn)
{
	return gprs_rlcmac_rlc_v_b_is_state(v_b, bsn, GPRS_RLCMAC_RLC_UL_BSN_INVALID);
}

enum gprs_rlcmac_rlc_ul_bsn_state gprs_rlcmac_rlc_v_b_get_state(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn)
{
	return v_b->v_b[bsn & mod_sns_half()];
}

/* Mark a RLC frame for something */
void gprs_rlcmac_rlc_v_b_mark_unacked(struct gprs_rlcmac_rlc_v_b *v_b, int bsn)
{
	return gprs_rlcmac_rlc_v_b_mark(v_b, bsn, GPRS_RLCMAC_RLC_UL_BSN_UNACKED);
}

void gprs_rlcmac_rlc_v_b_mark_nacked(struct gprs_rlcmac_rlc_v_b *v_b, int bsn)
{
	return gprs_rlcmac_rlc_v_b_mark(v_b, bsn, GPRS_RLCMAC_RLC_UL_BSN_NACKED);
}

void gprs_rlcmac_rlc_v_b_mark_acked(struct gprs_rlcmac_rlc_v_b *v_b, int bsn)
{
	return gprs_rlcmac_rlc_v_b_mark(v_b, bsn, GPRS_RLCMAC_RLC_UL_BSN_ACKED);
}

void gprs_rlcmac_rlc_v_b_mark_resend(struct gprs_rlcmac_rlc_v_b *v_b, int bsn)
{
	return gprs_rlcmac_rlc_v_b_mark(v_b, bsn, GPRS_RLCMAC_RLC_UL_BSN_RESEND);
}

void gprs_rlcmac_rlc_v_b_mark_invalid(struct gprs_rlcmac_rlc_v_b *v_b, int bsn)
{
	return gprs_rlcmac_rlc_v_b_mark(v_b, bsn, GPRS_RLCMAC_RLC_UL_BSN_INVALID);
}


/*************
 * UL WINDOW
*************/
struct gprs_rlcmac_rlc_ul_window *gprs_rlcmac_rlc_ul_window_alloc(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	struct gprs_rlcmac_rlc_ul_window *ulw;

	ulw = talloc_zero(ul_tbf, struct gprs_rlcmac_rlc_ul_window);
	if (!ulw)
		return NULL;

	gprs_rlcmac_rlc_window_constructor(rlc_ulw_as_w(ulw));

	ulw->ul_tbf = ul_tbf;
	gprs_rlcmac_rlc_ul_window_reset(ulw);

	return ulw;
}

void gprs_rlcmac_rlc_ul_window_free(struct gprs_rlcmac_rlc_ul_window *ulw)
{
	if (!ulw)
		return;

	gprs_rlcmac_rlc_window_destructor(rlc_ulw_as_w(ulw));
	talloc_free(ulw);
}

void gprs_rlcmac_rlc_ul_window_reset(struct gprs_rlcmac_rlc_ul_window *ulw)
{
	ulw->v_s = 0;
	ulw->v_a = 0;
	gprs_rlcmac_rlc_v_b_reset(&ulw->v_b);
}

bool gprs_rlcmac_rlc_ul_window_window_stalled(const struct gprs_rlcmac_rlc_ul_window *ulw)
{
	const struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w_const(ulw);

	return (gprs_rlcmac_rlc_window_mod_sns_bsn(w, ulw->v_s - ulw->v_a) ==
		gprs_rlcmac_rlc_window_ws(w));
}

bool gprs_rlcmac_rlc_ul_window_window_empty(const struct gprs_rlcmac_rlc_ul_window *ulw)
{
	return ulw->v_s == ulw->v_a;
}

void gprs_rlcmac_rlc_ul_window_increment_send(struct gprs_rlcmac_rlc_ul_window *ulw)
{
	struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w(ulw);

	ulw->v_s = (ulw->v_s + 1) & gprs_rlcmac_rlc_window_mod_sns(w);
}

void gprs_rlcmac_rlc_ul_window_raise(struct gprs_rlcmac_rlc_ul_window *ulw, int moves)
{
	struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w(ulw);

	ulw->v_a = (ulw->v_a + moves) & gprs_rlcmac_rlc_window_mod_sns(w);
}

uint16_t gprs_rlcmac_rlc_ul_window_v_s(const struct gprs_rlcmac_rlc_ul_window *ulw)
{
	return ulw->v_s;
}

uint16_t gprs_rlcmac_rlc_ul_window_v_s_mod(const struct gprs_rlcmac_rlc_ul_window *ulw, int offset)
{
	const struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w_const(ulw);

	return gprs_rlcmac_rlc_window_mod_sns_bsn(w, ulw->v_s + offset);
}

uint16_t gprs_rlcmac_rlc_ul_window_v_a(const struct gprs_rlcmac_rlc_ul_window *ulw)
{
	return ulw->v_a;
}

uint16_t gprs_rlcmac_rlc_ul_window_distance(const struct gprs_rlcmac_rlc_ul_window *ulw)
{
	const struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w_const(ulw);

	return (ulw->v_s - ulw->v_a) & gprs_rlcmac_rlc_window_mod_sns(w);
}

/* Methods to manage reception */
int gprs_rlcmac_rlc_ul_window_resend_needed(const struct gprs_rlcmac_rlc_ul_window *ulw)
{
	uint16_t bsn;
	const struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w_const(ulw);

	for (bsn = gprs_rlcmac_rlc_ul_window_v_a(ulw);
	     bsn != gprs_rlcmac_rlc_ul_window_v_s(ulw);
	     bsn = gprs_rlcmac_rlc_window_mod_sns_bsn(w, bsn + 1)) {
		if (gprs_rlcmac_rlc_v_b_is_nacked(&ulw->v_b, bsn) ||
		    gprs_rlcmac_rlc_v_b_is_resend(&ulw->v_b, bsn))
			return bsn;
	}

	return -1;
}

unsigned int gprs_rlcmac_rlc_ul_window_mark_for_resend(struct gprs_rlcmac_rlc_ul_window *ulw)
{
	struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w(ulw);
	unsigned int resend = 0;
	uint16_t bsn;

	for (bsn = gprs_rlcmac_rlc_ul_window_v_a(ulw);
	     bsn != gprs_rlcmac_rlc_ul_window_v_s(ulw);
	     bsn = gprs_rlcmac_rlc_window_mod_sns_bsn(w, bsn + 1)) {
		if (gprs_rlcmac_rlc_v_b_is_unacked(&ulw->v_b, bsn)) {
			/* mark to be re-send */
			gprs_rlcmac_rlc_v_b_mark_resend(&ulw->v_b, bsn);
			resend += 1;
		}
	}

	return resend;
}

static inline uint16_t bitnum_to_bsn(int bitnum, uint16_t ssn)
{
	return (ssn - 1 - bitnum);
}

void gprs_rlcmac_rlc_ul_window_update_ssn(struct gprs_rlcmac_rlc_ul_window *ulw, char *show_rbb,
					  uint16_t ssn, uint16_t *lost, uint16_t *received)
{
	struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w(ulw);
	unsigned int bitpos;

	/* SSN - 1 is in range V(A)..V(S)-1 */
	for (bitpos = 0; bitpos < gprs_rlcmac_rlc_window_ws(w); bitpos++) {
		uint16_t bsn = gprs_rlcmac_rlc_window_mod_sns_bsn(w, bitnum_to_bsn(bitpos, ssn));

		if (bsn == gprs_rlcmac_rlc_window_mod_sns_bsn(w, gprs_rlcmac_rlc_ul_window_v_a(ulw) - 1))
			break;

		if (show_rbb[gprs_rlcmac_rlc_window_ws(w) - 1 - bitpos] == 'R') {
			LOGRLCMAC(LOGL_DEBUG, "- got ack for BSN=%u\n", bsn);
			if (!gprs_rlcmac_rlc_v_b_is_acked(&ulw->v_b, bsn))
				*received += 1;
			gprs_rlcmac_rlc_v_b_mark_acked(&ulw->v_b, bsn);
		} else {
			LOGRLCMAC(LOGL_DEBUG, "- got NACK for BSN=%u\n", bsn);
			gprs_rlcmac_rlc_v_b_mark_nacked(&ulw->v_b, bsn);
			*lost += 1;
		}
	}
}

void gprs_rlcmac_rlc_ul_window_update(struct gprs_rlcmac_rlc_ul_window *ulw, const struct bitvec *rbb,
				      uint16_t first_bsn, uint16_t *lost, uint16_t *received)
{
	struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w(ulw);
	unsigned int dist = gprs_rlcmac_rlc_ul_window_distance(ulw);
	unsigned int num_blocks = rbb->cur_bit > dist
				? dist : rbb->cur_bit;
	unsigned int bsn;
	unsigned int bitpos;

	/* first_bsn is in range V(A)..V(S) */

	for (bitpos = 0; bitpos < num_blocks; bitpos++) {
		bool is_ack;
		bsn = gprs_rlcmac_rlc_window_mod_sns_bsn(w, first_bsn + bitpos);
		if (bsn == gprs_rlcmac_rlc_window_mod_sns_bsn(w, gprs_rlcmac_rlc_ul_window_v_a(ulw) - 1))
			break;

		is_ack = bitvec_get_bit_pos(rbb, bitpos) == 1;

		if (is_ack) {
			LOGRLCMAC(LOGL_DEBUG, "- got ack for BSN=%u\n", bsn);
			if (!gprs_rlcmac_rlc_v_b_is_acked(&ulw->v_b, bsn))
				*received += 1;
			gprs_rlcmac_rlc_v_b_mark_acked(&ulw->v_b, bsn);
		} else {
			LOGRLCMAC(LOGL_DEBUG, "- got NACK for BSN=%u\n", bsn);
			gprs_rlcmac_rlc_v_b_mark_nacked(&ulw->v_b, bsn);
			*lost += 1;
		}
	}
}

unsigned int gprs_rlcmac_rlc_ul_window_move_window(struct gprs_rlcmac_rlc_ul_window *ulw)
{
	struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w(ulw);
	unsigned int moved = 0;
	uint16_t bsn;

	for (bsn = gprs_rlcmac_rlc_ul_window_v_a(ulw);
	     bsn != gprs_rlcmac_rlc_ul_window_v_s(ulw);
	     bsn = gprs_rlcmac_rlc_window_mod_sns_bsn(w, bsn + 1)) {
		if (!gprs_rlcmac_rlc_v_b_is_acked(&ulw->v_b, bsn))
			break;
		moved += 1;
		gprs_rlcmac_rlc_v_b_mark_invalid(&ulw->v_b, bsn);
	}

	return moved;
}

void gprs_rlcmac_rlc_ul_window_show_state(const struct gprs_rlcmac_rlc_ul_window *ulw, char *show_v_b)
{
	const struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w_const(ulw);
	unsigned int i;
	uint16_t bsn;

	for (i = 0, bsn = gprs_rlcmac_rlc_ul_window_v_a(ulw);
	     bsn != gprs_rlcmac_rlc_ul_window_v_s(ulw);
	     i++, bsn = gprs_rlcmac_rlc_window_mod_sns_bsn(w, bsn + 1)) {
		uint16_t index = bsn & mod_sns_half();
		switch (gprs_rlcmac_rlc_v_b_get_state(&ulw->v_b, index)) {
		case GPRS_RLCMAC_RLC_UL_BSN_INVALID:
			show_v_b[i] = 'I';
			break;
		case GPRS_RLCMAC_RLC_UL_BSN_ACKED:
			show_v_b[i] = 'A';
			break;
		case GPRS_RLCMAC_RLC_UL_BSN_RESEND:
			show_v_b[i] = 'X';
			break;
		case GPRS_RLCMAC_RLC_UL_BSN_NACKED:
			show_v_b[i] = 'N';
			break;
		default:
			show_v_b[i] = '?';
		}
	}
	show_v_b[i] = '\0';
}

unsigned int gprs_rlcmac_rlc_ul_window_count_unacked(const struct gprs_rlcmac_rlc_ul_window *ulw)
{
	const struct gprs_rlcmac_rlc_window *w = rlc_ulw_as_w_const(ulw);
	unsigned int unacked = 0;
	uint16_t bsn;

	for (bsn = gprs_rlcmac_rlc_ul_window_v_a(ulw);
	     bsn != gprs_rlcmac_rlc_ul_window_v_s(ulw);
	     bsn = gprs_rlcmac_rlc_window_mod_sns_bsn(w, bsn + 1)) {
		if (!gprs_rlcmac_rlc_v_b_is_acked(&ulw->v_b, bsn))
			unacked += 1;
	}

	return unacked;
}
