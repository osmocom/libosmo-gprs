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
#include <osmocom/core/logging.h>

#include <osmocom/gprs/rlcmac/rlc.h>
#include <osmocom/gprs/rlcmac/rlcmac_dec.h>
#include <osmocom/gprs/rlcmac/rlc_window_dl.h>
#include <osmocom/gprs/rlcmac/tbf_dl.h>


static inline bool gprs_rlcmac_rlc_v_n_is_state(const struct gprs_rlcmac_rlc_v_n *v_n,
						int bsn, enum gprs_rlcmac_rlc_dl_bsn_state type)
{
	return v_n->v_n[bsn & mod_sns_half()] == type;
}

static inline void gprs_rlcmac_rlc_v_n_mark(struct gprs_rlcmac_rlc_v_n *v_n,
					    int bsn, enum gprs_rlcmac_rlc_dl_bsn_state type)
{
	v_n->v_n[bsn & mod_sns_half()] = type;
}

void gprs_rlcmac_rlc_v_n_reset(struct gprs_rlcmac_rlc_v_n *v_n)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(v_n->v_n); i++)
		v_n->v_n[i] = GPRS_RLCMAC_RLC_DL_BSN_INVALID;
}

/* Check for an individual frame */
bool gprs_rlcmac_rlc_v_n_is_received(const struct gprs_rlcmac_rlc_v_n *v_n, int bsn)
{
	return gprs_rlcmac_rlc_v_n_is_state(v_n, bsn, GPRS_RLCMAC_RLC_DL_BSN_RECEIVED);
}

enum gprs_rlcmac_rlc_dl_bsn_state gprs_rlcmac_rlc_v_n_get_state(const struct gprs_rlcmac_rlc_v_n *v_n, int bsn)
{
	return v_n->v_n[bsn & mod_sns_half()];
}

/* Mark a RLC frame for something */
void gprs_rlcmac_rlc_v_n_mark_received(struct gprs_rlcmac_rlc_v_n *v_n, int bsn)
{
	return gprs_rlcmac_rlc_v_n_mark(v_n, bsn, GPRS_RLCMAC_RLC_DL_BSN_RECEIVED);
}

void gprs_rlcmac_rlc_v_n_mark_missing(struct gprs_rlcmac_rlc_v_n *v_n, int bsn)
{
	return gprs_rlcmac_rlc_v_n_mark(v_n, bsn, GPRS_RLCMAC_RLC_DL_BSN_MISSING);
}

/*************
 * UL WINDOW
*************/
struct gprs_rlcmac_rlc_dl_window *gprs_rlcmac_rlc_dl_window_alloc(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	struct gprs_rlcmac_rlc_dl_window *dlw;

	dlw = talloc_zero(dl_tbf, struct gprs_rlcmac_rlc_dl_window);
	if (!dlw)
		return NULL;

	gprs_rlcmac_rlc_window_constructor(rlc_dlw_as_w(dlw));

	dlw->dl_tbf = dl_tbf;
	gprs_rlcmac_rlc_dl_window_reset(dlw);

	return dlw;
}

void gprs_rlcmac_rlc_dl_window_free(struct gprs_rlcmac_rlc_dl_window *dlw)
{
	if (!dlw)
		return;

	gprs_rlcmac_rlc_window_destructor(rlc_dlw_as_w(dlw));
	talloc_free(dlw);
}

static void gprs_rlcmac_rlc_dl_window_reset_state(struct gprs_rlcmac_rlc_dl_window *dlw)
{
	dlw->v_r = 0;
	dlw->v_q = 0;
}

void gprs_rlcmac_rlc_dl_window_reset(struct gprs_rlcmac_rlc_dl_window *dlw)
{
	gprs_rlcmac_rlc_dl_window_reset_state(dlw);
	gprs_rlcmac_rlc_v_n_reset(&dlw->v_n);
}

uint16_t gprs_rlcmac_rlc_dl_window_v_r(const struct gprs_rlcmac_rlc_dl_window *dlw)
{
	return dlw->v_r;
}

uint16_t gprs_rlcmac_rlc_dl_window_v_q(const struct gprs_rlcmac_rlc_dl_window *dlw)
{
	return dlw->v_q;
}

void gprs_rlcmac_rlc_dl_window_set_v_r(struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t v_r)
{
	dlw->v_r = v_r;
}

void gprs_rlcmac_rlc_dl_window_set_v_q(struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t v_q)
{
	dlw->v_q = v_q;
}

bool gprs_rlcmac_rlc_dl_window_is_in_window(const struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t bsn)
{
	const struct gprs_rlcmac_rlc_window *w = rlc_dlw_as_w_const(dlw);
	uint16_t offset_v_q;

	/* current block relative to lowest unreceived block */
	offset_v_q = (bsn - dlw->v_q) & gprs_rlcmac_rlc_window_mod_sns(w);
	/* If out of window (may happen if blocks below V(Q) are received
	 * again. */
	return offset_v_q < gprs_rlcmac_rlc_window_ws(w);
}

bool gprs_rlcmac_rlc_dl_window_is_received(const struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t bsn)
{
	const struct gprs_rlcmac_rlc_window *w = rlc_dlw_as_w_const(dlw);
	uint16_t offset_v_r;

	/* Offset to the end of the received window */
	offset_v_r = (dlw->v_r - 1 - bsn) & gprs_rlcmac_rlc_window_mod_sns(w);
	return gprs_rlcmac_rlc_dl_window_is_in_window(dlw, bsn) &&
	       gprs_rlcmac_rlc_v_n_is_received(&dlw->v_n, bsn) &&
	       offset_v_r < gprs_rlcmac_rlc_window_ws(w);
}

void gprs_rlcmac_rlc_dl_window_update_rbb(const struct gprs_rlcmac_rlc_dl_window *dlw, char *rbb)
{
	const struct gprs_rlcmac_rlc_window *w = rlc_dlw_as_w_const(dlw);
	uint16_t mod_sns = gprs_rlcmac_rlc_window_mod_sns(w);
	uint16_t ws = gprs_rlcmac_rlc_window_ws(w);
	uint16_t ssn = gprs_rlcmac_rlc_dl_window_ssn(dlw);

	unsigned int i;

	for (i = 0; i < ws; i++) {
		if (gprs_rlcmac_rlc_v_n_is_received(&dlw->v_n, ssn - 1 - i) & mod_sns)
			rbb[ws - 1 - i] = 'R';
		else
			rbb[ws - 1 - i] = 'I';
	}
}

/* Update the receive block bitmap */
uint16_t gprs_rlcmac_rlc_dl_window_update_rbb_egprs(const struct gprs_rlcmac_rlc_dl_window *dlw, uint8_t *rbb)
{
	const struct gprs_rlcmac_rlc_window *w = rlc_dlw_as_w_const(dlw);
	uint16_t ws = gprs_rlcmac_rlc_window_ws(w);
	uint16_t i;
	uint16_t bsn;
	uint16_t bitmask = 0x80;
	int8_t pos = 0;
	int8_t bit_pos = 0;

	for (i = 0, bsn = (dlw->v_q + 1); ((bsn < (dlw->v_r)) && (i < ws)); i++,
					bsn = gprs_rlcmac_rlc_window_mod_sns_bsn(w, bsn + 1)) {
		if (gprs_rlcmac_rlc_v_n_is_received(&dlw->v_n, bsn))
			rbb[pos] = rbb[pos] | bitmask;
		else
			rbb[pos] = rbb[pos] & (~bitmask);
		bitmask = bitmask >> 1;
		bit_pos++;
		bit_pos = bit_pos % 8;
		if (bit_pos == 0) {
			pos++;
			bitmask = 0x80;
		}
	}
	return i;
}

void gprs_rlcmac_rlc_dl_window_raise_v_r_to(struct gprs_rlcmac_rlc_dl_window *dlw, int moves)
{
	struct gprs_rlcmac_rlc_window *w = rlc_dlw_as_w(dlw);
	dlw->v_r = gprs_rlcmac_rlc_window_mod_sns_bsn(w, dlw->v_r + moves);
}

void gprs_rlcmac_rlc_dl_window_raise_v_q_to(struct gprs_rlcmac_rlc_dl_window *dlw, int incr)
{
	struct gprs_rlcmac_rlc_window *w = rlc_dlw_as_w(dlw);
	dlw->v_q = gprs_rlcmac_rlc_window_mod_sns_bsn(w, dlw->v_q + incr);
}

/* Raise V(R) to highest received sequence number not received. */
void gprs_rlcmac_rlc_dl_window_raise_v_r(struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t bsn)
{
	struct gprs_rlcmac_rlc_window *w = rlc_dlw_as_w(dlw);
	uint16_t offset_v_r;

	offset_v_r = gprs_rlcmac_rlc_window_mod_sns_bsn(w, bsn + 1 - gprs_rlcmac_rlc_dl_window_v_r(dlw));
	/* Positive offset, so raise. */
	if (offset_v_r < (gprs_rlcmac_rlc_window_sns(w) >> 1)) {
		while (offset_v_r--) {
			if (offset_v_r) /* all except the received block */
				gprs_rlcmac_rlc_v_n_mark_missing(&dlw->v_n, gprs_rlcmac_rlc_dl_window_v_r(dlw));
			gprs_rlcmac_rlc_dl_window_raise_v_r_to(dlw, 1);
		}
		LOGRLCMAC(LOGL_DEBUG, "- Raising V(R) to %d\n", gprs_rlcmac_rlc_dl_window_v_r(dlw));
	}
}

/*
 * Raise V(Q) if possible. This is looped until there is a gap
 * (non received block) or the window is empty.
 */
uint16_t gprs_rlcmac_rlc_dl_window_raise_v_q(struct gprs_rlcmac_rlc_dl_window *dlw)
{
	struct gprs_rlcmac_rlc_window *w = rlc_dlw_as_w(dlw);
	uint16_t count = 0;

	while (gprs_rlcmac_rlc_dl_window_v_q(dlw) != gprs_rlcmac_rlc_dl_window_v_r(dlw)) {
		if (!gprs_rlcmac_rlc_v_n_is_received(&dlw->v_n, gprs_rlcmac_rlc_dl_window_v_q(dlw)))
			break;
		LOGRLCMAC(LOGL_DEBUG, "- Taking block %d out, raising V(Q) to %d\n",
			  gprs_rlcmac_rlc_dl_window_v_q(dlw),
			  gprs_rlcmac_rlc_window_mod_sns_bsn(w, gprs_rlcmac_rlc_dl_window_v_q(dlw) + 1));
		gprs_rlcmac_rlc_dl_window_raise_v_q_to(dlw, 1);
		count += 1;
	}

	return count;
}

void gprs_rlcmac_rlc_dl_window_receive_bsn(struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t bsn)
{
	gprs_rlcmac_rlc_v_n_mark_received(&dlw->v_n, bsn);
	gprs_rlcmac_rlc_dl_window_raise_v_r(dlw, bsn);
}

bool gprs_rlcmac_rlc_dl_window_invalidate_bsn(struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t bsn)
{
	bool was_valid = gprs_rlcmac_rlc_v_n_is_received(&dlw->v_n, bsn);
	gprs_rlcmac_rlc_v_n_mark_missing(&dlw->v_n, bsn);

	return was_valid;
}
