/* RLC Window as per 3GPP TS 44.060 */
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

#include <osmocom/core/utils.h>

#include <osmocom/gprs/rlcmac/rlc.h>
#include <osmocom/gprs/rlcmac/rlc_window.h>

#define RLC_GPRS_WS  64 /* max window size */
#define RLC_EGPRS_MIN_WS 64 /* min window size */
#define RLC_EGPRS_MAX_WS 1024 /* min window size */
#define RLC_EGPRS_MAX_BSN_DELTA 512
#define RLC_MAX_WS   RLC_EGPRS_MAX_WS

void gprs_rlcmac_rlc_window_constructor(struct gprs_rlcmac_rlc_window *w)
{
	w->sns = RLC_GPRS_SNS;
	w->ws = RLC_GPRS_WS;
}

void gprs_rlcmac_rlc_window_destructor(struct gprs_rlcmac_rlc_window *w)
{
	/* Nothing to be done here yet */
}

uint16_t gprs_rlcmac_rlc_window_mod_sns(const struct gprs_rlcmac_rlc_window *w)
{
	return gprs_rlcmac_rlc_window_sns(w) - 1;
}

uint16_t gprs_rlcmac_rlc_window_mod_sns_bsn(const struct gprs_rlcmac_rlc_window *w, uint16_t bsn)
{
	return bsn & gprs_rlcmac_rlc_window_mod_sns(w);
}

uint16_t gprs_rlcmac_rlc_window_sns(const struct gprs_rlcmac_rlc_window *w)
{
	return w->sns;
}

uint16_t gprs_rlcmac_rlc_window_ws(const struct gprs_rlcmac_rlc_window *w)
{
	return w->ws;
}

void gprs_rlcmac_rlc_window_set_sns(struct gprs_rlcmac_rlc_window *w, uint16_t sns)
{
	OSMO_ASSERT(sns >= RLC_GPRS_SNS);
	OSMO_ASSERT(sns <= RLC_MAX_SNS);
	/* check for 2^n */
	OSMO_ASSERT((sns & (-sns)) == sns);
	w->sns = sns;
}

void gprs_rlcmac_rlc_window_set_ws(struct gprs_rlcmac_rlc_window *w, uint16_t ws)
{
	OSMO_ASSERT(ws >= RLC_GPRS_SNS/2);
	OSMO_ASSERT(ws <= RLC_MAX_SNS/2);
	w->ws = ws;
}
