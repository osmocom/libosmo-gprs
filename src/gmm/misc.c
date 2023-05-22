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

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/gprs/gmm/gmm.h>
#include <osmocom/gprs/gmm/gmm_ms_fsm.h>

int g_gmm_log_cat[_OSMO_GPRS_GMM_LOGC_MAX] = { [0 ... _OSMO_GPRS_GMM_LOGC_MAX - 1] = DLGLOBAL };

void osmo_gprs_gmm_set_log_cat(enum osmo_gprs_gmm_log_cat logc, int logc_num)
{
	OSMO_ASSERT(logc < _OSMO_GPRS_GMM_LOGC_MAX);
	g_gmm_log_cat[logc] = logc_num;

	gprs_gmm_ms_fsm_set_log_cat(logc_num);
}


/* 3GPP TS 24.008, 10.5.7.3 GPRS Timer */
int gprs_gmm_gprs_tmr_to_secs(uint8_t gprs_tmr)
{
	switch (gprs_tmr & GPRS_TMR_UNIT_MASK) {
	case GPRS_TMR_2SECONDS:
		return 2 * (gprs_tmr & GPRS_TMR_FACT_MASK);
	default:
	case GPRS_TMR_MINUTE:
		return 60 * (gprs_tmr & GPRS_TMR_FACT_MASK);
	case GPRS_TMR_6MINUTE:
		return 360 * (gprs_tmr & GPRS_TMR_FACT_MASK);
	case GPRS_TMR_DEACTIVATED:
		return -1;
	}
}

/* This functions returns a tmr value such that
 *   - f is monotonic
 *   - f(s) <= s
 *   - f(s) == s if a tmr exists with s = gprs_tmr_to_secs(tmr)
 *   - the best possible resolution is used
 * where
 *   f(s) = gprs_tmr_to_secs(gprs_secs_to_tmr_floor(s))
 */
uint8_t gprs_gmm_secs_to_gprs_tmr_floor(int secs)
{
	if (secs < 0)
		return GPRS_TMR_DEACTIVATED;
	if (secs < 2 * 32)
		return GPRS_TMR_2SECONDS | (secs / 2);
	if (secs < 60 * 2)
		/* Ensure monotonicity */
		return GPRS_TMR_2SECONDS | GPRS_TMR_FACT_MASK;
	if (secs < 60 * 32)
		return GPRS_TMR_MINUTE | (secs / 60);
	if (secs < 360 * 6)
		/* Ensure monotonicity */
		return GPRS_TMR_MINUTE | GPRS_TMR_FACT_MASK;
	if (secs < 360 * 32)
		return GPRS_TMR_6MINUTE | (secs / 360);

	return GPRS_TMR_6MINUTE | GPRS_TMR_FACT_MASK;
}
