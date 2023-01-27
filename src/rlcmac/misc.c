/*
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Vadim Yanitskiy <vyanitskiy@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/tbf_ul_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_ul_ass_fsm.h>

int g_rlcmac_log_cat[_OSMO_GPRS_RLCMAC_LOGC_MAX] = {
	[0 ... _OSMO_GPRS_RLCMAC_LOGC_MAX - 1] = DLGLOBAL
};

void osmo_gprs_rlcmac_set_log_cat(enum osmo_gprs_rlcmac_log_cat logc, int logc_num)
{
	OSMO_ASSERT(logc < _OSMO_GPRS_RLCMAC_LOGC_MAX);
	g_rlcmac_log_cat[logc] = logc_num;

	if (logc == OSMO_GPRS_RLCMAC_LOGC_TBFUL) {
		gprs_rlcmac_tbf_ul_fsm_set_log_cat(logc_num);
		gprs_rlcmac_tbf_ul_ass_fsm_set_log_cat(logc_num);
	}
}
