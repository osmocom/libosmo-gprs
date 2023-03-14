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
#include <osmocom/gprs/gmm/gmm.h>

int g_gmm_log_cat[_OSMO_GPRS_GMM_LOGC_MAX] = { [0 ... _OSMO_GPRS_GMM_LOGC_MAX - 1] = DLGLOBAL };

void osmo_gprs_gmm_set_log_cat(enum osmo_gprs_gmm_log_cat logc, int logc_num)
{
	OSMO_ASSERT(logc < _OSMO_GPRS_GMM_LOGC_MAX);
	g_gmm_log_cat[logc] = logc_num;
}
