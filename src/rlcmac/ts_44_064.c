/* GPRS RLC/MAC definitions from TS 44.064 (LLC) */
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

#include <osmocom/core/utils.h>
#include <osmocom/gprs/rlcmac/rlcmac.h>

const struct value_string osmo_gprs_rlcmac_llc_sapi_names[] = {
	{ OSMO_GPRS_RLCMAC_LLC_SAPI_GMM,	"GMM" },
	{ OSMO_GPRS_RLCMAC_LLC_SAPI_TOM2,	"TOM2" },
	{ OSMO_GPRS_RLCMAC_LLC_SAPI_SNDCP3,	"SNDCP3" },
	{ OSMO_GPRS_RLCMAC_LLC_SAPI_SNDCP5,	"SNDCP5" },
	{ OSMO_GPRS_RLCMAC_LLC_SAPI_SMS,	"SMS" },
	{ OSMO_GPRS_RLCMAC_LLC_SAPI_TOM8,	"TOM8" },
	{ OSMO_GPRS_RLCMAC_LLC_SAPI_SNDCP9,	"SNDCP9" },
	{ OSMO_GPRS_RLCMAC_LLC_SAPI_SNDCP11,	"SNDCP11" },
	{ 0, NULL }
};
