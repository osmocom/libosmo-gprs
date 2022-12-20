/* GPRS LLC protocol primitive implementation as per 3GPP TS 44.064 */
/*
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/gprs/llc/llc.h>
#include <osmocom/gprs/llc/llc_prim.h>

const struct value_string osmo_gprs_llc_prim_sap_names[] = {
	{ OSMO_GPRS_LLC_SAP_LLGM,	"LLGM" },
	{ OSMO_GPRS_LLC_SAP_LL,		"LL" },
	{ OSMO_GPRS_LLC_SAP_GRR,	"GRR" },
	{ OSMO_GPRS_LLC_SAP_BSSGP,	"BSSGP" },
	{ 0, NULL }
};
