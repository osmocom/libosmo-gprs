/* GPRS LLC protocol implementation as per 3GPP TS 44.064 */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2022 by Sysmocom s.f.m.c. GmbH
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

const struct value_string osmo_gprs_llc_xid_type_names[] = {
	{ OSMO_GPRS_LLC_XID_T_VERSION,		"LLC-Version" },
	{ OSMO_GPRS_LLC_XID_T_IOV_UI,		"IOV-UI" },
	{ OSMO_GPRS_LLC_XID_T_IOV_I,		"IOV-I" },
	{ OSMO_GPRS_LLC_XID_T_T200,		"T200" },
	{ OSMO_GPRS_LLC_XID_T_N200,		"N200" },
	{ OSMO_GPRS_LLC_XID_T_N201_U,		"N201-U" },
	{ OSMO_GPRS_LLC_XID_T_N201_I,		"N201-I" },
	{ OSMO_GPRS_LLC_XID_T_mD,		"mD" },
	{ OSMO_GPRS_LLC_XID_T_mU,		"mU" },
	{ OSMO_GPRS_LLC_XID_T_kD,		"kD" },
	{ OSMO_GPRS_LLC_XID_T_kU,		"kU" },
	{ OSMO_GPRS_LLC_XID_T_L3_PAR,		"L3-Params" },
	{ OSMO_GPRS_LLC_XID_T_RESET,		"Reset" },
	{ 0, NULL }
};
