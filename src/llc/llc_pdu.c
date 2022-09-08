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

const struct value_string osmo_gprs_llc_frame_fmt_names[] = {
	{ OSMO_GPRS_LLC_FMT_I,		"I" },
	{ OSMO_GPRS_LLC_FMT_S,		"U" },
	{ OSMO_GPRS_LLC_FMT_UI,		"UI" },
	{ OSMO_GPRS_LLC_FMT_U,		"U" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_llc_frame_func_names[] = {
	/* 6.4.1 Unnumbered (U) frames */
	{ OSMO_GPRS_LLC_FUNC_SABM,	"SABM" },
	{ OSMO_GPRS_LLC_FUNC_DISC,	"DISC" },
	{ OSMO_GPRS_LLC_FUNC_UA,	"UA" },
	{ OSMO_GPRS_LLC_FUNC_DM,	"DM" },
	{ OSMO_GPRS_LLC_FUNC_FRMR,	"FRMR" },
	{ OSMO_GPRS_LLC_FUNC_XID,	"XID" },
	{ OSMO_GPRS_LLC_FUNC_NULL,	"NULL" },
	/* 6.4.2 Unconfirmed Information (UI) frame */
	{ OSMO_GPRS_LLC_FUNC_UI,	"UI" },
	{ OSMO_GPRS_LLC_FUNC_UI_DUMMY,	"UI Dummy" },
	/* 6.4.3 Combined Information (I) and Supervisory (S) frames */
	{ OSMO_GPRS_LLC_FUNC_RR,	"RR" },
	{ OSMO_GPRS_LLC_FUNC_ACK,	"ACK" },
	{ OSMO_GPRS_LLC_FUNC_SACK,	"SACK" },
	{ OSMO_GPRS_LLC_FUNC_RNR,	"RNR" },
	{ 0, NULL }
};
