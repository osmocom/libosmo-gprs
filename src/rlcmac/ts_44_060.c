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
#include <osmocom/gprs/rlcmac/types.h>

const struct value_string osmo_gprs_rlcmac_egprs_pkt_ch_req_type_names[] = {
	{ OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_ONE_PHASE,			"One Phase Access" },
	{ OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_SHORT,			"Short Access" },
	{ OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_ONE_PHASE_RED_LATENCY,	"One Phase Access (Reduced Latency MS)" },
	{ OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_TWO_PHASE,			"Two Phase Access" },
	{ OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_SIGNALLING,			"Signalling" },
	{ OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_ONE_PHASE_UNACK,		"One Phase Access (RLC unack mode)" },
	{ OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_DEDICATED_CHANNEL,		"Dedicated Channel Request" },
	{ OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_EMERGENCY_CALL,		"Emergency call" },
	{ OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_TWO_PHASE_IPA,		"Two Phase Access (by IPA capable MS)" },
	{ OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_SIGNALLING_IPA,		"Signalling (by IPA capable MS)" },
	{ 0, NULL }
};
