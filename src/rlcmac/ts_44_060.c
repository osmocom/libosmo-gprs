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

const struct value_string osmo_gprs_rlcmac_dl_msg_type_names[] = {
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_CELL_CHANGE_ORDER,		"Pkt Cell Change Order" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_DOWNLINK_ASSIGNMENT,		"Pkt DL ASS" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_MEASUREMENT_ORDER,		 "Pkt Meas Order" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_POLLING_REQ,			"Pkt Polling Req" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_POWER_CONTROL_TIMING_ADVANCE,	"Pkt PWR CTRL TA" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_QUEUEING_NOTIFICATION,	"Pkt Queueing Notification" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_TIMESLOT_RECONFIGURE,		"Pkt TS Reconf" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_TBF_RELEASE,			"Pkt TBF Release" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_UPLINK_ACK_NACK,		"Pkt UL ACK/NACK" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_UPLINK_ASSIGNMENT,		"Pkt UL ASS" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_CELL_CHANGE_CONTINUE,		"Pkt Cell Change Continue" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_NEIGHBOUR_CELL_DATA,		"Pkt Neightbour Cell Data" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SERVING_CELL_DATA,		"Pkt Serving Cell Data" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_HANDOVER_COMMAND,		"Pkt Handover Cmd" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_PHYSICAL_INFORMATION,		"Pkt Physical Info" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_ACCESS_REJECT,		"Pkt Access Reject" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_PAGING_REQUEST,		"Pkt Paging Request" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_PDCH_RELEASE,			"Pkt PDCH Release" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_PRACH_PARAMETERS,		"Pkt PRACH Params" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK,	"Pkt DL Dummy Ctrl Block" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_6,		"Pkt SI 6" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_1,		"Pkt SI 1" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_2,		"Pkt SI 2" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_3,		"Pkt SI 3" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_3_BIS,		"Pkt SI 3bis" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_4,		"Pkt SI 4" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_5,		"Pkt SI 5" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_13,		"Pkt SI 13" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_7,		"Pkt SI 7" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_8,		"Pkt SI 8" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_14,		"Pkt SI 14" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_3_TER,		"Pkt SI 3ter" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_3_QUATER,		"Pkt SI 3quater" },
	{ OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_15,		"Pkt SI 15" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_rlcmac_ul_msg_type_names[] = {
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_CELL_CHANGE_FAILURE,		"Pkt Cell Change Failure" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_CONTROL_ACK,			"Pkt Control Ack" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_DOWNLINK_ACK_NACK,		"Pkt DL ACK/NACK" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK,	"Pkt UL Dummy Ctrl Block" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_MEASUREMENT_REPORT,		"Pkt Meas Report" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_RESOURCE_REQUEST,		"Pkt Resource Req" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_MOBILE_TBF_STATUS,		"Pkt Mobile TBF Status" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_PSI_STATUS,			"Pkt PSI Status" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_EGPRS_PACKET_DOWNLINK_ACK_NACK,	"EGPRS Pkt DL ACK/NACK" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_PAUSE,			"Pkt Pause" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_ENHANCED_MEASUREMENT_REPORT,	"Pkt Enhanced Meas Report" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_ADDITIONAL_MS_RAC,			"Additional MS RAC" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_CELL_CHANGE_NOTIFICATION,	"Pkt Cell Change Notification" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_SI_STATUS,			"Pkt SI Status" },
	{ OSMO_GPRS_RLCMAC_UL_MSGT_ENHANCED_MEASUREMENT_REPORT,		"Enhanced Meas Report" },
	{ 0, NULL }
};
