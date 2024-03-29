/* Types & defines from TS 44.060, TS 44.064 */
#pragma once

/* TS 44.060 Table 11.2.5a.2 "EGPRS Packet channel request" */
enum osmo_gprs_rlcmac_egprs_pkt_ch_req_type {
	OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_ONE_PHASE = 0,
	OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_SHORT,
	OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_ONE_PHASE_RED_LATENCY,
	OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_TWO_PHASE,
	OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_SIGNALLING,
	OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_ONE_PHASE_UNACK,
	OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_DEDICATED_CHANNEL,
	OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_EMERGENCY_CALL,
	OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_TWO_PHASE_IPA,
	OSMO_GPRS_RLCMAC_EGPRS_PKT_CH_REQ_SIGNALLING_IPA,
};
extern const struct value_string osmo_gprs_rlcmac_egprs_pkt_ch_req_type_names[];

/* TS 44.064 Section 6.2.3 Service Access Point Identifier (SAPI) */
enum osmo_gprs_rlcmac_llc_sapi {
	OSMO_GPRS_RLCMAC_LLC_SAPI_GMM		= 1,
	OSMO_GPRS_RLCMAC_LLC_SAPI_TOM2		= 2,
	OSMO_GPRS_RLCMAC_LLC_SAPI_SNDCP3	= 3,
	OSMO_GPRS_RLCMAC_LLC_SAPI_SNDCP5	= 5,
	OSMO_GPRS_RLCMAC_LLC_SAPI_SMS		= 7,
	OSMO_GPRS_RLCMAC_LLC_SAPI_TOM8		= 8,
	OSMO_GPRS_RLCMAC_LLC_SAPI_SNDCP9	= 9,
	OSMO_GPRS_RLCMAC_LLC_SAPI_SNDCP11	= 11,
};
extern const struct value_string osmo_gprs_rlcmac_llc_sapi_names[];

/* TS 44.060 11.2.0.1 Downlink RLC/MAC messages */
enum osmo_gprs_rlcmac_dl_msg_type {
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_CELL_CHANGE_ORDER		= 0x01,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_DOWNLINK_ASSIGNMENT		= 0x02,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_MEASUREMENT_ORDER		= 0x03,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_POLLING_REQ			= 0x04,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_POWER_CONTROL_TIMING_ADVANCE	= 0x05,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_QUEUEING_NOTIFICATION		= 0x06,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_TIMESLOT_RECONFIGURE		= 0x07,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_TBF_RELEASE			= 0x08,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_UPLINK_ACK_NACK			= 0x09,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_UPLINK_ASSIGNMENT		= 0x0A,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_CELL_CHANGE_CONTINUE		= 0x0B,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_NEIGHBOUR_CELL_DATA		= 0x0C,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SERVING_CELL_DATA		= 0x0D,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_HANDOVER_COMMAND		= 0x15,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_PHYSICAL_INFORMATION		= 0x16,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_ACCESS_REJECT			= 0x21,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_PAGING_REQUEST			= 0x22,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_PDCH_RELEASE			= 0x23,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_PRACH_PARAMETERS		= 0x24,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK	= 0x25,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_6			= 0x30,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_1			= 0x31,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_2			= 0x32,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_3			= 0x33,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_3_BIS		= 0x34,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_4			= 0x35,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_5			= 0x36,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_13			= 0x37,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_7			= 0x38,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_8			= 0x39,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_14			= 0x3A,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_3_TER		= 0x3C,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_3_QUATER		= 0x3D,
	OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_SYSTEM_INFO_15			= 0x3E,
};
extern const struct value_string osmo_gprs_rlcmac_dl_msg_type_names[];

/* TS 44.060 11.2.0.2 Uplink RLC/MAC messages */
enum osmo_gprs_rlcmac_ul_msg_type {
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_CELL_CHANGE_FAILURE		= 0x00,
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_CONTROL_ACK			= 0x01,
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_DOWNLINK_ACK_NACK		= 0x02,
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK	= 0x03,
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_MEASUREMENT_REPORT		= 0x04,
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_RESOURCE_REQUEST		= 0x05,
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_MOBILE_TBF_STATUS		= 0x06,
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_PSI_STATUS			= 0x07,
	OSMO_GPRS_RLCMAC_UL_MSGT_EGPRS_PACKET_DOWNLINK_ACK_NACK		= 0x08,
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_PAUSE				= 0x09,
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_ENHANCED_MEASUREMENT_REPORT	= 0x0A,
	OSMO_GPRS_RLCMAC_UL_MSGT_ADDITIONAL_MS_RAC			= 0x0B,
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_CELL_CHANGE_NOTIFICATION	= 0x0C,
	OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_SI_STATUS			= 0x0D,
	OSMO_GPRS_RLCMAC_UL_MSGT_ENHANCED_MEASUREMENT_REPORT		= 0x04,
};
extern const struct value_string osmo_gprs_rlcmac_ul_msg_type_names[];
