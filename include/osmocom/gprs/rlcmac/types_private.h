/* Types & defines from TS 44.060, TS 44.064, private extensions */
#pragma once

#include <osmocom/gprs/rlcmac/types.h>

/* TS 44.060 able 10.4.5.1 RRBP offsets */
enum gprs_rlcmac_rrbp_field {
	GPRS_RLCMAC_RRBP_N_plus_13 = 0x0,
	GPRS_RLCMAC_RRBP_N_plus_17_18 = 0x1,
	GPRS_RLCMAC_RRBP_N_plus_21_22 = 0x2,
	GPRS_RLCMAC_RRBP_N_plus_26 = 0x3,
};

/* TS 44.060 Section 10.4.7 Table 10.4.7.1: Payload Type field */
enum gprs_rlcmac_payload_type {
	GPRS_RLCMAC_PT_DATA_BLOCK = 0x0,
	GPRS_RLCMAC_PT_CONTROL_BLOCK = 0x1,
	GPRS_RLCMAC_PT_CONTROL_BLOCK_OPT = 0x2,
	GPRS_RLCMAC_PT_RESERVED = 0x3
};

/* TS 44.060 Table 11.2.16.2 "ACCESS_TYPE" */
enum gprs_rlcmac_access_type {
	GPRS_RLCMAC_ACCESS_TYPE_2PHASE_ACC_REQ = 0, /* Two Phase Access Request */
	GPRS_RLCMAC_ACCESS_TYPE_PAGE_RESP = 1, /* Page Response */
	GPRS_RLCMAC_ACCESS_TYPE_CELL_UPD = 2, /* Cell Update */
	GPRS_RLCMAC_ACCESS_TYPE_MM = 3, /* Mobility Management procedure */
};

/* TS 44.060 Table Table 11.2.5. "Radio Priority" */
enum gprs_rlcmac_radio_priority {
	GPRS_RLCMAC_RADIO_PRIORITY_1 = 0, /* Radio Priority 1 (Highest priority) */
	GPRS_RLCMAC_RADIO_PRIORITY_2 = 1, /* Radio Priority 2 */
	GPRS_RLCMAC_RADIO_PRIORITY_3 = 2, /* Radio Priority 3 */
	GPRS_RLCMAC_RADIO_PRIORITY_4 = 3, /* Radio Priority 4 (Lower priority) */
};

/* TS 44.060 Table Table 12.7.2 "RLC_MODE" */
enum gprs_rlcmac_rlc_mode {
	GPRS_RLCMAC_RLC_MODE_ACKNOWLEDGED = 0,
	GPRS_RLCMAC_RLC_MODE_UNACKNOWLEDGED = 1,
};

/* TS 44.060 Table Table Table 12.7.2 "LLC_PDU_TYPE" */
enum gprs_rlcmac_llc_pdu_type {
	GPRS_RLCMAC_LLC_PDU_TYPE_ACKNOWLEDGED = 0,
	GPRS_RLCMAC_LLC_PDU_TYPE_UNACKNOWLEDGED = 1,
};

/* TS 44.060 12.20 "PAGE_MODE" */
enum gprs_rlcmac_page_mode {
	GPRS_RLCMAC_PAGE_MODE_NORMAL = 0,
	GPRS_RLCMAC_PAGE_MODE_EXTENDED = 1,
	GPRS_RLCMAC_PAGE_MODE_REORGANIZATION = 2,
	GPRS_RLCMAC_PAGE_MODE_SAME_BEFORE = 3,
};
