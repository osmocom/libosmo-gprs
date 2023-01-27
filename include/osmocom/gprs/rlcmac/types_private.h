/* Types & defines from TS 44.060, TS 44.064, private extensions */
#pragma once

#include <osmocom/gprs/rlcmac/types.h>

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
