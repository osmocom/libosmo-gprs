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
