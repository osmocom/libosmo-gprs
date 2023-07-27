/* GPRS QoS definitions from 3GPP TS 24.008 sec 10.5.6.5 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <osmocom/core/endian.h>

/* 3GPP TS 24.008 10.5.6.5 Quality of service */
#define OSMO_GPRS_SM_QOS_MAXLEN 22

/* TS 24.008 10.5.6.5 Quality of service */
struct osmo_gprs_sm_qos_profile_data_extended_bit_rate {
	uint8_t max_bit_rate_uplink;
	uint8_t guaranteed_bit_rate_uplink;
	uint8_t max_bit_rate_downlink;
	uint8_t guaranteed_bit_rate_downlink;
} __attribute__ ((packed));

struct osmo_gprs_sm_qos_profile_data {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t reliability_class:3,
		delay_class:2,
		spare1:3;
	uint8_t precedence_class:3,
		spare2:1,
		peak_throughput:4;
	uint8_t mean_throughput:5,
		spare3:3;
	uint8_t delivery_erroneous_sdu:3,
		delivery_order:2,
		traffic_class:3;
	uint8_t max_sdu_size;
	uint8_t max_bit_rate_uplink;
	uint8_t max_bit_rate_downlink;
	uint8_t sdu_error_ratio:4,
		residual_ber:4;
	uint8_t traffic_handling_priority:2,
		transfer_delay:6;
	uint8_t guaranteed_bit_rate_uplink;
	uint8_t guaranteed_bit_rate_downlink;
	uint8_t source_statistics_descriptor:4,
		signalling_indication:1,
		spare4:3;
	struct osmo_gprs_sm_qos_profile_data_extended_bit_rate extended;
	struct osmo_gprs_sm_qos_profile_data_extended_bit_rate extended2;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t spare1:3, delay_class:2, reliability_class:3;
	uint8_t peak_throughput:4, spare2:1, precedence_class:3;
	uint8_t spare3:3, mean_throughput:5;
	uint8_t traffic_class:3, delivery_order:2, delivery_erroneous_sdu:3;
	uint8_t max_sdu_size;
	uint8_t max_bit_rate_uplink;
	uint8_t max_bit_rate_downlink;
	uint8_t residual_ber:4, sdu_error_ratio:4;
	uint8_t transfer_delay:6, traffic_handling_priority:2;
	uint8_t guaranteed_bit_rate_uplink;
	uint8_t guaranteed_bit_rate_downlink;
	uint8_t spare4:3, signalling_indication:1, source_statistics_descriptor:4;
	struct osmo_gprs_sm_qos_profile_data_extended_bit_rate extended;
	struct osmo_gprs_sm_qos_profile_data_extended_bit_rate extended2;
#endif
} __attribute__ ((packed));

struct osmo_gprs_sm_qos_profile {
	struct osmo_gprs_sm_qos_profile_data data;
} __attribute__ ((packed));
struct osmo_gprs_sm_qos_profile_decoded {
	struct osmo_gprs_sm_qos_profile qos_profile;
	/* Filled in by the decoder function: */
	bool data_octet6_to_13_present; /* from traffic_class to guaranteed_bit_rate_downlink */
	bool data_octet14_present; /* byte containing signalling_indication */
	bool bit_rate_downlink_extended_present;
	bool bit_rate_uplink_extended_present;
	bool bit_rate_downlink_extended2_present;
	bool bit_rate_uplink_extended2_present;
	uint16_t dec_transfer_delay;
	uint32_t dec_mbr_kbps_dl; /* decoded MBR in kbps */
	uint32_t dec_mbr_kbps_ul; /* decoded MBR in kbps */
	uint32_t dec_gbr_kbps_dl; /* decoded GBR in kbps */
	uint32_t dec_gbr_kbps_ul; /* decoded GBR in kbps */
} __attribute__ ((packed));

#define OSMO_GPRS_SM_QOS_TRAFFIC_CLASS_SUBSCRIBED 0
#define OSMO_GPRS_SM_QOS_TRAFFIC_CLASS_CONVERSATIONAL 1
#define OSMO_GPRS_SM_QOS_TRAFFIC_CLASS_STREAMING 2
#define OSMO_GPRS_SM_QOS_TRAFFIC_CLASS_INTERACTIVE 3
#define OSMO_GPRS_SM_QOS_TRAFFIC_CLASS_BACKGROUND 4

#define OSMO_GPRS_SM_QOS_SRC_STATS_DESC_UNKNOWN 0
#define OSMO_GPRS_SM_QOS_SRC_STATS_DESC_SPEECH 1

int16_t osmo_gprs_sm_qos_parse_qos_profile(
	struct osmo_gprs_sm_qos_profile_decoded *decoded, const uint8_t *data, size_t data_len);
int16_t osmo_gprs_sm_qos_build_qos_profile(const struct osmo_gprs_sm_qos_profile_decoded *decoded, void *data, int data_len);
