/* GPRS QoS definitions from 3GPP TS 24.008 sec 10.5.6.5 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <osmocom/gprs/sm/sm_qos.h>

int16_t gprs_qos_parse_qos_profile(
	struct osmo_gprs_sm_qos_profile_decoded *decoded, const uint8_t *data, size_t data_len);
int16_t gprs_qos_build_qos_profile(const struct osmo_gprs_sm_qos_profile_decoded *decoded, void *data, int data_len);
