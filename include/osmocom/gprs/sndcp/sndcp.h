#pragma once

/* Subnetwork Dependent Convergence Protocol (SNDCP) definitions from 3GPP TS 44.065 */

#include <stdint.h>
#include <stddef.h>

/* 3GPP TS 24.008 10.5.6.5 Quality of service */
#define OSMO_GPRS_SNDCP_QOS_MAXLEN 22

enum osmo_gprs_sndcp_location {
	OSMO_GPRS_SNDCP_LOCATION_UNSET,
	OSMO_GPRS_SNDCP_LOCATION_MS,
	OSMO_GPRS_SNDCP_LOCATION_NET,
};

int osmo_gprs_sndcp_init(enum osmo_gprs_sndcp_location location);

enum osmo_gprs_sndcp_log_cat {
	OSMO_GPRS_SNDCP_LOGC_SNDCP,
	OSMO_GPRS_SNDCP_LOGC_SLHC,
	_OSMO_GPRS_SNDCP_LOGC_MAX,
};

void osmo_gprs_sndcp_set_log_cat(enum osmo_gprs_sndcp_log_cat logc, int logc_num);
