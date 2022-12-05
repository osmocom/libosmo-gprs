#pragma once

/* Subnetwork Dependent Convergence Protocol (SNDCP) definitions from 3GPP TS 44.065 */

#include <stdint.h>
#include <stddef.h>

int osmo_gprs_sndcp_init(void);

enum osmo_gprs_sndcp_log_cat {
	OSMO_GPRS_SNDCP_LOGC_SNDCP,
	OSMO_GPRS_SNDCP_LOGC_SLHC,
	_OSMO_GPRS_SNDCP_LOGC_MAX,
};

void osmo_gprs_sndcp_set_log_cat(enum osmo_gprs_sndcp_log_cat logc, int logc_num);
