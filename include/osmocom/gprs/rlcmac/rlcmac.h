#pragma once

/* Radio Link Control / Medium Access Control (RLCMAC) definitions from 3GPP TS 44.060 */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/msgb.h>

enum osmo_gprs_rlcmac_location {
	OSMO_GPRS_RLCMAC_LOCATION_UNSET,
	OSMO_GPRS_RLCMAC_LOCATION_MS,
	OSMO_GPRS_RLCMAC_LOCATION_PCU,
};

int osmo_gprs_rlcmac_init(enum osmo_gprs_rlcmac_location location);

enum osmo_gprs_rlcmac_log_cat {
	OSMO_GPRS_RLCMAC_LOGC_RLCMAC,
	OSMO_GPRS_RLCMAC_LOGC_TBFUL,
	OSMO_GPRS_RLCMAC_LOGC_TBFDL,
	_OSMO_GPRS_RLCMAC_LOGC_MAX,
};

void osmo_gprs_rlcmac_set_log_cat(enum osmo_gprs_rlcmac_log_cat logc, int logc_num);
int osmo_gprs_rlcmac_set_codel_params(bool use, unsigned int interval_msec);
