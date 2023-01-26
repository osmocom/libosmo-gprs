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

/* Section TS 44.064 6.2.3 Service Access Point Identifier (SAPI) */
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

int osmo_gprs_rlcmac_init(enum osmo_gprs_rlcmac_location location);

enum osmo_gprs_rlcmac_log_cat {
	OSMO_GPRS_RLCMAC_LOGC_RLCMAC,
	_OSMO_GPRS_RLCMAC_LOGC_MAX,
};

void osmo_gprs_rlcmac_set_log_cat(enum osmo_gprs_rlcmac_log_cat logc, int logc_num);
int osmo_gprs_rlcmac_set_codel_params(bool use, unsigned int interval_msec);
