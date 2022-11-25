#pragma once

/* LLC (Logical Link Control) definitions from 3GPP TS 44.064 */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/msgb.h>

/* Section 7.1.2 LLC layer service primitives */
enum osmo_gprs_llc_location {
	OSMO_GPRS_LLC_LOCATION_UNSET,
	OSMO_GPRS_LLC_LOCATION_MS,
	OSMO_GPRS_LLC_LOCATION_SGSN,
};

/* Section 6.2.3 Service Access Point Identifier (SAPI) */
enum osmo_gprs_llc_sapi {
	OSMO_GPRS_LLC_SAPI_GMM		= 1,
	OSMO_GPRS_LLC_SAPI_TOM2		= 2,
	OSMO_GPRS_LLC_SAPI_SNDCP3	= 3,
	OSMO_GPRS_LLC_SAPI_SNDCP5	= 5,
	OSMO_GPRS_LLC_SAPI_SMS		= 7,
	OSMO_GPRS_LLC_SAPI_TOM8		= 8,
	OSMO_GPRS_LLC_SAPI_SNDCP9	= 9,
	OSMO_GPRS_LLC_SAPI_SNDCP11	= 11,
};

extern const struct value_string osmo_gprs_llc_sapi_names[];

static inline const char *osmo_gprs_llc_sapi_name(enum osmo_gprs_llc_sapi val)
{
	return get_value_string(osmo_gprs_llc_sapi_names, val);
}

int osmo_gprs_llc_init(enum osmo_gprs_llc_location location);

enum osmo_gprs_llc_log_cat {
	OSMO_GPRS_LLC_LOGC_LLC,
	_OSMO_GPRS_LLC_LOGC_MAX,
};

void osmo_gprs_llc_set_log_cat(enum osmo_gprs_llc_log_cat logc, int logc_num);
