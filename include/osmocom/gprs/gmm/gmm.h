#pragma once

/* GPRS Mobility Management (GMM) definitions from 3GPP TS 24.008 */

#include <stdint.h>
#include <stddef.h>

/* Use stack as MS or as network? */
enum osmo_gprs_gmm_location {
	OSMO_GPRS_GMM_LOCATION_UNSET,
	OSMO_GPRS_GMM_LOCATION_MS,
	OSMO_GPRS_GMM_LOCATION_NETWORK,
};

int osmo_gprs_gmm_init(enum osmo_gprs_gmm_location location);

enum osmo_gprs_gmm_log_cat {
	OSMO_GPRS_GMM_LOGC_GMM,
	_OSMO_GPRS_GMM_LOGC_MAX,
};

void osmo_gprs_gmm_set_log_cat(enum osmo_gprs_gmm_log_cat logc, int logc_num);

void osmo_gprs_gmm_enable_gprs(bool enable_gprs);
