#pragma once

/* Radio Link Control / Medium Access Control (RLCMAC) definitions from 3GPP TS 44.060 */

enum osmo_gprs_rlcmac_log_cat {
	OSMO_GPRS_RLCMAC_LOGC_RLCMAC,
	_OSMO_GPRS_RLCMAC_LOGC_MAX,
};

void osmo_gprs_rlcmac_set_log_cat(enum osmo_gprs_rlcmac_log_cat logc, int logc_num);
