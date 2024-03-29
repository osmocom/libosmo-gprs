/* RLC Window (common for both UL/DL TBF), 3GPP TS 44.060 */
#pragma once

#include <stdint.h>

#define GPRS_RLCMAC_GPRS_WS  64 /* max window size */
#define GPRS_RLCMAC_EGPRS_MIN_WS 64 /* min window size */
#define GPRS_RLCMAC_EGPRS_MAX_WS 1024 /* min window size */
#define GPRS_RLCMAC_EGPRS_MAX_BSN_DELTA 512
#define GPRS_RLCMAC_MAX_WS   RLC_EGPRS_MAX_WS

struct gprs_rlcmac_rlc_window {
	uint16_t sns;
	uint16_t ws;
};

struct gprs_rlcmac_rlc_window;

void gprs_rlcmac_rlc_window_constructor(struct gprs_rlcmac_rlc_window *w);
void gprs_rlcmac_rlc_window_destructor(struct gprs_rlcmac_rlc_window *w);

uint16_t gprs_rlcmac_rlc_window_mod_sns(const struct gprs_rlcmac_rlc_window *w);
uint16_t gprs_rlcmac_rlc_window_mod_sns_bsn(const struct gprs_rlcmac_rlc_window *w, uint16_t bsn);
uint16_t gprs_rlcmac_rlc_window_sns(const struct gprs_rlcmac_rlc_window *w);
uint16_t gprs_rlcmac_rlc_window_ws(const struct gprs_rlcmac_rlc_window *w);

void gprs_rlcmac_rlc_window_set_sns(struct gprs_rlcmac_rlc_window *w, uint16_t sns);
void gprs_rlcmac_rlc_window_set_ws(struct gprs_rlcmac_rlc_window *w, uint16_t ws);
