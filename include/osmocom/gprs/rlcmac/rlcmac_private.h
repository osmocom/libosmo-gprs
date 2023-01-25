#pragma once

/* RLCMAC private header */

#include <osmocom/gprs/rlcmac/rlcmac.h>

extern int g_rlcmac_log_cat[_OSMO_GPRS_RLCMAC_LOGC_MAX];

#define LOGRLCMAC(lvl, fmt, args...) LOGP(g_rlcmac_log_cat[OSMO_GPRS_RLCMAC_LOGC_RLCMAC], lvl, fmt, ## args)
#define LOGRLCMACC(lvl, fmt, args...) LOGPC(g_rlcmac_log_cat[OSMO_GPRS_RLCMAC_LOGC_RLCMAC], lvl, fmt, ## args)
