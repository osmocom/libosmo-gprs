#pragma once

/* RLCMAC private header */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/msgb.h>

#include <osmocom/gprs/rlcmac/rlcmac_prim.h>
#include <osmocom/gprs/rlcmac/rlcmac.h>

extern int g_rlcmac_log_cat[_OSMO_GPRS_RLCMAC_LOGC_MAX];

#define LOGRLCMAC(lvl, fmt, args...) LOGP(g_rlcmac_log_cat[OSMO_GPRS_RLCMAC_LOGC_RLCMAC], lvl, fmt, ## args)
#define LOGRLCMACC(lvl, fmt, args...) LOGPC(g_rlcmac_log_cat[OSMO_GPRS_RLCMAC_LOGC_RLCMAC], lvl, fmt, ## args)

#define msgb_rlcmac_prim(msg) ((struct osmo_gprs_rlcmac_prim *)(msg)->l1h)

struct gprs_rlcmac_ctx {
	enum osmo_gprs_rlcmac_location location;
	osmo_gprs_rlcmac_prim_up_cb rlcmac_up_cb;
	void *rlcmac_up_cb_user_data;

	osmo_gprs_rlcmac_prim_down_cb rlcmac_down_cb;
	void *rlcmac_down_cb_user_data;
};

extern struct gprs_rlcmac_ctx *g_ctx;

/* rlcmac_prim.c */
int gprs_rlcmac_prim_call_up_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim);
int gprs_rlcmac_prim_call_down_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim);

struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_grr_unitdata_ind(
				uint32_t tlli, uint8_t *ll_pdu, size_t ll_pdu_len);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_gmmrr_page_ind(uint32_t tlli);
