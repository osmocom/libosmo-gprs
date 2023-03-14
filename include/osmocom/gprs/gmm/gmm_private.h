#pragma once

/* 3GPP TS 24.008, private header */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/endian.h>

#include <osmocom/gprs/gmm/gmm.h>

extern int g_gmm_log_cat[_OSMO_GPRS_GMM_LOGC_MAX];

#define LOGGMM(lvl, fmt, args...) LOGP(g_gmm_log_cat[OSMO_GPRS_GMM_LOGC_GMM], lvl, fmt, ## args)

#define msgb_gmm_prim(msg) ((struct osmo_gprs_gmm_prim *)(msg)->l1h)

struct gprs_gmm_ctx {
	enum osmo_gprs_gmm_location location;
	osmo_gprs_gmm_prim_up_cb gmm_up_cb;
	void *gmm_up_cb_user_data;

	osmo_gprs_gmm_prim_down_cb gmm_down_cb;
	void *gmm_down_cb_user_data;

	struct llist_head gmme_list; /* list of struct gprs_gmm_entity->list */
};

extern struct gprs_gmm_ctx *g_ctx;

/* GMM Entity: */
struct gprs_gmm_entity {
	struct llist_head list; /* item in (struct gprs_gmm_ctx)->gmme_list */
};

/* gmm_prim.c: */
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmm_gmmreg_attach_cnf(void);
int gprs_gmm_prim_call_up_cb(struct osmo_gprs_gmm_prim *gmm_prim);
int gprs_gmm_prim_call_down_cb(struct osmo_gprs_gmm_prim *gmm_prim);

/* gmm.c: */
struct gprs_gmm_entity *gprs_gmm_gmme_alloc(void);
void gprs_gmm_gmme_free(struct gprs_gmm_entity *gmme);

#define LOGGMME(snme, level, fmt, args...) \
	LOGGMM(level, "GMME(%08x) " fmt, \
		 23 /*TODO: use ID */, \
		 ## args)
