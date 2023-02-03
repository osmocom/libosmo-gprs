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
	struct {
		enum osmo_gprs_rlcmac_location location;
		struct {
			bool use;
			uint32_t interval_msec;
		} codel;
	} cfg;
	osmo_gprs_rlcmac_prim_up_cb rlcmac_up_cb;
	void *rlcmac_up_cb_user_data;

	osmo_gprs_rlcmac_prim_down_cb rlcmac_down_cb;
	void *rlcmac_down_cb_user_data;

	struct llist_head gre_list; /* contains (struct gprs_rlcmac_entity)->entry */
};

extern struct gprs_rlcmac_ctx *g_ctx;

/* rlcmac.c */
struct gprs_rlcmac_entity *gprs_rlcmac_find_entity_by_tlli(uint32_t tlli);

/* rlcmac_prim.c */
int gprs_rlcmac_prim_call_up_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim);
int gprs_rlcmac_prim_call_down_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim);

struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_grr_unitdata_ind(
				uint32_t tlli, uint8_t *ll_pdu, size_t ll_pdu_len);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_gmmrr_page_ind(uint32_t tlli);

struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_rach8_req(uint8_t ra);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_rach11_req(uint16_t ra11, uint8_t synch_seq);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_pdch_data_req(uint8_t ts_nr, uint32_t fn,
									uint8_t *data, uint8_t data_len);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_cfg_dl_tbf_req(uint8_t dl_tbf_nr, uint8_t dl_slotmask, uint8_t dl_tfi);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_cfg_ul_tbf_req(uint8_t ul_tbf_nr, uint8_t ul_slotmask);
