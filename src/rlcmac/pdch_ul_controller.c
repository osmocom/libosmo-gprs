/* pdch_ul_controller.c
 *
 * Copyright (C) 2021-2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <inttypes.h>
#include <unistd.h>
#include <talloc.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/linuxrbtree.h>
#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/gprs/rlcmac/pdch_ul_controller.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/rlcmac/types_private.h>

/* TS 44.060 Table 10.4.5.1 states maximum RRBP is N + 26. Give extra space for time diff between Tx and Rx? */
#define MAX_FN_RESERVED (27 + 50)

const struct value_string gprs_rlcmac_pdch_ulc_poll_reason_names[] = {
	{ GPRS_RLCMAC_PDCH_ULC_POLL_UL_ASS,		"UL_ASS" },
	{ GPRS_RLCMAC_PDCH_ULC_POLL_DL_ASS,		"DL_ASS" },
	{ GPRS_RLCMAC_PDCH_ULC_POLL_UL_ACK,		"UL_ACK" },
	{ GPRS_RLCMAC_PDCH_ULC_POLL_DL_ACK,		"DL_ACK" },
	{ GPRS_RLCMAC_PDCH_ULC_POLL_CELL_CHG_CONTINUE,	"CELL_CHG_CONTINUE" },
	{ 0, NULL }
};

#define GSM_MAX_FN_THRESH (GSM_MAX_FN >> 1)
/* 0: equal, -1: fn1 BEFORE fn2, 1: fn1 AFTER fn2 */
static inline int fn_cmp(uint32_t fn1, uint32_t fn2)
{
	if (fn1 == fn2)
		return 0;
	/* FN1 goes before FN2: */
	if ((fn1 < fn2 && (fn2 - fn1) < GSM_MAX_FN_THRESH) ||
	    (fn1 > fn2 && (fn1 - fn2) > GSM_MAX_FN_THRESH))
		return -1;
	/* FN1 goes after FN2: */
	return 1;
}

struct gprs_rlcmac_pdch_ulc *gprs_rlcmac_pdch_ulc_alloc(void *ctx, uint8_t ts_nr)
{
	struct gprs_rlcmac_pdch_ulc *ulc;
	ulc = talloc_zero(ctx, struct gprs_rlcmac_pdch_ulc);
	if (!ulc)
		return ulc;

	ulc->ts_nr = ts_nr;
	ulc->pool_ctx = talloc_pool(ulc, sizeof(struct gprs_rlcmac_pdch_ulc_node) * MAX_FN_RESERVED);
	return ulc;
}

struct gprs_rlcmac_pdch_ulc_node *gprs_rlcmac_pdch_ulc_get_node(struct gprs_rlcmac_pdch_ulc *ulc, uint32_t fn)
{
	OSMO_ASSERT(ulc);
	struct rb_node *node = ulc->tree_root.rb_node;
	struct gprs_rlcmac_pdch_ulc_node *it;
	int res;

	while (node) {
		it = rb_entry(node, struct gprs_rlcmac_pdch_ulc_node, node);
		res = fn_cmp(it->fn, fn);
		if (res > 0) /* it->fn AFTER fn */
			node = node->rb_left;
		else if (res < 0) /* it->fn BEFORE fn */
			node = node->rb_right;
		else /* it->fn == fn */
			return it;
	}
	return NULL;
}
struct gprs_rlcmac_pdch_ulc_node *gprs_rlcmac_pdch_ulc_pop_node(struct gprs_rlcmac_pdch_ulc *ulc, uint32_t fn)
{
	struct gprs_rlcmac_pdch_ulc_node *item = gprs_rlcmac_pdch_ulc_get_node(ulc, fn);
	if (!item)
		return NULL;
	rb_erase(&item->node, &ulc->tree_root);
	return item;
}

struct rrbp_opt {
	uint8_t offset;
	enum gprs_rlcmac_rrbp_field coding;
};

static struct gprs_rlcmac_pdch_ulc_node *_alloc_node(struct gprs_rlcmac_pdch_ulc *ulc, uint32_t fn)
{
	struct gprs_rlcmac_pdch_ulc_node *node;
	node = talloc_zero(ulc->pool_ctx, struct gprs_rlcmac_pdch_ulc_node);
	node->fn = fn;
	return node;
}

static int gprs_rlcmac_pdch_ulc_add_node(struct gprs_rlcmac_pdch_ulc *ulc, struct gprs_rlcmac_pdch_ulc_node *item)
{
	struct rb_node **n = &(ulc->tree_root.rb_node);
	struct rb_node *parent = NULL;

	while (*n) {
		struct gprs_rlcmac_pdch_ulc_node *it;
		int res;

		it = container_of(*n, struct gprs_rlcmac_pdch_ulc_node, node);

		parent = *n;
		res = fn_cmp(item->fn, it->fn);
		if (res < 0) { /* item->fn "BEFORE" it->fn */
			n = &((*n)->rb_left);
		} else if (res > 0) { /* item->fn "AFTER" it->fn */
			n = &((*n)->rb_right);
		} else {
			LOGRLCMAC(LOGL_ERROR, "TS=%" PRIu8 " Trying to reserve already reserved FN %u\n",
				  ulc->ts_nr, item->fn);
			return -EEXIST;
		}
	}

	rb_link_node(&item->node, parent, n);
	rb_insert_color(&item->node, &ulc->tree_root);
	return 0;
}

int gprs_rlcmac_pdch_ulc_reserve(struct gprs_rlcmac_pdch_ulc *ulc, uint32_t fn,
				 enum gprs_rlcmac_pdch_ulc_poll_reason reason,
				 struct gprs_rlcmac_tbf *tbf)
{
	struct gprs_rlcmac_pdch_ulc_node *item = _alloc_node(ulc, fn);
	item->reason = reason;
	item->tbf = tbf;
	LOGRLCMAC(LOGL_DEBUG, "Register POLL (TS=%u FN=%u, reason=%s)\n",
		  ulc->ts_nr, item->fn,
		  get_value_string(gprs_rlcmac_pdch_ulc_poll_reason_names, item->reason));
	return gprs_rlcmac_pdch_ulc_add_node(ulc, item);
}

void gprs_rlcmac_pdch_ulc_release_node(struct gprs_rlcmac_pdch_ulc *ulc, struct gprs_rlcmac_pdch_ulc_node *item)
{
	rb_erase(&item->node, &ulc->tree_root);
	talloc_free(item);
}

int gprs_rlcmac_pdch_ulc_release_fn(struct gprs_rlcmac_pdch_ulc *ulc, uint32_t fn)
{
	struct gprs_rlcmac_pdch_ulc_node *item = gprs_rlcmac_pdch_ulc_get_node(ulc, fn);
	if (!item)
		return -ENOKEY;
	gprs_rlcmac_pdch_ulc_release_node(ulc, item);
	return 0;
}

void gprs_rlcmac_pdch_ulc_release_tbf(struct gprs_rlcmac_pdch_ulc *ulc, const struct gprs_rlcmac_tbf *tbf)
{
	bool tree_modified;
	do {
		struct rb_node *node;
		struct gprs_rlcmac_pdch_ulc_node *item;

		tree_modified = false;
		for (node = rb_first(&ulc->tree_root); node; node = rb_next(node)) {
			item = container_of(node, struct gprs_rlcmac_pdch_ulc_node, node);
			if (item->tbf != tbf)
				continue;
			/* One entry found, remove it from tree and restart
			 * search from start (to avoid traverse continue from
			 * no-more existent node */
			tree_modified = true;
			gprs_rlcmac_pdch_ulc_release_node(ulc, item);
			break;
		}
	} while (tree_modified);
}

void gprs_rlcmac_pdch_ulc_expire_fn(struct gprs_rlcmac_pdch_ulc *ulc, uint32_t fn)
{
	struct gprs_rlcmac_pdch_ulc_node *item;
	int res;

	struct rb_node *first;
	while ((first = rb_first(&ulc->tree_root))) {
		item = container_of(first, struct gprs_rlcmac_pdch_ulc_node, node);
		res = fn_cmp(item->fn, fn);
		if (res > 0) /* item->fn AFTER fn */
			break;
		if (res < 0) { /* item->fn BEFORE fn */
			/* Sanity check: */
			LOGRLCMAC(LOGL_ERROR,
				"TS=%" PRIu8 " Expiring FN=%" PRIu32 " but previous FN=%" PRIu32 " is still reserved!\n",
				ulc->ts_nr, fn, item->fn);
		}
		rb_erase(&item->node, &ulc->tree_root);

		LOGRLCMAC(LOGL_NOTICE, "TS=%u Timeout for registered POLL (FN=%u, reason=%s)\n",
			  ulc->ts_nr, item->fn, get_value_string(gprs_rlcmac_pdch_ulc_poll_reason_names, item->reason));

		talloc_free(item);
	}
}
