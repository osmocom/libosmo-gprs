/* pdch_ul_controller.h
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
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/linuxrbtree.h>
#include <osmocom/core/utils.h>

struct gprs_rlcmac_dl_tbf;

struct gprs_rlcmac_pdch_ulc {
	uint8_t ts_nr;
	struct rb_root tree_root;
	void *pool_ctx; /* talloc pool of struct pdch_ulc_node  */
};


enum gprs_rlcmac_pdch_ulc_poll_reason {
	GPRS_RLCMAC_PDCH_ULC_POLL_UL_ASS, /* Tx CTRL ACK for received UL ASS */
	GPRS_RLCMAC_PDCH_ULC_POLL_DL_ASS, /* Tx CTRL ACK for received DL ASS */
	GPRS_RLCMAC_PDCH_ULC_POLL_UL_ACK, /* Tx CTRL ACK (or PKT RES REQ on final UL ACK/NACK) for received UL ACK/NACK */
	GPRS_RLCMAC_PDCH_ULC_POLL_DL_ACK, /* Tx DL ACK/NACK (or others 8.1.2.2) for received data block */
	GPRS_RLCMAC_PDCH_ULC_POLL_CELL_CHG_CONTINUE, /* Tx CTRL ACK for received Pkt cell Change Continue */
};
extern const struct value_string gprs_rlcmac_pdch_ulc_poll_reason_names[];

struct gprs_rlcmac_pdch_ulc_node {
	struct rb_node node;	/*! entry in gprs_rlcmac_pdch_ulc->tree_root */
	uint32_t fn;
	enum gprs_rlcmac_pdch_ulc_poll_reason reason;
	struct gprs_rlcmac_tbf *tbf;
};

struct gprs_rlcmac_pdch_ulc *gprs_rlcmac_pdch_ulc_alloc(void *ctx, uint8_t ts_nr);

int gprs_rlcmac_pdch_ulc_reserve(struct gprs_rlcmac_pdch_ulc *ulc, uint32_t fn, enum gprs_rlcmac_pdch_ulc_poll_reason reason, struct gprs_rlcmac_tbf *tbf);

struct gprs_rlcmac_pdch_ulc_node *gprs_rlcmac_pdch_ulc_get_node(struct gprs_rlcmac_pdch_ulc *ulc, uint32_t fn);
struct gprs_rlcmac_pdch_ulc_node *gprs_rlcmac_pdch_ulc_pop_node(struct gprs_rlcmac_pdch_ulc *ulc, uint32_t fn);

void gprs_rlcmac_pdch_ulc_release_node(struct gprs_rlcmac_pdch_ulc *ulc, struct gprs_rlcmac_pdch_ulc_node *item);
void gprs_rlcmac_pdch_ulc_release_tbf(struct gprs_rlcmac_pdch_ulc *ulc, const struct gprs_rlcmac_tbf *tbf);
int gprs_rlcmac_pdch_ulc_release_fn(struct gprs_rlcmac_pdch_ulc *ulc, uint32_t fn);

void gprs_rlcmac_pdch_ulc_expire_fn(struct gprs_rlcmac_pdch_ulc *ulc, uint32_t fn);
