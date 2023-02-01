/* coding_scheme.h
 *
 * Copyright (C) 2015-2023 by sysmocom s.f.m.c. GmbH
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

#include <osmocom/core/utils.h>

#include <stdbool.h>

enum gprs_rlcmac_coding_scheme {
	GPRS_RLCMAC_CS_UNKNOWN,
	/* GPRS Coding Schemes: */
	GPRS_RLCMAC_CS_1,
	GPRS_RLCMAC_CS_2,
	GPRS_RLCMAC_CS_3,
	GPRS_RLCMAC_CS_4,
	/* EDGE/EGPRS Modulation and Coding Schemes: */
	GPRS_RLCMAC_MCS_1,
	GPRS_RLCMAC_MCS_2,
	GPRS_RLCMAC_MCS_3,
	GPRS_RLCMAC_MCS_4,
	GPRS_RLCMAC_MCS_5,
	GPRS_RLCMAC_MCS_6,
	GPRS_RLCMAC_MCS_7,
	GPRS_RLCMAC_MCS_8,
	GPRS_RLCMAC_MCS_9,
	GPRS_RLCMAC_NUM_SCHEMES
};

enum gprs_rlcmac_coding_scheme_kind {
	GPRS_RLCMAC_SCHEME_GPRS,
	GPRS_RLCMAC_SCHEME_EGPRS_GMSK,
	GPRS_RLCMAC_SCHEME_EGPRS,
};

enum gprs_rlcmac_egprs_arq_type {
	GPRS_RLCMAC_EGPRS_ARQ1 = 0,
	GPRS_RLCMAC_EGPRS_ARQ2 = 1,
};

extern const struct value_string gprs_rlcmac_coding_scheme_names[];
const char *gprs_rlcmac_mcs_name(enum gprs_rlcmac_coding_scheme val);
enum gprs_rlcmac_coding_scheme gprs_rlcmac_get_retx_mcs(enum gprs_rlcmac_coding_scheme initial_mcs, enum gprs_rlcmac_coding_scheme commanded_mcs, bool resegment_bit);

bool gprs_rlcmac_mcs_is_gprs(enum gprs_rlcmac_coding_scheme cs);
bool gprs_rlcmac_mcs_is_edge(enum gprs_rlcmac_coding_scheme cs);
bool gprs_rlcmac_mcs_is_edge_gmsk(enum gprs_rlcmac_coding_scheme cs);

uint8_t gprs_rlcmac_mcs_chan_code(enum gprs_rlcmac_coding_scheme cs);

enum gprs_rlcmac_coding_scheme gprs_rlcmac_mcs_get_by_size_ul(unsigned size);
enum gprs_rlcmac_coding_scheme gprs_rlcmac_mcs_get_gprs_by_num(unsigned num);
enum gprs_rlcmac_coding_scheme gprs_rlcmac_mcs_get_egprs_by_num(unsigned num);
bool gprs_rlcmac_mcs_is_valid(enum gprs_rlcmac_coding_scheme cs);
bool gprs_rlcmac_mcs_is_compat(enum gprs_rlcmac_coding_scheme cs, enum gprs_rlcmac_coding_scheme o);
bool gprs_rlcmac_mcs_is_compat_kind(enum gprs_rlcmac_coding_scheme cs, enum gprs_rlcmac_coding_scheme_kind mode);

uint8_t gprs_rlcmac_mcs_size_ul(enum gprs_rlcmac_coding_scheme cs);
uint8_t gprs_rlcmac_mcs_size_dl(enum gprs_rlcmac_coding_scheme cs);
uint8_t gprs_rlcmac_mcs_used_size_ul(enum gprs_rlcmac_coding_scheme cs);
uint8_t gprs_rlcmac_mcs_used_size_dl(enum gprs_rlcmac_coding_scheme cs);
uint8_t gprs_rlcmac_mcs_max_bytes_ul(enum gprs_rlcmac_coding_scheme cs);
uint8_t gprs_rlcmac_mcs_max_bytes_dl(enum gprs_rlcmac_coding_scheme cs);
uint8_t gprs_rlcmac_mcs_spare_bits_ul(enum gprs_rlcmac_coding_scheme cs);
uint8_t gprs_rlcmac_mcs_spare_bits_dl(enum gprs_rlcmac_coding_scheme cs);
uint8_t gprs_rlcmac_mcs_max_data_block_bytes(enum gprs_rlcmac_coding_scheme cs);
uint8_t gprs_rlcmac_mcs_opt_padding_bits(enum gprs_rlcmac_coding_scheme cs);

void gprs_rlcmac_mcs_inc_kind(enum gprs_rlcmac_coding_scheme *cs, enum gprs_rlcmac_coding_scheme_kind mode);
void gprs_rlcmac_mcs_dec_kind(enum gprs_rlcmac_coding_scheme *cs, enum gprs_rlcmac_coding_scheme_kind mode);
void gprs_rlcmac_mcs_inc(enum gprs_rlcmac_coding_scheme *cs);
void gprs_rlcmac_mcs_dec(enum gprs_rlcmac_coding_scheme *cs);

bool gprs_rlcmac_mcs_is_family_compat(enum gprs_rlcmac_coding_scheme cs, enum gprs_rlcmac_coding_scheme o);
void gprs_rlcmac_mcs_dec_to_single_block(enum gprs_rlcmac_coding_scheme *cs, bool *need_stuffing);

enum gprs_rlcmac_header_type {
	GPRS_RLCMAC_HEADER_INVALID,
	GPRS_RLCMAC_HEADER_GPRS_CONTROL,
	GPRS_RLCMAC_HEADER_GPRS_DATA,
	GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_1,
	GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_2,
	GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_3,
	GPRS_RLCMAC_NUM_HEADER_TYPES
};

enum gprs_rlcmac_header_type gprs_rlcmac_mcs_header_type(enum gprs_rlcmac_coding_scheme mcs);

uint8_t gprs_rlcmac_num_data_blocks(enum gprs_rlcmac_header_type ht);
uint8_t gprs_rlcmac_num_data_header_bits_UL(enum gprs_rlcmac_header_type ht);
uint8_t gprs_rlcmac_num_data_header_bits_DL(enum gprs_rlcmac_header_type ht);
uint8_t gprs_rlcmac_num_data_block_header_bits(enum gprs_rlcmac_header_type ht);

const char *gprs_rlcmac_msc_kind_name(enum gprs_rlcmac_coding_scheme_kind val);
