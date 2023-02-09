/* coding_scheme.c
 *
 * Copyright (C) 2019-2023 by sysmocom s.f.m.c. GmbH
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

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/utils.h>

#include <osmocom/gprs/rlcmac/coding_scheme.h>

const struct value_string gprs_rlcmac_coding_scheme_names[] = {
	{ GPRS_RLCMAC_CS_UNKNOWN, "UNKNOWN" },
	{ GPRS_RLCMAC_CS_1, "CS-1" },
	{ GPRS_RLCMAC_CS_2, "CS-2" },
	{ GPRS_RLCMAC_CS_3, "CS-3" },
	{ GPRS_RLCMAC_CS_4, "CS-4" },
	{ GPRS_RLCMAC_MCS_1, "MCS-1" },
	{ GPRS_RLCMAC_MCS_2, "MCS-2" },
	{ GPRS_RLCMAC_MCS_3, "MCS-3" },
	{ GPRS_RLCMAC_MCS_4, "MCS-4" },
	{ GPRS_RLCMAC_MCS_5, "MCS-5" },
	{ GPRS_RLCMAC_MCS_6, "MCS-6" },
	{ GPRS_RLCMAC_MCS_7, "MCS-7" },
	{ GPRS_RLCMAC_MCS_8, "MCS-8" },
	{ GPRS_RLCMAC_MCS_9, "MCS-9" },
	{ 0, NULL }
};

enum gprs_rlcmac_family {
	FAMILY_INVALID,
	FAMILY_A,
	FAMILY_B,
	FAMILY_C,
};

const static struct {
	struct {
		uint8_t bytes;
		uint8_t ext_bits;
		uint8_t data_header_bits;
	} uplink, downlink;
	uint8_t data_bytes;
	uint8_t optional_padding_bits;
	enum gprs_rlcmac_header_type data_hdr;
	enum gprs_rlcmac_family family;
} mcs_info[GPRS_RLCMAC_NUM_SCHEMES] = {
	{{0, 0},   {0, 0},    0,  0,
		GPRS_RLCMAC_HEADER_INVALID, FAMILY_INVALID},
	{{23, 0},  {23, 0},  20,  0,
		GPRS_RLCMAC_HEADER_GPRS_DATA, FAMILY_INVALID},
	{{33, 7},  {33, 7},  30,  0,
		GPRS_RLCMAC_HEADER_GPRS_DATA, FAMILY_INVALID},
	{{39, 3},  {39, 3},  36,  0,
		GPRS_RLCMAC_HEADER_GPRS_DATA, FAMILY_INVALID},
	{{53, 7},  {53, 7},  50,  0,
		GPRS_RLCMAC_HEADER_GPRS_DATA, FAMILY_INVALID},

	{{26, 1},  {26, 1},  22,  0,
		GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_3, FAMILY_C},
	{{32, 1},  {32, 1},  28,  0,
		GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_3, FAMILY_B},
	{{41, 1},  {41, 1},  37, 48,
		GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_3, FAMILY_A},
	{{48, 1},  {48, 1},  44,  0,
		GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_3, FAMILY_C},

	{{60, 7},  {59, 6},  56,  0,
		GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_2, FAMILY_B},
	{{78, 7},  {77, 6},  74, 48,
		GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_2, FAMILY_A},
	{{118, 2}, {117, 4}, 56,  0,
		GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_1, FAMILY_B},
	{{142, 2}, {141, 4}, 68,  0,
		GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_1, FAMILY_A},
	{{154, 2}, {153, 4}, 74,  0,
		GPRS_RLCMAC_HEADER_EGPRS_DATA_TYPE_1, FAMILY_A},
};

const char *gprs_rlcmac_mcs_name(enum gprs_rlcmac_coding_scheme val)
{
	return get_value_string(gprs_rlcmac_coding_scheme_names, val);
}

bool gprs_rlcmac_mcs_is_gprs(enum gprs_rlcmac_coding_scheme cs)
{
	return GPRS_RLCMAC_CS_1 <= cs && cs <= GPRS_RLCMAC_CS_4;
}

bool gprs_rlcmac_mcs_is_edge(enum gprs_rlcmac_coding_scheme cs)
{
	return GPRS_RLCMAC_MCS_1 <= cs && cs <= GPRS_RLCMAC_MCS_9;
}

bool gprs_rlcmac_mcs_is_edge_gmsk(enum gprs_rlcmac_coding_scheme cs)
{
	if (gprs_rlcmac_mcs_is_edge(cs))
		return cs <= GPRS_RLCMAC_MCS_4;

	return false;
}

/* Return 3GPP TS 44.060 §12.10d (EDGE) or Table 11.2.28.2 (GPRS) Channel Coding Command value */
uint8_t gprs_rlcmac_mcs_chan_code(enum gprs_rlcmac_coding_scheme cs)
{
	if (gprs_rlcmac_mcs_is_gprs(cs))
		return cs - GPRS_RLCMAC_CS_1;

	if (gprs_rlcmac_mcs_is_edge(cs))
		return cs - GPRS_RLCMAC_MCS_1;

	/* Defaults to (M)GPRS_RLCMAC_CS_1 */
	return 0;
}

enum gprs_rlcmac_coding_scheme gprs_rlcmac_mcs_get_by_size_ul(unsigned size)
{
	switch (size) {
	case 23: return GPRS_RLCMAC_CS_1;
	case 27: return GPRS_RLCMAC_MCS_1;
	case 33: return GPRS_RLCMAC_MCS_2;
	case 34: return GPRS_RLCMAC_CS_2;
	case 40: return GPRS_RLCMAC_CS_3;
	case 42: return GPRS_RLCMAC_MCS_3;
	case 49: return GPRS_RLCMAC_MCS_4;
	case 54: return GPRS_RLCMAC_CS_4;
	case 61: return GPRS_RLCMAC_MCS_5;
	case 79: return GPRS_RLCMAC_MCS_6;
	case 119: return GPRS_RLCMAC_MCS_7;
	case 143: return GPRS_RLCMAC_MCS_8;
	case 155: return GPRS_RLCMAC_MCS_9;
	default: return GPRS_RLCMAC_CS_UNKNOWN;
	}
}

/* Same as UL. Sizes only change in EGPRS2 blocks, which we don't support */
enum gprs_rlcmac_coding_scheme gprs_rlcmac_mcs_get_by_size_dl(unsigned size)
{
	switch (size) {
	case 23: return GPRS_RLCMAC_CS_1;
	case 27: return GPRS_RLCMAC_MCS_1;
	case 33: return GPRS_RLCMAC_MCS_2;
	case 34: return GPRS_RLCMAC_CS_2;
	case 40: return GPRS_RLCMAC_CS_3;
	case 42: return GPRS_RLCMAC_MCS_3;
	case 49: return GPRS_RLCMAC_MCS_4;
	case 54: return GPRS_RLCMAC_CS_4;
	case 61: return GPRS_RLCMAC_MCS_5;
	case 79: return GPRS_RLCMAC_MCS_6;
	case 119: return GPRS_RLCMAC_MCS_7;
	case 143: return GPRS_RLCMAC_MCS_8;
	case 155: return GPRS_RLCMAC_MCS_9;
	default: return GPRS_RLCMAC_CS_UNKNOWN;
	}
}

enum gprs_rlcmac_coding_scheme gprs_rlcmac_mcs_get_gprs_by_num(unsigned num)
{
	if (num < 1 || num > 4)
		return GPRS_RLCMAC_CS_UNKNOWN;
	return GPRS_RLCMAC_CS_1 + (num - 1);
}

enum gprs_rlcmac_coding_scheme gprs_rlcmac_mcs_get_egprs_by_num(unsigned num)
{
	if (num < 1 || num > 9)
		return GPRS_RLCMAC_CS_UNKNOWN;
	return GPRS_RLCMAC_MCS_1 + (num - 1);
}

bool gprs_rlcmac_mcs_is_valid(enum gprs_rlcmac_coding_scheme cs)
{
	return GPRS_RLCMAC_CS_UNKNOWN < cs && cs <= GPRS_RLCMAC_MCS_9;
}

bool gprs_rlcmac_mcs_is_compat_kind(enum gprs_rlcmac_coding_scheme cs, enum gprs_rlcmac_coding_scheme_kind mode)
{
	switch (mode) {
	case GPRS_RLCMAC_SCHEME_GPRS: return gprs_rlcmac_mcs_is_gprs(cs);
	case GPRS_RLCMAC_SCHEME_EGPRS_GMSK: return gprs_rlcmac_mcs_is_edge_gmsk(cs);
	case GPRS_RLCMAC_SCHEME_EGPRS: return gprs_rlcmac_mcs_is_edge(cs);
	}

	return false;
}

bool gprs_rlcmac_mcs_is_compat(enum gprs_rlcmac_coding_scheme cs, enum gprs_rlcmac_coding_scheme o)
{
	return (gprs_rlcmac_mcs_is_gprs(cs) && gprs_rlcmac_mcs_is_gprs(o)) ||
		(gprs_rlcmac_mcs_is_edge(cs) && gprs_rlcmac_mcs_is_edge(o));
}

uint8_t gprs_rlcmac_mcs_size_ul(enum gprs_rlcmac_coding_scheme cs)
{
	return mcs_info[cs].uplink.bytes + (gprs_rlcmac_mcs_spare_bits_ul(cs) ? 1 : 0);
}

uint8_t gprs_rlcmac_mcs_size_dl(enum gprs_rlcmac_coding_scheme cs)
{
	return mcs_info[cs].downlink.bytes + (gprs_rlcmac_mcs_spare_bits_dl(cs) ? 1 : 0);
}

uint8_t gprs_rlcmac_mcs_used_size_ul(enum gprs_rlcmac_coding_scheme cs)
{
	if (mcs_info[cs].data_hdr == GPRS_RLCMAC_HEADER_GPRS_DATA)
		return mcs_info[cs].uplink.bytes;
	else
		return gprs_rlcmac_mcs_size_ul(cs);
}

uint8_t gprs_rlcmac_mcs_used_size_dl(enum gprs_rlcmac_coding_scheme cs)
{
	if (mcs_info[cs].data_hdr == GPRS_RLCMAC_HEADER_GPRS_DATA)
		return mcs_info[cs].downlink.bytes;
	else
		return gprs_rlcmac_mcs_size_dl(cs);
}

uint8_t gprs_rlcmac_mcs_max_bytes_ul(enum gprs_rlcmac_coding_scheme cs)
{
	return mcs_info[cs].uplink.bytes;
}

uint8_t gprs_rlcmac_mcs_max_bytes_dl(enum gprs_rlcmac_coding_scheme cs)
{
	return mcs_info[cs].downlink.bytes;
}

uint8_t gprs_rlcmac_mcs_spare_bits_ul(enum gprs_rlcmac_coding_scheme cs)
{
	return mcs_info[cs].uplink.ext_bits;
}

uint8_t gprs_rlcmac_mcs_spare_bits_dl(enum gprs_rlcmac_coding_scheme cs)
{
	return mcs_info[cs].downlink.ext_bits;
}

uint8_t gprs_rlcmac_mcs_max_data_block_bytes(enum gprs_rlcmac_coding_scheme cs)
{
	return mcs_info[cs].data_bytes;
}

uint8_t gprs_rlcmac_mcs_opt_padding_bits(enum gprs_rlcmac_coding_scheme cs)
{
	return mcs_info[cs].optional_padding_bits;
}

void gprs_rlcmac_mcs_inc_kind(enum gprs_rlcmac_coding_scheme *cs, enum gprs_rlcmac_coding_scheme_kind mode)
{
	if (!gprs_rlcmac_mcs_is_compat_kind(*cs, mode))
		/* This should not happen. TODO: Use assert? */
		return;

	enum gprs_rlcmac_coding_scheme new_cs = *cs + 1;
	if (!gprs_rlcmac_mcs_is_compat_kind(new_cs, mode))
		/* Clipping, do not change the value */
		return;

	*cs = new_cs;
}

void gprs_rlcmac_mcs_dec_kind(enum gprs_rlcmac_coding_scheme *cs, enum gprs_rlcmac_coding_scheme_kind mode)
{
	if (!gprs_rlcmac_mcs_is_compat_kind(*cs, mode))
		/* This should not happen. TODO: Use assert? */
		return;

	enum gprs_rlcmac_coding_scheme new_cs = *cs - 1;
	if (!gprs_rlcmac_mcs_is_compat_kind(new_cs, mode))
		/* Clipping, do not change the value */
		return;

	*cs = new_cs;
}

void gprs_rlcmac_mcs_inc(enum gprs_rlcmac_coding_scheme *cs)
{
	if (gprs_rlcmac_mcs_is_gprs(*cs) && *cs == GPRS_RLCMAC_CS_4)
		return;

	if (gprs_rlcmac_mcs_is_edge(*cs) && *cs == GPRS_RLCMAC_MCS_9)
		return;

	if (!gprs_rlcmac_mcs_is_valid(*cs))
		return;

	*cs = *cs + 1;
}

void gprs_rlcmac_mcs_dec(enum gprs_rlcmac_coding_scheme *cs)
{
	if (gprs_rlcmac_mcs_is_gprs(*cs) && *cs == GPRS_RLCMAC_CS_1)
		return;

	if (gprs_rlcmac_mcs_is_edge(*cs) && *cs == GPRS_RLCMAC_MCS_1)
		return;

	if (!gprs_rlcmac_mcs_is_valid(*cs))
		return;

	*cs = *cs - 1;
}

bool gprs_rlcmac_mcs_is_family_compat(enum gprs_rlcmac_coding_scheme cs, enum gprs_rlcmac_coding_scheme o)
{
	if (cs == o)
		return true;

	if (mcs_info[cs].family == FAMILY_INVALID)
		return false;

	return mcs_info[cs].family == mcs_info[o].family;
}

void gprs_rlcmac_mcs_dec_to_single_block(enum gprs_rlcmac_coding_scheme *cs, bool *need_stuffing)
{
	switch (*cs) {
	case GPRS_RLCMAC_MCS_7:
		*need_stuffing = false;
		*cs = GPRS_RLCMAC_MCS_5;
		break;
	case GPRS_RLCMAC_MCS_8:
		*need_stuffing = true;
		*cs = GPRS_RLCMAC_MCS_6;
		break;
	case GPRS_RLCMAC_MCS_9:
		*need_stuffing = false;
		*cs = GPRS_RLCMAC_MCS_6;
		break;
	default:
		*need_stuffing = false;
		break;
	}
}

static struct {
	struct {
		uint8_t data_header_bits;
	} uplink, downlink;
	uint8_t data_block_header_bits;
	uint8_t num_blocks;
	const char *name;
} hdr_type_info[GPRS_RLCMAC_NUM_HEADER_TYPES] = {
	{ { 0 },         { 0 },         0, 0, "INVALID" },
	{ { 1 * 8 + 0 }, { 1 * 8 + 0 }, 0, 0, "CONTROL" },
	{ { 3 * 8 + 0 }, { 3 * 8 + 0 }, 0, 1, "GPRS_DATA" },
	{ { 5 * 8 + 6 }, { 5 * 8 + 0 }, 2, 2, "EGPRS_DATA_TYPE1" },
	{ { 4 * 8 + 5 }, { 3 * 8 + 4 }, 2, 1, "EGPRS_DATA_TYPE2" },
	{ { 3 * 8 + 7 }, { 3 * 8 + 7 }, 2, 1, "EGPRS_DATA_TYPE3" },
};

enum gprs_rlcmac_header_type gprs_rlcmac_mcs_header_type(enum gprs_rlcmac_coding_scheme mcs)
{
	return mcs_info[mcs].data_hdr;
}

uint8_t gprs_rlcmac_num_data_blocks(enum gprs_rlcmac_header_type ht)
{
	OSMO_ASSERT(ht < GPRS_RLCMAC_NUM_HEADER_TYPES);
	return hdr_type_info[ht].num_blocks;
}

uint8_t gprs_rlcmac_num_data_header_bits_UL(enum gprs_rlcmac_header_type ht)
{
	OSMO_ASSERT(ht < GPRS_RLCMAC_NUM_HEADER_TYPES);
	return hdr_type_info[ht].uplink.data_header_bits;
}

uint8_t gprs_rlcmac_num_data_header_bits_DL(enum gprs_rlcmac_header_type ht)
{
	OSMO_ASSERT(ht < GPRS_RLCMAC_NUM_HEADER_TYPES);
	return hdr_type_info[ht].downlink.data_header_bits;
}

uint8_t gprs_rlcmac_num_data_block_header_bits(enum gprs_rlcmac_header_type ht)
{
	OSMO_ASSERT(ht < GPRS_RLCMAC_NUM_HEADER_TYPES);
	return hdr_type_info[ht].data_block_header_bits;
}

static const struct value_string gprs_rlcmac_mcs_kind_names[] = {
	{ GPRS_RLCMAC_SCHEME_GPRS, "GPRS" },
	{ GPRS_RLCMAC_SCHEME_EGPRS_GMSK, "EGPRS_GMSK-only"},
	{ GPRS_RLCMAC_SCHEME_EGPRS, "EGPRS"},
	{ 0, NULL }
};

const char *gprs_rlcmac_msc_kind_name(enum gprs_rlcmac_coding_scheme_kind val)
{
	return get_value_string(gprs_rlcmac_mcs_kind_names, val);
}

/* FIXME: take into account padding and special cases of commanded MCS (MCS-6-9 and MCS-5-7) */
enum gprs_rlcmac_coding_scheme gprs_rlcmac_get_retx_mcs(enum gprs_rlcmac_coding_scheme initial_mcs, enum gprs_rlcmac_coding_scheme commanded_mcs, bool resegment_bit)
{
	OSMO_ASSERT(gprs_rlcmac_mcs_is_edge(initial_mcs));
	OSMO_ASSERT(gprs_rlcmac_mcs_is_edge(commanded_mcs));
	OSMO_ASSERT(GPRS_RLCMAC_NUM_SCHEMES - GPRS_RLCMAC_MCS_1 == 9);

	if (resegment_bit) { /* 3GPP TS 44.060 Table 8.1.1.1, reflected over antidiagonal */
		enum gprs_rlcmac_coding_scheme egprs_reseg[GPRS_RLCMAC_NUM_SCHEMES - GPRS_RLCMAC_MCS_1][GPRS_RLCMAC_NUM_SCHEMES - GPRS_RLCMAC_MCS_1] = {
			{ GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1 },
			{ GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2 },
			{ GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3 },
			{ GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4 },
			{ GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_7, GPRS_RLCMAC_MCS_7, GPRS_RLCMAC_MCS_7 },
			{ GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_9 },
			{ GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_7, GPRS_RLCMAC_MCS_7, GPRS_RLCMAC_MCS_7 },
			{ GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_8, GPRS_RLCMAC_MCS_8 },
			{ GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_9 },
		};
		return egprs_reseg[gprs_rlcmac_mcs_chan_code(initial_mcs)][gprs_rlcmac_mcs_chan_code(commanded_mcs)];
	}
	/* else: 3GPP TS 44.060 Table 8.1.1.2, reflected over antidiagonal */
	enum gprs_rlcmac_coding_scheme egprs_no_reseg[GPRS_RLCMAC_NUM_SCHEMES - GPRS_RLCMAC_MCS_1][GPRS_RLCMAC_NUM_SCHEMES - GPRS_RLCMAC_MCS_1] = {
		{ GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1, GPRS_RLCMAC_MCS_1 },
		{ GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2, GPRS_RLCMAC_MCS_2 },
		{ GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3, GPRS_RLCMAC_MCS_3 },
		{ GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4, GPRS_RLCMAC_MCS_4 },
		{ GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_7, GPRS_RLCMAC_MCS_7, GPRS_RLCMAC_MCS_7 },
		{ GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_9 },
		{ GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_5, GPRS_RLCMAC_MCS_7, GPRS_RLCMAC_MCS_7, GPRS_RLCMAC_MCS_7 },
		{ GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_8, GPRS_RLCMAC_MCS_8 },
		{ GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_6, GPRS_RLCMAC_MCS_9 },
	};
	return egprs_no_reseg[gprs_rlcmac_mcs_chan_code(initial_mcs)][gprs_rlcmac_mcs_chan_code(commanded_mcs)];
}
