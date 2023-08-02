/* rlcmac_types_test.c
 *
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#include <stdio.h>

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/select.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48_rest_octets.h>

#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/rlcmac_dec.h>

static void *tall_ctx = NULL;


/* SGSN->PCU->BTS --PCH--> MS containing "Paging Request Type 1" asking for PS services.
 * RLCMAC will send GMMRR-PAGE.ind to GMM layer, which is in charge of orchestrating the response. */
static void test_tbf_starting_time_to_fn(const uint32_t cur_fn, const uint32_t fn)
{
	const uint16_t rfn = gsm_fn2rfn(fn);
	StartingTime_t st;

	printf("=== %s(cur_fn=%u, fn=%u) start ===\n", __func__, cur_fn, fn);

	/* TBF_STARTING_TIME -- same as 3GPP TS 44.018 §10.5.2.38 Starting Time without tag: */
	st.N32 = (rfn / (26 * 51)) % 32;
	st.N51 = rfn % 51;
	st.N26 = rfn % 26;

	printf("cur_fn=%u fn=%u rfn=%u [T1'=%u T3=%u T2=%u]\n",
	       cur_fn, fn, rfn, st.N32, st.N51, st.N26);

	uint32_t res_fn = TBF_StartingTime_to_fn(&st, cur_fn);
	printf("res_fn=%u\n", res_fn);
	OSMO_ASSERT(res_fn == fn);

	printf("=== %s(cur_fn=%u, fn=%u) end ===\n", __func__, cur_fn, fn);
}

static const struct log_info_cat test_log_categories[] = { };
static const struct log_info test_log_info = {
	.cat = test_log_categories,
	.num_cat = ARRAY_SIZE(test_log_categories),
};

int main(int argc, char *argv[])
{
	tall_ctx = talloc_named_const(NULL, 1, __FILE__);

	osmo_init_logging2(tall_ctx, &test_log_info);
	log_parse_category_mask(osmo_stderr_target, "DLGLOBAL,1:");
	osmo_fsm_log_addr(false);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	test_tbf_starting_time_to_fn(0, 0);
	test_tbf_starting_time_to_fn(0, 4);
	test_tbf_starting_time_to_fn(4953, 4961);
	test_tbf_starting_time_to_fn(2229729, 2229786);
	test_tbf_starting_time_to_fn(2229777, 2229786);
	test_tbf_starting_time_to_fn(1320458, 1320462);

	talloc_free(tall_ctx);
}
