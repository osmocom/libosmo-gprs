/* LLC stack miscellaneous tests
 *
 * (C) 2011 Holger Hans Peter Freyther <holger@moiji-mobile.com>
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/gprs/llc/llc.h>
#include <osmocom/gprs/llc/llc_private.h>

static void *tall_ctx = NULL;

#define ASSERT_FALSE(x) do if (x)  { printf("Should have returned false.\n"); abort(); } while (0)
#define ASSERT_TRUE(x)  do if (!x) { printf("Should have returned true.\n"); abort(); } while (0)

/**
 * GSM 04.64 8.4.2 Receipt of unacknowledged information
 */
static int nu_is_retransmission(uint16_t nu, uint16_t vur)
{
	int ret = gprs_llc_is_retransmit(nu, vur);
	printf("N(U) = %d, V(UR) = %d => %s\n", nu, vur,
	       ret == 1 ? "retransmit" : "new");
	return ret;
}

static void test_8_4_2(void)
{
	printf("Testing gprs_llc_is_retransmit.\n");

	ASSERT_FALSE(nu_is_retransmission(0, 0));
	ASSERT_TRUE(nu_is_retransmission(0, 1));

	/* expect 1... check for retransmissions */
	ASSERT_TRUE(nu_is_retransmission(0, 1));
	ASSERT_TRUE(nu_is_retransmission(511, 1));
	ASSERT_TRUE(nu_is_retransmission(483, 1));
	ASSERT_TRUE(nu_is_retransmission(482, 1));
	ASSERT_FALSE(nu_is_retransmission(481, 1));

	/* expect 511... check for retransmissions */
	ASSERT_FALSE(nu_is_retransmission(0, 240)); // ahead
	ASSERT_FALSE(nu_is_retransmission(0, 511)); // ahead
	ASSERT_FALSE(nu_is_retransmission(1, 511)); // ahead
	ASSERT_FALSE(nu_is_retransmission(511, 511)); // same
	ASSERT_TRUE(nu_is_retransmission(510, 511)); // behind
	ASSERT_TRUE(nu_is_retransmission(481, 511)); // behind
	ASSERT_FALSE(nu_is_retransmission(479, 511)); // wrapped
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

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	test_8_4_2();

	talloc_free(tall_ctx);
}
