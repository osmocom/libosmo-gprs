/* RLCMACTest.c
 *
 * Copyright (C) 2011 Ivan Klyuchnikov
 * Contributions by sysmocom - s.f.m.c. GmbH
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

#include <osmocom/csn1/csn1.h>
#include <osmocom/gprs/rlcmac/gprs_rlcmac.h>

static void *tall_ctx = NULL;

static void test_si13ro(void)
{
	printf("*** %s ***\n", __func__);

	static const char *testData[] = {
		"9000185a6fc9f2b5304208eb2b2b2b2b2b2b2b2b", // osmo-pcu, with EGPRS
		"a000185a6fc9f14608411b2b2b2b2b2b2b2b2b2b", // osmo-pcu, without EGPRS
		"90005847eb4a93e51a218a16ab2b2b2b2b2b2b2b", // real network (Iran, Tehran)
		"90005847eb4a93e50a218a162b2b2b2b2b2b2b2b", // real network (Turkey, Istanbul)
		"b0005840654a92b53c2942db2b2b2b2b2b2b2b2b", // real network (Turkey, Trabzon)
	};

	for (unsigned int i = 0; i < ARRAY_SIZE(testData); i++) {
		uint8_t buf[20]; /* GSM_MACBLOCK_LEN - 3 */
		SI_13_t si13ro = { 0 };
		int rc;

		printf("testData[%d] = %s\n", i, testData[i]);

		rc = osmo_hexparse(testData[i], &buf[0], sizeof(buf));
		OSMO_ASSERT(rc == sizeof(buf));

		rc = osmo_gprs_rlcmac_decode_si13ro(&si13ro, &buf[0], sizeof(buf));
		printf("osmo_gprs_rlcmac_decode_si13ro() returns %d\n", rc);
	}
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
	log_parse_category_mask(osmo_stderr_target, "DLGLOBAL,1:DLCSN1,1:");

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	test_si13ro();

	talloc_free(tall_ctx);
}
