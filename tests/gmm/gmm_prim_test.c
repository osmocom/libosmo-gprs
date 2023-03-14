/* gmm_prim tests
 *
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau espin Pedrol <pespin@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <stdio.h>

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gprs/gmm/gmm.h>
#include <osmocom/gprs/gmm/gmm_prim.h>

static void *tall_ctx = NULL;

int test_gmm_prim_up_cb(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_gmm_prim_name(gmm_prim);

	switch (gmm_prim->oph.sap) {
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

int test_gmm_prim_down_cb(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_gmm_prim_name(gmm_prim);

	switch (gmm_prim->oph.sap) {
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

static void test_gmm_prim_ms(void)
{
	//struct osmo_gprs_gmm_prim *gmm_prim;
	int rc;

	printf("==== %s() [start] ====\n", __func__);

	rc = osmo_gprs_gmm_init(OSMO_GPRS_GMM_LOCATION_MS);
	OSMO_ASSERT(rc == 0);

	osmo_gprs_gmm_prim_set_up_cb(test_gmm_prim_up_cb, NULL);
	osmo_gprs_gmm_prim_set_down_cb(test_gmm_prim_down_cb, NULL);

	//gmm_prim = osmo_gprs_gmm_prim_alloc_gmmreg_attach_req();
	//OSMO_ASSERT(gmm_prim);
	//rc = osmo_gprs_gmm_prim_upper_down(gmm_prim);
	//OSMO_ASSERT(rc == 0);

	printf("==== %s() [end] ====\n", __func__);
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

	test_gmm_prim_ms();

	talloc_free(tall_ctx);
}
