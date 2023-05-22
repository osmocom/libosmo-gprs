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
#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/gprs/gmm/gmm_private.h>

static void *tall_ctx = NULL;

/* Test: TS 24.008 10.5.7.3 GPRS Timer */
static void test_gprs_timer_enc_dec(void)
{
	int i, u, secs, tmr;
	const int upper_secs_test_limit = 12000;
	int dec_secs, last_dec_secs = -1;

	printf("==== %s() [start] ====\n", __func__);

	/* Check gprs_gmm_gprs_tmr_to_secs() with all 256 encoded values */
	for (u = 0; u <= GPRS_TMR_DEACTIVATED; u += 32) {
		fprintf(stderr, "Testing decoding with timer value unit %u\n",
			u / 32);
		for (i = 0; i < 32; i++) {
			switch (u) {
			case GPRS_TMR_2SECONDS:
				OSMO_ASSERT(gprs_gmm_gprs_tmr_to_secs(u + i) == 2 * i);
				break;

			default:
			case GPRS_TMR_MINUTE:
				OSMO_ASSERT(gprs_gmm_gprs_tmr_to_secs(u + i) == 60 * i);
				break;

			case GPRS_TMR_6MINUTE:
				OSMO_ASSERT(gprs_gmm_gprs_tmr_to_secs(u + i) == 360 * i);
				break;

			case GPRS_TMR_DEACTIVATED:
				OSMO_ASSERT(gprs_gmm_gprs_tmr_to_secs(u + i) == -1);
				break;
			}

			OSMO_ASSERT(gprs_gmm_gprs_tmr_to_secs(u + i) < upper_secs_test_limit);
		}
	}

	/* Check gprs_secs_to_tmr_floor for secs that can exactly be
	 * represented as GPRS timer values */
	for (i = 0; i < GPRS_TMR_DEACTIVATED; i++) {
		int j;
		secs = gprs_gmm_gprs_tmr_to_secs(i);
		tmr = gprs_gmm_secs_to_gprs_tmr_floor(secs);
		OSMO_ASSERT(secs == gprs_gmm_gprs_tmr_to_secs(tmr));

		/* Check that the highest resolution is used */
		for (j = 0; j < tmr; j++)
			OSMO_ASSERT(secs != gprs_gmm_gprs_tmr_to_secs(j));
	}
	OSMO_ASSERT(GPRS_TMR_DEACTIVATED == gprs_gmm_secs_to_gprs_tmr_floor(-1));

	/* Check properties of gprs_secs_to_tmr_floor */
	for (secs = 0; secs <= upper_secs_test_limit; secs++) {
		int tmr = gprs_gmm_secs_to_gprs_tmr_floor(secs);
		int delta_secs = gprs_gmm_gprs_tmr_to_secs((tmr & ~0x1f) | 1);
		dec_secs = gprs_gmm_gprs_tmr_to_secs(tmr);

		/* Check floor */
		OSMO_ASSERT(dec_secs <= secs);
		/* Check monotonicity */
		OSMO_ASSERT(dec_secs >= last_dec_secs);
		/* Check max distance (<= resolution) */
		OSMO_ASSERT(dec_secs - last_dec_secs <= delta_secs);

		last_dec_secs = dec_secs;
	}

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
	osmo_fsm_log_addr(false);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	test_gprs_timer_enc_dec();

	talloc_free(tall_ctx);
}
