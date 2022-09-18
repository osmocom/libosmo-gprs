/* LLC PDU codec tests
 *
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Vadim Yanitskiy <vyanitskiy@sysmocom.de>
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

static void *tall_ctx = NULL;

static void test_pdu_dec_enc(void)
{
	static const char *testData[] = {
		/* SAPI=1 (GMM), UI func=UI C/R=0 PM=0 N(U)=4 */
		"01c010080509afe633",
		/* SAPI=1 (GMM), UI func=UI C/R=1 PM=1 N(U)=0 */
		"41c001081502de8e9a",
		/* SAPI=1 (GMM), U func=NULL C/R=0 P/F=0 */
		"01e01ca2b3",
		/* SAPI=3 (SNDCP3), U func=XID C/R=1 P/F=1 */
		"43fb01001601f41a05df8c7c4e",
		/* SAPI=3 (SNDCP3), U func=XID C/R=1 P/F=1 */
		"03fb1604d216f984",
	};

	struct msgb *msg = msgb_alloc(1024, "LLC-PDU");
	OSMO_ASSERT(msg != NULL);

	for (unsigned int i = 0; i < ARRAY_SIZE(testData); i++) {
		struct osmo_gprs_llc_pdu_decoded hdr = { 0 };
		uint8_t pdu[256];
		size_t pdu_len;
		int rc;

		printf("%s(): decoding testData[%u] = %s\n", __func__, i, testData[i]);

		rc = osmo_hexparse(testData[i], &pdu[0], sizeof(pdu));
		pdu_len = strlen(testData[i]) / 2;
		OSMO_ASSERT(rc == pdu_len);

		rc = osmo_gprs_llc_pdu_decode(&hdr, &pdu[0], pdu_len);
		printf("  osmo_gprs_llc_pdu_decode() returns %d\n", rc);
		printf("  osmo_gprs_llc_pdu_hdr_dump(): %s\n", osmo_gprs_llc_pdu_hdr_dump(&hdr));
		if (hdr.data_len > 0) {
			printf("  hdr.data[] (len=%zu): %s\n", hdr.data_len,
			       osmo_hexdump_nospc(hdr.data, hdr.data_len));
		}

		printf("%s(): encoding decoded testData[%u]\n", __func__, i);

		msgb_reset(msg);
		rc = osmo_gprs_llc_pdu_encode(msg, &hdr);
		printf("  osmo_gprs_llc_pdu_encode() returns %d\n", rc);
		printf("  osmo_gprs_llc_pdu_encode(): %s\n", osmo_hexdump_nospc(msg->data, msg->len));
		printf("  memcmp() returns %d\n", memcmp(&pdu, msg->data, pdu_len));
	}

	msgb_free(msg);
	printf("\n");
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

	test_pdu_dec_enc();

	talloc_free(tall_ctx);
}
