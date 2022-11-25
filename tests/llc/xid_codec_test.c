/* LLC XID codec tests
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
#include <osmocom/gprs/llc/llc_private.h>

static void *tall_ctx = NULL;

static void print_xid_fields(const struct gprs_llc_xid_field *fields,
			     unsigned int num_fields)
{
	for (unsigned int i = 0; i < num_fields; i++) {
		const struct gprs_llc_xid_field *field = &fields[i];

		printf("  field[%02d]: type=0x%02x (%s)",
		       i, field->type, gprs_llc_xid_type_name(field->type));
		if (field->type == OSMO_GPRS_LLC_XID_T_L3_PAR) {
			printf(" data[] (len=%u): %s\n", field->var.val_len,
			       osmo_hexdump_nospc(field->var.val, field->var.val_len));
		} else {
			printf(" val=%u\n", field->val);
		}
	}
}

static void test_xid_dec_enc(void)
{
	static const char * const testData[] = {
		/* TODO: more test vectors */
		"25401602082c",
		"16020825402c",
		"01001601f41a05df",
		"01001605f01a05f0ac18112233445566",
		"01001601f41a02081e00002200002908",
	};

	struct msgb *msg = msgb_alloc(1024, "LLC-XID");
	OSMO_ASSERT(msg != NULL);

	for (unsigned int i = 0; i < ARRAY_SIZE(testData); i++) {
		struct gprs_llc_xid_field fields[16] = { 0 };
		uint8_t xid[256];
		size_t xid_len;
		int rc;

		printf("%s(): decoding testData[%u] = %s\n", __func__, i, testData[i]);

		rc = osmo_hexparse(testData[i], &xid[0], sizeof(xid));
		xid_len = strlen(testData[i]) / 2;
		OSMO_ASSERT(rc == xid_len);

		rc = gprs_llc_xid_decode(fields, ARRAY_SIZE(fields),
					      &xid[0], xid_len);
		printf("  gprs_llc_xid_decode() returns %d\n", rc);

		if (rc > 0)
			print_xid_fields(&fields[0], rc);
		else
			continue;

		printf("%s(): encoding decoded testData[%u]\n", __func__, i);

		msgb_reset(msg);
		rc = gprs_llc_xid_encode(msgb_data(msg), msgb_tailroom(msg), fields, rc);
		printf("  gprs_llc_xid_encode() returns %d\n", rc);
		if (rc < 0)
			continue;
		msgb_put(msg, rc);
		printf("  gprs_llc_xid_encode(): %s\n", osmo_hexdump_nospc(msg->data, msg->len));
		printf("  memcmp() returns %d\n", memcmp(&xid, msg->data, xid_len));
	}

	msgb_free(msg);
	printf("\n");
}

static void test_xid_enc_dec(void)
{
	struct gprs_llc_xid_field dec_fields[16] = { 0 };
	int rc;

	uint8_t l3_params[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	const struct gprs_llc_xid_field test_fields[] = {
		{ .type = OSMO_GPRS_LLC_XID_T_VERSION,	.val = 0 },
		{ .type = OSMO_GPRS_LLC_XID_T_T200,	.val = 4095 },
		{ .type = OSMO_GPRS_LLC_XID_T_N200,	.val = 10 },
		{ .type = OSMO_GPRS_LLC_XID_T_IOV_I,	.val = 0x42424242 },
		{ .type = OSMO_GPRS_LLC_XID_T_IOV_UI,	.val = 0xdeadbeef },
		{ .type = OSMO_GPRS_LLC_XID_T_L3_PAR,
		  .var = { .val_len = sizeof(l3_params), .val = &l3_params[0] } },
		{ .type = OSMO_GPRS_LLC_XID_T_RESET },
	};

	struct msgb *msg = msgb_alloc(1024, "LLC-XID");
	OSMO_ASSERT(msg != NULL);

	printf("%s(): encoding hand-crafted testData\n", __func__);

	rc = gprs_llc_xid_encode(msgb_data(msg), msgb_tailroom(msg), &test_fields[0], ARRAY_SIZE(test_fields));
	printf("  gprs_llc_xid_encode() returns %d\n", rc);
	OSMO_ASSERT(rc > 0);
	msgb_put(msg, rc);
	printf("  gprs_llc_xid_encode(): %s\n", osmo_hexdump_nospc(msg->data, msg->len));

	printf("%s(): decoding encoded hand-crafted testData\n", __func__);

	rc = gprs_llc_xid_decode(&dec_fields[0], ARRAY_SIZE(dec_fields),
				      msg->data, msg->len);
	printf("  gprs_llc_xid_decode() returns %d\n", rc);
	if (rc > 0)
		print_xid_fields(&dec_fields[0], rc);

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

	test_xid_dec_enc();
	test_xid_enc_dec();

	talloc_free(tall_ctx);
}
