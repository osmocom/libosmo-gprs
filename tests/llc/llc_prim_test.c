/* llc_prim tests
 *
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/gprs/llc/llc_prim.h>

static void *tall_ctx = NULL;

/* stub to get reproducible output, since llme->iov_ui is printed: */
int osmo_get_rand_id(uint8_t *out, size_t len)
{
	memset(out, 0x2b, len);
	return 0;
}

int test_llc_prim_up_cb(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_llc_prim_name(llc_prim);

	switch (llc_prim->oph.sap) {
	case OSMO_GPRS_LLC_SAP_LLGM:
		printf("%s(): Rx %s TLLI=0x%08x\n", __func__, pdu_name, llc_prim->llgmm.tlli);
		break;
	case OSMO_GPRS_LLC_SAP_LL:
		printf("%s(): Rx %s TLLI=0x%08x SAPI=%s l3=[%s]\n", __func__, pdu_name,
		       llc_prim->ll.tlli, osmo_gprs_llc_sapi_name(llc_prim->ll.sapi),
		       osmo_hexdump(llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len));
		break;
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

int test_llc_prim_down_cb(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_llc_prim_name(llc_prim);

	switch (llc_prim->oph.sap) {
	case OSMO_GPRS_LLC_SAP_GRR:
				printf("%s(): Rx %s l3=[%s]\n", __func__, pdu_name, osmo_hexdump(llc_prim->grr.ll_pdu, llc_prim->grr.ll_pdu_len));
		break;
	case OSMO_GPRS_LLC_SAP_BSSGP:
		printf("%s(): Rx %s TLLI=0x%08x l3=[%s]\n", __func__, pdu_name,
		       llc_prim->bssgp.tlli, osmo_hexdump(llc_prim->bssgp.ll_pdu, llc_prim->bssgp.ll_pdu_len));
		break;
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

static void test_llc_prim_ms(void)
{
	//struct osmo_gprs_llc_prim *llc_prim;
	//uint32_t tlli = 0x11223344;
	int rc;

	printf("==== %s() [start] ====\n", __func__);

	rc = osmo_gprs_llc_init(OSMO_GPRS_LLC_LOCATION_MS, NULL);
	OSMO_ASSERT(rc == 0);

	osmo_gprs_llc_prim_set_up_cb(test_llc_prim_up_cb, NULL);
	osmo_gprs_llc_prim_set_down_cb(test_llc_prim_down_cb, NULL);

	//llc_prim = osmo_gprs_llc_prim_alloc_llgm_reset_req(tlli);
	//OSMO_ASSERT(llc_prim);
	//rc = osmo_gprs_llc_prim_upper_down(llc_prim);
	//OSMO_ASSERT(rc == 0);

	printf("==== %s() [end] ====\n", __func__);
}

/**
MS-SGSN LLC (Mobile Station - Serving GPRS Support Node Logical Link Control)  SAPI: GPRS Mobility Management
 Address field  SAPI: LLGMM
  0... .... = Protocol Discriminator_bit: OK
  .0.. .... = Command/Response bit: DownLink/UpLink = Response/Command
  .... 0001 = SAPI: GPRS Mobility Management (1)
 Unconfirmed Information format - UI: UI format: 0x6, Spare bits: 0x0, N(U): 0, E bit: non encrypted frame, PM bit: FCS covers only the frame header and first N202 octets of the information field
  110. .... .... .... = UI format: 0x6
  ...0 0... .... .... = Spare bits: 0x0
  .... .000 0000 00.. = N(U): 0
  .... .... .... ..0. = E bit: non encrypted frame
  .... .... .... ...0 = PM bit: FCS covers only the frame header and first N202 octets of the information field
 FCS: 0xf218e2 (correct)
GSM A-I/F DTAP - Attach Request
 Protocol Discriminator: GPRS mobility management messages (8)
 DTAP GPRS Mobility Management Message Type: Attach Request (0x01)
 MS Network Capability
 Attach Type
 Ciphering Key Sequence Number
 DRX Parameter
 Mobile Identity - IMSI (262420000000017)
 Routing Area Identification - Old routing area identification - RAI: 262-42-27780-68
 MS Radio Access Capability
*/
static uint8_t pdu_llc_gmm_att_req[] = {
	0x01, 0xc0, 0x00, 0x08, 0x01, 0x01, 0xd5, 0x71, 0x00, 0x00, 0x08, 0x29, 0x26,
	0x24, 0x00, 0x00, 0x00, 0x00, 0x71, 0x62, 0xf2, 0x24, 0x6c, 0x84, 0x44, 0x04,
	0x11, 0xe5, 0x10, 0x00, 0xe2, 0x18, 0xf2
};

/*
GSM A-I/F DTAP - Identity Request
 Protocol Discriminator: GPRS mobility management messages (8)
 DTAP GPRS Mobility Management Message Type: Identity Request (0x15)
 Identity Type 2
 Force to Standby
*/
static uint8_t pdu_gmm_id_req[] = { 0x08, 0x15, 0x02 };

static void test_llc_prim_sgsn(void)
{
	struct osmo_gprs_llc_prim *llc_prim;
	const uint32_t tlli = 0xe1c5d364;
	int rc;
	struct osmo_gprs_llc_bssgp_prim_cell_id cell_id = {
		.rai = {
			.mcc = 901,
			.mnc = 70,
			.mnc_3_digits = false,
			.lac = 0x0304,
			.rac = 0x01,
		},
		.ci = 0x9876,
	};

	printf("==== %s() [start] ====\n", __func__);

	rc = osmo_gprs_llc_init(OSMO_GPRS_LLC_LOCATION_SGSN, NULL);
	OSMO_ASSERT(rc == 0);

	osmo_gprs_llc_prim_set_up_cb(test_llc_prim_up_cb, NULL);
	osmo_gprs_llc_prim_set_down_cb(test_llc_prim_down_cb, NULL);

	/* Rx LLC-GMM-Attach-Req at SGSN from MS: */
	llc_prim = osmo_gprs_llc_prim_alloc_bssgp_ul_unitdata_ind(tlli, pdu_llc_gmm_att_req, sizeof(pdu_llc_gmm_att_req));
	llc_prim->bssgp.ul_unitdata_ind.cell_id = cell_id;
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_llc_prim_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);

	/* SGSN wants to submit GMM Id Req: */
	llc_prim = osmo_gprs_llc_prim_alloc_ll_unitdata_req(tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_id_req, sizeof(pdu_gmm_id_req));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_llc_prim_upper_down(llc_prim);
	OSMO_ASSERT(rc == 0);

	llc_prim = osmo_gprs_llc_prim_alloc_llgm_assign_req(tlli);
	OSMO_ASSERT(llc_prim);
	llc_prim->llgmm.assign_req.tlli_new = tlli;
	rc = osmo_gprs_llc_prim_upper_down(llc_prim);
	OSMO_ASSERT(rc == 0);

	llc_prim = osmo_gprs_llc_prim_alloc_llgm_reset_req(tlli);
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_llc_prim_upper_down(llc_prim);
	OSMO_ASSERT(rc == 0);

	char xid_l3_pars[] = "xid-l3-dummy-buffer";
	llc_prim = osmo_gprs_llc_prim_alloc_ll_xid_req(tlli, OSMO_GPRS_LLC_SAPI_SNDCP3, (uint8_t *)xid_l3_pars, sizeof(xid_l3_pars));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_llc_prim_upper_down(llc_prim);
	OSMO_ASSERT(rc == 0);

	char sndcp_data[] = "some-sndcp-data";
	llc_prim = osmo_gprs_llc_prim_alloc_ll_unitdata_req(tlli, OSMO_GPRS_LLC_SAPI_SNDCP3, (uint8_t *)sndcp_data, sizeof(sndcp_data));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_llc_prim_upper_down(llc_prim);
	OSMO_ASSERT(rc == 0);

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

	test_llc_prim_ms();
	test_llc_prim_sgsn();

	talloc_free(tall_ctx);
}
