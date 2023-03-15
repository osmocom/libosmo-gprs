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

#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/llc/llc_private.h>
#include <osmocom/gprs/gmm/gmm.h>
#include <osmocom/gprs/gmm/gmm_prim.h>
#include <osmocom/gprs/gmm/gmm_pdu.h>

static void *tall_ctx = NULL;

/*
GSM A-I/F DTAP - Identity Request
 Protocol Discriminator: GPRS mobility management messages (8)
  .... 1000 = Protocol discriminator: GPRS mobility management messages (0x8)
  0000 .... = Skip Indicator: No indication of selected PLMN (0)
 DTAP GPRS Mobility Management Message Type: Identity Request (0x15)
 Identity Type 2
  .... 0... = Spare bit(s): 0
  .... .010 = Type of identity: IMEI (2)
 Force to Standby
  0... .... = Spare bit(s): 0
  .000 .... = Force to standby: Force to standby not indicated (0)
*/
static uint8_t pdu_gmm_identity_req[] = { 0x08, 0x15, 0x02 };

/*
Frame 101: 127 bytes on wire (1016 bits), 127 bytes captured (1016 bits) on interface lo, id 0
Ethernet II, Src: 00:00:00_00:00:00 (00:00:00:00:00:00), Dst: 00:00:00_00:00:00 (00:00:00:00:00:00)
Internet Protocol Version 4, Src: 192.168.1.140, Dst: 192.168.1.140
User Datagram Protocol, Src Port: 23000, Dst Port: 23010
GPRS Network Service, PDU type: NS_UNITDATA, BVCI 1800
Base Station Subsystem GPRS Protocol
MS-SGSN LLC (Mobile Station - Serving GPRS Support Node Logical Link Control)  SAPI: GPRS Mobility Management
GSM A-I/F DTAP - Authentication and Ciphering Req
 Protocol Discriminator: GPRS mobility management messages (8)
  .... 1000 = Protocol discriminator: GPRS mobility management messages (0x8)
  0000 .... = Skip Indicator: No indication of selected PLMN (0)
 DTAP GPRS Mobility Management Message Type: Authentication and Ciphering Req (0x12)
 Ciphering Algorithm
  .... 0... = Spare bit(s): 0
  .... .000 = Type of ciphering algorithm: ciphering not used (0)
 IMEISV Request
  0... .... = Spare bit(s): 0
  .001 .... = IMEISV request: IMEISV requested (1)
 Force to Standby
  .... 0... = Spare bit(s): 0
  .... .000 = Force to standby: Force to standby not indicated (0)
 A&C Reference Number
  0010 .... = A&C reference number: 2
 Authentication Parameter RAND
  Element ID: 0x21
  RAND value: e2a6f3f8bb9ea701e0ce4f3364a99175
 Ciphering Key Sequence Number
  1000 .... = Element ID: 0x8-
  .... 0... = Spare bit(s): 0
  .... .000 = key sequence: Ciphering key sequence number (0)
*/
static uint8_t pdu_gmm_auth_ciph_req[] = {
	0x08, 0x12, 0x10, 0x20, 0x21, 0xe2, 0xa6, 0xf3, 0xf8, 0xbb, 0x9e, 0xa7, 0x01, 0xe0, 0xce, 0x4f,
	0x33, 0x64, 0xa9, 0x91, 0x75, 0x80
};

/*
GSM A-I/F DTAP - Attach Accept
 Protocol Discriminator: GPRS mobility management messages (8)
  .... 1000 = Protocol discriminator: GPRS mobility management messages (0x8)
  0000 .... = Skip Indicator: No indication of selected PLMN (0)
 DTAP GPRS Mobility Management Message Type: Attach Accept (0x02)
 Attach Result
  .... 0... = Follow-on proceed: False
  .... .001 = Result of attach: GPRS only attached (1)
 Force to Standby
  0... .... = Spare bit(s): 0
  .000 .... = Force to standby: Force to standby not indicated (0)
 GPRS Timer
  GPRS Timer: 10 min
  001. .... = Unit: value is incremented in multiples of 1 minute (1)
  ...0 1010 = Timer value: 10
 Radio Priority 2 - Radio priority for TOM8
  .100 .... = Radio Priority (TOM8): priority level 4 (lowest) (4)
 Radio Priority - Radio priority for SMS
  .... .100 = Radio Priority (PDP or SMS): priority level 4 (lowest) (4)
 Routing Area Identification - RAI: 234-70-5-0
  Routing area identification: 234-70-5-0
  Mobile Country Code (MCC): United Kingdom (234)
  Mobile Network Code (MNC): AMSUK Limited (70)
  Location Area Code (LAC): 0x0005 (5)
  Routing Area Code (RAC): 0x00 (0)
 GPRS Timer - Negotiated Ready Timer
  Element ID: 0x17
  GPRS Timer: 44 sec
  000. .... = Unit: value is incremented in multiples of 2 seconds (0)
  ...1 0110 = Timer value: 22
 Mobile Identity - Allocated P-TMSI - TMSI/P-TMSI (0xea711b41)
  Element ID: 0x18
  Length: 5
  1111 .... = Unused: 0xf
  .... 0... = Odd/even indication: Even number of identity digits
  .... .100 = Mobile Identity Type: TMSI/P-TMSI/M-TMSI (4)
  TMSI/P-TMSI/M-TMSI/5G-TMSI: 3933281089 (0xea711b41)
*/
static uint8_t pdu_gmm_att_acc[] = {
0x08, 0x02, 0x01, 0x2a, 0x44, 0x32, 0xf4, 0x07, 0x00, 0x05, 0x00, 0x17, 0x16, 0x18, 0x05, 0xf4,
0xea, 0x71, 0x1b, 0x41
};

int test_gmm_prim_up_cb(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_gmm_prim_name(gmm_prim);

	switch (gmm_prim->oph.sap) {
	case OSMO_GPRS_GMM_SAP_GMMREG:
		switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMREG_ATTACH, PRIM_OP_CONFIRM):
			printf("%s(): Rx %s accepted=%u rej_cause=%u\n", __func__, pdu_name,
			       gmm_prim->gmmreg.attach_cnf.accepted,
			       gmm_prim->gmmreg.attach_cnf.rej.cause);
			break;
		default:
			printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
			OSMO_ASSERT(0)
		}
		break;
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
	case OSMO_GPRS_GMM_SAP_GMMRR:
		OSMO_ASSERT(OSMO_PRIM_HDR(&gmm_prim->oph) ==
			    OSMO_PRIM(OSMO_GPRS_GMM_GMMRR_ASSIGN, PRIM_OP_REQUEST));
		printf("%s(): Rx %s new_tlli=0x%08x\n", __func__, pdu_name, gmm_prim->gmmrr.assign_req.new_tlli);
		break;
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

int test_gmm_prim_llc_down_cb(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
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

static void test_gmm_prim_ms(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	uint32_t ptmsi = 0x00000000;
	uint32_t tlli = 0x00000000;
	char *imsi = "1234567890";
	char *imei = "42342342342342";
	char *imeisv = "4234234234234275";

	printf("==== %s() [start] ====\n", __func__);

	rc = osmo_gprs_gmm_init(OSMO_GPRS_GMM_LOCATION_MS);
	OSMO_ASSERT(rc == 0);
	osmo_gprs_gmm_enable_gprs(true);

	osmo_gprs_gmm_prim_set_up_cb(test_gmm_prim_up_cb, NULL);
	osmo_gprs_gmm_prim_set_down_cb(test_gmm_prim_down_cb, NULL);
	osmo_gprs_gmm_prim_set_llc_down_cb(test_gmm_prim_llc_down_cb, NULL);

	/* MS sends GMM Attach Req */
	gmm_prim = osmo_gprs_gmm_prim_alloc_gmmreg_attach_req();
	gmm_prim->gmmreg.attach_req.attach_type = OSMO_GPRS_GMM_ATTACH_TYPE_GPRS;
	gmm_prim->gmmreg.attach_req.ptmsi = ptmsi;
	OSMO_STRLCPY_ARRAY(gmm_prim->gmmreg.attach_req.imsi, imsi);
	OSMO_STRLCPY_ARRAY(gmm_prim->gmmreg.attach_req.imei, imei);
	OSMO_STRLCPY_ARRAY(gmm_prim->gmmreg.attach_req.imeisv, imeisv);

	OSMO_ASSERT(gmm_prim);
	rc = osmo_gprs_gmm_prim_upper_down(gmm_prim);
	OSMO_ASSERT(rc == 0);

	/* Network answers with GMM Identity Req: */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_identity_req, sizeof(pdu_gmm_identity_req));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* As a result, MS answers GMM Identity Resp */

	/* Network sends GMM Ciph Auth Req */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_auth_ciph_req, sizeof(pdu_gmm_auth_ciph_req));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* As a result, MS answers GMM Ciph Auth Resp */

	/* Network sends GMM Attach Accept */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_att_acc, sizeof(pdu_gmm_att_acc));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* As a result, MS answers GMM Attach Complete */

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

	test_gmm_prim_ms();

	talloc_free(tall_ctx);
}
