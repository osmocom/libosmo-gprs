/* sm_prim tests
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

#include <osmocom/gprs/gmm/gmm_prim.h>
#include <osmocom/gprs/gmm/gmm_private.h>
#include <osmocom/gprs/sm/sm.h>
#include <osmocom/gprs/sm/sm_prim.h>

static void *tall_ctx = NULL;

static uint32_t last_gmm_establish_sess_id = 0;

/*
GSM A-I/F DTAP - Activate PDP Context Accept
 Protocol Discriminator: GPRS session management messages (10)
  .... 1010 = Protocol discriminator: GPRS session management messages (0xa)
  1... .... = TI flag: allocated by receiver
  .000 .... = TIO: 0
 01.. .... = Sequence number: 1
 DTAP GPRS Session Management Message Type: Activate PDP Context Accept (0x42)
 LLC Service Access Point Identifier - Negotiated LLC SAPI
  0000 .... = Spare bit(s): 0
  .... 0011 = LLC SAPI: SAPI 3 (3)
 Quality Of Service - Negotiated QoS
  Length: 14
  00.. .... = Spare bit(s): 0
  ..10 0... = Quality of Service Delay class: Delay class 4 (best effort) (4)
  .... .011 = Reliability class: Unacknowledged GTP/LLC, Ack RLC, Protected data (3)
  0110 .... = Peak throughput: Up to 32 000 octet/s (6)
  .... 0... = Spare bit(s): 0
  .... .010 = Precedence class: Normal priority (2)
  000. .... = Spare bit(s): 0
  ...1 1111 = Mean throughput: Best effort (31)
  011. .... = Traffic class: Interactive class (3)
  ...1 0... = Delivery order: Without delivery order ('no') (2)
  .... .010 = Delivery of erroneous SDUs: Erroneous SDUs are delivered('yes') (2)
  Maximum SDU size: 1520 octets (153)
  Maximum bitrate for uplink: 63 kbps (63)
  Maximum bitrate for downlink: 63 kbps (63)
  0001 .... = Residual Bit Error Rate (BER): 5*10-2 (1)
  .... 0001 = SDU error ratio: 1*10-2 (1)
  0100 00.. = Transfer delay: 200 ms (16)
  .... ..11 = Traffic handling priority: Priority level 3 (3)
  Guaranteed bitrate for uplink: 0 kbps (255)
  Guaranteed bitrate for downlink: 0 kbps (255)
  000. .... = Spare bit(s): 0
  ...0 .... = Signalling indication: Not optimised for signalling traffic
  .... 0000 = Source statistics description: unknown (0)
  Maximum bitrate for downlink (extended): Use the value indicated by the Maximum bit rate for downlink (0)
  Guaranteed bitrate for downlink (extended): Use the value indicated by the Guaranteed bit rate for downlink (0)
 Radio Priority
  .... .100 = Radio Priority (PDP or SMS): priority level 4 (lowest) (4)
 Packet Data Protocol Address - PDP address
  Element ID: 0x2b
  Length: 6
  0000 .... = Spare bit(s): 0
  .... 0001 = PDP type organization: IETF allocated address (1)
  PDP type number: IPv4 address (33)
  IPv4 address: 176.16.222.2
 Protocol Configuration Options
  Element ID: 0x27
  Length: 20
  [Link direction: Network to MS (1)]
  1... .... = Extension: True
  .... .000 = Configuration Protocol: PPP for use with IP PDP type or IP PDN type (0)
  Protocol or Container ID: Internet Protocol Control Protocol (0x8021)
   Length: 0x10 (16)
   PPP IP Control Protocol
    Code: Configuration Ack (2)
    Identifier: 0 (0x00)
    Length: 16
    Options: (12 bytes), Primary DNS Server IP Address, Secondary DNS Server IP Address
  Primary DNS Server IP Address
      Type: Primary DNS Server IP Address (129)
      Length: 6
      Primary DNS Address: 8.8.8.8
  Secondary DNS Server IP Address
      Type: Secondary DNS Server IP Address (131)
      Length: 6
      Secondary DNS Address: 8.8.8.4
*/

static uint8_t pdu_sm_act_pdp_ctx_acc[] = {
0x8a, 0x42, 0x03, 0x0e, 0x23, 0x62, 0x1f, 0x72,
0x99, 0x3f, 0x3f, 0x11, 0x43, 0xff, 0xff, 0x00,
0x00, 0x00, 0x04, 0x2b, 0x06, 0x01, 0x21, 0xb0,
0x10, 0xde, 0x02, 0x27, 0x14, 0x80, 0x80, 0x21,
0x10, 0x02, 0x00, 0x00, 0x10, 0x81, 0x06, 0x08,
0x08, 0x08, 0x08, 0x83, 0x06, 0x08, 0x08, 0x08,
0x04
};

int test_sm_prim_up_cb(struct osmo_gprs_sm_prim *sm_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_sm_prim_name(sm_prim);

	switch (sm_prim->oph.sap) {
	case OSMO_GPRS_SM_SAP_SMREG:
		switch (OSMO_PRIM_HDR(&sm_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_SM_SMREG_PDP_ACTIVATE, PRIM_OP_CONFIRM):
			printf("%s(): Rx %s\n", __func__, pdu_name);
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

int test_sm_prim_down_cb(struct osmo_gprs_sm_prim *sm_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_sm_prim_name(sm_prim);

	switch (sm_prim->oph.sap) {
	case OSMO_GPRS_SM_SAP_SMREG:
		switch (OSMO_PRIM_HDR(&sm_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_SM_SMREG_PDP_ACTIVATE, PRIM_OP_REQUEST):
			printf("%s(): Rx %s\n", __func__, pdu_name);
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

int test_sm_prim_gmm_down_cb(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_gmm_prim_name(gmm_prim);

	switch (gmm_prim->oph.sap) {
	case OSMO_GPRS_GMM_SAP_GMMSM:
		switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_ESTABLISH, PRIM_OP_REQUEST):
			printf("%s(): Rx %s sess_id=%u\n", __func__, pdu_name,
			       gmm_prim->gmmsm.sess_id);
			last_gmm_establish_sess_id = gmm_prim->gmmsm.sess_id;
			break;
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_UNITDATA, PRIM_OP_REQUEST):
			printf("%s(): Rx %s sess_id=%u SMPDU=[%s]\n", __func__, pdu_name,
			       gmm_prim->gmmsm.sess_id,
			       osmo_hexdump(gmm_prim->gmmsm.unitdata_req.smpdu,
					    gmm_prim->gmmsm.unitdata_req.smpdu_len));
			break;
		default:
			printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
			OSMO_ASSERT(0);
		}
		break;
	case OSMO_GPRS_GMM_SAP_GMMRR:
		printf("%s(): Rx %s\n", __func__, pdu_name);
		break;
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

static void test_sm_prim_ms(void)
{
	struct osmo_gprs_sm_prim *sm_prim;
	struct osmo_gprs_gmm_prim *gmm_prim;
	int rc;
	uint8_t nsapi = 6;
	enum osmo_gprs_sm_llc_sapi llc_sapi = OSMO_GPRS_SM_LLC_SAPI_SAPI3;
	struct osmo_sockaddr pdp_addr_any = {0};
	uint8_t qos[OSMO_GPRS_SM_QOS_MAXLEN] = {0};
	uint8_t pco[OSMO_GPRS_SM_QOS_MAXLEN] = {0};
	char apn[OSMO_GPRS_SM_APN_MAXLEN] = "apn";
	uint32_t ptmsi = 0x00000000;
	char *imsi = "1234567890";
	char *imei = "42342342342342";
	char *imeisv = "4234234234234275";

	printf("==== %s() [start] ====\n", __func__);

	rc = osmo_gprs_sm_init(OSMO_GPRS_SM_LOCATION_MS);
	OSMO_ASSERT(rc == 0);

	osmo_gprs_sm_prim_set_up_cb(test_sm_prim_up_cb, NULL);
	osmo_gprs_sm_prim_set_down_cb(test_sm_prim_down_cb, NULL);
	osmo_gprs_sm_prim_set_gmm_down_cb(test_sm_prim_gmm_down_cb, NULL);

	/* MS sends SM PDP Act Req (GMMSM-ESTABLISH.req is submitted down to GMM layer) */
	sm_prim = osmo_gprs_sm_prim_alloc_smreg_pdp_act_req();
	OSMO_ASSERT(sm_prim);
	sm_prim->smreg.pdp_act_req.nsapi = nsapi;
	sm_prim->smreg.pdp_act_req.llc_sapi = llc_sapi;
	sm_prim->smreg.pdp_act_req.pdp_addr_ietf_type = OSMO_GPRS_SM_PDP_ADDR_IETF_IPV4;
	sm_prim->smreg.pdp_act_req.pdp_addr_v4 = pdp_addr_any;
	memcpy(sm_prim->smreg.pdp_act_req.qos, qos, sizeof(qos));
	sm_prim->smreg.pdp_act_req.qos_len = 1;
	memcpy(sm_prim->smreg.pdp_act_req.pco, pco, sizeof(pco));
	sm_prim->smreg.pdp_act_req.pco_len = 1;
	OSMO_STRLCPY_ARRAY(sm_prim->smreg.pdp_act_req.apn, apn);
	sm_prim->smreg.pdp_act_req.gmm.ptmsi = ptmsi;
	OSMO_STRLCPY_ARRAY(sm_prim->smreg.pdp_act_req.gmm.imsi, imsi);
	OSMO_STRLCPY_ARRAY(sm_prim->smreg.pdp_act_req.gmm.imei, imei);
	OSMO_STRLCPY_ARRAY(sm_prim->smreg.pdp_act_req.gmm.imeisv, imeisv);
	rc = osmo_gprs_sm_prim_upper_down(sm_prim);
	OSMO_ASSERT(rc == 0);

	/* GMM internaly does GMM Attach and confirms it is attached to SM: */
	gmm_prim = gprs_gmm_prim_alloc_gmmsm_establish_cnf(last_gmm_establish_sess_id, 0);
	OSMO_ASSERT(gmm_prim);
	rc = osmo_gprs_sm_prim_gmm_lower_up(gmm_prim);
	OSMO_ASSERT(rc == 0);

	/* SM layer is now sending GMMSM-UNITDATA.req with the Active Pdp Context Req... */
	/* Network accepts the pdp ctx req with Activate Pdp Context Accept: */
	gmm_prim = gprs_gmm_prim_alloc_gmmsm_unitdata_ind(last_gmm_establish_sess_id,
							  (uint8_t *)pdu_sm_act_pdp_ctx_acc,
							  sizeof(pdu_sm_act_pdp_ctx_acc));
	OSMO_ASSERT(gmm_prim);
	rc = osmo_gprs_sm_prim_gmm_lower_up(gmm_prim);
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
	osmo_fsm_log_addr(false);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	test_sm_prim_ms();

	talloc_free(tall_ctx);
}
