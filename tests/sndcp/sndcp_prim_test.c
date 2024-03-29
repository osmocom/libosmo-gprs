/* sndcp_prim tests
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

#include <osmocom/gprs/llc/llc.h>
#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/sndcp/sndcp_prim.h>
#include <osmocom/gprs/sndcp/sndcp.h>
/* Included to have access to some internal functions in general only used by the LLC layer: */
#include <osmocom/gprs/llc/llc_private.h>

static void *tall_ctx = NULL;

int test_sndcp_prim_up_cb(struct osmo_gprs_sndcp_prim *sndcp_prim, void *user_data)
{
	const char *npdu_name = osmo_gprs_sndcp_prim_name(sndcp_prim);

	if (sndcp_prim->oph.sap != OSMO_GPRS_SNDCP_SAP_SN) {
		printf("%s(): Unexpected Rx %s\n", __func__, npdu_name);
		OSMO_ASSERT(0);
	}

	switch (OSMO_PRIM_HDR(&sndcp_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SN_UNITDATA, PRIM_OP_INDICATION):
		printf("%s(): Rx %s TLLI=0x%08x SAPI=%s NSAPI=%u NPDU=[%s]\n",
		       __func__, npdu_name,
		       sndcp_prim->sn.tlli, osmo_gprs_llc_sapi_name(sndcp_prim->sn.sapi),
		       sndcp_prim->sn.data_req.nsapi,
		       osmo_hexdump(sndcp_prim->sn.data_ind.npdu, sndcp_prim->sn.data_ind.npdu_len));
		break;
	default:
		printf("%s(): Rx %s\n", __func__, npdu_name);
		break;
	};
	return 0;
}

int test_sndcp_prim_down_cb(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_llc_prim_name(llc_prim);

	if (llc_prim->oph.sap != OSMO_GPRS_LLC_SAP_LL) {
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}

	switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_UNITDATA, PRIM_OP_REQUEST):
		printf("%s(): Rx %s TLLI=0x%08x SAPI=%s L3=[%s]\n",
		       __func__, pdu_name,
		       llc_prim->ll.tlli, osmo_gprs_llc_sapi_name(llc_prim->ll.sapi),
		       osmo_hexdump(llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len));
		break;
	default:
		printf("%s(): Rx %s\n", __func__, pdu_name);
		break;
	};
	return 0;
}

int test_sndcp_prim_snsm_cb(struct osmo_gprs_sndcp_prim *sndcp_prim, void *user_data)
{
	const char *npdu_name = osmo_gprs_sndcp_prim_name(sndcp_prim);

	if (sndcp_prim->oph.sap != OSMO_GPRS_SNDCP_SAP_SNSM) {
		printf("%s(): Unexpected Rx %s\n", __func__, npdu_name);
		OSMO_ASSERT(0);
	}

	switch (OSMO_PRIM_HDR(&sndcp_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_ACTIVATE, PRIM_OP_RESPONSE):
		printf("%s(): Rx %s\n", __func__, npdu_name);
		break;
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_DEACTIVATE, PRIM_OP_RESPONSE):
		printf("%s(): Rx %s\n", __func__, npdu_name);
		break;
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, npdu_name);
		OSMO_ASSERT(0);
	}

	return 0;
}

/*
Subnetwork Dependent Convergence Protocol
    Address field NSAPI: Unknown (101)
    No compression
    Unacknowledged mode, N-PDU 0 (segment 0)
*/
static const char sndcp_data_hex[] = "650000007522fa7cffd956ba86c72af3d21dcebc883a8eb6247dde266a58de29be96d240947f9f4df59c61d419e99a58752121a9fd1fd79690a73ffe5b59f0e7c1522caaa139b6c5fd682efcf4c0109b7a649dae3affa30fb0567d4b5233741367446ace6245eacb";

	/* Example of a real world SNDCP-XID message */
static const  uint8_t sndcp_xid[] = {
	      0x00, 0x01, 0x00, 0x02, 0x31, 0x82, 0x02, 0x27, 0x89, 0xff, 0xe0,
	0x00, 0x0f, 0x00, 0xa8, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x02,
	0x01, 0x02, 0x00, 0x03, 0x01, 0x03, 0x00, 0x04, 0x01, 0x04, 0x00, 0x05,
	0x01, 0x05, 0x00, 0x06, 0x00, 0x07, 0x01, 0x07, 0x00, 0x08, 0x01, 0x08,
	0x80, 0x00, 0x04, 0x12, 0x00, 0x40, 0x07 };


/* Quality Of Service - Negotiated QoS (taken from PDP Ctx Act msg)
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
*/
static const uint8_t qos_profile_ie_val[] = {
	0x23, 0x62, 0x1f, 0x72, 0x9, 0x3f, 0x3f, 0x11,
	0x43, 0xff, 0xff, 0x00, 0x00, 0x00 };


static void test_sndcp_prim_net(void)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	struct osmo_gprs_llc_prim *llc_prim;
	const uint32_t tlli = 0xe1c5d364;
	const enum osmo_gprs_llc_sapi ll_sapi = OSMO_GPRS_LLC_SAPI_SNDCP3;
	const uint8_t nsapi = 0x05;
	uint8_t sndcp_data[1024];
	int rc;
	printf("==== %s() [start] ====\n", __func__);

	rc = osmo_gprs_sndcp_init(OSMO_GPRS_SNDCP_LOCATION_NET);
	OSMO_ASSERT(rc == 0);

	osmo_gprs_sndcp_prim_set_up_cb(test_sndcp_prim_up_cb, NULL);
	osmo_gprs_sndcp_prim_set_down_cb(test_sndcp_prim_down_cb, NULL);
	osmo_gprs_sndcp_prim_set_snsm_cb(test_sndcp_prim_snsm_cb, NULL);

	/* SNSM-ACTIVATE.Ind, internally submits LL-XID.Req (it would submit
	 * LL-ESTABLISH.Req in ABM mode if we supported it): */
	sndcp_prim = osmo_gprs_sndcp_prim_alloc_snsm_activate_ind(tlli, nsapi, ll_sapi);
	OSMO_ASSERT(sndcp_prim);
	rc = osmo_gprs_sndcp_prim_dispatch_snsm(sndcp_prim);
	OSMO_ASSERT(rc == 0);

	/* Id we supported and use ABM: Submit LL-ESTABLISH.Ind, triggers rx of  LL-ESTABLISH.Rsp */

	/* Submit LL-XID.Ind, triggers rx of SN-XID.Ind: */
	llc_prim = gprs_llc_prim_alloc_ll_xid_ind(tlli, ll_sapi, (uint8_t *)sndcp_xid, sizeof(sndcp_xid));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_sndcp_prim_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);

	/* Submit SN-XID.Rsp, triggers rx of LL-XID.Rsp */
	sndcp_prim = osmo_gprs_sndcp_prim_alloc_sn_xid_rsp(tlli, ll_sapi, nsapi);
	OSMO_ASSERT(sndcp_prim);
	rc = osmo_gprs_sndcp_prim_upper_down(sndcp_prim);
	OSMO_ASSERT(rc == 0);

	OSMO_ASSERT(osmo_hexparse(sndcp_data_hex, sndcp_data, sizeof(sndcp_data)) > 0);
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(tlli, ll_sapi, (uint8_t *)sndcp_data, sizeof(sndcp_data));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_sndcp_prim_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);

	char ndpu_data[] = "some-npdu-data-like-an-ip-pkt";
	sndcp_prim = osmo_gprs_sndcp_prim_alloc_sn_unitdata_req(tlli, ll_sapi, nsapi, (uint8_t *)ndpu_data, sizeof(ndpu_data));
	OSMO_ASSERT(sndcp_prim);
	rc = osmo_gprs_sndcp_prim_upper_down(sndcp_prim);
	OSMO_ASSERT(rc == 0);


	/* TODO: SN-XID REQ / IND / RESP / CONF
	 * TODO: Other primitives coming from LLC layer
	 */

	/* SNSM-DEACTIVATE.Ind: */
	sndcp_prim = osmo_gprs_sndcp_prim_alloc_snsm_deactivate_ind(tlli, nsapi);
	OSMO_ASSERT(sndcp_prim);
	rc = osmo_gprs_sndcp_prim_dispatch_snsm(sndcp_prim);
	OSMO_ASSERT(rc == 0);

	printf("==== %s() [end] ====\n", __func__);
}

static void test_sndcp_prim_ms(void)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	struct osmo_gprs_llc_prim *llc_prim;
	const uint32_t tlli = 0xe1c5d364;
	const enum osmo_gprs_llc_sapi ll_sapi = OSMO_GPRS_LLC_SAPI_SNDCP3;
	const uint8_t nsapi = 0x05;
	uint8_t sndcp_data[1024];
	int rc;
	printf("==== %s() [start] ====\n", __func__);

	rc = osmo_gprs_sndcp_init(OSMO_GPRS_SNDCP_LOCATION_MS);
	OSMO_ASSERT(rc == 0);

	osmo_gprs_sndcp_prim_set_up_cb(test_sndcp_prim_up_cb, NULL);
	osmo_gprs_sndcp_prim_set_down_cb(test_sndcp_prim_down_cb, NULL);
	osmo_gprs_sndcp_prim_set_snsm_cb(test_sndcp_prim_snsm_cb, NULL);

	/* SNSM-ACTIVATE.Ind, internally submits LL-XID.Req (it would submit
	 * LL-ESTABLISH.Req in ABM mode if we supported it): */
	sndcp_prim = osmo_gprs_sndcp_prim_alloc_snsm_activate_ind(tlli, nsapi, ll_sapi);
	OSMO_ASSERT(sndcp_prim);
	sndcp_prim->snsm.activate_ind.radio_prio = 1;
	sndcp_prim->snsm.activate_ind.qos_profile_len = sizeof(qos_profile_ie_val);
	memcpy(sndcp_prim->snsm.activate_ind.qos_profile, qos_profile_ie_val, sizeof(qos_profile_ie_val));
	rc = osmo_gprs_sndcp_prim_dispatch_snsm(sndcp_prim);
	OSMO_ASSERT(rc == 0);

	/* Id we supported and use ABM: Submit LL-ESTABLISH.Cnf, triggers rx of SNSM-ACTIVATE.Rsp */
	//llc_prim = gprs_llc_prim_alloc_ll_establish_cnf(tlli, ll_sapi, (uint8_t *)sndcp_xid, sizeof(sndcp_xid));
	//OSMO_ASSERT(llc_prim);
	//rc = osmo_gprs_sndcp_prim_lower_up(llc_prim);
	//OSMO_ASSERT(rc == 0);

	/* Network answers XID req, Submit LL-XID.Cnf, triggers rx of SNSM-ACTIVATE-RSP */
	llc_prim = gprs_llc_prim_alloc_ll_xid_cnf(tlli, ll_sapi, (uint8_t *)sndcp_xid, sizeof(sndcp_xid));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_sndcp_prim_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);

	/* Submit SN-XID.Req from upper layers, triggers rx of LL-XID.Req: */
	sndcp_prim = osmo_gprs_sndcp_prim_alloc_sn_xid_req(tlli, ll_sapi, nsapi);
	OSMO_ASSERT(sndcp_prim);
	sndcp_prim->sn.xid_req.pcomp_rfc1144.active = true;
	sndcp_prim->sn.xid_req.pcomp_rfc1144.s01 = 7;
	rc = osmo_gprs_sndcp_prim_upper_down(sndcp_prim);
	OSMO_ASSERT(rc == 0);

	/* Submit LL-XID.Cnf, triggers rx of SN-XID.cnf */
	llc_prim = gprs_llc_prim_alloc_ll_xid_cnf(tlli, ll_sapi, (uint8_t *)sndcp_xid, sizeof(sndcp_xid));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_sndcp_prim_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);

	OSMO_ASSERT(osmo_hexparse(sndcp_data_hex, sndcp_data, sizeof(sndcp_data)) > 0);
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(tlli, ll_sapi, (uint8_t *)sndcp_data, sizeof(sndcp_data));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_sndcp_prim_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);

	char ndpu_data[] = "some-npdu-data-like-an-ip-pkt";
	sndcp_prim = osmo_gprs_sndcp_prim_alloc_sn_unitdata_req(tlli, ll_sapi, nsapi, (uint8_t *)ndpu_data, sizeof(ndpu_data));
	OSMO_ASSERT(sndcp_prim);
	rc = osmo_gprs_sndcp_prim_upper_down(sndcp_prim);
	OSMO_ASSERT(rc == 0);


	/* TODO: SN-XID REQ / IND / RESP / CONF
	 * TODO: Other primitives coming from LLC layer
	 */

	/* SNSM-DEACTIVATE.Ind: */
	sndcp_prim = osmo_gprs_sndcp_prim_alloc_snsm_deactivate_ind(tlli, nsapi);
	OSMO_ASSERT(sndcp_prim);
	rc = osmo_gprs_sndcp_prim_dispatch_snsm(sndcp_prim);
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

	test_sndcp_prim_net();
	test_sndcp_prim_ms();

	talloc_free(tall_ctx);
}
