/* gmm_prim tests (MS side)
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
#include <osmocom/core/select.h>

#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/llc/llc_private.h>
#include <osmocom/gprs/gmm/gmm.h>
#include <osmocom/gprs/gmm/gmm_prim.h>
#include <osmocom/gprs/gmm/gmm_pdu.h>

#include "gmm_prim_test.h"

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

/*
GSM A-I/F DTAP - Routing Area Update Accept
 Protocol Discriminator: GPRS mobility management messages (8)
  .... 1000 = Protocol discriminator: GPRS mobility management messages (0x8)
  0000 .... = Skip Indicator: No indication of selected PLMN (0)
 DTAP GPRS Mobility Management Message Type: Routing Area Update Accept (0x09)
 Force to Standby
  .... 0... = Spare bit(s): 0
  .... .000 = Force to standby: Force to standby not indicated (0)
 Update Result
  .000 .... = Update Result: RA updated (0)
 GPRS Timer - Periodic RA update timer
  GPRS Timer: 10 sec
   000. .... = Unit: value is incremented in multiples of 2 seconds (0)
   ...0 0101 = Timer value: 5
 Routing Area Identification - RAI: 234-70-5-0
  Routing area identification: 234-70-5-0
   Mobile Country Code (MCC): United Kingdom (234)
   Mobile Network Code (MNC): AMSUK Limited (70)
   Location Area Code (LAC): 0x0005 (5)
   Routing Area Code (RAC): 0x00 (0)
 Mobile Identity - Allocated P-TMSI - TMSI/P-TMSI (0xec999002)
  Element ID: 0x18
  Length: 5
  1111 .... = Unused: 0xf
  .... 0... = Odd/even indication: Even number of identity digits
  .... .100 = Mobile Identity Type: TMSI/P-TMSI/M-TMSI (4)
  TMSI/P-TMSI/M-TMSI/5G-TMSI: 3969486850 (0xec999002)
 GPRS Timer - Negotiated Ready Timer
  Element ID: 0x17
  GPRS Timer: 10 sec
   000. .... = Unit: value is incremented in multiples of 2 seconds (0)
   ...0 0101 = Timer value: 5
*/
static uint8_t pdu_gmm_rau_acc[] = {
0x08, 0x09, 0x00, 0x05, 0x32, 0xf4, 0x07, 0x00,
0x05, 0x00, 0x18, 0x05, 0xf4, 0xec, 0x99, 0x90,
0x02, 0x17, 0x05
};

static uint8_t pdu_gmm_detach_acc[] = {
0x08, 0x06, 0x00
};

/* override, requires '-Wl,--wrap=osmo_get_rand_id' */
int __real_osmo_get_rand_id(uint8_t *data, size_t len);
int __wrap_osmo_get_rand_id(uint8_t *data, size_t len)
{
	memset(data, 0x00, len);
	return 0;
}

int test_gmm_prim_up_cb(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_gmm_prim_name(gmm_prim);
	struct osmo_gprs_gmm_prim *gmm_prim_tx;
	int rc;

	switch (gmm_prim->oph.sap) {
	case OSMO_GPRS_GMM_SAP_GMMREG:
		switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMREG_ATTACH, PRIM_OP_CONFIRM):
			if (gmm_prim->gmmreg.attach_cnf.accepted) {
				printf("%s(): Rx %s accepted=%u allocated_ptmsi=0x%08x allocated_ptmsi_sig=0x%06x allocated_tlli=0x%08x\n", __func__, pdu_name,
				       gmm_prim->gmmreg.attach_cnf.accepted,
				       gmm_prim->gmmreg.attach_cnf.acc.allocated_ptmsi,
				       gmm_prim->gmmreg.attach_cnf.acc.allocated_ptmsi_sig,
				       gmm_prim->gmmreg.attach_cnf.acc.allocated_tlli);
			} else {
				printf("%s(): Rx %s accepted=%u rej_cause=%u\n", __func__, pdu_name,
				       gmm_prim->gmmreg.attach_cnf.accepted,
				       gmm_prim->gmmreg.attach_cnf.rej.cause);
			}
			break;
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMREG_DETACH, PRIM_OP_CONFIRM):
			printf("%s(): Rx %s detach_type='%s'\n", __func__, pdu_name,
			       osmo_gprs_gmm_detach_ms_type_name(gmm_prim->gmmreg.detach_cnf.detach_type));
			break;
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMREG_SIM_AUTH, PRIM_OP_INDICATION):
			printf("%s(): Rx %s ac_ref_nr=%u key_seq=%u rand=%s\n",
				__func__, pdu_name,
			       gmm_prim->gmmreg.sim_auth_ind.ac_ref_nr,
			       gmm_prim->gmmreg.sim_auth_ind.key_seq,
			       osmo_hexdump(gmm_prim->gmmreg.sim_auth_ind.rand,
					    sizeof(gmm_prim->gmmreg.sim_auth_ind.rand)));
			/* Emulate SIM, asnwer SRES=0xacacacac, Kc=bdbdbd... */
			gmm_prim_tx = osmo_gprs_gmm_prim_alloc_gmmreg_sim_auth_rsp();
			OSMO_ASSERT(gmm_prim_tx);
			gmm_prim_tx->gmmreg.sim_auth_rsp.ac_ref_nr = gmm_prim->gmmreg.sim_auth_ind.ac_ref_nr;
			gmm_prim_tx->gmmreg.sim_auth_rsp.key_seq  = gmm_prim->gmmreg.sim_auth_ind.key_seq;
			memcpy(gmm_prim_tx->gmmreg.sim_auth_rsp.rand, gmm_prim->gmmreg.sim_auth_ind.rand,
			       sizeof(gmm_prim_tx->gmmreg.sim_auth_rsp.rand));
			memset(gmm_prim_tx->gmmreg.sim_auth_rsp.sres, 0xac,
			       sizeof(gmm_prim_tx->gmmreg.sim_auth_rsp.sres));
			memset(gmm_prim_tx->gmmreg.sim_auth_rsp.kc, 0xbd,
			       sizeof(gmm_prim_tx->gmmreg.sim_auth_rsp.kc));
			rc = osmo_gprs_gmm_prim_upper_down(gmm_prim_tx);
			OSMO_ASSERT(rc == 0);
			break;
		default:
			printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
			OSMO_ASSERT(0)
		}
		break;
	case OSMO_GPRS_GMM_SAP_GMMSM:
		switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_ESTABLISH, PRIM_OP_CONFIRM):
			if (gmm_prim->gmmsm.establish_cnf.accepted)
				printf("%s(): Rx %s sess_id=%u accepted\n", __func__, pdu_name,
				       gmm_prim->gmmsm.sess_id);
			else
				printf("%s(): Rx %s sess_id=%u rejected cause=%u\n", __func__, pdu_name,
				       gmm_prim->gmmsm.sess_id,
				       gmm_prim->gmmsm.establish_cnf.rej.cause);
			break;
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_UNITDATA, PRIM_OP_INDICATION):
			printf("%s(): Rx %s sess_id=%u sm_pdu=%s\n", __func__, pdu_name,
			       gmm_prim->gmmsm.sess_id,
			       osmo_hexdump(gmm_prim->gmmsm.unitdata_ind.smpdu,
					    gmm_prim->gmmsm.unitdata_ind.smpdu_len));
			break;
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_RELEASE, PRIM_OP_INDICATION):
			printf("%s(): Rx %s sess_id=%u\n", __func__, pdu_name,
			       gmm_prim->gmmsm.sess_id);
			break;
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_MODIFY, PRIM_OP_INDICATION):
			printf("%s(): Rx %s sess_id=%u allocated_ptmsi=0x%08x allocated_ptmsi_sig=0x%06x allocated_tlli=0x%08x\n", __func__, pdu_name,
			       gmm_prim->gmmsm.sess_id,
			       gmm_prim->gmmsm.modify_ind.allocated_ptmsi,
			       gmm_prim->gmmsm.modify_ind.allocated_ptmsi_sig,
			       gmm_prim->gmmsm.modify_ind.allocated_tlli);
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
		printf("%s(): Rx %s old_tlli=0x%08x new_tlli=0x%08x\n",
		       __func__, pdu_name,
		       gmm_prim->gmmrr.tlli, gmm_prim->gmmrr.assign_req.new_tlli);
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
	struct osmo_gprs_gmm_prim *gmm_prim_tx;

	switch (llc_prim->oph.sap) {
	case OSMO_GPRS_LLC_SAP_LLGMM:
		switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_ASSIGN, PRIM_OP_REQUEST):
			printf("%s(): Rx %s old_TLLI=0x%08x new_TLLI=0x%08x\n",
			       __func__, pdu_name,
			       llc_prim->llgmm.tlli, llc_prim->llgmm.assign_req.tlli_new);
			break;
		default:
			printf("%s(): Rx %s TLLI=0x%08x\n", __func__, pdu_name, llc_prim->llgmm.tlli);
		}
		break;
	case OSMO_GPRS_LLC_SAP_LL:
		printf("%s(): Rx %s TLLI=0x%08x SAPI=%s l3=[%s]\n", __func__, pdu_name,
		       llc_prim->ll.tlli, osmo_gprs_llc_sapi_name(llc_prim->ll.sapi),
		       osmo_hexdump(llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len));
		switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_LLC_LL_UNITDATA, PRIM_OP_REQUEST):
			/* Immediately notify GMM that it was transmitted over the air: */
			gmm_prim_tx = (struct osmo_gprs_gmm_prim *)gprs_rlcmac_prim_alloc_gmmrr_llc_transmitted_ind(llc_prim->ll.tlli);
			gmm_prim_tx->oph.sap = OSMO_GPRS_GMM_SAP_GMMRR;
			gmm_prim_tx->oph.primitive = OSMO_GPRS_GMM_GMMRR_LLC_TRANSMITTED;
			osmo_gprs_gmm_prim_lower_up(gmm_prim_tx);
			break;
		}
		break;
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

/* Test explicit GPRS attach through GMMREG, TS 24.007 Annex C.1 */
static void test_gmm_prim_ms_gmmreg(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	uint32_t ptmsi = 0x00001234;
	uint32_t ptmsi_sig = 0x556677;
	uint32_t rand_tlli = 0x80001234;
	uint32_t tlli;
	char *imsi = "1234567890";
	char *imei = "42342342342342";
	char *imeisv = "4234234234234275";

	printf("==== %s() [start] ====\n", __func__);

	clock_override_set(0, 0);

	rc = osmo_gprs_gmm_init(OSMO_GPRS_GMM_LOCATION_MS);
	OSMO_ASSERT(rc == 0);
	osmo_gprs_gmm_enable_gprs(true);

	osmo_gprs_gmm_prim_set_up_cb(test_gmm_prim_up_cb, NULL);
	osmo_gprs_gmm_prim_set_down_cb(test_gmm_prim_down_cb, NULL);
	osmo_gprs_gmm_prim_set_llc_down_cb(test_gmm_prim_llc_down_cb, NULL);

	/* MS sends GMM Attach Req */
	gmm_prim = osmo_gprs_gmm_prim_alloc_gmmreg_attach_req();
	OSMO_ASSERT(gmm_prim);
	gmm_prim->gmmreg.attach_req.attach_type = OSMO_GPRS_GMM_ATTACH_TYPE_GPRS;
	gmm_prim->gmmreg.attach_req.ptmsi = ptmsi;
	gmm_prim->gmmreg.attach_req.ptmsi_sig = ptmsi_sig;
	OSMO_STRLCPY_ARRAY(gmm_prim->gmmreg.attach_req.imsi, imsi);
	OSMO_STRLCPY_ARRAY(gmm_prim->gmmreg.attach_req.imei, imei);
	OSMO_STRLCPY_ARRAY(gmm_prim->gmmreg.attach_req.imeisv, imeisv);
	gmm_prim->gmmreg.attach_req.old_rai = (struct gprs_ra_id){
		.mcc = 0,
		.mnc = 0,
		.mnc_3_digits = false,
		.lac = 0,
		.rac = 0,
	};
	rc = osmo_gprs_gmm_prim_upper_down(gmm_prim);
	OSMO_ASSERT(rc == 0);

	/* Network answers with GMM Identity Req: */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(rand_tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_identity_req, sizeof(pdu_gmm_identity_req));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* As a result, MS answers GMM Identity Resp */

	/* Network sends GMM Ciph Auth Req */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(rand_tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_auth_ciph_req, sizeof(pdu_gmm_auth_ciph_req));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* As a result, MS answers GMM Ciph Auth Resp */

	/* Network sends GMM Attach Accept */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(rand_tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_att_acc, sizeof(pdu_gmm_att_acc));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* update the used ptmsi to align with what was assigned from the network: */
	ptmsi = 0xea711b41;
	tlli = gprs_tmsi2tlli(ptmsi, TLLI_LOCAL);
	/* As a result, MS answers GMM Attach Complete */
	/* As a result, MS submits GMMREG ATTACH.cnf */

	/* Wait for READY timer to expire: */
	clock_override_add(44, 0); /* 44: See GMM Attach Accept (pdu_gmm_att_acc) fed above */
	clock_debug("Expect T3314 (READY) timeout");
	osmo_select_main(0);

	clock_override_add(10*60, 0); /* 10*60: See GMM Attach Accept (pdu_gmm_att_acc) fed above */
	clock_debug("Expect T3312 (periodic RAU) timeout");
	osmo_select_main(0);

	/* Network sends GMM RAU Accept */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_rau_acc, sizeof(pdu_gmm_rau_acc));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* update the used ptmsi to align with what was assigned from the network: */
	ptmsi = 0xec999002;
	tlli = gprs_tmsi2tlli(ptmsi, TLLI_LOCAL);
	/* As a result, MS answers GMM RAU Complete */

	/* ... */

	/* Test PS paging request arriving from CCCH (RR): */
	gmm_prim = osmo_gprs_gmm_prim_alloc_gmmrr_page_ind(tlli);
	OSMO_ASSERT(gmm_prim);
	rc = osmo_gprs_gmm_prim_lower_up(gmm_prim);
	OSMO_ASSERT(rc == 0);

	/* ... */

	/* Test Network sends P-TMSI Reallocation Cmd */
#if 0
	/* TODO: find a pcap with a P-TMSI Reallocation Cmd */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_ptmsi_realloc_cmd, sizeof(pdu_gmm_ptmsi_realloc_cmd));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* update the used ptmsi to align with what was assigned from the network: */
	ptmsi = 0xea711b41;
	tlli = gprs_tmsi2tlli(ptmsi, TLLI_LOCAL);
	/* As a result, MS answers GMM P-TMSI Reallocation Complete */
#endif


	/* ... */

	/* DETACH */
	gmm_prim = osmo_gprs_gmm_prim_alloc_gmmreg_detach_req();
	OSMO_ASSERT(gmm_prim);
	gmm_prim->gmmreg.detach_req.detach_type = OSMO_GPRS_GMM_DETACH_MS_TYPE_GPRS;
	gmm_prim->gmmreg.detach_req.poweroff_type = OSMO_GPRS_GMM_DETACH_POWEROFF_TYPE_NORMAL;
	gmm_prim->gmmreg.detach_req.ptmsi = ptmsi;
	rc = osmo_gprs_gmm_prim_upper_down(gmm_prim);
	OSMO_ASSERT(rc == 0);

	/* Network sends GMM Detach Accept */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_detach_acc, sizeof(pdu_gmm_detach_acc));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* As a result, MS answers GMM Attach Complete */

	printf("==== %s() [end] ====\n", __func__);
}

/* Test implicit GPRS attach through SM (ACT PDP CTX), TS 24.007 Annex C.3 */
static void test_gmm_prim_ms_gmmsm(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	uint32_t ptmsi = 0x00001234;
	uint32_t ptmsi_sig = 0x556677;
	uint32_t rand_tlli = 0x80001234;
	uint32_t tlli;
	char *imsi = "1234567890";
	char *imei = "42342342342342";
	char *imeisv = "4234234234234275";
	uint32_t sess_id = 1234;
	uint8_t sm_pdu[] = {GSM48_PDISC_SM_GPRS, 0x28, 0x29, 0x30}; /* fake SM PDU */

	printf("==== %s() [start] ====\n", __func__);

	clock_override_set(0, 0);

	rc = osmo_gprs_gmm_init(OSMO_GPRS_GMM_LOCATION_MS);
	OSMO_ASSERT(rc == 0);
	osmo_gprs_gmm_enable_gprs(true);

	osmo_gprs_gmm_prim_set_up_cb(test_gmm_prim_up_cb, NULL);
	osmo_gprs_gmm_prim_set_down_cb(test_gmm_prim_down_cb, NULL);
	osmo_gprs_gmm_prim_set_llc_down_cb(test_gmm_prim_llc_down_cb, NULL);

	/* MS sends primitive to active a PDP ctx: */
	gmm_prim = osmo_gprs_gmm_prim_alloc_gmmsm_establish_req(sess_id);
	OSMO_ASSERT(gmm_prim);
	gmm_prim->gmmsm.establish_req.attach_type = OSMO_GPRS_GMM_ATTACH_TYPE_GPRS;
	gmm_prim->gmmsm.establish_req.ptmsi = ptmsi;
	gmm_prim->gmmsm.establish_req.ptmsi_sig = ptmsi_sig;
	OSMO_STRLCPY_ARRAY(gmm_prim->gmmsm.establish_req.imsi, imsi);
	OSMO_STRLCPY_ARRAY(gmm_prim->gmmsm.establish_req.imei, imei);
	OSMO_STRLCPY_ARRAY(gmm_prim->gmmsm.establish_req.imeisv, imeisv);
	rc = osmo_gprs_gmm_prim_upper_down(gmm_prim);
	OSMO_ASSERT(rc == 0);
	/* MS sends GMM Attach Req first since its not eyt attached */

	/* Network answers with GMM Identity Req: */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(rand_tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_identity_req, sizeof(pdu_gmm_identity_req));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* As a result, MS answers GMM Identity Resp */

	/* Network sends GMM Ciph Auth Req */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(rand_tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_auth_ciph_req, sizeof(pdu_gmm_auth_ciph_req));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* As a result, MS answers GMM Ciph Auth Resp */

	/* Network sends GMM Attach Accept */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(rand_tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_att_acc, sizeof(pdu_gmm_att_acc));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* As a result, MS answers GMM Attach Complete */
	/* As a result, MS submits GMMSM Establish.cnf */

	/* SM layer submits Activate PDP Context Req: */
	gmm_prim = osmo_gprs_gmm_prim_alloc_gmmsm_unitdata_req(sess_id, sm_pdu, sizeof(sm_pdu));
	rc = osmo_gprs_gmm_prim_upper_down(gmm_prim);
	OSMO_ASSERT(rc == 0);
	/* As a result, GMM submits LLC-LL-UNITDATA.req */

	/* Network answers with Activate PDP Ctx Accept, LLC submits the pdu up to GMM: */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(rand_tlli, OSMO_GPRS_LLC_SAPI_GMM, sm_pdu, sizeof(sm_pdu));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* As a result, GMM submits GMMSM-UNITDATA.ind */

	/* Wait for READY timer to expire: */
	clock_override_add(44, 0); /* 44: See GMM Attach Accept (pdu_gmm_att_acc) fed above */
	clock_debug("Expect T3314 (READY) timeout");
	osmo_select_main(0);

	clock_override_add(10*60, 0); /* 10*60: See GMM Attach Accept (pdu_gmm_att_acc) fed above */
	clock_debug("Expect T3312 (periodic RAU) timeout");
	osmo_select_main(0);

	/* Network sends GMM RAU Accept */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(rand_tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_rau_acc, sizeof(pdu_gmm_rau_acc));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	OSMO_ASSERT(rc == 0);
	/* update the used ptmsi to align with what was assigned from the network: */
	ptmsi = 0xec999002;
	tlli = gprs_tmsi2tlli(ptmsi, TLLI_LOCAL);
	(void)tlli;
	/* As a result, GMM submits GMMSM-MODIFY.ind */
	/* As a result, MS answers GMM RAU Complete */

	/* DEACT: TODO */

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

	clock_override_enable(true);

	test_gmm_prim_ms_gmmreg();
	test_gmm_prim_ms_gmmsm();

	talloc_free(tall_ctx);
}
