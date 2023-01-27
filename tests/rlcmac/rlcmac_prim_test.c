/* rlcmac_prim_test.c
 *
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#include <osmocom/core/fsm.h>

#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/gre.h>

static void *tall_ctx = NULL;

uint8_t last_rach_req_ra = 0;

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

/**
GSM CCCH - Immediate Assignment
	L2 Pseudo Length
		0010 11.. = L2 Pseudo Length value: 11
	.... 0110 = Protocol discriminator: Radio Resources Management messages (0x6)
		.... 0110 = Protocol discriminator: Radio Resources Management messages (0x6)
		0000 .... = Skip Indicator: No indication of selected PLMN (0)
	Message Type: Immediate Assignment
	Page Mode
		.... 0000 = Page Mode: Normal paging (0)
	Dedicated mode or TBF
		0001 .... = Dedicated mode or TBF: This message assigns an uplink TBF or is the second message of two in a two-message assignment of an uplink or downlink TBF (1)
	Packet Channel Description
		0000 1... = Channel Type: 1
		.... .111 = Timeslot: 7
		111. .... = Training Sequence: 7
		.... .0.. = Spare: 0x00
		.... ..11  0110 0111 = Single channel ARFCN: 871
	Request Reference
		Random Access Information (RA): 120
		0000 1... = T1': 1
		.... .001 011. .... = T3: 11
		...0 1011 = T2: 11
		[RFN: 1337]
	Timing Advance
		Timing advance value: 0
	Mobile Allocation
		Length: 0
	IA Rest Octets
		H... .... = First Discriminator Bit: High
		.H.. .... = Second Discriminator Bit: High
		..0. .... = Discriminator Bit: Packet Assignment
		...0 .... = Discriminator Bit: Packet Uplink Assignment
		Packet Uplink Assignment
			.... 1... = Packet Uplink Assignment: Normal
			.... .000  00.. .... = TFI_Assignment: 0
			..0. .... = Polling: no action is required from MS
			...0 .... = Allocation Type: Dynamic Allocation (mandatory after Rel-4)
			.... 000. = USF: 0
			.... ...0 = USF_granularity: the mobile station shall transmit one RLC/MAC block
			0... .... = P0: Not Present
			.01. .... = Channel_Coding_Command: CS-2 (1)
			...1 .... = TLLI_Block_Channel_Coding: mobile station shall use coding scheme as specified by the corresponding CHANNEL CODING COMMAND or EGPRS CHANNEL CODING COMMAND field
			.... 0... = Alpha: Not Present
			.... .000  00.. .... = Gamma: 0 dB (0)
			..0. .... = Timing Advance Index: Not Present
			...0 .... = TBF Starting Time: Not Present
			.... L... = Additions in R99: Not Present
			.... .L.. = Additions in Rel-6: Not Present
		.... ..L. = Additions in Rel-10: Not Present
		.... ...L = Additions in Rel-13: Not Present
		Padding Bits: default padding
*/
static uint8_t ccch_imm_ass_pkt_ul_tbf_normal[] = {
	0x2d, 0x06, 0x3f, 0x10, 0x0f, 0xe3, 0x67, 0x78, 0x09, 0x6b,
	0x00, 0x00, 0xc8, 0x00, 0x30, 0x0b,
	0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b
};

static int test_rlcmac_prim_up_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_rlcmac_prim_name(rlcmac_prim);

	switch (rlcmac_prim->oph.sap) {
	case OSMO_GPRS_RLCMAC_SAP_GMMRR:
		printf("%s(): Rx %s TLLI=0x%08x\n", __func__, pdu_name, rlcmac_prim->gmmrr.page_ind.tlli);
		break;
	case OSMO_GPRS_RLCMAC_SAP_GRR:
		printf("%s(): Rx %s TLLI=0x%08x SAPI=%s ll=[%s]\n", __func__, pdu_name,
		       rlcmac_prim->grr.tlli,
		       get_value_string(osmo_gprs_rlcmac_llc_sapi_names, rlcmac_prim->grr.unitdata_req.sapi),
		       osmo_hexdump(rlcmac_prim->grr.ll_pdu, rlcmac_prim->grr.ll_pdu_len));
		break;
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

static int test_rlcmac_prim_down_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_rlcmac_prim_name(rlcmac_prim);

	switch (rlcmac_prim->oph.sap) {
	case OSMO_GPRS_RLCMAC_SAP_L1CTL:
		switch (OSMO_PRIM_HDR(&rlcmac_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_RLCMAC_L1CTL_RACH, PRIM_OP_REQUEST):
			last_rach_req_ra = rlcmac_prim->l1ctl.rach_req.ra;
			printf("%s(): Rx %s ra=0x%02x\n", __func__, pdu_name, last_rach_req_ra);
			break;
		case OSMO_PRIM(OSMO_GPRS_RLCMAC_L1CTL_CFG_UL_TBF, PRIM_OP_REQUEST):
			printf("%s(): Rx %s ul_tbf_nr=%u ul_slotmask=0x%02x\n", __func__, pdu_name,
			       rlcmac_prim->l1ctl.cfg_ul_tbf_req.ul_tbf_nr,
			       rlcmac_prim->l1ctl.cfg_ul_tbf_req.ul_slotmask);
			break;
		default:
			printf("%s(): Rx %s\n", __func__, pdu_name);
		}
		break;
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

void prepare_test(void)
{
	int rc;
	rc = osmo_gprs_rlcmac_init(OSMO_GPRS_RLCMAC_LOCATION_MS);
	OSMO_ASSERT(rc == 0);

	osmo_gprs_rlcmac_prim_set_up_cb(test_rlcmac_prim_up_cb, NULL);
	osmo_gprs_rlcmac_prim_set_down_cb(test_rlcmac_prim_down_cb, NULL);
}

static void test_ul_tbf_attach(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	uint32_t tlli = 0x2342;

	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, pdu_llc_gmm_att_req,
					    sizeof(pdu_llc_gmm_att_req));
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	OSMO_ASSERT(sizeof(ccch_imm_ass_pkt_ul_tbf_normal) == GSM_MACBLOCK_LEN);
	ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);

	OSMO_ASSERT(rc == 0);
	printf("=== %s end ===\n", __func__);
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

	test_ul_tbf_attach();

	talloc_free(tall_ctx);
}
