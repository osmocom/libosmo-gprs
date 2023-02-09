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
#include <osmocom/gprs/rlcmac/rlc.h>

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

/*
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
		0011 .... = Dedicated mode or TBF: This message assigns a downlink TBF to the mobile station identified in the IA Rest Octets IE (3)
	Packet Channel Description
		0000 1... = Channel Type: 1
		.... .111 = Timeslot: 7
		111. .... = Training Sequence: 7
		.... .0.. = Spare: 0x00
		.... ..11  0110 0111 = Single channel ARFCN: 871
	Request Reference
		Random Access Information (RA): 125
		1000 0... = T1': 16
		.... .000 000. .... = T3: 0
		...0 0000 = T2: 0
		[RFN: 21216]
	Timing Advance
		Timing advance value: 28
	Mobile Allocation
		Length: 0
	IA Rest Octets
		H... .... = First Discriminator Bit: High
		.H.. .... = Second Discriminator Bit: High
		..0. .... = Discriminator Bit: Packet Assignment
		...1 .... = Discriminator Bit: Packet Downlink Assignment
		Packet Downlink Assignment
			.... 0000  0000 0000  0000 0000  0000 0000  0001 .... = TLLI: 0x00000001
			.... 1... = TFI Assignment (etc): Present
			.... .000  00.. .... = TFI_Assignment: 0
			..0. .... = RLC_Mode: RLC acknowledged mode
			...0 .... = Alpha: Not Present
			.... 0000  0... .... = Gamma: 0 dB (0)
			.0.. .... = Polling: no action is required from MS
			..0. .... = TA_Valid: the timing advance value is not valid
			...0 .... = Timing Advance Index: Not Present
			.... 0... = TBF Starting Time: Not Present
			.... .0.. = P0: Not Present
			.... ..L. = Additions in R99: Not Present
			.... ...L = Additions in Rel-6: Not Present
			L... .... = Additions in Rel-7: Not Present
		.L.. .... = Additions in Rel-10: Not Present
		..L. .... = Additions in Rel-13: Not Present
		Padding Bits: default padding
*/
static uint8_t ccch_imm_ass_pkt_dl_tbf[] = {
	0x2d, 0x06, 0x3f, 0x30, 0x0f, 0xe3, 0x67, 0x7d, 0x80, 0x00,
	0x1c, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x18, 0x00, 0x03,
	0x2b, 0x2b, 0x2b, 0x2b
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
		case OSMO_PRIM(OSMO_GPRS_RLCMAC_L1CTL_PDCH_DATA, PRIM_OP_REQUEST):
			printf("%s(): Rx %s fn=%u ts=%u data_len=%u data=[%s]\n", __func__, pdu_name,
			       rlcmac_prim->l1ctl.pdch_data_req.fn,
			       rlcmac_prim->l1ctl.pdch_data_req.ts_nr,
			       rlcmac_prim->l1ctl.pdch_data_req.data_len,
			       osmo_hexdump(rlcmac_prim->l1ctl.pdch_data_req.data, rlcmac_prim->l1ctl.pdch_data_req.data_len));
			break;
		case OSMO_PRIM(OSMO_GPRS_RLCMAC_L1CTL_RACH, PRIM_OP_REQUEST):
			last_rach_req_ra = rlcmac_prim->l1ctl.rach_req.ra;
			printf("%s(): Rx %s ra=0x%02x\n", __func__, pdu_name, last_rach_req_ra);
			break;
		case OSMO_PRIM(OSMO_GPRS_RLCMAC_L1CTL_CFG_UL_TBF, PRIM_OP_REQUEST):
			printf("%s(): Rx %s ul_tbf_nr=%u ul_slotmask=0x%02x\n", __func__, pdu_name,
			       rlcmac_prim->l1ctl.cfg_ul_tbf_req.ul_tbf_nr,
			       rlcmac_prim->l1ctl.cfg_ul_tbf_req.ul_slotmask);
			break;
		case OSMO_PRIM(OSMO_GPRS_RLCMAC_L1CTL_CFG_DL_TBF, PRIM_OP_REQUEST):
			printf("%s(): Rx %s dl_tbf_nr=%u dl_slotmask=0x%02x dl_tfi=%u\n", __func__, pdu_name,
			       rlcmac_prim->l1ctl.cfg_dl_tbf_req.dl_tbf_nr,
			       rlcmac_prim->l1ctl.cfg_dl_tbf_req.dl_slotmask,
			       rlcmac_prim->l1ctl.cfg_dl_tbf_req.dl_tfi);
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

static const uint8_t llc_dummy_command[] = {
	0x43, 0xc0, 0x01, 0x2b, 0x2b, 0x2b
};

static struct msgb *create_dl_data_block(uint8_t dl_tfi, uint8_t usf, enum gprs_rlcmac_coding_scheme cs, uint8_t bsn, bool fbi)
{
	struct msgb *msg = msgb_alloc(128, __func__);
	struct gprs_rlcmac_rlc_dl_data_header *hdr;
	struct gprs_rlcmac_rlc_li_field *lime;

	hdr = (struct gprs_rlcmac_rlc_dl_data_header *)msgb_put(msg, gprs_rlcmac_mcs_size_dl(cs));
	hdr->pt = 0; /* RLC/MAC block contains an RLC data block */
	hdr->rrbp = 0;
	hdr->s_p = 0;
	hdr->usf = usf;
	hdr->pr = 0;
	hdr->tfi = dl_tfi;
	hdr->fbi = fbi ? 1 : 0;
	hdr->tfi = dl_tfi;
	hdr->bsn = bsn;
	hdr->e = 0;
	lime = &hdr->lime[0];
	lime->li = sizeof(llc_dummy_command);
	lime->m = 0;
	lime->e = 1;
	msg->l3h = &lime->ll_pdu[0];
	memset(msg->l3h, 0x2b, msgb_l3len(msg));
	memcpy(msg->l3h, llc_dummy_command, sizeof(llc_dummy_command));
	return msg;
}

void prepare_test(void)
{
	int rc;
	rc = osmo_gprs_rlcmac_init(OSMO_GPRS_RLCMAC_LOCATION_MS);
	OSMO_ASSERT(rc == 0);

	osmo_gprs_rlcmac_prim_set_up_cb(test_rlcmac_prim_up_cb, NULL);
	osmo_gprs_rlcmac_prim_set_down_cb(test_rlcmac_prim_down_cb, NULL);
}

void cleanup_test(void)
{
	/* Reinit the RLCMAC layer so that data generated during the test is freed within the test context: */
	osmo_gprs_rlcmac_init(OSMO_GPRS_RLCMAC_LOCATION_MS);
}

static void test_ul_tbf_attach(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	uint32_t tlli = 0x2342;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;

	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, pdu_llc_gmm_att_req,
					    sizeof(pdu_llc_gmm_att_req));
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	OSMO_ASSERT(sizeof(ccch_imm_ass_pkt_ul_tbf_normal) == GSM_MACBLOCK_LEN);
	ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);

	/* Trigger transmission of LLC data (GMM Attach) */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);

	OSMO_ASSERT(rc == 0);

	printf("=== %s end ===\n", __func__);
	cleanup_test();
}

/* PCU allocates a DL TBF through PCH ImmAss for MS (when in packet-idle) */
static void test_dl_tbf_ccch_assign(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;
	struct msgb *dl_data_msg;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	uint32_t tlli = 0x0000001;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;
	uint8_t dl_tfi = 0;

	/* Notify RLCMAC about our TLLI */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_gmmrr_assign_req(tlli);
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	OSMO_ASSERT(sizeof(ccch_imm_ass_pkt_dl_tbf) == GSM_MACBLOCK_LEN);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_dl_tbf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Transmit some DL LLC data MS<-PCU */
	dl_data_msg = create_dl_data_block(dl_tfi, usf, GPRS_RLCMAC_CS_1, 0, 1);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_data_ind(ts_nr, rts_fn, 0, 0, 0,
								      msgb_data(dl_data_msg),
								      msgb_length(dl_data_msg));
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);
	msgb_free(dl_data_msg);

	printf("=== %s end ===\n", __func__);
	cleanup_test();
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
	test_dl_tbf_ccch_assign();

	talloc_free(tall_ctx);
}
