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
#include <osmocom/core/timer.h>
#include <osmocom/core/timer_compat.h>
#include <osmocom/core/select.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48_rest_octets.h>

#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/rlc.h>
#include <osmocom/gprs/rlcmac/rlc_window.h>
#include <osmocom/gprs/rlcmac/types_private.h>
#include <osmocom/gprs/rlcmac/sched.h>

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

/* GMM Attach Compl */
static uint8_t pdu_llc_gmm_att_compl[] = { 0x01, 0xc0, 0x0d, 0x08, 0x03, 0x55, 0x1c, 0xea };

/* SM Activate PDP Context Request */
static uint8_t pdu_llc_sm_act_pdp_ctx_req[] = {
	0x01, 0xc0, 0x11, 0x8a, 0x41, 0x06, 0x03, 0x0e,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01,
	0x21, 0x28, 0x09, 0x08, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x9e, 0x49, 0x7a
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

/*
GSM CCCH - Paging Request Type 1
 L2 Pseudo Length
  0011 00.. = L2 Pseudo Length value: 12
 .... 0110 = Protocol discriminator: Radio Resources Management messages (0x6)
  .... 0110 = Protocol discriminator: Radio Resources Management messages (0x6)
  0000 .... = Skip Indicator: No indication of selected PLMN (0)
 Message Type: Paging Request Type 1
 Page Mode
  .... 0000 = Page Mode: Normal paging (0)
 Channel Needed
  ..00 .... = Channel 1: Any channel (0)
  00.. .... = Channel 2: Any channel (0)
 Mobile Identity - Mobile Identity 1 - IMSI (262420000000423)
  Length: 8
  0010 .... = Identity Digit 1: 2
  .... 1... = Odd/even indication: Odd number of identity digits
  .... .001 = Mobile Identity Type: IMSI (1)
  IMSI: 262420000000423
  [Association IMSI: 262420000000423]
    Mobile Country Code (MCC): Germany (262)
    Mobile Network Code (MNC): Vodafone GmbH (42)
 P1 Rest Octets
  L... .... = NLN(PCH): Not Present
  .L.. .... = Priority 1: Not Present
  ..L. .... = Priority 2: Not Present
  ...L .... = Group Call Information: Not Present
  .... H... = Packet Page Indication 1: For GPRS
  .... .H.. = Packet Page Indication 2: For GPRS
  Padding Bits: default padding

*/
static uint8_t ccch_pag_req_1[] = {
	0x31, 0x06, 0x21, 0x00, 0x08, 0x29, 0x26, 0x24, 0x00, 0x00,
	0x00, 0x40, 0x32, 0x27, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b,
	0x2b, 0x2b, 0x2b, 0x2b
};


#define clock_debug(fmt, args...) \
	do { \
		struct timespec ts; \
		struct timeval tv; \
		osmo_clock_gettime(CLOCK_MONOTONIC, &ts); \
		osmo_gettimeofday(&tv, NULL); \
		fprintf(stdout, "sys={%lu.%06lu}, mono={%lu.%06lu}: " fmt "\n", \
			tv.tv_sec, tv.tv_usec, ts.tv_sec, ts.tv_nsec/1000, ##args); \
	} while (0)

static void clock_override_enable(bool enable)
{
	osmo_gettimeofday_override = enable;
	osmo_clock_override_enable(CLOCK_MONOTONIC, enable);
}

static void clock_override_set(long sec, long usec)
{
	struct timespec *mono;
	osmo_gettimeofday_override_time.tv_sec = sec;
	osmo_gettimeofday_override_time.tv_usec = usec;
	mono = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	mono->tv_sec = sec;
	mono->tv_nsec = usec*1000;

	clock_debug("clock_override_set");
}

static void clock_override_add_debug(long sec, long usec, bool dbg)
{
	osmo_gettimeofday_override_add(sec, usec);
	osmo_clock_override_add(CLOCK_MONOTONIC, sec, usec*1000);
	if (dbg)
		clock_debug("clock_override_add");
}
#define clock_override_add(sec, usec) clock_override_add_debug(sec, usec, true)

static struct osmo_gprs_rlcmac_prim *create_dl_ctrl_block_buf(uint8_t *buf, int num_bytes, uint8_t tn, uint32_t fn)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;


	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_data_ind(tn, fn, 0, 0, 0,
								      NULL, num_bytes);
	rlcmac_prim->l1ctl.pdch_data_ind.data = msgb_put(rlcmac_prim->oph.msg, num_bytes);
	memcpy(rlcmac_prim->l1ctl.pdch_data_ind.data, buf, num_bytes);
	return rlcmac_prim;
}

static struct osmo_gprs_rlcmac_prim *create_dl_ctrl_block(RlcMacDownlink_t *dl_block, uint8_t tn, uint32_t fn)
{
	struct bitvec *rlc_block;
	uint8_t buf[64];
	int num_bytes;

	rlc_block = bitvec_alloc(23, tall_ctx);

	OSMO_ASSERT(osmo_gprs_rlcmac_encode_downlink(rlc_block, dl_block) == 0);
	num_bytes = bitvec_pack(rlc_block, &buf[0]);
	OSMO_ASSERT((size_t)num_bytes < sizeof(buf));
	bitvec_free(rlc_block);

	return create_dl_ctrl_block_buf(&buf[0], num_bytes, tn, fn);
}

static void ul_ack_nack_init(RlcMacDownlink_t *dl_block, uint8_t ul_tfi, enum gprs_rlcmac_coding_scheme cs)
{
	Packet_Uplink_Ack_Nack_t *ack = &dl_block->u.Packet_Uplink_Ack_Nack;
	PU_AckNack_GPRS_t *gprs = &ack->u.PU_AckNack_GPRS_Struct;

	memset(dl_block, 0, sizeof(*dl_block));
	dl_block->PAYLOAD_TYPE = GPRS_RLCMAC_PT_CONTROL_BLOCK;
	dl_block->RRBP = 0;
	dl_block->SP = 0;
	dl_block->USF = 0x00;
	dl_block->u.MESSAGE_TYPE = OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_UPLINK_ACK_NACK;

	ack->MESSAGE_TYPE = OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_UPLINK_ACK_NACK;
	ack->PAGE_MODE = GPRS_RLCMAC_PAGE_MODE_NORMAL;
	ack->UPLINK_TFI = ul_tfi;
	ack->UnionType = 0; /* GPRS */

	gprs->CHANNEL_CODING_COMMAND = gprs_rlcmac_mcs_chan_code(cs);
}

static void ul_ack_nack_mark(Ack_Nack_Description_t *ack_desc, unsigned int idx, bool received)
{
	//ack_desc->RECEIVED_BLOCK_BITMAP[sizeof(ack_desc->RECEIVED_BLOCK_BITMAP) - 1] = 0xff;
	//memset(ack_desc->RECEIVED_BLOCK_BITMAP, 0xff, sizeof(ack_desc->RECEIVED_BLOCK_BITMAP));
	if (received)
		ack_desc->RECEIVED_BLOCK_BITMAP[sizeof(ack_desc->RECEIVED_BLOCK_BITMAP) - idx/8 - 1] |= (1 << (idx & 0x03));
	else
		ack_desc->RECEIVED_BLOCK_BITMAP[sizeof(ack_desc->RECEIVED_BLOCK_BITMAP) - idx/8 - 1] &= ~(1 << (idx & 0x03));
}

static void pkt_ul_ass_from_dl_tbf_init(RlcMacDownlink_t *block, uint8_t dl_tfi, uint8_t new_ul_tfi, uint16_t arfcn, uint8_t *usf_li)
{
	Packet_Uplink_Assignment_t *pua = &block->u.Packet_Uplink_Assignment;
	PUA_GPRS_t *gprs = &pua->u.PUA_GPRS_Struct;
	Packet_Timing_Advance_t *pta = &gprs->Packet_Timing_Advance;
	Frequency_Parameters_t *fp = &gprs->Frequency_Parameters;
	Dynamic_Allocation_t *da = &gprs->u.Dynamic_Allocation;
	unsigned int tn;

	memset(block, 0, sizeof(*block));
	block->PAYLOAD_TYPE = GPRS_RLCMAC_PT_CONTROL_BLOCK;
	block->RRBP = 0;
	block->SP = 0;
	block->USF = 0x00;
	block->u.MESSAGE_TYPE = OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_UPLINK_ASSIGNMENT;

	/* See 3GPP TS 44.060, section 11.2.29 */
	pua = &block->u.Packet_Uplink_Assignment;
	pua->MESSAGE_TYPE = OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_UPLINK_ASSIGNMENT;
	pua->PAGE_MODE    = 0x00;

	/* TLLI or Global DL TFI */
	pua->ID.UnionType = 0x00;
	pua->ID.u.Global_TFI.UnionType = 0x01;
	pua->ID.u.Global_TFI.u.UPLINK_TFI = dl_tfi;

	/* GPRS specific parameters */
	pua->UnionType = 0x00;
	/* Use the commanded CS/MCS value during the content resolution */
	gprs->CHANNEL_CODING_COMMAND    = gprs_rlcmac_mcs_chan_code(GPRS_RLCMAC_MCS_2);
	gprs->TLLI_BLOCK_CHANNEL_CODING = 0x01;  // ^^^
	/* Dynamic allocation */
	gprs->UnionType = 0x01;
	/* Frequency Parameters IE is present */
	gprs->Exist_Frequency_Parameters = 0x01;

	/* Packet Timing Advance (if known) */
	pta->Exist_TIMING_ADVANCE_VALUE = 0x01;  // Present
	pta->TIMING_ADVANCE_VALUE       = 1;

	/* Continuous Timing Advance Control */
	pta->Exist_IndexAndtimeSlot         = 0x01;  // Present
	pta->TIMING_ADVANCE_TIMESLOT_NUMBER = 0;  // FIXME!
	pta->TIMING_ADVANCE_INDEX           = 2;

	/* Frequency Parameters IE */
	fp->TSC = 2;
	fp->UnionType = 0x00;
	fp->u.ARFCN = arfcn;

	/* Dynamic allocation parameters */
	da->USF_GRANULARITY = 0x00;

	/* Assign an Uplink TFI */
	da->Exist_UPLINK_TFI_ASSIGNMENT = 0x01;
	da->UPLINK_TFI_ASSIGNMENT = new_ul_tfi;

	/* Timeslot Allocation with or without Power Control */
	da->UnionType = 0x00;

	for (tn = 0; tn < 8; tn++) {
		Timeslot_Allocation_t *slot = &da->u.Timeslot_Allocation[tn];
		if (usf_li[tn] == 0xff)
			continue;
		slot->Exist  = 0x01;  // Enable this timeslot
		slot->USF_TN = usf_li[tn];  // USF_TN(i)
	}
}

static uint8_t *create_si13(uint8_t bs_cv_max /* 0..15 */)
{
	static uint8_t si13_buf[GSM_MACBLOCK_LEN];
	struct gsm48_system_information_type_13 *si13 = (struct gsm48_system_information_type_13 *)&si13_buf[0];
	struct osmo_gsm48_si13_info si13_info;
	int ret;

	memset(si13, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si13->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si13->header.skip_indicator = 0;
	si13->header.system_information = GSM48_MT_RR_SYSINFO_13;

	si13_info = (struct osmo_gsm48_si13_info){
		.cell_opts = {
			.nmo		= GPRS_NMO_II,
			.t3168		= 2000,
			.t3192		= 1500,
			.drx_timer_max	= 3,
			.bs_cv_max	= bs_cv_max,
			.ctrl_ack_type_use_block = 1,
			.ext_info_present = true,
			.ext_info = {
				.egprs_supported = 1,
				.use_egprs_p_ch_req = 1,
				.bep_period = 5,
				.pfc_supported = 0,
				.dtm_supported = 0,
				.bss_paging_coordination = 1,
				.ccn_active = true,
			},
		},
		.pwr_ctrl_pars = {
			.alpha		= 0,	/* a = 0.0 */
			.t_avg_w	= 16,
			.t_avg_t	= 16,
			.pc_meas_chan	= 0,	/* downling measured on CCCH */
			.n_avg_i	= 8,
		},
		.bcch_change_mark	= 1, /* Information about the other SIs */
		.si_change_field	= 0,
		.rac		= 33,
		.spgc_ccch_sup	= 0,
		.net_ctrl_ord	= 1 /* NC1 */,
		.prio_acc_thr	= 6,
	};

	ret = osmo_gsm48_rest_octets_si13_encode(si13->rest_octets, &si13_info);
	if (ret < 0)
		return NULL;

	/* length is coded in bit 2 an up */
	si13->header.l2_plen = 0x01;

	return &si13_buf[0];
}

static int test_rlcmac_prim_up_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_rlcmac_prim_name(rlcmac_prim);

	switch (rlcmac_prim->oph.sap) {
	case OSMO_GPRS_RLCMAC_SAP_GMMRR:
		printf("%s(): Rx %s TLLI=0x%08x\n", __func__, pdu_name,
		       rlcmac_prim->gmmrr.tlli);
		break;
	case OSMO_GPRS_RLCMAC_SAP_GRR:
		printf("%s(): Rx %s TLLI=0x%08x ll=[%s]\n", __func__, pdu_name,
		       rlcmac_prim->grr.tlli,
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

static struct msgb *create_dl_data_block(uint8_t dl_tfi, uint8_t usf, enum gprs_rlcmac_coding_scheme cs, uint8_t bsn, bool fbi, bool s_p, uint8_t rrbp)
{
	struct msgb *msg = msgb_alloc(128, __func__);
	struct gprs_rlcmac_rlc_dl_data_header *hdr;
	struct gprs_rlcmac_rlc_li_field *lime;

	hdr = (struct gprs_rlcmac_rlc_dl_data_header *)msgb_put(msg, gprs_rlcmac_mcs_size_dl(cs));
	hdr->pt = 0; /* RLC/MAC block contains an RLC data block */
	hdr->rrbp = rrbp;
	hdr->s_p = s_p ? 1 : 0;
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
	clock_override_set(0, 0);

	rc = osmo_gprs_rlcmac_init(OSMO_GPRS_RLCMAC_LOCATION_MS);
	OSMO_ASSERT(rc == 0);

	osmo_gprs_rlcmac_prim_set_up_cb(test_rlcmac_prim_up_cb, NULL);
	osmo_gprs_rlcmac_prim_set_down_cb(test_rlcmac_prim_down_cb, NULL);
}

void cleanup_test(void)
{
	struct gprs_rlcmac_entity *gre;
	llist_for_each_entry(gre, &g_rlcmac_ctx->gre_list, entry) {
		if (osmo_timer_pending(&gre->defer_pkt_idle_timer)) {
			/* increase time DEFER_SCHED_PDCH_REL_REQ_uS, defer_pkt_idle_timer should trigger */
			clock_override_add(0, DEFER_SCHED_PDCH_REL_REQ_uS);
			clock_debug("Expect defer_pkt_idle_timer timeout");
			osmo_select_main(0);
			break;
		}
	}

	/* Reinit the RLCMAC layer so that data generated during the test is freed within the test context: */
	osmo_gprs_rlcmac_init(OSMO_GPRS_RLCMAC_LOCATION_MS);
}

static void test_ul_tbf_attach(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	RlcMacDownlink_t dl_block;
	Ack_Nack_Description_t *ack_desc = &dl_block.u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description;
	uint32_t tlli = 0x2342;
	uint8_t ul_tfi = 0;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;

	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, pdu_llc_gmm_att_req,
					    sizeof(pdu_llc_gmm_att_req));
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rlcmac_prim->grr.unitdata_req.radio_prio = 1;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	OSMO_ASSERT(sizeof(ccch_imm_ass_pkt_ul_tbf_normal) == GSM_MACBLOCK_LEN);
	ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);

	/* Trigger transmission of LLC data (GMM Attach) (first part) */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Trigger transmission of LLC data (GMM Attach) (second part) */
	rts_fn = fn_next_block(rts_fn);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* PCU acks it: */
	ul_ack_nack_init(&dl_block, ul_tfi, GPRS_RLCMAC_CS_2);
	ack_desc->STARTING_SEQUENCE_NUMBER = 1;
	ack_desc->FINAL_ACK_INDICATION = 1;
	ul_ack_nack_mark(ack_desc, 0, true);
	ul_ack_nack_mark(ack_desc, 1, true);
	/* Final ACK has Poll set: */
	dl_block.SP = 1;
	dl_block.RRBP = GPRS_RLCMAC_RRBP_N_plus_13;
	rlcmac_prim = create_dl_ctrl_block(&dl_block, ts_nr, rts_fn);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Trigger transmission of PKT CTRL ACK */
	rts_fn = rrbp2fn(rts_fn, dl_block.RRBP);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Trigger transmission confirmation of PKT CTRL ACK */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_data_cnf(ts_nr, rts_fn, NULL, 0);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);


	printf("=== %s end ===\n", __func__);
	cleanup_test();
}

/* Test UL TBF requesting assignment of a new UL TBF through PACCH when
 * answering UL ACK/NACK w/ FinalACK=1 */
static void test_ul_tbf_request_another_ul_tbf(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	RlcMacDownlink_t dl_block;
	PU_AckNack_GPRS_t *ack_gprs = &dl_block.u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct;
	Ack_Nack_Description_t *ack_desc = &ack_gprs->Ack_Nack_Description;
	uint32_t tlli = 0x2342;
	uint8_t ul_tfi = 0;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;

	/* Send only 14 data to feed it in 1 UL block and speed up test length: */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, pdu_llc_gmm_att_req,
					    14);
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rlcmac_prim->grr.unitdata_req.radio_prio = 1;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	OSMO_ASSERT(sizeof(ccch_imm_ass_pkt_ul_tbf_normal) == GSM_MACBLOCK_LEN);
	ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);

	/* Trigger transmission of LLC data (GMM Attach) */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* PCU acks it: */
	ul_ack_nack_init(&dl_block, ul_tfi, GPRS_RLCMAC_CS_2);
	ack_desc->STARTING_SEQUENCE_NUMBER = 1;
	ack_desc->FINAL_ACK_INDICATION = 1;
	ul_ack_nack_mark(ack_desc, 0, true);
	ul_ack_nack_mark(ack_desc, 1, true);
	/* TBF Est is set: */
	ack_gprs->Exist_AdditionsR99 = 1;
	ack_gprs->AdditionsR99.TBF_EST = 1;
	/* Final ACK has Poll set: */
	dl_block.SP = 1;
	dl_block.RRBP = GPRS_RLCMAC_RRBP_N_plus_13;
	rlcmac_prim = create_dl_ctrl_block(&dl_block, ts_nr, rts_fn);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* New data from upper layers arrive which needs to be transmitted. This
	 * will make UL_TBF request a new UL_TBF when triggered to answer the final
	 * UL ACK/NACK, because there's no active DL TBF: */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, pdu_llc_gmm_att_req,
					    14);
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rlcmac_prim->grr.unitdata_req.radio_prio = 1;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	/* Trigger transmission of PKT RES REQ: */
	rts_fn = rrbp2fn(rts_fn, dl_block.RRBP);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	printf("=== %s end ===\n", __func__);
	cleanup_test();
}

static void test_ul_tbf_t3164_timeout(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;
	unsigned int i;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	uint32_t tlli = 0x2342;

	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, pdu_llc_gmm_att_req,
					    sizeof(pdu_llc_gmm_att_req));
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rlcmac_prim->grr.unitdata_req.radio_prio = 1;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	OSMO_ASSERT(sizeof(ccch_imm_ass_pkt_ul_tbf_normal) == GSM_MACBLOCK_LEN);

	for (i = 0; i < 4; i++) {
		ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
		rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
		rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
		OSMO_ASSERT(rc == 0);

		/* increase time 5 seconds, timeout should trigger */
		clock_override_add(5, 0);
		clock_debug("Expect T3164 timeout");
		osmo_select_main(0);
	}

	printf("=== %s end ===\n", __func__);
	cleanup_test();
}

static void test_ul_tbf_t3166_timeout(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	uint32_t tlli = 0x2342;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;
	unsigned int i;

	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, pdu_llc_gmm_att_req,
					    sizeof(pdu_llc_gmm_att_req));
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rlcmac_prim->grr.unitdata_req.radio_prio = 1;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	for (i = 0; i < 4; i++) { /* 4 packet access procedure attempts */
		OSMO_ASSERT(sizeof(ccch_imm_ass_pkt_ul_tbf_normal) == GSM_MACBLOCK_LEN);
		ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
		rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
		rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);

		/* Trigger transmission of LLC data (GMM Attach) (first part) */
		rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
		rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
		OSMO_ASSERT(rc == 0);

		/* In 5 seconds, T3166 will trigger. T3180 has also been armed
		* at 5s, so scenify PCU USF-polling the MS to avoid trigger T3180
		* instead of T3166. First increase 2 of the 5 seconds: */
		clock_override_add(2, 0);
		rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
		rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
		OSMO_ASSERT(rc == 0);

		/* Increase time (remaining 3 out of 5 seconds), T3166 timeout should trigger */
		clock_override_add(3, 0);
		clock_debug("Expect T3166 timeout");
		osmo_select_main(0);
	}

	printf("=== %s end ===\n", __func__);
	cleanup_test();
}

static void test_ul_tbf_t3180_timeout(void)
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
	rlcmac_prim->grr.unitdata_req.radio_prio = 1;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	OSMO_ASSERT(sizeof(ccch_imm_ass_pkt_ul_tbf_normal) == GSM_MACBLOCK_LEN);
	ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);

	/* Trigger transmission of LLC data (GMM Attach) (first part) */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Transmit another block */
	rts_fn = fn_next_block(rts_fn);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* increase time 5 seconds, T3180 timeout should trigger */
	clock_override_add(5, 0);
	clock_debug("Expect T3180 timeout");
	osmo_select_main(0);

	printf("=== %s end ===\n", __func__);
	cleanup_test();
}

static void test_ul_tbf_n3104_timeout(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	uint32_t tlli = 0x2342;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;
	unsigned int i;
	const unsigned int bs_cv_max = 1; /* 0 interpreted as 1 for N3104max */
	const unsigned int num_ts = 1;
	const unsigned int n3104_max = 3 * (bs_cv_max + 3) * num_ts;

	/* Submit an SI13 with bs_cv_max=0: */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, create_si13(0));
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Fill in several LLC PDUs: */
	for (i = 0; i < 2; i++) {
		rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, pdu_llc_gmm_att_req,
						sizeof(pdu_llc_gmm_att_req));
		rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
		rlcmac_prim->grr.unitdata_req.radio_prio = 1;
		rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);
		OSMO_ASSERT(rc == 0);
	}


	ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	for (i = 0; i < n3104_max; i++) {
		rts_fn = fn_next_block(rts_fn);
		printf("RTS %u: FN=%u\n", i, rts_fn);
		/* Trigger transmission of LLC data (GMM Attach) (first part) */
		rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
		rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
		OSMO_ASSERT(rc == 0);
	}

	/* After N3104 triggers, MS re-tries pkt access: */
	ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);

	printf("=== %s end ===\n", __func__);
	cleanup_test();
}

/* 9.3.2.4.2 (acked mode): When the mobile station has sent the RLC data block
 * with CV = 0 and there are no elements in the V(B) array set to the value
 * Nacked, it shall start timer T3182 for this TBF. The mobile station shall
 * continue to send RLC data blocks on each assigned uplink data block,
 * according to the algorithm defined in sub-clause 9.1.3.
 * 9.3.3.3.2 (unacked mode): Upon each retransmission of the last block with
 * CV=0, the mobile station shall restart timer T3182 for the TBF. The block
 * with CV=0 shall not be retransmitted more than four times. If the medium
 * access mode is dynamic allocation, the repetitions are transmitted when the
 * mobile station is scheduled USFs.
 */
static void test_ul_tbf_t3182_timeout(bool acked_mode)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;
	unsigned int i;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	uint32_t tlli = 0x2342;
	uint8_t ul_tfi = 0;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;
	RlcMacDownlink_t dl_block;
	Ack_Nack_Description_t *ack_desc = &dl_block.u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description;

	/* Submit 14 bytes to fit in 1 RLCMAC block to shorten test and end up in FINISHED state quickly: */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, pdu_llc_gmm_att_req,
					    sizeof(pdu_llc_gmm_att_req));
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rlcmac_prim->grr.unitdata_req.radio_prio = 1;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Trigger transmission of LLC data (GMM Attach) (first part) */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* PCU acks it: */
	ul_ack_nack_init(&dl_block, ul_tfi, GPRS_RLCMAC_CS_2);
	ack_desc->STARTING_SEQUENCE_NUMBER = 1;
	ack_desc->FINAL_ACK_INDICATION = 0;
	ul_ack_nack_mark(ack_desc, 0, true);
	rlcmac_prim = create_dl_ctrl_block(&dl_block, ts_nr, rts_fn);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Trigger transmission of LLC data (GMM Attach) (second part, CV=0) */
	rts_fn = fn_next_block(rts_fn);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Now T3182 is armed and will trigger in 5 seconds. */

	if (acked_mode) {
		/* Keep sending some USF-polling from PCU to avoid T3180 triggering.
		 * while at it, make sure we don't apply the max-4-cv0-tx limit as with unacked mode: */
		for (i = 0; i < 5; i++) {
			/* increase time 1 seconds, timeout should trigger */
			clock_override_add(1, 0);
			rts_fn = fn_next_block(rts_fn);
			printf("RTS %u: FN=%u\n", i, rts_fn);
			/* Trigger transmission of LLC data (GMM Attach) (second part) */
			rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
			rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
			OSMO_ASSERT(rc == 0);
		}
	} else {
		for (i = 0; i < 2; i++) {
			/* Keep sending some USF-polling from PCU to avoid T3180 triggering:
			 * increase time 2.500 seconds 2 times = 5s, */
			clock_override_add(2, 500000);
			rts_fn = fn_next_block(rts_fn);
			printf("RTS %u: FN=%u\n", i, rts_fn);
			/* Trigger transmission of LLC data (GMM Attach) (second part) */
			rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
			rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
			OSMO_ASSERT(rc == 0);
		}
	}

	/* Timeout should trigger now: */
	clock_debug("Expect T3182 timeout");
	osmo_select_main(0);

	printf("=== %s end ===\n", __func__);
	cleanup_test();
}

#if 0
/* FIXME: enable this whenever unacknowledged mode is supported. */
/* 9.3.3.3.2: The block with CV=0 shall not be retransmitted more than four times. */
static void test_ul_tbf_unack_mode_last_data_cv0_retrans_max(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	uint32_t tlli = 0x2342;
	uint8_t ul_tfi = 0;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;
	unsigned int i;
	RlcMacDownlink_t dl_block;
	Ack_Nack_Description_t *ack_desc = &dl_block.u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description;

	/* Submit 14 bytes to fit in 1 RLCMAC block to shorten test and end up in FINISHED state quickly: */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, pdu_llc_gmm_att_req,
					    sizeof(pdu_llc_gmm_att_req));
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rlcmac_prim->grr.unitdata_req.radio_prio = 1;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Trigger transmission of LLC data (GMM Attach) (first part) */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* PCU acks it: */
	ul_ack_nack_init(&dl_block, ul_tfi, GPRS_RLCMAC_CS_2);
	ack_desc->STARTING_SEQUENCE_NUMBER = 1;
	ack_desc->FINAL_ACK_INDICATION = 0;
	ul_ack_nack_mark(ack_desc, 0, true);
	rlcmac_prim = create_dl_ctrl_block(&dl_block, ts_nr, rts_fn);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Trigger transmission of LLC data (GMM Attach) (second part) */
	rts_fn = fn_next_block(rts_fn);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	for (i = 0; i < 4; i++) {
		rts_fn = fn_next_block(rts_fn);
		printf("RTS %u: FN=%u\n", i, rts_fn);
		/* Trigger transmission of LLC data (GMM Attach) (second part) */
		rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
		rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
		OSMO_ASSERT(rc == 0);
	}

	printf("=== %s end ===\n", __func__);
	cleanup_test();
}
#endif

/* 9.3.1 Countdown procedure */
static void test_ul_tbf_countdown_procedure(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	uint32_t tlli = 0x2342;
	uint8_t ul_tfi = 0;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;
	uint8_t bs_cv_max = 4;
	unsigned int i;
	RlcMacDownlink_t dl_block;
	struct msgb *llc_msg = msgb_alloc(200, "llc_msg");
	Ack_Nack_Description_t *ack_desc = &dl_block.u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description;

	/* Submit an SI13 with bs_cv_max: */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, create_si13(bs_cv_max));
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);


	/* Submit LLC bytes */
	msgb_put(llc_msg, msgb_tailroom(llc_msg));
	memset(msgb_data(llc_msg), 0xab, msgb_length(llc_msg));
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, msgb_data(llc_msg), msgb_length(llc_msg));
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_SNDCP3;
	rlcmac_prim->grr.unitdata_req.radio_prio = 2;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	ccch_imm_ass_pkt_ul_tbf_normal[7] = last_rach_req_ra; /* Update RA to match */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_ul_tbf_normal);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Trigger transmission of LLC data (first part) */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* PCU acks it: */
	ul_ack_nack_init(&dl_block, ul_tfi, GPRS_RLCMAC_CS_2);
	ack_desc->STARTING_SEQUENCE_NUMBER = 1;
	ack_desc->FINAL_ACK_INDICATION = 0;
	ul_ack_nack_mark(ack_desc, 0, true);
	rlcmac_prim = create_dl_ctrl_block(&dl_block, ts_nr, rts_fn);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	for (i = 0; i < 6; i++) {
		rts_fn = fn_next_block(rts_fn);
		printf("RTS %u: FN=%u\n", i, rts_fn);
		/* Trigger transmission of LLC data (GMM Attach) (second part) */
		rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
		rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
		OSMO_ASSERT(rc == 0);
	}

	printf("=== %s end ===\n", __func__);
	msgb_free(llc_msg);
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
	uint32_t ptmsi = 0x00001234;
	char *imsi = "1234567890";
	uint32_t tlli = 0x0000001;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;
	uint8_t dl_tfi = 0;
	uint8_t rrbp = GPRS_RLCMAC_RRBP_N_plus_17_18;

	/* Notify RLCMAC about our TLLI */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_gmmrr_assign_req(GPRS_RLCMAC_TLLI_UNASSIGNED, tlli);
	rlcmac_prim->gmmrr.assign_req.ptmsi = ptmsi;
	OSMO_STRLCPY_ARRAY(rlcmac_prim->gmmrr.assign_req.imsi, imsi);
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	OSMO_ASSERT(sizeof(ccch_imm_ass_pkt_dl_tbf) == GSM_MACBLOCK_LEN);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_dl_tbf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Transmit some DL LLC data MS<-PCU */
	dl_data_msg = create_dl_data_block(dl_tfi, usf, GPRS_RLCMAC_CS_1, 0, true, true, rrbp);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_data_ind(ts_nr, rts_fn, 0, 0, 0,
								      msgb_data(dl_data_msg),
								      msgb_length(dl_data_msg));
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);
	msgb_free(dl_data_msg);

	/* Trigger transmission of DL ACK/NACK */
	rts_fn = rrbp2fn(rts_fn, rrbp);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	printf("=== %s end ===\n", __func__);
	cleanup_test();
}

/* PCU allocates a DL TBF through PCH ImmAss for MS (when in packet-idle). Then
 * upper layers want to transmit more data so during DL ACK/NACK a new UL TBF is
 * requested. */
static void test_dl_tbf_ccch_assign_requests_ul_tbf_pacch(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;
	struct msgb *dl_data_msg;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	RlcMacDownlink_t dl_block;
	uint32_t ptmsi = 0x00001234;
	char *imsi = "1234567890";
	uint32_t tlli = 0x0000001;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;
	uint8_t dl_tfi = 0;
	uint8_t ul_tfi = 3;
	uint8_t rrbp = GPRS_RLCMAC_RRBP_N_plus_17_18;
	uint16_t arfcn = 871;
	uint8_t usf_li[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 2 };

	/* Notify RLCMAC about our TLLI */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_gmmrr_assign_req(GPRS_RLCMAC_TLLI_UNASSIGNED, tlli);
	rlcmac_prim->gmmrr.assign_req.ptmsi = ptmsi;
	OSMO_STRLCPY_ARRAY(rlcmac_prim->gmmrr.assign_req.imsi, imsi);
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	OSMO_ASSERT(sizeof(ccch_imm_ass_pkt_dl_tbf) == GSM_MACBLOCK_LEN);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_imm_ass_pkt_dl_tbf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Transmit some DL LLC data MS<-PCU */
	dl_data_msg = create_dl_data_block(dl_tfi, usf, GPRS_RLCMAC_CS_1, 0, true, true, rrbp);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_data_ind(ts_nr, rts_fn, 0, 0, 0,
								      msgb_data(dl_data_msg),
								      msgb_length(dl_data_msg));
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);
	msgb_free(dl_data_msg);

	/* Upper layers wants to transmit some payload, but no UL TBF exists yet: */
	/* Submit 14 bytes to fit in 1 RLCMAC block to shorten test and end up in FINISHED state quickly: */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, pdu_llc_gmm_att_req, 14);
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rlcmac_prim->grr.unitdata_req.radio_prio = 1;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Trigger transmission of DL ACK/NACK, which should request a UL TBF in "Channel Request Description" */
	rts_fn = rrbp2fn(rts_fn, rrbp);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Network sends a Pkt Ul Ass to DL TBF's PACCH: */
	rts_fn = fn_next_block(rts_fn);
	pkt_ul_ass_from_dl_tbf_init(&dl_block, dl_tfi, ul_tfi, arfcn, &usf_li[0]);
	/* has Poll set: */
	dl_block.SP = 1;
	dl_block.RRBP = rrbp;
	rlcmac_prim = create_dl_ctrl_block(&dl_block, ts_nr, rts_fn);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Trigger transmission of PKT CTRL ACK */
	rts_fn = rrbp2fn(rts_fn, rrbp);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf_li[ts_nr]);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* from now on use one of the assigned TS in UL TBF.*/
	rts_fn = fn_next_block(rts_fn);
	ts_nr = 6;

	/* FIXME: see extra fn_next_block() in libosmo-gprs-rlcmac st_wait_tbf_starting_time2() */
	rts_fn = fn_next_block(rts_fn);

	/* Trigger transmission of LLC data (GMM Attach) (first part) */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf_li[ts_nr]);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	printf("=== %s end ===\n", __func__);
	cleanup_test();
}

/* SGSN->PCU->BTS --PCH--> MS containing "Paging Request Type 1" asking for PS services.
 * RLCMAC will send GMMRR-PAGE.ind to GMM layer, which is in charge of orchestrating the response. */
static void test_ccch_pag_req1(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	uint32_t ptmsi = 0x00001234;
	char *imsi = "262420000000423";
	uint32_t tlli = 0x0000001;

	/* Notify RLCMAC about our TLLI */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_gmmrr_assign_req(GPRS_RLCMAC_TLLI_UNASSIGNED, tlli);
	rlcmac_prim->gmmrr.assign_req.ptmsi = ptmsi;
	OSMO_STRLCPY_ARRAY(rlcmac_prim->gmmrr.assign_req.imsi, imsi);
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);

	OSMO_ASSERT(sizeof(ccch_pag_req_1) == GSM_MACBLOCK_LEN);
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, ccch_pag_req_1);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);
	/* Above prim is expected to trigger RLCMAC layer submitting GMMRR-Page.ind as here. */

	/* Here GMM would start UL TBF through LLGM-TRIGGER.req(PAGE_RESPONSE),
	 * and LLC in turn submits GRR-UNITDATA.req */

	printf("=== %s end ===\n", __func__);
	cleanup_test();
}


/* Validate 2 LLC frames (GMM Attach Compl + SM Act PDP Context Req) in the tx
 * queue are transmitted in 1 UL TBF in CS4 (OS#6351): */
static void test_ul_tbf_2_llc_blocks_in_1_cs4_rlc_block(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	int rc;

	printf("=== %s start ===\n", __func__);
	prepare_test();
	uint32_t tlli = 0x2342;
	uint8_t ts_nr = 7;
	uint8_t usf = 0;
	uint32_t rts_fn = 4;
	uint8_t bs_cv_max = 15;
	struct msgb *llc_msg = msgb_alloc(200, "llc_msg");
	uint8_t imm_ass[sizeof(ccch_imm_ass_pkt_ul_tbf_normal)];

	/* Submit an SI13 with bs_cv_max: */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, create_si13(bs_cv_max));
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);


	/* Submit LLC bytes containing GMM ATTACH COMPL */
	memcpy(msgb_put(llc_msg, sizeof(pdu_llc_gmm_att_compl)),
			pdu_llc_gmm_att_compl,
			sizeof(pdu_llc_gmm_att_compl));
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, msgb_data(llc_msg), msgb_length(llc_msg));
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rlcmac_prim->grr.unitdata_req.radio_prio = 1;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Submit LLC bytes containing SM ACT PDP CTX REQ */
	msgb_trim(llc_msg, 0);
	memcpy(msgb_put(llc_msg, sizeof(pdu_llc_sm_act_pdp_ctx_req)),
			pdu_llc_sm_act_pdp_ctx_req,
			sizeof(pdu_llc_sm_act_pdp_ctx_req));
	/* -4: The scenario where this was seen is actually reproduced by having
	 * a DL TBF sending GMM Attach Accept, and MS requesting a UL TBF through
	 * DL AKC/NACK and getting it assigned over PACCH. As a result, no
	 * contention resolution is needed and the UL TBF block doesn't contain
	 * TLLI. Since it's far easy writing here a test by directlly allocating
	 * the UL TBF, we simply account for the extra TLLI added in the RLC block
	 * by discounting 4 bytes from the upper LLC layer payload to end up with
	 * the same packet size as the one reproduced in the real case scenario.
	 */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(tlli, msgb_data(llc_msg), msgb_length(llc_msg) - 4);
	rlcmac_prim->grr.unitdata_req.sapi = OSMO_GPRS_RLCMAC_LLC_SAPI_GMM;
	rlcmac_prim->grr.unitdata_req.radio_prio = 1;
	rc = osmo_gprs_rlcmac_prim_upper_down(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	memcpy(imm_ass, ccch_imm_ass_pkt_ul_tbf_normal, sizeof(imm_ass));
	imm_ass[7] = last_rach_req_ra; /* Update RA to match */
	imm_ass[14] = 0x70; /* Set CS4 */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(0, imm_ass);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	/* Trigger transmission of LLC data (first part) */
	rlcmac_prim = osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(ts_nr, rts_fn, usf);
	rc = osmo_gprs_rlcmac_prim_lower_up(rlcmac_prim);
	OSMO_ASSERT(rc == 0);

	printf("=== %s end ===\n", __func__);
	msgb_free(llc_msg);
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

	clock_override_enable(true);

	test_ul_tbf_attach();
	test_ul_tbf_t3164_timeout();
	test_ul_tbf_t3166_timeout();
	test_ul_tbf_t3180_timeout();
	test_ul_tbf_n3104_timeout();
	test_ul_tbf_t3182_timeout(true);
#if 0
	test_ul_tbf_t3182_timeout(false);
	test_ul_tbf_unack_mode_last_data_cv0_retrans_max();
#endif
	test_ul_tbf_countdown_procedure();
	test_ul_tbf_request_another_ul_tbf();
	test_dl_tbf_ccch_assign();
	test_dl_tbf_ccch_assign_requests_ul_tbf_pacch();
	test_ccch_pag_req1();
	test_ul_tbf_2_llc_blocks_in_1_cs4_rlc_block();

	talloc_free(tall_ctx);
}
