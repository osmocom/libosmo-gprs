/* GPRS RLCMAC as per 3GPP TS 44.060 */
/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <stdbool.h>

#include <osmocom/gsm/rsl.h>

#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/rlcmac_prim.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/rlcmac/rlcmac_dec.h>
#include <osmocom/gprs/rlcmac/pdch_ul_controller.h>
#include <osmocom/gprs/rlcmac/tbf_ul_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_ul_ass_fsm.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/rlc.h>
#include <osmocom/gprs/rlcmac/types_private.h>
#include <osmocom/gprs/rlcmac/rlc_window.h>

#define GPRS_CODEL_SLOW_INTERVAL_MS 4000

struct gprs_rlcmac_ctx *g_ctx;

/* TS 44.060 Table 13.1.1 */
static struct osmo_tdef T_defs_rlcmac[] = {
	{ .T=3164, .default_val=5, .desc="Wait for Uplink State Flag After Assignment (s)" },
	{ .T=3166, .default_val=5, .desc="Wait for Packet Uplink ACK/NACK after sending of first data block (s)" },
	{ 0 } /* empty item at the end */
};

static void gprs_rlcmac_ctx_free(void)
{
	struct gprs_rlcmac_entity *gre;

	while ((gre = llist_first_entry_or_null(&g_ctx->gre_list, struct gprs_rlcmac_entity, entry)))
		gprs_rlcmac_entity_free(gre);

	talloc_free(g_ctx);
}

int osmo_gprs_rlcmac_init(enum osmo_gprs_rlcmac_location location)
{
	bool first_init = true;
	int rc;
	unsigned int i;
	OSMO_ASSERT(location == OSMO_GPRS_RLCMAC_LOCATION_MS || location == OSMO_GPRS_RLCMAC_LOCATION_PCU)

	if (g_ctx) {
		gprs_rlcmac_ctx_free();
		first_init = false;
	}

	g_ctx = talloc_zero(NULL, struct gprs_rlcmac_ctx);
	g_ctx->cfg.location = location;
	g_ctx->cfg.codel.use = true;
	g_ctx->cfg.codel.interval_msec = GPRS_CODEL_SLOW_INTERVAL_MS;
	g_ctx->cfg.egprs_arq_type = GPRS_RLCMAC_EGPRS_ARQ1;
	g_ctx->cfg.ul_tbf_preemptive_retransmission = true;
	g_ctx->T_defs = T_defs_rlcmac;
	INIT_LLIST_HEAD(&g_ctx->gre_list);

	osmo_tdefs_reset(g_ctx->T_defs);

	if (first_init) {
		rc = gprs_rlcmac_tbf_dl_fsm_init();
		if (rc != 0) {
			TALLOC_FREE(g_ctx);
			return rc;
		}
		rc = gprs_rlcmac_tbf_ul_fsm_init();
		if (rc != 0) {
			TALLOC_FREE(g_ctx);
			return rc;
		}
		rc = gprs_rlcmac_tbf_ul_ass_fsm_init();
		if (rc != 0) {
			TALLOC_FREE(g_ctx);
			return rc;
		}
	}

	for (i = 0; i < ARRAY_SIZE(g_ctx->sched.ulc); i++) {
		g_ctx->sched.ulc[i] = gprs_rlcmac_pdch_ulc_alloc(g_ctx, i);
		OSMO_ASSERT(g_ctx->sched.ulc[i]);
	}

	return 0;
}

/*! Set CoDel parameters used in the Tx queue of LLC PDUs waiting to be transmitted.
 *  \param[in] use Whether to enable or disable use of CoDel algo.
 *  \param[in] interval_msec Interval at which CoDel triggers, in milliseconds. (0 = use default interval value)
 *  \returns 0 on success; negative on error.
 */
int osmo_gprs_rlcmac_set_codel_params(bool use, unsigned int interval_msec)
{
	if (interval_msec == 0)
		interval_msec = GPRS_CODEL_SLOW_INTERVAL_MS;

	g_ctx->cfg.codel.use = use;
	g_ctx->cfg.codel.interval_msec = interval_msec;
	return 0;
}

struct gprs_rlcmac_entity *gprs_rlcmac_find_entity_by_tlli(uint32_t tlli)
{
	struct gprs_rlcmac_entity *gre;

	llist_for_each_entry(gre, &g_ctx->gre_list, entry) {
		if (gre->tlli == tlli)
			return gre;
	}
	return NULL;
}

struct gprs_rlcmac_dl_tbf *gprs_rlcmac_find_dl_tbf_by_tfi(uint8_t dl_tfi)
{
	struct gprs_rlcmac_entity *gre;

	llist_for_each_entry(gre, &g_ctx->gre_list, entry) {
		if (!gre->dl_tbf)
			continue;
		if (gre->dl_tbf->cur_alloc.dl_tfi != dl_tfi)
			continue;
		return gre->dl_tbf;
	}
	return NULL;
}

struct gprs_rlcmac_ul_tbf *gprs_rlcmac_find_ul_tbf_by_tfi(uint8_t ul_tfi)
{
	struct gprs_rlcmac_entity *gre;

	llist_for_each_entry(gre, &g_ctx->gre_list, entry) {
		if (!gre->ul_tbf)
			continue;
		if (gre->ul_tbf->cur_alloc.ul_tfi != ul_tfi)
			continue;
		return gre->ul_tbf;
	}
	return NULL;
}

static int gprs_rlcmac_handle_ccch_imm_ass_ul_tbf(uint8_t ts_nr, const struct gsm48_imm_ass *ia, const IA_RestOctets_t *iaro)
{
	int rc = -ENOENT;
	struct gprs_rlcmac_entity *gre;
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	struct tbf_ul_ass_ev_rx_ccch_imm_ass_ctx d = {
		.ts_nr = ts_nr,
		.ia = ia,
		.iaro = iaro
	};

	llist_for_each_entry(gre, &g_ctx->gre_list, entry) {
		ul_tbf = gre->ul_tbf;
		if (!ul_tbf)
			continue;
		if (!gprs_rlcmac_tbf_ul_ass_match_rach_req(ul_tbf, ia->req_ref.ra))
			continue;
		rc = osmo_fsm_inst_dispatch(ul_tbf->ul_ass_fsm.fi,
					    GPRS_RLCMAC_TBF_UL_ASS_EV_RX_CCCH_IMM_ASS,
					    &d);
		break;
	}
	return rc;
}

static int gprs_rlcmac_handle_ccch_imm_ass_dl_tbf(uint8_t ts_nr, const struct gsm48_imm_ass *ia, const IA_RestOctets_t *iaro)
{
	int rc;
	struct gprs_rlcmac_entity *gre;
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	const Packet_Downlink_ImmAssignment_t *pkdlass;

	if (iaro->UnionType == 1) {
		/* TODO */
		return -ENOENT;
	}

	pkdlass = &iaro->u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Downlink_ImmAssignment;

	gre = gprs_rlcmac_find_entity_by_tlli(pkdlass->TLLI);
	if (!gre) {
		LOGRLCMAC(LOGL_NOTICE, "Got IMM_ASS (DL_TBF) for unknown TLLI=0x%08x\n", pkdlass->TLLI);
		return -ENOENT;
	}

	LOGGRE(gre, LOGL_INFO, "Got PCH IMM_ASS (DL_TBF): DL_TFI=%u TS=%u\n",
	       pkdlass->TFI_ASSIGNMENT, ts_nr);
	dl_tbf = gprs_rlcmac_dl_tbf_alloc(gre);
	dl_tbf->cur_alloc.dl_tfi = pkdlass->TFI_ASSIGNMENT;
	dl_tbf->cur_alloc.ts[ts_nr].allocated = true;

	/* replace old DL TBF with new one: */
	gprs_rlcmac_dl_tbf_free(gre->dl_tbf);
	gre->dl_tbf = dl_tbf;

	rc = osmo_fsm_inst_dispatch(dl_tbf->state_fsm.fi, GPRS_RLCMAC_TBF_UL_EV_DL_ASS_COMPL, NULL);
	return rc;
}

int gprs_rlcmac_handle_ccch_imm_ass(const struct gsm48_imm_ass *ia)
{
	int rc;
	uint8_t ch_type, ch_subch, ch_ts;
	IA_RestOctets_t iaro;
	const uint8_t *iaro_raw = ((uint8_t *)ia) + sizeof(*ia) + ia->mob_alloc_len;
	size_t iaro_raw_len = GSM_MACBLOCK_LEN - (sizeof(*ia) + ia->mob_alloc_len);

	rc = rsl_dec_chan_nr(ia->chan_desc.chan_nr, &ch_type, &ch_subch, &ch_ts);
	if (rc != 0) {
		LOGRLCMAC(LOGL_ERROR, "rsl_dec_chan_nr(chan_nr=0x%02x) failed\n",
			  ia->chan_desc.chan_nr);
		return rc;
	}

	rc = osmo_gprs_rlcmac_decode_imm_ass_ro(&iaro, iaro_raw, iaro_raw_len);
	if (rc != 0) {
		LOGRLCMAC(LOGL_ERROR, "Failed to decode IA Rest Octets IE\n");
		return rc;
	}

	switch (iaro.UnionType) {
	case 0: /* iaro.u.ll.* (IA_RestOctetsLL_t) */
		/* TODO: iaro.u.ll.Compressed_Inter_RAT_HO_INFO_IND */
		/* TODO: iaro.u.ll.AdditionsR13.* (IA_AdditionsR13_t) */
		break;
	case 1: /* iaro.u.lh.* (IA_RestOctetsLH_t) */
		switch (iaro.u.lh.lh0x.UnionType) {
		case 0: /* iaro.u.ll.lh0x.EGPRS_PktUlAss.* (IA_EGPRS_PktUlAss_t) */
			rc = gprs_rlcmac_handle_ccch_imm_ass_ul_tbf(ch_ts, ia, &iaro);
			break;
		case 1: /* iaro.u.ll.lh0x.MultiBlock_PktDlAss.* (IA_MultiBlock_PktDlAss_t) */
			rc = gprs_rlcmac_handle_ccch_imm_ass_dl_tbf(ch_ts, ia, &iaro);
			break;
		}
		/* TODO: iaro.u.lh.AdditionsR13.* (IA_AdditionsR13_t) */
		break;
	case 2: /* iaro.u.hl.* (IA_RestOctetsHL_t) */
		/* TODO: iaro.u.hl.IA_FrequencyParams (IA_FreqParamsBeforeTime_t) */
		/* TODO: iaro.u.hl.Compressed_Inter_RAT_HO_INFO_IND */
		/* TODO: iaro.u.hl.AdditionsR13.* (IA_AdditionsR13_t) */
		break;
	case 3: /* iaro.u.hh.* (IA_RestOctetsHH_t) */
		switch (iaro.u.hh.UnionType) {
		case 0: /* iaro.u.hh.u.UplinkDownlinkAssignment.* (IA_PacketAssignment_UL_DL_t) */
			switch (iaro.u.hh.u.UplinkDownlinkAssignment.UnionType) {
			case 0: /* iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.* (Packet_Uplink_ImmAssignment_t) */
				switch (iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.UnionType) {
				case 0: /* iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.SingleBlockAllocation.* (GPRS_SingleBlockAllocation_t) */
					/* TODO: 2phase access support: Schedule transmit of PKT_RES_REQ on FN=(GPRS_SingleBlockAllocation_t).TBF_STARTING_TIME */
					LOGRLCMAC(LOGL_ERROR, "ImmAss SingleBlock (2phase access) not yet supported!\n");
					break;
				case 1: /* iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.* (GPRS_DynamicOrFixedAllocation_t) */
					switch (iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.UnionType) {
					case 0: /* iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.Allocation.DynamicAllocation (DynamicAllocation_t) */
						rc = gprs_rlcmac_handle_ccch_imm_ass_ul_tbf(ch_ts, ia, &iaro);
						break;
					case 1: /* iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.Allocation.FixedAllocationDummy (guint8) */
						rc = gprs_rlcmac_handle_ccch_imm_ass_ul_tbf(ch_ts, ia, &iaro);
						break;
					}
					break;
				}
				break;
			case 1: /* iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Downlink_ImmAssignment* (Packet_Downlink_ImmAssignment_t) */
				rc = gprs_rlcmac_handle_ccch_imm_ass_dl_tbf(ch_ts, ia, &iaro);
				break;
			}
			break;
		case 1: /* iaro.u.hh.u.SecondPartPacketAssignment.* (Second_Part_Packet_Assignment_t) */
			break;
		}
		break;
	}

	return rc;
}

static int gprs_rlcmac_handle_pkt_ul_ack_nack(const struct osmo_gprs_rlcmac_prim *rlcmac_prim, const RlcMacDownlink_t *dl_block)
{
	const Packet_Uplink_Ack_Nack_t *ack = &dl_block->u.Packet_Uplink_Ack_Nack;
	const PU_AckNack_GPRS_t *gprs = &ack->u.PU_AckNack_GPRS_Struct;
	const Ack_Nack_Description_t *ack_desc = &gprs->Ack_Nack_Description;
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	int bsn_begin, bsn_end;
	int num_blocks;
	uint8_t bits_data[GPRS_RLCMAC_GPRS_WS/8];
	char show_bits[GPRS_RLCMAC_GPRS_WS + 1];
	struct bitvec bits = {
		.data = bits_data,
		.data_len = sizeof(bits_data),
		.cur_bit = 0,
	};
	int rc;

	ul_tbf = gprs_rlcmac_find_ul_tbf_by_tfi(dl_block->TFI);
	if (!ul_tbf) {
		LOGRLCMAC(LOGL_INFO, "TS=%u FN=%u Rx Pkt UL ACK/NACK: UL_TBF TFI=%u not found\n",
			  rlcmac_prim->l1ctl.pdch_data_ind.ts_nr,
			  rlcmac_prim->l1ctl.pdch_data_ind.fn,
			  dl_block->TFI);
		return -ENOENT;
	}

	num_blocks = gprs_rlcmac_decode_gprs_acknack_bits(
		ack_desc, &bits, &bsn_begin, &bsn_end, ul_tbf->ulw);

	LOGPTBFUL(ul_tbf, LOGL_DEBUG,
		"Got GPRS UL ACK bitmap: SSN: %d, BSN %d to %d - 1 (%d blocks), \"%s\"\n",
		ack_desc->STARTING_SEQUENCE_NUMBER,
		bsn_begin, bsn_end, num_blocks,
		(gprs_rlcmac_extract_rbb(&bits, show_bits), show_bits));

	rc = gprs_rlcmac_ul_tbf_handle_pkt_ul_ack_nack(ul_tbf, ack_desc->FINAL_ACK_INDICATION, bsn_begin, &bits);
	return rc;
}

static int gprs_rlcmac_handle_gprs_dl_ctrl_block(const struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	struct bitvec *bv;
	RlcMacDownlink_t *dl_ctrl_block;
	size_t max_len = gprs_rlcmac_mcs_max_bytes_dl(GPRS_RLCMAC_CS_1);
	int rc;

	bv = bitvec_alloc(max_len, g_ctx);
	OSMO_ASSERT(bv);
	bitvec_unpack(bv, rlcmac_prim->l1ctl.pdch_data_ind.data);

	dl_ctrl_block = (RlcMacDownlink_t *)talloc_zero(g_ctx, RlcMacDownlink_t);
	OSMO_ASSERT(dl_ctrl_block);
	rc = osmo_gprs_rlcmac_decode_downlink(bv, dl_ctrl_block);
	if (rc < 0) {
		LOGRLCMAC(LOGL_NOTICE, "Failed decoding dl ctrl block: %s\n",
			  osmo_hexdump(rlcmac_prim->l1ctl.pdch_data_ind.data,
				       rlcmac_prim->l1ctl.pdch_data_ind.data_len));
		goto free_ret;
	}

	LOGRLCMAC(LOGL_INFO, "TS=%u FN=%u Rx %s\n",
		  rlcmac_prim->l1ctl.pdch_data_ind.ts_nr,
		  rlcmac_prim->l1ctl.pdch_data_ind.fn,
		  get_value_string(osmo_gprs_rlcmac_dl_msg_type_names, dl_ctrl_block->u.MESSAGE_TYPE));

	switch (dl_ctrl_block->u.MESSAGE_TYPE) {
	case OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_UPLINK_ACK_NACK:
		rc = gprs_rlcmac_handle_pkt_ul_ack_nack(rlcmac_prim, dl_ctrl_block);
		break;
	default:
		LOGRLCMAC(LOGL_ERROR, "TS=%u FN=%u Rx %s NOT SUPPORTED! ignoring\n",
			  rlcmac_prim->l1ctl.pdch_data_ind.ts_nr,
			  rlcmac_prim->l1ctl.pdch_data_ind.fn,
			  get_value_string(osmo_gprs_rlcmac_dl_msg_type_names, dl_ctrl_block->u.MESSAGE_TYPE));
	}

free_ret:
	talloc_free(dl_ctrl_block);
	bitvec_free(bv);
	return rc;
}

static int gprs_rlcmac_handle_gprs_dl_data_block(const struct osmo_gprs_rlcmac_prim *rlcmac_prim,
						 enum gprs_rlcmac_coding_scheme cs)
{
	const struct gprs_rlcmac_rlc_dl_data_header *data_hdr = (const struct gprs_rlcmac_rlc_dl_data_header *)rlcmac_prim->l1ctl.pdch_data_ind.data;
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	struct gprs_rlcmac_rlc_data_info rlc_dec;
	int rc;

	rc = gprs_rlcmac_rlc_parse_dl_data_header(&rlc_dec, rlcmac_prim->l1ctl.pdch_data_ind.data, cs);
	if (rc < 0) {
		LOGRLCMAC(LOGL_ERROR, "Got %s DL data block but header parsing has failed\n",
			  gprs_rlcmac_mcs_name(cs));
		return rc;
	}

	dl_tbf = gprs_rlcmac_find_dl_tbf_by_tfi(rlc_dec.tfi);
	if (!dl_tbf) {
		LOGPTBFDL(dl_tbf, LOGL_INFO, "Rx DL data for unknown dl_tfi=%u\n", data_hdr->tfi);
		return -ENOENT;
	}
	LOGPTBFDL(dl_tbf, LOGL_DEBUG, "Rx new DL data\n");
	rc = gprs_rlcmac_dl_tbf_rcv_data_block(dl_tbf, &rlc_dec, rlcmac_prim->l1ctl.pdch_data_ind.data,
					       rlcmac_prim->l1ctl.pdch_data_ind.fn, rlcmac_prim->l1ctl.pdch_data_ind.ts_nr);
	return rc;
}

int gprs_rlcmac_handle_gprs_dl_block(const struct osmo_gprs_rlcmac_prim *rlcmac_prim,
				     enum gprs_rlcmac_coding_scheme cs)
{
	const struct gprs_rlcmac_rlc_dl_data_header *data_hdr = (const struct gprs_rlcmac_rlc_dl_data_header *)rlcmac_prim->l1ctl.pdch_data_ind.data;
	/* Check block content (data vs ctrl) based on Payload Type: TS 44.060 10.4.7 */
	switch ((enum gprs_rlcmac_payload_type)data_hdr->pt) {
	case GPRS_RLCMAC_PT_DATA_BLOCK:
		/* "Contains an RLC data block" */
		return gprs_rlcmac_handle_gprs_dl_data_block(rlcmac_prim, cs);
	case GPRS_RLCMAC_PT_CONTROL_BLOCK:
		/* "Contains an RLC/MAC control block that does not include the optional octets of the RLC/MAC
		 * control header" */
		return gprs_rlcmac_handle_gprs_dl_ctrl_block(rlcmac_prim);
	case GPRS_RLCMAC_PT_CONTROL_BLOCK_OPT:
		/* Contains an RLC/MAC control block that includes the optional first octet of the RLC/MAC
		 * control header" */
		return gprs_rlcmac_handle_gprs_dl_ctrl_block(rlcmac_prim);
	case GPRS_RLCMAC_PT_RESERVED: /* Reserved. In this version of the protocol, the mobile station shall ignore all fields of the
		 * RLC/MAC block except for the USF field */
		return 0;
	default:
		OSMO_ASSERT(0);
	}
}
