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

struct gprs_rlcmac_ctx *g_rlcmac_ctx;

/* TS 44.060 Table 13.1.1 */
static struct osmo_tdef T_defs_rlcmac[] = {
	{ .T=3164, .default_val=5,	.unit = OSMO_TDEF_S,	.desc="Wait for Uplink State Flag After Assignment (s)" },
	{ .T=3166, .default_val=5,	.unit = OSMO_TDEF_S,	.desc="Wait for Packet Uplink ACK/NACK after sending of first data block (s)" },
	/* T3168: dynamically updated with what's received in BCCH SI13 */
	{ .T=3168, .default_val=5000,	.unit = OSMO_TDEF_MS,	.desc="Wait for PACKET UPLINK ASSIGNMENT (updated by BCCH SI13) (ms)" },
	{ .T=3182, .default_val=5,	.unit = OSMO_TDEF_S,	.desc="Wait for Acknowledgement (s)" },
	{ .T=3190, .default_val=5,	.unit = OSMO_TDEF_S,	.desc="Wait for Valid Downlink Data Received from the Network (s)" },
	{ .T=3192, .default_val=0,	.unit = OSMO_TDEF_MS,	.desc="Wait for release of the TBF after reception of the final block (ms)" },
	{ 0 } /* empty item at the end */
};

static void gprs_rlcmac_ctx_free(void)
{
	struct gprs_rlcmac_entity *gre;

	while ((gre = llist_first_entry_or_null(&g_rlcmac_ctx->gre_list, struct gprs_rlcmac_entity, entry)))
		gprs_rlcmac_entity_free(gre);

	talloc_free(g_rlcmac_ctx);
}

int osmo_gprs_rlcmac_init(enum osmo_gprs_rlcmac_location location)
{
	bool first_init = true;
	int rc;
	unsigned int i;
	OSMO_ASSERT(location == OSMO_GPRS_RLCMAC_LOCATION_MS || location == OSMO_GPRS_RLCMAC_LOCATION_PCU)

	if (g_rlcmac_ctx) {
		gprs_rlcmac_ctx_free();
		first_init = false;
	}

	g_rlcmac_ctx = talloc_zero(NULL, struct gprs_rlcmac_ctx);
	g_rlcmac_ctx->cfg.location = location;
	g_rlcmac_ctx->cfg.codel.use = true;
	g_rlcmac_ctx->cfg.codel.interval_msec = GPRS_CODEL_SLOW_INTERVAL_MS;
	g_rlcmac_ctx->cfg.egprs_arq_type = GPRS_RLCMAC_EGPRS_ARQ1;
	g_rlcmac_ctx->cfg.ul_tbf_preemptive_retransmission = true;
	g_rlcmac_ctx->T_defs = T_defs_rlcmac;
	INIT_LLIST_HEAD(&g_rlcmac_ctx->gre_list);

	osmo_tdefs_reset(g_rlcmac_ctx->T_defs);

	if (first_init) {
		rc = gprs_rlcmac_tbf_dl_ass_fsm_init();
		if (rc != 0) {
			TALLOC_FREE(g_rlcmac_ctx);
			return rc;
		}
		rc = gprs_rlcmac_tbf_dl_fsm_init();
		if (rc != 0) {
			TALLOC_FREE(g_rlcmac_ctx);
			return rc;
		}
		rc = gprs_rlcmac_tbf_ul_fsm_init();
		if (rc != 0) {
			TALLOC_FREE(g_rlcmac_ctx);
			return rc;
		}
		rc = gprs_rlcmac_tbf_ul_ass_fsm_init();
		if (rc != 0) {
			TALLOC_FREE(g_rlcmac_ctx);
			return rc;
		}
	}

	for (i = 0; i < ARRAY_SIZE(g_rlcmac_ctx->sched.ulc); i++) {
		g_rlcmac_ctx->sched.ulc[i] = gprs_rlcmac_pdch_ulc_alloc(g_rlcmac_ctx, i);
		OSMO_ASSERT(g_rlcmac_ctx->sched.ulc[i]);
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

	g_rlcmac_ctx->cfg.codel.use = use;
	g_rlcmac_ctx->cfg.codel.interval_msec = interval_msec;
	return 0;
}

struct gprs_rlcmac_entity *gprs_rlcmac_find_entity_by_tlli(uint32_t tlli)
{
	struct gprs_rlcmac_entity *gre;
	llist_for_each_entry(gre, &g_rlcmac_ctx->gre_list, entry) {
		if (gre->tlli == tlli || gre->old_tlli == tlli)
			return gre;
	}
	return NULL;
}

struct gprs_rlcmac_entity *gprs_rlcmac_find_entity_by_ptmsi(uint32_t ptmsi)
{
	struct gprs_rlcmac_entity *gre;
	llist_for_each_entry(gre, &g_rlcmac_ctx->gre_list, entry) {
		if (gre->ptmsi == ptmsi)
			return gre;
	}
	return NULL;
}

struct gprs_rlcmac_entity *gprs_rlcmac_find_entity_by_imsi(const char *imsi)
{
	struct gprs_rlcmac_entity *gre;
	llist_for_each_entry(gre, &g_rlcmac_ctx->gre_list, entry) {
		if (strncmp(gre->imsi, imsi, ARRAY_SIZE(gre->imsi)) == 0)
			return gre;
	}
	return NULL;
}

struct gprs_rlcmac_dl_tbf *gprs_rlcmac_find_dl_tbf_by_tfi(uint8_t dl_tfi)
{
	struct gprs_rlcmac_entity *gre;

	llist_for_each_entry(gre, &g_rlcmac_ctx->gre_list, entry) {
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

	llist_for_each_entry(gre, &g_rlcmac_ctx->gre_list, entry) {
		if (!gre->ul_tbf)
			continue;
		if (gre->ul_tbf->cur_alloc.ul_tfi != ul_tfi)
			continue;
		return gre->ul_tbf;
	}
	return NULL;
}

/* Request lower layers to go to packet-idle mode: */
int gprs_rlcmac_submit_l1ctl_pdch_rel_req(void)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;

	rlcmac_prim = gprs_rlcmac_prim_alloc_l1ctl_pdch_rel_req();

	LOGRLCMAC(LOGL_INFO, "Tx L1CTL-PDCH_REL.req\n");

	return gprs_rlcmac_prim_call_down_cb(rlcmac_prim);
}

static int gprs_rlcmac_handle_ccch_imm_ass_ul_tbf(uint8_t ts_nr, uint32_t fn, const struct gsm48_imm_ass *ia, const IA_RestOctets_t *iaro)
{
	int rc = -ENOENT;
	struct gprs_rlcmac_entity *gre;
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	struct tbf_ul_ass_ev_rx_ccch_imm_ass_ctx d = {
		.fn = fn,
		.ts_nr = ts_nr,
		.ia = ia,
		.iaro = iaro
	};

	llist_for_each_entry(gre, &g_rlcmac_ctx->gre_list, entry) {
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

static int gprs_rlcmac_handle_ccch_imm_ass_dl_tbf(uint8_t ts_nr, uint32_t fn, const struct gsm48_imm_ass *ia, const IA_RestOctets_t *iaro)
{
	int rc;
	struct gprs_rlcmac_entity *gre;
	const Packet_Downlink_ImmAssignment_t *pkdlass;
	struct tbf_start_ev_rx_ccch_imm_ass_ctx ev_data;

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

	ev_data = (struct tbf_start_ev_rx_ccch_imm_ass_ctx) {
		.ts_nr = ts_nr,
		.fn = fn,
		.ia = ia,
		.iaro = iaro,
	};
	rc = gprs_rlcmac_tbf_start_from_ccch(&gre->dl_tbf_dl_ass_fsm, &ev_data);
	return rc;
}

int gprs_rlcmac_handle_ccch_imm_ass(const struct gsm48_imm_ass *ia, uint32_t fn)
{
	int rc;
	uint8_t ch_type, ch_subch, ch_ts;
	IA_RestOctets_t iaro;
	const uint8_t *iaro_raw = ((uint8_t *)ia) + sizeof(*ia) + ia->mob_alloc_len;
	size_t iaro_raw_len = GSM_MACBLOCK_LEN - (sizeof(*ia) + ia->mob_alloc_len);
	struct osmo_gprs_rlcmac_prim *prim;

	rc = rsl_dec_chan_nr(ia->chan_desc.chan_nr, &ch_type, &ch_subch, &ch_ts);
	if (rc != 0) {
		LOGRLCMAC(LOGL_ERROR, "rsl_dec_chan_nr(chan_nr=0x%02x) failed\n",
			  ia->chan_desc.chan_nr);
		return rc;
	}

	/* TS 44.018 10.5.2.16 IA Rest Octets */
	rc = osmo_gprs_rlcmac_decode_imm_ass_ro(&iaro, iaro_raw, iaro_raw_len);
	if (rc != 0) {
		LOGRLCMAC(LOGL_ERROR, "Failed to decode IA Rest Octets IE\n");
		return rc;
	}

	prim = gprs_rlcmac_prim_alloc_l1ctl_pdch_est_req(ch_ts,
							 ia->chan_desc.h0.tsc,
							 ia->timing_advance);
	if (!ia->chan_desc.h0.h) {
		/* TODO: indirect encoding of hopping RF channel configuration
		 * see 3GPP TS 44.018, section 10.5.2.25a */
		if (ia->chan_desc.h0.spare & 0x02) {
			LOGRLCMAC(LOGL_ERROR,
				  "Indirect encoding of hopping RF channel "
				  "configuration is not supported\n");
			msgb_free(prim->oph.msg);
			return -ENOTSUP;
		}
		/* non-hopping RF channel configuraion */
		prim->l1ctl.pdch_est_req.fh = false;
		prim->l1ctl.pdch_est_req.arfcn = (ia->chan_desc.h0.arfcn_low)
					       | (ia->chan_desc.h0.arfcn_high << 8);
	} else {
		/* direct encoding of hopping RF channel configuration */
		prim->l1ctl.pdch_est_req.fh = true;
		prim->l1ctl.pdch_est_req.fhp.hsn = ia->chan_desc.h1.hsn;
		prim->l1ctl.pdch_est_req.fhp.maio = (ia->chan_desc.h1.maio_low)
						  | (ia->chan_desc.h1.maio_high << 2);

		const size_t ma_len_max = sizeof(prim->l1ctl.pdch_est_req.fhp.ma);
		prim->l1ctl.pdch_est_req.fhp.ma_len = OSMO_MIN(ia->mob_alloc_len, ma_len_max);
		memcpy(&prim->l1ctl.pdch_est_req.fhp.ma[0], &ia->mob_alloc[0],
		       prim->l1ctl.pdch_est_req.fhp.ma_len);
	}

	/* Request the lower layers to establish a PDCH channel */
	rc = gprs_rlcmac_prim_call_down_cb(prim);
	if (rc != 0) {
		LOGRLCMAC(LOGL_ERROR, "PDCH channel establishment failed\n");
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
			rc = gprs_rlcmac_handle_ccch_imm_ass_ul_tbf(ch_ts, fn, ia, &iaro);
			break;
		case 1: /* iaro.u.ll.lh0x.MultiBlock_PktDlAss.* (IA_MultiBlock_PktDlAss_t) */
			rc = gprs_rlcmac_handle_ccch_imm_ass_dl_tbf(ch_ts, fn, ia, &iaro);
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
					rc = gprs_rlcmac_handle_ccch_imm_ass_ul_tbf(ch_ts, fn, ia, &iaro);
					break;
				case 1: /* iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.* (GPRS_DynamicOrFixedAllocation_t) */
					switch (iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.UnionType) {
					case 0: /* iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.Allocation.DynamicAllocation (DynamicAllocation_t) */
						rc = gprs_rlcmac_handle_ccch_imm_ass_ul_tbf(ch_ts, fn, ia, &iaro);
						break;
					case 1: /* iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Uplink_ImmAssignment.Access.DynamicOrFixedAllocation.Allocation.FixedAllocationDummy (guint8) */
						rc = gprs_rlcmac_handle_ccch_imm_ass_ul_tbf(ch_ts, fn, ia, &iaro);
						break;
					}
					break;
				}
				break;
			case 1: /* iaro.u.hh.u.UplinkDownlinkAssignment.ul_dl.Packet_Downlink_ImmAssignment* (Packet_Downlink_ImmAssignment_t) */
				rc = gprs_rlcmac_handle_ccch_imm_ass_dl_tbf(ch_ts, fn, ia, &iaro);
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


/* TS 44.018 3.3.2.1.1:
* It is used when sending paging information to a mobile station in packet idle mode, if PCCCH is not present in the cell.
* If the mobile station in packet idle mode is identified by its IMSI, it shall parse the message for a corresponding Packet
* Page Indication field:
* - if the Packet Page Indication field indicates a packet paging procedure, the mobile station shall proceed as
*   specified in sub-clause 3.5.1.2.
* 3.5.1.2 "On receipt of a packet paging request":
* On the receipt of a paging request message, the RR sublayer of addressed mobile station indicates the receipt of a
* paging request to the MM sublayer, see 3GPP TS 24.007.
*/
/* TS 44.018 9.1.22 "Paging request type 1" */
int gprs_rlcmac_handle_ccch_pag_req1(const struct gsm48_paging1 *pag)
{
	uint8_t len;
	const uint8_t *buf = pag->data;
	int rc;
	struct osmo_mobile_identity mi1 = {}; /* GSM_MI_TYPE_NONE */
	struct osmo_mobile_identity mi2 = {}; /* GSM_MI_TYPE_NONE */
	P1_Rest_Octets_t p1ro = {};
	unsigned p1_rest_oct_len;
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	struct gprs_rlcmac_entity *gre;

	LOGRLCMAC(LOGL_INFO, "Rx Paging Request Type 1\n");


	/* The L2 pseudo length of this message is the sum of lengths of all
	 * information elements present in the message except the P1 Rest Octets and L2
	 * Pseudo Length information elements. */
	if (pag->l2_plen == GSM_MACBLOCK_LEN - sizeof(pag->l2_plen)) {
		/* no P1 Rest Octets => no Packet Page Indication => Discard */
		return 0;
	}

	len = *buf;
	buf++;

	if (GSM_MACBLOCK_LEN < (buf - (uint8_t *)pag) + len)
		return -EBADMSG;

	if ((rc = osmo_mobile_identity_decode(&mi1, buf, len, false)) < 0)
		return rc;
	buf += len;

	if (GSM_MACBLOCK_LEN < (buf - (uint8_t *)pag) + 1) {
		/* No MI2 and no P1 Rest Octets => no Packet Page Indication => Discard */
		return 0;
	}

	if (*buf == GSM48_IE_MOBILE_ID) {
		buf++;
		if (GSM_MACBLOCK_LEN < (buf - (uint8_t *)pag) + 1)
			return -EBADMSG;
		len = *buf;
		buf++;
		if (GSM_MACBLOCK_LEN < (buf - (uint8_t *)pag) + len)
			return -EBADMSG;
		if ((rc = osmo_mobile_identity_decode(&mi2, buf, len, false)) < 0)
			return rc;
		buf += len;
	}

	p1_rest_oct_len = GSM_MACBLOCK_LEN - (buf - (uint8_t *)pag);
	if (p1_rest_oct_len == 0) {
		/*No P1 Rest Octets => no Packet Page Indication => Discard */
		return 0;
	}

	rc = osmo_gprs_rlcmac_decode_p1ro(&p1ro, buf, p1_rest_oct_len);
	if (rc != 0) {
		LOGRLCMAC(LOGL_ERROR, "Failed to parse P1 Rest Octets\n");
		return rc;
	}

	if (p1ro.Packet_Page_Indication_1 == 1) { /* for GPRS */
		switch (mi1.type) {
		case GSM_MI_TYPE_IMSI:
			if ((gre = gprs_rlcmac_find_entity_by_imsi(mi1.imsi))) {
				/* TS 24.007 C.13: Submit GMMRR-PAGE.ind: */
				rlcmac_prim = gprs_rlcmac_prim_alloc_gmmrr_page_ind(gre->tlli);
				rc = gprs_rlcmac_prim_call_up_cb(rlcmac_prim);
			}
			break;
		case GSM_MI_TYPE_TMSI:
			if ((gre = gprs_rlcmac_find_entity_by_ptmsi(mi1.tmsi))) {
				/* TS 24.007 C.13: Submit GMMRR-PAGE.ind: */
				rlcmac_prim = gprs_rlcmac_prim_alloc_gmmrr_page_ind(gre->tlli);
				rc = gprs_rlcmac_prim_call_up_cb(rlcmac_prim);
			}
			break;
		default:
			return -EINVAL;
		}
	}

	if (p1ro.Packet_Page_Indication_2 == 1) { /* for GPRS */
		switch (mi2.type) {
		case GSM_MI_TYPE_IMSI:
			if ((gre = gprs_rlcmac_find_entity_by_imsi(mi2.imsi))) {
				/* TS 24.007 C.13: Submit GMMRR-PAGE.ind: */
				rlcmac_prim = gprs_rlcmac_prim_alloc_gmmrr_page_ind(gre->tlli);
				rc = gprs_rlcmac_prim_call_up_cb(rlcmac_prim);
			}
			break;
		case GSM_MI_TYPE_TMSI:
			if ((gre = gprs_rlcmac_find_entity_by_ptmsi(mi2.tmsi))) {
				/* TS 24.007 C.13: Submit GMMRR-PAGE.ind: */
				rlcmac_prim = gprs_rlcmac_prim_alloc_gmmrr_page_ind(gre->tlli);
				rc = gprs_rlcmac_prim_call_up_cb(rlcmac_prim);
			}
			break;
		default:
			break; /* MI2 not present */
		}
	}

	return rc;
}

/* TS 44.018 9.1.23 "Paging request type 2" */
int gprs_rlcmac_handle_ccch_pag_req2(const struct gsm48_paging2 *pag)
{
	uint8_t len;
	const uint8_t *buf = pag->data;
	int rc;
	struct osmo_mobile_identity mi3 = {}; /* GSM_MI_TYPE_NONE */
	P2_Rest_Octets_t p2ro = {};
	unsigned p2_rest_oct_len;
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	struct gprs_rlcmac_entity *gre;

	LOGRLCMAC(LOGL_INFO, "Rx Paging Request Type 2\n");

	/* The L2 pseudo length of this message is the sum of lengths of all
	 * information elements present in the message except the P1 Rest Octets and L2
	 * Pseudo Length information elements. */
	if (pag->l2_plen == GSM_MACBLOCK_LEN - sizeof(pag->l2_plen)) {
		/* no P2 Rest Octets => no Packet Page Indication => Discard */
		return 0;
	}

	if (GSM_MACBLOCK_LEN < (buf - (uint8_t *)pag) + 1)
		return -EBADMSG;

	/* No MI3 => Discard */
	if (*buf != GSM48_IE_MOBILE_ID)
		return 0;

	buf++;
	if (GSM_MACBLOCK_LEN < (buf - (uint8_t *)pag) + 1)
		return -EBADMSG;
	len = *buf;
	buf++;
	if (GSM_MACBLOCK_LEN < (buf - (uint8_t *)pag) + len)
		return -EBADMSG;
	if ((rc = osmo_mobile_identity_decode(&mi3, buf, len, false)) < 0)
		return rc;
	buf += len;

	p2_rest_oct_len = GSM_MACBLOCK_LEN - (buf - (uint8_t *)pag);
	if (p2_rest_oct_len == 0) {
		/*No P1 Rest Octets => no Packet Page Indication => Discard */
		return 0;
	}

	rc = osmo_gprs_rlcmac_decode_p2ro(&p2ro, buf, p2_rest_oct_len);
	if (rc != 0) {
		LOGRLCMAC(LOGL_ERROR, "Failed to parse P2 Rest Octets\n");
		return rc;
	}

	if (p2ro.Packet_Page_Indication_3 != 1) /* NOT for GPRS */
		return 0;

	switch (mi3.type) {
	case GSM_MI_TYPE_IMSI:
		if ((gre = gprs_rlcmac_find_entity_by_imsi(mi3.imsi))) {
			/* TS 24.007 C.13: Submit GMMRR-PAGE.ind: */
			rlcmac_prim = gprs_rlcmac_prim_alloc_gmmrr_page_ind(gre->tlli);
			rc = gprs_rlcmac_prim_call_up_cb(rlcmac_prim);
		}
		break;
	case GSM_MI_TYPE_TMSI:
		if ((gre = gprs_rlcmac_find_entity_by_ptmsi(mi3.tmsi))) {
			/* TS 24.007 C.13: Submit GMMRR-PAGE.ind: */
			rlcmac_prim = gprs_rlcmac_prim_alloc_gmmrr_page_ind(gre->tlli);
			rc = gprs_rlcmac_prim_call_up_cb(rlcmac_prim);
		}
		break;
	default:
		return -EINVAL;
	}

	return rc;
}

/* Decode T3192. 3GPP TS 44.060 Table 12.24.2: GPRS Cell Options information element details */
static unsigned int gprs_rlcmac_decode_t3192(unsigned int t3192_encoded)
{
	static const unsigned int decode_t3192_tbl[8] = {500, 1000, 1500, 0, 80, 120, 160, 200};
	OSMO_ASSERT(t3192_encoded <= 7);
	return decode_t3192_tbl[t3192_encoded];
}

int gprs_rlcmac_handle_bcch_si13(const struct gsm48_system_information_type_13 *si13)
{
	int rc;
	unsigned int t3192;

	LOGRLCMAC(LOGL_DEBUG, "Rx SI13 from lower layers\n");
	memcpy(g_rlcmac_ctx->si13, si13, GSM_MACBLOCK_LEN);

	rc = osmo_gprs_rlcmac_decode_si13ro(&g_rlcmac_ctx->si13ro, si13->rest_octets,
					    GSM_MACBLOCK_LEN - offsetof(struct gsm48_system_information_type_13, rest_octets));
	if (rc < 0) {
		LOGRLCMAC(LOGL_ERROR, "Error decoding SI13: %s\n",
			  osmo_hexdump((uint8_t *)si13, GSM_MACBLOCK_LEN));
		return rc;
	}

	g_rlcmac_ctx->si13_available = true;

	/* Update tdef for T3168:
	 * TS 44.060 Table 12.24.2: Range: 0 to 7. The timeout value is given as the binary value plus one in units of 500 ms. */
	osmo_tdef_set(g_rlcmac_ctx->T_defs, 3168,
		      (g_rlcmac_ctx->si13ro.u.PBCCH_Not_present.GPRS_Cell_Options.T3168 + 1) * 500,
		      OSMO_TDEF_MS);

	/* Update tdef for T3192 as per TS 44.060 Table 12.24.2 */
	t3192 = gprs_rlcmac_decode_t3192(g_rlcmac_ctx->si13ro.u.PBCCH_Not_present.GPRS_Cell_Options.T3192);
	osmo_tdef_set(g_rlcmac_ctx->T_defs, 3192, t3192, OSMO_TDEF_MS);

	return rc;
}

static struct gprs_rlcmac_tbf *find_tbf_by_global_tfi(const Global_TFI_t *gtfi)
{
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	switch (gtfi->UnionType) {
	case 0: /* UL TFI */
		ul_tbf = gprs_rlcmac_find_ul_tbf_by_tfi(gtfi->u.UPLINK_TFI);
		if (ul_tbf)
			return ul_tbf_as_tbf(ul_tbf);
		break;
	case 1: /* DL TFI */
		dl_tbf = gprs_rlcmac_find_dl_tbf_by_tfi(gtfi->u.DOWNLINK_TFI);
		if (dl_tbf)
			return dl_tbf_as_tbf(dl_tbf);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return NULL;
}

static struct gprs_rlcmac_entity *find_gre_by_global_tfi(const Global_TFI_t *gtfi)
{
	struct gprs_rlcmac_tbf *tbf = find_tbf_by_global_tfi(gtfi);
	if (tbf)
		return tbf->gre;
	return NULL;
}


static int gprs_rlcmac_handle_pkt_dl_ass(const struct osmo_gprs_rlcmac_prim *rlcmac_prim, const RlcMacDownlink_t *dl_block)
{
	struct gprs_rlcmac_tbf *tbf = NULL;
	struct gprs_rlcmac_entity *gre = NULL;
	const Packet_Downlink_Assignment_t *dlass = &dl_block->u.Packet_Downlink_Assignment;
	struct tbf_start_ev_rx_pacch_pkt_ass_ctx ev_data;
	int rc;

	/* Attempt to find relevant MS in assignment state from ID (set "gre" ptr): */
	switch (dlass->ID.UnionType) {
	case 0: /* GLOBAL_TFI: */
		tbf = find_tbf_by_global_tfi(&dlass->ID.u.Global_TFI);
		if (tbf)
			gre = tbf->gre;
		break;
	case 1: /* TLLI */
		gre = gprs_rlcmac_find_entity_by_tlli(dlass->ID.u.TLLI);
		break;
	default:
		OSMO_ASSERT(0);
	}

	if (!gre) {
		LOGRLCMAC(LOGL_INFO, "TS=%u FN=%u Rx Pkt DL ASS: MS not found\n",
			  rlcmac_prim->l1ctl.pdch_data_ind.ts_nr,
			  rlcmac_prim->l1ctl.pdch_data_ind.fn);
		return -ENOENT;
	}

	ev_data = (struct tbf_start_ev_rx_pacch_pkt_ass_ctx) {
		.ts_nr = rlcmac_prim->l1ctl.pdch_data_ind.ts_nr,
		.fn = rlcmac_prim->l1ctl.pdch_data_ind.fn,
		.dl_block = dl_block,
	};
	rc = gprs_rlcmac_tbf_start_from_pacch(&gre->dl_tbf_dl_ass_fsm, &ev_data);

	if (dl_block->SP) {
		uint32_t poll_fn = rrbp2fn(rlcmac_prim->l1ctl.pdch_data_ind.fn, dl_block->RRBP);
		gprs_rlcmac_pdch_ulc_reserve(g_rlcmac_ctx->sched.ulc[rlcmac_prim->l1ctl.pdch_data_ind.ts_nr],
					     poll_fn,
					     GPRS_RLCMAC_PDCH_ULC_POLL_DL_ASS,
					     gre);
	}

	/* 9.3.2.6 Release of downlink Temporary Block Flow:
	 * If the MS, [...] receives a PACKET DOWNLINK ASSIGNMENT with the Control Ack bit
	 * set to '1' [...] while its timer T3192 is running, the MS shall stop timer T3192,
	 * consider this downlink TBF released and act upon the new assignments.
	 */
	if (dlass->CONTROL_ACK && gre->dl_tbf) {
		if (osmo_timer_pending(&gre->dl_tbf->t3192))
			gprs_rlcmac_dl_tbf_free(gre->dl_tbf);
	}
	return rc;
}

static int gprs_rlcmac_handle_pkt_ul_ack_nack(const struct osmo_gprs_rlcmac_prim *rlcmac_prim, const RlcMacDownlink_t *dl_block)
{
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	int rc;
	const Packet_Uplink_Ack_Nack_t *pkt_ul_ack = &dl_block->u.Packet_Uplink_Ack_Nack;

	ul_tbf = gprs_rlcmac_find_ul_tbf_by_tfi(pkt_ul_ack->UPLINK_TFI);
	if (!ul_tbf) {
		LOGRLCMAC(LOGL_INFO, "TS=%u FN=%u Rx Pkt UL ACK/NACK: UL_TBF TFI=%u not found\n",
			  rlcmac_prim->l1ctl.pdch_data_ind.ts_nr,
			  rlcmac_prim->l1ctl.pdch_data_ind.fn,
			  pkt_ul_ack->UPLINK_TFI);
		return -ENOENT;
	}

	rc = gprs_rlcmac_ul_tbf_handle_pkt_ul_ack_nack(ul_tbf, dl_block);

	/* If RRBP contains valid data, schedule a response (PKT CONTROL ACK or PKT RESOURCE REQ). */
	if (dl_block->SP) {
		uint32_t poll_fn = rrbp2fn(rlcmac_prim->l1ctl.pdch_data_ind.fn, dl_block->RRBP);
		gprs_rlcmac_pdch_ulc_reserve(g_rlcmac_ctx->sched.ulc[rlcmac_prim->l1ctl.pdch_data_ind.ts_nr], poll_fn,
					     GPRS_RLCMAC_PDCH_ULC_POLL_UL_ACK,
					     ul_tbf_as_tbf(ul_tbf));
	}
	return rc;
}

static int gprs_rlcmac_handle_pkt_ul_ass(const struct osmo_gprs_rlcmac_prim *rlcmac_prim, const RlcMacDownlink_t *dl_block)
{
	struct gprs_rlcmac_entity *gre = NULL;
	const Packet_Uplink_Assignment_t *ulass = &dl_block->u.Packet_Uplink_Assignment;
	int rc;

	/* Attempt to find relevant MS owning UL TBF in assignment state from ID (set "gre" ptr): */
	switch (ulass->ID.UnionType) {
	case 0: /* GLOBAL_TFI: */
		gre = find_gre_by_global_tfi(&ulass->ID.u.Global_TFI);
		break;
	case 1: /* TLLI */
		gre = gprs_rlcmac_find_entity_by_tlli(ulass->ID.u.TLLI);
		break;
	case 2: /* TQI */
	case 3: /* Packet_Request_Reference */
		LOGRLCMAC(LOGL_NOTICE, "TS=%u FN=%u Rx Pkt UL ASS: HANDLING OF ID=%u NOT IMPLEMENTED!\n",
			  ulass->ID.UnionType,
			  rlcmac_prim->l1ctl.pdch_data_ind.ts_nr,
			  rlcmac_prim->l1ctl.pdch_data_ind.fn);
		break;
	}

	if (!gre) {
		LOGRLCMAC(LOGL_INFO, "TS=%u FN=%u Rx Pkt UL ASS: MS not found\n",
			  rlcmac_prim->l1ctl.pdch_data_ind.ts_nr,
			  rlcmac_prim->l1ctl.pdch_data_ind.fn);
		return -ENOENT;
	}

	if (!gre->ul_tbf) {
		LOGGRE(gre, LOGL_INFO, "TS=%u FN=%u Rx Pkt UL ASS: MS has no UL TBF\n",
		       rlcmac_prim->l1ctl.pdch_data_ind.ts_nr,
		       rlcmac_prim->l1ctl.pdch_data_ind.fn);
		return -ENOENT;
	}

	rc = gprs_rlcmac_ul_tbf_handle_pkt_ul_ass(gre->ul_tbf, rlcmac_prim, dl_block);

	return rc;
}

static int gprs_rlcmac_handle_gprs_dl_ctrl_block(const struct osmo_gprs_rlcmac_prim *rlcmac_prim)
{
	struct bitvec *bv;
	RlcMacDownlink_t *dl_ctrl_block;
	size_t max_len = gprs_rlcmac_mcs_max_bytes_dl(GPRS_RLCMAC_CS_1);
	int rc;

	bv = bitvec_alloc(max_len, g_rlcmac_ctx);
	OSMO_ASSERT(bv);
	bitvec_unpack(bv, rlcmac_prim->l1ctl.pdch_data_ind.data);

	dl_ctrl_block = (RlcMacDownlink_t *)talloc_zero(g_rlcmac_ctx, RlcMacDownlink_t);
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
	case OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_DOWNLINK_ASSIGNMENT:
		rc = gprs_rlcmac_handle_pkt_dl_ass(rlcmac_prim, dl_ctrl_block);
		break;
	case OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_UPLINK_ACK_NACK:
		rc = gprs_rlcmac_handle_pkt_ul_ack_nack(rlcmac_prim, dl_ctrl_block);
		break;
	case OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_UPLINK_ASSIGNMENT:
		rc = gprs_rlcmac_handle_pkt_ul_ass(rlcmac_prim, dl_ctrl_block);
		break;
	case OSMO_GPRS_RLCMAC_DL_MSGT_PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK:
		break; /* Ignore dummy blocks */
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
		LOGRLCMAC(LOGL_INFO, "Rx DL data for unknown dl_tfi=%u\n", data_hdr->tfi);
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
