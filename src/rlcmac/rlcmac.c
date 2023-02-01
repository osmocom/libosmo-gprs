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
#include <osmocom/gprs/rlcmac/tbf_ul_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_ul_ass_fsm.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/csn1_defs.h>

#define GPRS_CODEL_SLOW_INTERVAL_MS 4000

struct gprs_rlcmac_ctx *g_ctx;

static struct osmo_tdef T_defs_rlcmac[] = {
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
			/* TODO: Alloc DL TBF */
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
				/* TODO: Alloc DL TBF */
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
