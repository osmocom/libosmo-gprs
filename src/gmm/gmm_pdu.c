/* GMM PDUs, 3GPP TS 9.4 24.008 GPRS Mobility Management Messages */
/* (C) 2023 by Sysmocom s.f.m.c. GmbH
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

#include <osmocom/core/msgb.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/endian.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/gprs/gmm/gmm_private.h>
#include <osmocom/gprs/gmm/gmm_pdu.h>

/* MS network capability 10.5.5.12*/
struct gprs_gmm_ms_net_cap {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t gea1:1,
		sm_cap_dedicated:1,
		sm_cap_gprs:1,
		ucs2_support:1,
		ss_screening_ind:2,
		solsa_cap:1,
		rev_level_ind:1;
	uint8_t pfc_feature_mode:1,
		gea2:1,
		gea3:1,
		gea4:1,
		gea5:1,
		gea6:1,
		gea7:1,
		lcs_va_cap:1;
	uint8_t ps_inter_rat_ho_geran2utran:1,
		ps_inter_rat_ho_geran2eutran:1,
		emm_combined_proc_cap:1,
		isr_support:1,
		srvcc_cap:1,
		epc_cap:1,
		nf_capability:1,
		geran_net_sharing_cap:1;
	uint8_t user_plane_integrity_protection_sup:1,
		gia4:1,
		gia5:1,
		gia6:1,
		gia7:1,
		epco_ie_ind:1,
		restrict_use_enhanced_cov_cap:1,
		dual_conn_eutra_nr_cap:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t rev_level_ind:1, solsa_cap:1, ss_screening_ind:2, ucs2_support:1, sm_cap_gprs:1, sm_cap_dedicated:1, gea1:1;
	uint8_t lcs_va_cap:1, gea7:1, gea6:1, gea5:1, gea4:1, gea3:1, gea2:1, pfc_feature_mode:1;
	uint8_t geran_net_sharing_cap:1, nf_capability:1, epc_cap:1, srvcc_cap:1, isr_support:1, emm_combined_proc_cap:1, ps_inter_rat_ho_geran2eutran:1, ps_inter_rat_ho_geran2utran:1;
	uint8_t dual_conn_eutra_nr_cap:1, restrict_use_enhanced_cov_cap:1, epco_ie_ind:1, gia7:1, gia6:1, gia5:1, gia4:1, user_plane_integrity_protection_sup:1;
#endif
} __attribute__((packed));

static const struct gprs_gmm_ms_net_cap ms_net_cap_def = {
	.gea1 = 1,
	.sm_cap_dedicated = 1,
	.sm_cap_gprs = 1,
	.ucs2_support = 0,
	.ss_screening_ind = 1,
	.solsa_cap = 0,
	.rev_level_ind = 1,
	.pfc_feature_mode = 1,
	.gea2 = 1,
	.gea3 = 1,
	.gea4 = 0,
	.gea5 = 0,
	.gea6 = 0,
	.gea7 = 0,
	.lcs_va_cap = 0,
	.ps_inter_rat_ho_geran2utran = 0,
	.ps_inter_rat_ho_geran2eutran = 0,
	.emm_combined_proc_cap = 0,
	.isr_support = 0,
	.srvcc_cap = 0,
	.epc_cap = 0,
	.nf_capability = 0,
	.geran_net_sharing_cap = 0,
	.user_plane_integrity_protection_sup = 0,
	.gia4 = 0,
	.gia5 = 0,
	.gia6 = 0,
	.gia7 = 0,
	.epco_ie_ind = 0,
	.restrict_use_enhanced_cov_cap = 0,
	.dual_conn_eutra_nr_cap = 0,
};

/* 10.5.1.2 Ciphering Key Sequence Number */
#define CIPH_CKSN_UNAVAIL 0x03

/* 10.5.5.6 DRX parameter */
struct gprs_gmm_drx_param {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t split_pg_cycle_code;
	uint8_t coeff:4,
		split_ccch:1,
		non_drx_timer:3;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t split_pg_cycle_code;
	uint8_t non_drx_timer:3, split_ccch:1, coeff:4;
#endif
} __attribute__((packed));

static const struct gprs_gmm_drx_param drx_param_def = {
	.split_pg_cycle_code = 10,
	.coeff = 0,
	.split_ccch = 0,
	.non_drx_timer = 0,
};

/* Remove after depending on libosmocore > 1.10.0 */
#ifndef GSM48_IE_GMM_UE_NET_CAP
#define GSM48_IE_GMM_UE_NET_CAP 0x58
#endif
#ifndef GSM48_IE_GMM_VD_PREF_UE_USAGE
#define GSM48_IE_GMM_VD_PREF_UE_USAGE 0x5d
#endif
#ifndef GSM48_IE_GMM_ADD_IDENTITY
#define GSM48_IE_GMM_ADD_IDENTITY 0x1a
#endif
#ifndef GSM48_IE_GMM_RAI2
#define GSM48_IE_GMM_RAI2 0x1b
#endif

const struct tlv_definition gprs_gmm_att_tlvdef = {
	.def = {
		[GSM48_IE_GMM_CIPH_CKSN]	= { TLV_TYPE_SINGLE_TV, 1 },
		[GSM48_IE_GMM_PTMSI_TYPE]	= { TLV_TYPE_SINGLE_TV, 1 },
		[GSM48_IE_GMM_TMSI_BASED_NRI_C]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_TIMER_READY]	= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GMM_ALLOC_PTMSI]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PTMSI_SIG]	= { TLV_TYPE_FIXED, 3 },
		[GSM48_IE_GMM_ADD_IDENTITY]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_RAI2]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_AUTH_RAND]	= { TLV_TYPE_FIXED, 16 },
		[GSM48_IE_GMM_AUTH_SRES]	= { TLV_TYPE_FIXED, 4 },
		[GSM48_IE_GMM_IMEISV]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_CAUSE]		= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GMM_RX_NPDU_NUM_LIST]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_DRX_PARAM]	= { TLV_TYPE_FIXED, 2 },
		[GSM48_IE_GMM_AUTN]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_AUTH_RES_EXT]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_TIMER_T3302]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_AUTH_FAIL_PAR]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_MS_NET_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PDP_CTX_STATUS]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PS_LCS_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_GMM_MBMS_CTX_ST]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_TIMER_T3346]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_UE_NET_CAP]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_VD_PREF_UE_USAGE] = { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_NET_FEAT_SUPPORT] = { TLV_TYPE_SINGLE_TV, 1 },
	},
};

static int encode_ms_net_cap(struct gprs_gmm_entity *gmme, struct msgb *msg)
{
	int rc;
	uint8_t *l; /* len */
	struct bitvec bv = {
		.data = msg->tail,
		.data_len = GSM_MACBLOCK_LEN,
	};

	msgb_put_u8(msg, GSM48_IE_GMM_MS_NET_CAPA);

	l = msgb_put(msg, 1); /* len */

	/* TODO: we hardcode a MS Net Cap for now. We may want to pass it from the app at some point: */
	rc = bitvec_unhex(&bv, "e5e0");
	*l = OSMO_BYTES_FOR_BITS(bv.cur_bit);
	msgb_put(msg, *l);
	return rc;
}

static int encode_ms_ra_acc_cap(struct gprs_gmm_entity *gmme, struct msgb *msg)
{
	int rc;
	uint8_t *l; /* len */
	struct bitvec bv = {
		.data = msg->tail,
		.data_len = GSM_MACBLOCK_LEN,
	};

	l = msgb_put(msg, 1); /* len */

	/* TODO: we hardcode a MS Ra Cap for now. We may want to pass it from the app at some point: */
	rc = bitvec_unhex(&bv, "171933432b37159ef98879cba28c6621e72688b198879c00");
	*l = OSMO_BYTES_FOR_BITS(bv.cur_bit);
	msgb_put(msg, *l);
	return rc;
}

/* Chapter 9.4.1: Attach request */
int gprs_gmm_build_attach_req(struct gprs_gmm_entity *gmme,
			      enum osmo_gprs_gmm_attach_type attach_type,
			      bool attach_with_imsi,
			      struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t byte, cksn;
	struct osmo_mobile_identity mi;
	uint8_t *l;
	int rc;
	struct gsm48_ra_id *raid_enc;
	unsigned long t3314_sec;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_REQ;

	/* 10.5.5.12 MS network capability */
	msgb_lv_put(msg, sizeof(ms_net_cap_def), (const uint8_t *)&ms_net_cap_def);

	/* Attach type 10.5.5.2 */
	/* Ciphering key sequence number 10.5.1.2 */
	cksn = 0; /* Use 0 as Ciphering Key Sequence Number */
	byte = (cksn << 4) | (attach_type & 0x0f);
	msgb_put_u8(msg, byte);

	/* DRX parameter 10.5.5.6 */
	memcpy(msgb_put(msg, sizeof(drx_param_def)),
	       &drx_param_def,
	       sizeof(drx_param_def));

	/* Mobile identity 10.5.1.4 */
	/* 4.7.3.1.1: If "AttachWithIMSI" is configured, use IMSI instead: */
	if (attach_with_imsi) {
		mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_IMSI,
		};
		OSMO_STRLCPY_ARRAY(mi.imsi, gmme->imsi);
	} else {
		mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_TMSI,
			.tmsi = gmme->ptmsi,
		};
	}
	l = msgb_put(msg, 1); /* len */
	rc = osmo_mobile_identity_encode_msgb(msg, &mi, false);
	if (rc < 0)
		return -EINVAL;
	*l = rc;

	/* Old routing area identification 0.5.5.15 */
	raid_enc = (struct gsm48_ra_id *)msgb_put(msg, sizeof(struct gsm48_ra_id));
	gsm48_encode_ra(raid_enc, &gmme->ra);

	/* MS Radio Access capability 10.5.5.12a */
	rc = encode_ms_ra_acc_cap(gmme, msg);
	if (rc < 0)
		return -EINVAL;

	/* TODO: optional fields */

	/* 10.5.5.8 Old P-TMSI signature: */
	if (!attach_with_imsi && gmme->ptmsi != GSM_RESERVED_TMSI) {
		uint8_t ptmsi_sig[3] = { gmme->ptmsi_sig >> 16, gmme->ptmsi_sig >> 8, gmme->ptmsi_sig };
		msgb_tv_fixed_put(msg, GSM48_IE_GMM_PTMSI_SIG, sizeof(ptmsi_sig), ptmsi_sig);
	}

	/* 10.5.7.3 Requested READY timer value */
	t3314_sec = osmo_tdef_get(g_gmm_ctx->T_defs, 3314, OSMO_TDEF_S, -1);
	msgb_tv_put(msg, GSM48_IE_GMM_TIMER_READY, gprs_gmm_secs_to_gprs_tmr_floor(t3314_sec));

	/* 9.4.1.13 P-TMSI type: The MS shall include this IE if the
	 * type of identity in the Mobile identity IE is set to
	 * "TMSI/P-TMSI/M-TMSI". */
	if (!attach_with_imsi) {
		uint8_t ptmsi_type_native = 1; /* Table 10.5.5.29.1 */
		msgb_v_put(msg, (GSM48_IE_GMM_PTMSI_TYPE << 4) | (ptmsi_type_native & 0x01));
	}
	return 0;
}

/* 9.4.3 Attach complete */
int gprs_gmm_build_attach_compl(struct gprs_gmm_entity *gmme, struct msgb *msg)
{
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_COMPL;

	/* TODO: Add optional IEs */
	return 0;
}

/* 9.4.8 P-TMSI reallocation complete */
int gprs_gmm_build_ptmsi_realloc_compl(struct gprs_gmm_entity *gmme, struct msgb *msg)
{
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_PTMSI_REALL_COMPL;
	return 0;
}

/* 9.4.10a Authentication and Ciphering Failure */
int gprs_gmm_build_auth_ciph_fail(struct gprs_gmm_entity *gmme, struct msgb *msg,
				  enum gsm48_gmm_cause cause)
{
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_PTMSI_REALL_COMPL;

	/* 10.5.5.14 Cause */
	msgb_put_u8(msg, (uint8_t)cause);

	/* TODO: 10.5.3.2.2 Authentication Failure parameter */
	return 0;
}


/* Chapter 9.4.14: Routing area update request */
int gprs_gmm_build_rau_req(struct gprs_gmm_entity *gmme,
			   enum gprs_gmm_upd_type rau_type,
			   struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t byte, cksn;
	int rc;
	struct gsm48_ra_id *raid_enc;
	unsigned long t3314_sec;
	uint8_t ptmsi_type_native = 1; /* Table 10.5.5.29.1 */

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_RA_UPD_REQ;

	/* 10.5.5.18 Update type */
	cksn = gmme->auth_ciph.req.key_seq;
	byte = (cksn << 4) | (((uint8_t)rau_type) & 0x07);
	msgb_put_u8(msg, byte);

	/* Old routing area identification 0.5.5.15 */
	raid_enc = (struct gsm48_ra_id *)msgb_put(msg, sizeof(struct gsm48_ra_id));
	gsm48_encode_ra(raid_enc, &gmme->ra);

	/* MS Radio Access capability 10.5.5.12a */
	rc = encode_ms_ra_acc_cap(gmme, msg);
	if (rc < 0)
		return -EINVAL;

	/* 10.5.5.8 Old P-TMSI signature: */
	if (gmme->ptmsi_sig != GSM_RESERVED_TMSI) {
		uint8_t ptmsi_sig[3] = { gmme->ptmsi_sig >> 16, gmme->ptmsi_sig >> 8, gmme->ptmsi_sig };
		msgb_tv_fixed_put(msg, GSM48_IE_GMM_PTMSI_SIG, sizeof(ptmsi_sig), ptmsi_sig);
	}

	/* 10.5.7.3 Requested READY timer value */
	t3314_sec = osmo_tdef_get(g_gmm_ctx->T_defs, 3314, OSMO_TDEF_S, -1);
	msgb_tv_put(msg, GSM48_IE_GMM_TIMER_READY, gprs_gmm_secs_to_gprs_tmr_floor(t3314_sec));

	/* DRX parameter 10.5.5.6 */
	memcpy(msgb_put(msg, sizeof(drx_param_def)),
	       &drx_param_def,
	       sizeof(drx_param_def));

	/* 9.4.14.6 MS network capability */
	rc = encode_ms_net_cap(gmme, msg);
	if (rc < 0)
		return -EINVAL;

	/* 9.4.14.7 PDP context status */
	/* TODO: implement. Table 9.4.14/3GPP TS 24.00 states it is optional (O) but 9.4.14.7 states:
	 * "This IE shall be included by the MS." */

	/* 9.4.14.17 P-TMSI type */
	/* Table 9.4.14/3GPP TS 24.00 states it is optional (O) but 9.4.14.17 states:
	 * "This IE shall be included by the MS." */
	msgb_v_put(msg, (GSM48_IE_GMM_PTMSI_TYPE << 4) | (ptmsi_type_native & 0x01));

	return 0;
}

/* 9.2.11 Identity response */
int gprs_gmm_build_identity_resp(struct gprs_gmm_entity *gmme,
				 uint8_t mi_type,
				 struct msgb *msg)
{
	struct gsm48_hdr *gh;
	struct osmo_mobile_identity mi;
	uint8_t *l;
	int rc;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ID_RESP;

	/* Mobile identity 10.5.1.4 */
	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_IMSI,
		};
		OSMO_STRLCPY_ARRAY(mi.imsi, gmme->imsi);
		break;
	case GSM_MI_TYPE_TMSI:
		mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_TMSI,
			.tmsi = gmme->ptmsi,
		};
		break;
	case GSM_MI_TYPE_IMEI:
		mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_IMEI,
		};
		OSMO_STRLCPY_ARRAY(mi.imei, gmme->imei);
		break;
	case GSM_MI_TYPE_IMEISV:
		mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_IMEISV,
		};
		OSMO_STRLCPY_ARRAY(mi.imeisv, gmme->imeisv);
		break;
	default:
		LOGGMME(gmme, LOGL_ERROR, "Tx GMM IDENTITY RESPONSE: mi_type=%s not supported!\n",
			gsm48_mi_type_name(mi_type));
		return -EINVAL;
	}
	l = msgb_put(msg, 1); /* len */
	rc = osmo_mobile_identity_encode_msgb(msg, &mi, false);
	if (rc < 0)
		return -EINVAL;
	*l = rc;

	/* TODO: Optional IEs */
	return 0;
}

/* Tx GMM Authentication and ciphering response, 9.4.10 */
int gprs_gmm_build_auth_ciph_resp(const struct gprs_gmm_entity *gmme, const uint8_t *sres, struct msgb *msg)
{
	struct gsm48_hdr *gh;
	struct gsm48_auth_ciph_resp *acr;
	int rc = 0;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_AUTH_CIPH_RESP;

	acr = (struct gsm48_auth_ciph_resp *) msgb_put(msg, sizeof(*acr));
	acr->ac_ref_nr = gmme->auth_ciph.req.ac_ref_nr;

	/* Authentication parameter Response, 10.5.3.2 */
	if (sres)
		msgb_tv_fixed_put(msg, GSM48_IE_GMM_AUTH_SRES, 4, sres);

	/* IMEISV, 10.5.1.4 */
	if (gmme->auth_ciph.req.imeisv_requested) {
		uint8_t *l;
		struct osmo_mobile_identity mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_IMEISV,
		};
		OSMO_STRLCPY_ARRAY(mi.imeisv, gmme->imeisv);
		l = msgb_tl_put(msg, GSM48_IE_GMM_IMEISV);
		rc = osmo_mobile_identity_encode_msgb(msg, &mi, false);
		if (rc < 0)
			return -EINVAL;
		*l = rc;
	}

	/* TODO: Authentication Response parameter (extension) */
	/* TODO: Message authentication code */
	return rc;
}

int gprs_gmm_build_detach_req(struct gprs_gmm_entity *gmme,
			      enum osmo_gprs_gmm_detach_ms_type detach_type,
			      enum osmo_gprs_gmm_detach_poweroff_type poweroff_type,
			      struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t byte;
	struct osmo_mobile_identity mi;
	uint8_t *l;
	int rc;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_DETACH_REQ;

	/* Detach type 10.5.5.5 + Spare half octet 10.5.1.8 */
	byte = ((detach_type & 0x07) << 5) | (poweroff_type & 0x01) << 4;
	msgb_put_u8(msg, byte);

	/* DRX parameter 10.5.5.6 */
	memcpy(msgb_put(msg, sizeof(drx_param_def)),
	       &drx_param_def,
	       sizeof(drx_param_def));

	/* P-TMSI, Mobile identity 10.5.1.4 */
	mi = (struct osmo_mobile_identity){
		.type = GSM_MI_TYPE_TMSI,
		.tmsi = gmme->ptmsi,
	};
	l = msgb_put(msg, 1); /* len */
	rc = osmo_mobile_identity_encode_msgb(msg, &mi, false);
	if (rc < 0)
		return -EINVAL;
	*l = rc;

	/* TODO: optional fields: P-TMSI signature 10.5.5.8a */
	return 0;
}

int gprs_gmm_build_rau_compl(struct gprs_gmm_entity *gmme, struct msgb *msg)
{
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_RA_UPD_COMPL;

	/* TODO: 3GPP TS 24.008 4.7.5.1.3 "If Receive N-PDU Numbers were
	 * included, the Receive N-PDU Numbers values valid in the MS, shall be included in
	 * the ROUTING AREA UPDATE COMPLETE message."
	 */

	/* TODO: Add optional IEs */
	return 0;
}
