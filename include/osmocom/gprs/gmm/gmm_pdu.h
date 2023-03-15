/* GMM PDUs, 3GPP TS 9.4 24.008 GPRS Mobility Management Messages */
#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>

struct gprs_gmm_entity;

#define GPRS_GMM_ALLOC_SIZE        2048
#define  GPRS_GMM_ALLOC_HEADROOM    256

static inline struct msgb *gprs_gmm_msgb_alloc_name(const char *name)
{
	return msgb_alloc_headroom(GPRS_GMM_ALLOC_SIZE, GPRS_GMM_ALLOC_HEADROOM, name);
}

extern const struct tlv_definition gprs_gmm_att_tlvdef;
#define gprs_gmm_tlv_parse(dec, buf, len) \
	tlv_parse(dec, &gprs_gmm_att_tlvdef, buf, len, 0, 0)

int gprs_gmm_build_attach_req(struct gprs_gmm_entity *gmme,
			      enum osmo_gprs_gmm_attach_type attach_type,
			      bool attach_with_imsi,
			      struct msgb *msg);

int gprs_gmm_build_attach_compl(struct gprs_gmm_entity *gmme, struct msgb *msg);

int gprs_gmm_build_identity_resp(struct gprs_gmm_entity *gmme,
				 uint8_t mi_type,
				 struct msgb *msg);

int gprs_gmm_build_ciph_auth_resp(struct gprs_gmm_entity *gmme, bool imeisv_requested,
				  uint8_t ac_ref_nr, const uint8_t sres[4], struct msgb *msg);
