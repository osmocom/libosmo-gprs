/* GMM PDUs, 3GPP TS 24.008 9.4 GPRS Mobility Management Messages */
#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

struct gprs_gmm_entity;
enum gprs_gmm_upd_type;

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
int gprs_gmm_build_ptmsi_realloc_compl(struct gprs_gmm_entity *gmme, struct msgb *msg);

int gprs_gmm_build_identity_resp(struct gprs_gmm_entity *gmme,
				 uint8_t mi_type,
				 struct msgb *msg);

int gprs_gmm_build_auth_ciph_resp(const struct gprs_gmm_entity *gmme,
				  const uint8_t *sres, struct msgb *msg);

int gprs_gmm_build_detach_req(struct gprs_gmm_entity *gmme,
			      enum osmo_gprs_gmm_detach_ms_type detach_type,
			      enum osmo_gprs_gmm_detach_poweroff_type poweroff_type,
			      struct msgb *msg);

int gprs_gmm_build_auth_ciph_fail(struct gprs_gmm_entity *gmme,
				  struct msgb *msg, enum gsm48_gmm_cause cause);

int gprs_gmm_build_rau_req(struct gprs_gmm_entity *gmme,
			   enum gprs_gmm_upd_type rau_type,
			   struct msgb *msg);

int gprs_gmm_build_rau_compl(struct gprs_gmm_entity *gmme, struct msgb *msg);
