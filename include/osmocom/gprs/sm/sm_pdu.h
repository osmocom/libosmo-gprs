/* GMM PDUs, 3GPP TS 9.5 24.008 GPRS Session Management Messages */
#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>

struct gprs_gmm_entity;

#define GPRS_SM_ALLOC_SIZE        2048
#define  GPRS_SM_ALLOC_HEADROOM    256

extern const struct tlv_definition gprs_sm_att_tlvdef;
#define gprs_sm_tlv_parse(dec, buf, len) \
	tlv_parse(dec, &gprs_sm_att_tlvdef, buf, len, 0, 0)

int gprs_sm_build_act_pdp_ctx_req(struct gprs_sm_entity *sme,
			      struct msgb *msg);
