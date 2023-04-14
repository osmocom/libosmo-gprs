/* GMM PDUs, 3GPP TS 9.5 24.008 GPRS Session Management Messages */
#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/gprs/sm/sm.h>

struct gprs_gmm_entity;

#define GPRS_SM_ALLOC_SIZE        2048
#define  GPRS_SM_ALLOC_HEADROOM    256

extern const struct tlv_definition gprs_sm_att_tlvdef;
#define gprs_sm_tlv_parse(dec, buf, len) \
	tlv_parse(dec, &gprs_sm_att_tlvdef, buf, len, 0, 0)

int gprs_sm_build_act_pdp_ctx_req(struct gprs_sm_entity *sme,
			      struct msgb *msg);
int gprs_sm_pdp_addr_dec(const struct gprs_sm_pdp_addr *pdp_addr,
			 uint16_t pdp_addr_len,
			 enum osmo_gprs_sm_pdp_addr_ietf_type *pdp_addr_ietf_type,
			 struct osmo_sockaddr *osa4,
			 struct osmo_sockaddr *osa6);
