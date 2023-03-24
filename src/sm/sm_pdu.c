/* SM PDUs, 3GPP TS 9.5 24.008 Session Management Messages */
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

#include <stdint.h>
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/endian.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/apn.h>

#include <osmocom/gprs/sm/sm_private.h>
#include <osmocom/gprs/sm/sm_pdu.h>


const struct tlv_definition gprs_sm_att_tlvdef = {
	.def = {
		[GSM48_IE_GSM_RADIO_PRIO]	= {TLV_TYPE_SINGLE_TV, 1 },
		[GSM48_IE_GSM_APN]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_PROTO_CONF_OPT]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_PDP_ADDR]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_AA_TMR]		= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GSM_QOS]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_TFT]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_LLC_SAPI]		= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GSM_PFI]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_NAME_FULL]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_NAME_SHORT]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_TIMEZONE]		= { TLV_TYPE_FIXED, 1 },
		[GSM48_IE_GSM_UTC_AND_TZ]	= { TLV_TYPE_FIXED, 7 },
		[GSM48_IE_GSM_LSA_ID]		= { TLV_TYPE_TLV, 0 },
	},
};

/* 10.5.6.4 Packet data protocol address */
static uint8_t gprs_sm_pdp_addr_enc_ietf(struct gprs_sm_pdp_addr *out,
					 enum osmo_gprs_sm_pdp_addr_ietf_type pdp_addr_ietf_type,
					 const struct osmo_sockaddr *pdp_addr_v4,
					 const struct osmo_sockaddr *pdp_addr_v6)
{
	memset(out, 0, sizeof(*out));

	out->spare = 0x00;
	out->organization = GPRS_SM_PDP_ADDR_ORG_IETF;
	out->type = pdp_addr_ietf_type;

	switch (pdp_addr_ietf_type) {
	case OSMO_GPRS_SM_PDP_ADDR_IETF_IPV6:
		memcpy(out->addr6, pdp_addr_v6->u.sin6.sin6_addr.s6_addr, sizeof(out->addr6));
		return 2 + sizeof(out->addr6);
	case OSMO_GPRS_SM_PDP_ADDR_IETF_IPV4V6:
		out->both.addr = pdp_addr_v4->u.sin.sin_addr.s_addr;
		memcpy(out->both.addr6,  pdp_addr_v6->u.sin6.sin6_addr.s6_addr, sizeof(out->both.addr6));
		return 2 + sizeof(out->both.addr) + sizeof(out->both.addr6);
	case OSMO_GPRS_SM_PDP_ADDR_IETF_IPV4:
	default:
		/* All other values shall be interpreted as IPv4 address in this version of the protocol */
		out->addr = pdp_addr_v4->u.sin.sin_addr.s_addr;
		return 2 + sizeof(out->both.addr);
	}
}

/* Chapter 9.4.1: Attach request */
int gprs_sm_build_act_pdp_ctx_req(struct gprs_sm_entity *sme,
			      struct msgb *msg)
{

	struct gsm48_hdr *gh;
	uint8_t *l;
	int rc;
	uint8_t transaction_id = sme->ti ^ 0x8; /* flip */

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_ACT_PDP_REQ;

	/* 10.5.6.2 Requested NSAPI */
	msgb_v_put(msg, sme->nsapi);

	/* 10.5.6.9 Requested LLC SAPI */
	msgb_v_put(msg, sme->llc_sapi);

	/* 10.5.6.5 Requested QoS */
	msgb_lv_put(msg, sme->qos_len, (uint8_t *)&sme->qos);

	/* 10.5.6.4 Requested PDP address */
	l = msgb_put(msg, 1); /* len */
	*l = gprs_sm_pdp_addr_enc_ietf((struct gprs_sm_pdp_addr *)msg->tail,
					sme->pdp_addr_ietf_type,
					&sme->pdp_addr_v4,
					&sme->pdp_addr_v6);
	msgb_put(msg, *l);

	/* 10.5.6.1 Access point name (Optional) */
	if (sme->apn[0] != '\0') {
		msgb_v_put(msg, GSM48_IE_GSM_APN);
		l = msgb_put(msg, 1); /* len */
		rc = osmo_apn_from_str(msg->tail, msgb_tailroom(msg), sme->apn);
		if (rc < 0)
			return -EINVAL;
		*l = rc;
	}

	/* 10.5.6.3 Protocol configuration options (Optional) */
	if (sme->pco_len > 0)
		msgb_tlv_put(msg, GSM48_IE_GSM_PROTO_CONF_OPT,
			     sme->pco_len, sme->pco);

	/* TODO: other optional fields */
	return 0;
}
