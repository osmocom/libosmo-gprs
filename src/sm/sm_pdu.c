/* SM PDUs, 3GPP TS 24.008 Session Management Messages */
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
#include <osmocom/core/socket.h>
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
	unsigned int len = 2;

	out->spare = 0x00;
	out->organization = GPRS_SM_PDP_ADDR_ORG_IETF;
	out->type = pdp_addr_ietf_type;

	switch (pdp_addr_ietf_type) {
	case OSMO_GPRS_SM_PDP_ADDR_IETF_IPV6:
		if (pdp_addr_v6) {
			memcpy(out->addr6, pdp_addr_v6->u.sin6.sin6_addr.s6_addr, sizeof(out->addr6));
			len += sizeof(out->addr6);
		}
		break;
	case OSMO_GPRS_SM_PDP_ADDR_IETF_IPV4V6:
		if (pdp_addr_v4) {
			out->both.addr = pdp_addr_v4->u.sin.sin_addr.s_addr;
			len += sizeof(out->both.addr);
			if (pdp_addr_v6) {
				memcpy(out->both.addr6,  pdp_addr_v6->u.sin6.sin6_addr.s6_addr, sizeof(out->both.addr6));
				len += sizeof(out->both.addr6);
			}
		} else if (pdp_addr_v6) {
			memcpy(out->addr6, pdp_addr_v6->u.sin6.sin6_addr.s6_addr, sizeof(out->addr6));
			len += sizeof(out->addr6);
		}
		break;
	case OSMO_GPRS_SM_PDP_ADDR_IETF_IPV4:
	default:
		/* All other values shall be interpreted as IPv4 address in this version of the protocol */
		if (pdp_addr_v4) {
			out->addr = pdp_addr_v4->u.sin.sin_addr.s_addr;
			len += sizeof(out->both.addr);
		}
		break;
	}
	return len;
}

int gprs_sm_pdp_addr_dec(const struct gprs_sm_pdp_addr *pdp_addr,
			 uint16_t pdp_addr_len,
			 enum osmo_gprs_sm_pdp_addr_ietf_type *pdp_addr_ietf_type,
			 struct osmo_sockaddr *osa4,
			 struct osmo_sockaddr *osa6)
{

	OSMO_ASSERT(pdp_addr);
	OSMO_ASSERT(pdp_addr_ietf_type);
	OSMO_ASSERT(osa4);
	OSMO_ASSERT(osa6);

	memset(osa4, 0, sizeof(*osa4));
	memset(osa6, 0, sizeof(*osa6));
	osa4->u.sa.sa_family = AF_UNSPEC;
	osa6->u.sa.sa_family = AF_UNSPEC;

	switch (pdp_addr->organization) {
	case GPRS_SM_PDP_ADDR_ORG_IETF:
		break;
	case GPRS_SM_PDP_ADDR_ORG_ETSI:
	default:
		LOGSM(LOGL_INFO, "Unsupported PDP address organization %u\n", pdp_addr->organization);
		return -EINVAL;
	}

	pdp_addr_len -= 2;
	switch (pdp_addr->type) {
	case OSMO_GPRS_SM_PDP_ADDR_IETF_IPV4:
		if (pdp_addr_len == sizeof(pdp_addr->addr)) {
			osa4->u.sa.sa_family = AF_INET;
			osa4->u.sin.sin_addr.s_addr = pdp_addr->addr;
		} else if (pdp_addr_len != 0) {
			LOGSM(LOGL_INFO, "Wrong IPv4 PDP address length %u\n", pdp_addr_len);
			return -EINVAL;
		}
		break;
	case OSMO_GPRS_SM_PDP_ADDR_IETF_IPV6:
		if (pdp_addr_len == sizeof(pdp_addr->addr6)) {
			osa6->u.sa.sa_family = AF_INET6;
			memcpy(osa6->u.sin6.sin6_addr.s6_addr, pdp_addr->addr6, sizeof(pdp_addr->addr6));
		} else if (pdp_addr_len != 0) {
			LOGSM(LOGL_INFO, "Wrong IPv6 PDP address length %u\n", pdp_addr_len);
			return -EINVAL;
		}
		break;
	case OSMO_GPRS_SM_PDP_ADDR_IETF_IPV4V6:
		if (pdp_addr_len == sizeof(pdp_addr->addr)) {
			osa4->u.sa.sa_family = AF_INET;
			osa4->u.sin.sin_addr.s_addr = pdp_addr->both.addr;
		} else if (pdp_addr_len == sizeof(pdp_addr->both.addr6)) {
			osa6->u.sa.sa_family = AF_INET6;
			memcpy(osa6->u.sin6.sin6_addr.s6_addr, pdp_addr->both.addr6, sizeof(pdp_addr->both.addr6));
		} else if (pdp_addr_len == sizeof(pdp_addr->both)) {
			osa4->u.sa.sa_family = AF_INET;
			osa4->u.sin.sin_addr.s_addr = pdp_addr->both.addr;
			osa6->u.sa.sa_family = AF_INET6;
			memcpy(osa6->u.sin6.sin6_addr.s6_addr, pdp_addr->both.addr6, sizeof(pdp_addr->both.addr6));
		} else if (pdp_addr_len != 0) {
			LOGSM(LOGL_INFO, "Wrong IPv4v6 PDP address length %u\n", pdp_addr_len);
			return -EINVAL;
		}
		break;
	default:
		LOGSM(LOGL_INFO, "No IPv4 or IPv6\n");
		return -EINVAL;
	}
	*pdp_addr_ietf_type = pdp_addr->type;

	return 0;
}

/* Chapter 9.5.1: Activate PDP Context Request */
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
					!osmo_sockaddr_is_any(&sme->pdp_addr_v4) ? &sme->pdp_addr_v4 : NULL,
					!osmo_sockaddr_is_any(&sme->pdp_addr_v6) ? &sme->pdp_addr_v6 : NULL);
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
