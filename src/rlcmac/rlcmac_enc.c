/* RLC/MAC encoding helpers, 3GPP TS 44.060 */
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
#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/rlcmac_enc.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>

void gprs_rlcmac_enc_prepare_pkt_ul_dummy_block(RlcMacUplink_t *block, uint32_t tlli)
{
	Packet_Uplink_Dummy_Control_Block_t *dummy;

	memset(block, 0, sizeof(*block));

	dummy = &block->u.Packet_Uplink_Dummy_Control_Block;
	dummy->MESSAGE_TYPE = OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK;
	/* 10.4.7: RLC/MAC control block that does not include the optional octets of the RLC/MAC control header: */
	dummy->PayloadType = 0x1;
	dummy->R = 0; /* MS sent channel request message once */
	dummy->TLLI = tlli;
}

/* 11.2.16 Packet Resource Request */
void gprs_rlcmac_enc_prepare_pkt_resource_req(RlcMacUplink_t *block,
					      struct gprs_rlcmac_ul_tbf *ul_tbf,
					      enum gprs_rlcmac_access_type acc_type)
{
	Packet_Resource_Request_t *req;
	struct gprs_rlcmac_entity *gre = ul_tbf->tbf.gre;

	memset(block, 0, sizeof(*block));

	req = &block->u.Packet_Resource_Request;
	req->MESSAGE_TYPE = OSMO_GPRS_RLCMAC_UL_MSGT_PACKET_RESOURCE_REQUEST;
	/* 10.4.7: RLC/MAC control block that does not include the optional octets of the RLC/MAC control header: */
	req->PayloadType = 0x1;
	req->R = 0; /* MS sent channel request message once */

	req->Exist_ACCESS_TYPE = 1;
	req->ACCESS_TYPE = acc_type;

	req->ID.UnionType = 1; /* Use TLLI */
	req->ID.u.TLLI = gre->tlli; /* Use TLLI */
	req->Exist_MS_Radio_Access_capability2 = 1;

	req->MS_Radio_Access_capability2.Count_MS_RA_capability_value = 1;
	/* TODO: fill Content_t: */
	/* req->MS_Radio_Access_capability2.MS_RA_capability_value[0].Content.* */

	/* 3GPP TS 24.008 Peak Throughput Class, range 1..9 */
	req->Channel_Request_Description.PEAK_THROUGHPUT_CLASS = 1;
	req->Channel_Request_Description.RADIO_PRIORITY = GPRS_RLCMAC_RADIO_PRIORITY_4;
	req->Channel_Request_Description.RLC_MODE = GPRS_RLCMAC_RLC_MODE_ACKNOWLEDGED;
	req->Channel_Request_Description.LLC_PDU_TYPE = GPRS_RLCMAC_LLC_PDU_TYPE_ACKNOWLEDGED;
	req->Channel_Request_Description.RLC_OCTET_COUNT = gprs_rlcmac_llc_queue_octets(gre->llc_queue);

	/* "this field contains the SI13_CHANGE_MARK value stored by the mobile station.
	 * If the mobile station does not have a valid PSI2 or SI13 change mark for the current cell,
	 * the mobile station shall omit this field." */
	req->Exist_CHANGE_MARK = 0;
	/* req->CHANGE_MARK; */

	/* TODO: binary representation of the C value as specified in 3GPP TS 45.008. */
	req->C_VALUE = 0;

	/* SIGN_VAR: "This field is not present for TBF establishment using two phase access or for
	 *	      a TBF in EGPRS mode" (see 3GPP TS 45.008) */
	if (acc_type != GPRS_RLCMAC_ACCESS_TYPE_2PHASE_ACC_REQ) {
		req->Exist_SIGN_VAR = 1;
		req->SIGN_VAR = 0; /* TODO: calculate */
	}

	/* For element definition see sub-clause 11.2.6 - Packet Downlink Ack/Nack.  */
	/* TODO: req->I_LEVEL_TN[8]; */

	req->Exist_AdditionsR99 = 0;
	/* TODO: no req->AdditionsR99 yet */
}
