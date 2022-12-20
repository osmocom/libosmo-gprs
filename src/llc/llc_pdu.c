/* GPRS LLC protocol implementation as per 3GPP TS 44.064 */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2022 by Sysmocom s.f.m.c. GmbH
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
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/gprs/llc/llc.h>

#define UI_HDR_LEN	3
#define N202		4
#define CRC24_LENGTH	3

extern int g_log_cat;

const struct value_string osmo_gprs_llc_sapi_names[] = {
	{ OSMO_GPRS_LLC_SAPI_GMM,	"GMM" },
	{ OSMO_GPRS_LLC_SAPI_TOM2,	"TOM2" },
	{ OSMO_GPRS_LLC_SAPI_SNDCP3,	"SNDCP3" },
	{ OSMO_GPRS_LLC_SAPI_SNDCP5,	"SNDCP5" },
	{ OSMO_GPRS_LLC_SAPI_SMS,	"SMS" },
	{ OSMO_GPRS_LLC_SAPI_TOM8,	"TOM8" },
	{ OSMO_GPRS_LLC_SAPI_SNDCP9,	"SNDCP9" },
	{ OSMO_GPRS_LLC_SAPI_SNDCP11,	"SNDCP11" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_llc_frame_fmt_names[] = {
	{ OSMO_GPRS_LLC_FMT_I,		"I" },
	{ OSMO_GPRS_LLC_FMT_S,		"U" },
	{ OSMO_GPRS_LLC_FMT_UI,		"UI" },
	{ OSMO_GPRS_LLC_FMT_U,		"U" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_llc_frame_func_names[] = {
	/* 6.4.1 Unnumbered (U) frames */
	{ OSMO_GPRS_LLC_FUNC_SABM,	"SABM" },
	{ OSMO_GPRS_LLC_FUNC_DISC,	"DISC" },
	{ OSMO_GPRS_LLC_FUNC_UA,	"UA" },
	{ OSMO_GPRS_LLC_FUNC_DM,	"DM" },
	{ OSMO_GPRS_LLC_FUNC_FRMR,	"FRMR" },
	{ OSMO_GPRS_LLC_FUNC_XID,	"XID" },
	{ OSMO_GPRS_LLC_FUNC_NULL,	"NULL" },
	/* 6.4.2 Unconfirmed Information (UI) frame */
	{ OSMO_GPRS_LLC_FUNC_UI,	"UI" },
	{ OSMO_GPRS_LLC_FUNC_UI_DUMMY,	"UI Dummy" },
	/* 6.4.3 Combined Information (I) and Supervisory (S) frames */
	{ OSMO_GPRS_LLC_FUNC_RR,	"RR" },
	{ OSMO_GPRS_LLC_FUNC_ACK,	"ACK" },
	{ OSMO_GPRS_LLC_FUNC_SACK,	"SACK" },
	{ OSMO_GPRS_LLC_FUNC_RNR,	"RNR" },
	{ 0, NULL }
};

uint32_t crc24_calc(uint32_t fcs, const uint8_t *data, size_t len);

uint32_t osmo_gprs_llc_fcs(const uint8_t *data, size_t len)
{
	uint32_t fcs_calc;

	fcs_calc = crc24_calc(0xffffff, data, len);
	fcs_calc = ~fcs_calc;
	fcs_calc &= 0xffffff;

	return fcs_calc;
}

void osmo_gprs_llc_pdu_hdr_dump_buf(char *buf, size_t buf_size,
				    const struct osmo_gprs_llc_pdu_decoded *pdu)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buf_size };

	OSMO_STRBUF_PRINTF(sb, "SAPI=%u (%s), %s func=%s C/R=%c",
			   pdu->sapi, osmo_gprs_llc_sapi_name(pdu->sapi),
			   osmo_gprs_llc_frame_fmt_name(pdu->fmt),
			   osmo_gprs_llc_frame_func_name(pdu->func),
			   pdu->flags & OSMO_GPRS_LLC_PDU_F_CMD_RSP ? '1' : '0');

	switch (pdu->fmt) {
	case OSMO_GPRS_LLC_FMT_I:
		OSMO_STRBUF_PRINTF(sb, " A=%c N(R)=%u N(S)=%u",
				   pdu->flags & OSMO_GPRS_LLC_PDU_F_ACK_REQ ? '1' : '0',
				   pdu->seq_rx, pdu->seq_tx);
		break;
	case OSMO_GPRS_LLC_FMT_S:
		OSMO_STRBUF_PRINTF(sb, " A=%c N(R)=%u",
				   pdu->flags & OSMO_GPRS_LLC_PDU_F_ACK_REQ ? '1' : '0',
				   pdu->seq_rx);
		break;
	case OSMO_GPRS_LLC_FMT_UI:
		OSMO_STRBUF_PRINTF(sb, " PM=%c E=%c IP=%c N(U)=%u",
				   pdu->flags & OSMO_GPRS_LLC_PDU_F_PROT_MODE ? '1' : '0',
				   pdu->flags & OSMO_GPRS_LLC_PDU_F_ENC_MODE ? '1' : '0',
				   pdu->flags & OSMO_GPRS_LLC_PDU_F_MAC_PRES ? '1' : '0',
				   pdu->seq_tx);
		break;
	case OSMO_GPRS_LLC_FMT_U:
		OSMO_STRBUF_PRINTF(sb, " P/F=%c",
				   pdu->flags & OSMO_GPRS_LLC_PDU_F_FOLL_FIN ? '1' : '0');
		break;
	}

	if (pdu->flags & OSMO_GPRS_LLC_PDU_F_MAC_PRES)
		OSMO_STRBUF_PRINTF(sb, " MAC=%08x", pdu->mac);
	OSMO_STRBUF_PRINTF(sb, " FCS=%06x", pdu->fcs);
}

const char *osmo_gprs_llc_pdu_hdr_dump(const struct osmo_gprs_llc_pdu_decoded *pdu)
{
	static __thread char buf[256];
	osmo_gprs_llc_pdu_hdr_dump_buf(&buf[0], sizeof(buf), pdu);
	return buf;
}

/* 6.4.1 Unnumbered (U) frames */
#define GPRS_LLC_U_NULL_CMD		0x00
#define GPRS_LLC_U_DM_RESP		0x01
#define GPRS_LLC_U_DISC_CMD		0x04
#define GPRS_LLC_U_UA_RESP		0x06
#define GPRS_LLC_U_SABM_CMD		0x07
#define GPRS_LLC_U_FRMR_RESP		0x08
#define GPRS_LLC_U_XID			0x0b

int osmo_gprs_llc_pdu_encode(struct msgb *msg, const struct osmo_gprs_llc_pdu_decoded *pdu)
{
	uint8_t *addr = msgb_put(msg, 1);
	uint8_t *ctrl = NULL;
	size_t crc_len;
	uint32_t fcs;

	/* 6.2.3 Service Access Point Identifier (SAPI) */
	addr[0] = pdu->sapi & 0x0f;

	/* 6.2.2 Commmand/Response bit (C/R) */
	if (pdu->flags & OSMO_GPRS_LLC_PDU_F_CMD_RSP)
		addr[0] |= (1 << 6);

	switch (pdu->fmt) {
	case OSMO_GPRS_LLC_FMT_I:
		ctrl = msgb_put(msg, 3);

		ctrl[0] = 0x00; /* 0xxxxxxx */
		ctrl[1] = ctrl[2] = 0x00;

		if (pdu->flags & OSMO_GPRS_LLC_PDU_F_ACK_REQ)
			ctrl[0] |= (1 << 6);

		ctrl[0] |= (pdu->seq_tx >> 4) & 0x1f;
		ctrl[1] |= (pdu->seq_tx & 0x0f) << 4;

		ctrl[1] |= (pdu->seq_rx >> 6) & 0x07;
		ctrl[2] |= (pdu->seq_rx & 0x3f) << 2;

		ctrl[2] |= (pdu->func - OSMO_GPRS_LLC_FUNC_RR) & 0x03;

		if (pdu->func == OSMO_GPRS_LLC_FUNC_SACK) {
			if (pdu->sack.len == 0)
				return -EINVAL;
			msgb_put_u8(msg, pdu->sack.len - 1);
			memcpy(msgb_put(msg, pdu->sack.len),
			       &pdu->sack.r[0], pdu->sack.len);
		}
		break;
	case OSMO_GPRS_LLC_FMT_S:
		ctrl = msgb_put(msg, 2);

		ctrl[0] = 0x80; /* 10xxxxxx */
		ctrl[1] = 0x00;

		if (pdu->flags & OSMO_GPRS_LLC_PDU_F_ACK_REQ)
			ctrl[1] |= 0x20;

		ctrl[0] |= (pdu->seq_rx >> 6) & 0x07;
		ctrl[1] |= (pdu->seq_rx & 0x3f) << 2;

		ctrl[1] |= (pdu->func - OSMO_GPRS_LLC_FUNC_RR) & 0x03;

		if (pdu->func == OSMO_GPRS_LLC_FUNC_SACK) {
			if (pdu->sack.len == 0)
				return -EINVAL;
			memcpy(msgb_put(msg, pdu->sack.len),
			       &pdu->sack.r[0], pdu->sack.len);
		}
		break;
	case OSMO_GPRS_LLC_FMT_UI:
		ctrl = msgb_put(msg, 2);

		ctrl[0] = 0xc0; /* 110xxxxx */
		ctrl[1] = 0x00;

		if (pdu->flags & OSMO_GPRS_LLC_PDU_F_MAC_PRES)
			ctrl[0] |= (1 << 4);

		ctrl[0] |= (pdu->seq_tx >> 6) & 0x07;
		ctrl[1] |= (pdu->seq_tx & 0x3f) << 2;

		if (pdu->flags & OSMO_GPRS_LLC_PDU_F_ENC_MODE)
			ctrl[1] |= (1 << 1);
		if (pdu->flags & OSMO_GPRS_LLC_PDU_F_PROT_MODE)
			ctrl[1] |= (1 << 0);
		break;
	case OSMO_GPRS_LLC_FMT_U:
		ctrl = msgb_put(msg, 1);

		ctrl[0] = 0xe0; /* 111xxxxx */

		if (pdu->flags & OSMO_GPRS_LLC_PDU_F_FOLL_FIN)
			ctrl[0] |= (1 << 4);

		switch (pdu->func) {
		case OSMO_GPRS_LLC_FUNC_NULL:
			ctrl[0] |= GPRS_LLC_U_NULL_CMD;
			break;
		case OSMO_GPRS_LLC_FUNC_DM:
			ctrl[0] |= GPRS_LLC_U_DM_RESP;
			break;
		case OSMO_GPRS_LLC_FUNC_DISC:
			ctrl[0] |= GPRS_LLC_U_DISC_CMD;
			break;
		case OSMO_GPRS_LLC_FUNC_UA:
			ctrl[0] |= GPRS_LLC_U_UA_RESP;
			break;
		case OSMO_GPRS_LLC_FUNC_SABM:
			ctrl[0] |= GPRS_LLC_U_SABM_CMD;
			break;
		case OSMO_GPRS_LLC_FUNC_FRMR:
			ctrl[0] |= GPRS_LLC_U_FRMR_RESP;
			break;
		case OSMO_GPRS_LLC_FUNC_XID:
			ctrl[0] |= GPRS_LLC_U_XID;
			break;
		default:
			LOGP(g_log_cat, LOGL_ERROR,
			     "Unknown UI func=0x%02x\n", pdu->func);
			return -EINVAL;
		}
		break;
	}

	if (pdu->data_len > 0) {
		uint8_t *data = msgb_put(msg, pdu->data_len);
		memcpy(data, pdu->data, pdu->data_len);
	}

	/* 5.5a Message Authentication Code (MAC) field */
	if (pdu->flags & OSMO_GPRS_LLC_PDU_F_MAC_PRES) {
		/* TODO: calculate MAC (see 3GPP TS 43.020) */
		LOGP(g_log_cat, LOGL_ERROR,
		     "Message Authentication Code (MAC) is not implemented\n");
		return -ENOTSUP;
	}

	/* 5.5 Frame Check Sequence (FCS) field */
	crc_len = msg->tail - addr;
	if (~pdu->flags & OSMO_GPRS_LLC_PDU_F_PROT_MODE)
		crc_len = OSMO_MIN(crc_len, UI_HDR_LEN + N202);
	fcs = osmo_gprs_llc_fcs(addr, crc_len);

	msgb_put_u8(msg, fcs & 0xff);
	msgb_put_u8(msg, (fcs >> 8) & 0xff);
	msgb_put_u8(msg, (fcs >> 16) & 0xff);

	return 0;
}

int osmo_gprs_llc_pdu_decode(struct osmo_gprs_llc_pdu_decoded *pdu,
			     const uint8_t *data, size_t data_len)
{
	const uint8_t *addr = &data[0];
	const uint8_t *ctrl = &data[1];

#define check_len(len, text) \
	do { \
		if (data_len < (len)) { \
			LOGP(g_log_cat, LOGL_ERROR, "Failed to parse LLC PDU: %s\n", text); \
			return -EINVAL; \
		} \
	} while (0)

	/* 5.5 Frame Check Sequence (FCS) field */
	check_len(CRC24_LENGTH, "missing Frame Check Sequence (FCS) field");
	pdu->fcs  = data[data_len - 3];
	pdu->fcs |= data[data_len - 2] << 8;
	pdu->fcs |= data[data_len - 1] << 16;
	data_len -= CRC24_LENGTH;

	/* 6.2.0 Address field format */
	check_len(1, "missing Address field");
	data_len -= 1;

	/* Initial assumption: FCS covers hdr + all inf fields */
	pdu->flags |= OSMO_GPRS_LLC_PDU_F_PROT_MODE;

	/* 6.2.1 Protocol Discriminator bit (PD): shall be 0 */
	if (*addr & 0x80) {
		LOGP(g_log_cat, LOGL_ERROR, "Protocol Discriminator shall be 0\n");
		return -EINVAL;
	}

	/* 6.2.2 Commmand/Response bit (C/R) */
	if (*addr & 0x40)
		pdu->flags |= OSMO_GPRS_LLC_PDU_F_CMD_RSP;

	/* 6.2.3 Service Access Point Identifier (SAPI) */
	pdu->sapi = *addr & 0x0f;

	/* Check for reserved SAPI */
	switch (*addr & 0x0f) {
	case 0x00:
	case 0x04:
	case 0x06:
	case 0x0a:
	case 0x0c:
	case 0x0d:
	case 0x0f:
		LOGP(g_log_cat, LOGL_ERROR, "Unknown SAPI=%u\n", pdu->sapi);
		return -EINVAL;
	}

	/* U format has the shortest control field length=1 */
	check_len(1, "missing Control field");

	/* 6.3.0 Control field formats */
	if ((ctrl[0] & 0x80) == 0) {
		/* 6.3.1 Information transfer format - I */
		pdu->fmt = OSMO_GPRS_LLC_FMT_I;

		check_len(3, "I format Control field is too short");
		data_len -= 3;

		pdu->data = ctrl + 3;
		/* pdu->data_len is set below */

		if (ctrl[0] & 0x40)
			pdu->flags |= OSMO_GPRS_LLC_PDU_F_ACK_REQ;

		pdu->seq_tx  = (ctrl[0] & 0x1f) << 4;
		pdu->seq_tx |= (ctrl[1] >> 4);

		pdu->seq_rx  = (ctrl[1] & 0x7) << 6;
		pdu->seq_rx |= (ctrl[2] >> 2);

		switch (ctrl[2] & 0x03) {
		case 0:
			pdu->func = OSMO_GPRS_LLC_FUNC_RR;
			break;
		case 1:
			pdu->func = OSMO_GPRS_LLC_FUNC_ACK;
			break;
		case 2:
			pdu->func = OSMO_GPRS_LLC_FUNC_RNR;
			break;
		case 3:
			pdu->func = OSMO_GPRS_LLC_FUNC_SACK;
			check_len(1, "I func=SACK is too short");
			pdu->sack.len = (ctrl[3] & 0x1f) + 1; /* 1 .. 32 */
			/* The R(n) bitmask takes len=(K + 1) octets */
			check_len(pdu->sack.len, "I func=SACK is too short");
			memcpy(&pdu->sack.r[0], ctrl + 4, pdu->sack.len);
			pdu->data += 1 + pdu->sack.len;
			data_len -= 1 + pdu->sack.len;
			break;
		}
		pdu->data_len = data_len;
	} else if ((ctrl[0] & 0xc0) == 0x80) {
		/* 6.3.2 Supervisory format - S */
		pdu->fmt = OSMO_GPRS_LLC_FMT_S;

		check_len(2, "S format Control field is too short");
		data_len -= 2;

		pdu->data = NULL;
		pdu->data_len = 0;

		if (ctrl[0] & 0x20)
			pdu->flags |= OSMO_GPRS_LLC_PDU_F_ACK_REQ;

		pdu->seq_rx  = (ctrl[0] & 0x7) << 6;
		pdu->seq_rx |= (ctrl[1] >> 2);

		switch (ctrl[1] & 0x03) {
		case 0:
			pdu->func = OSMO_GPRS_LLC_FUNC_RR;
			break;
		case 1:
			pdu->func = OSMO_GPRS_LLC_FUNC_ACK;
			break;
		case 2:
			pdu->func = OSMO_GPRS_LLC_FUNC_RNR;
			break;
		case 3:
			pdu->func = OSMO_GPRS_LLC_FUNC_SACK;
			/* The R(n) bitmask takes all remaining octets */
			check_len(1, "S func=SACK is too short");
			pdu->sack.len = data_len; /* 1 .. 32 */
			memcpy(&pdu->sack.r[0], ctrl + 2, pdu->sack.len);
			break;
		}
	} else if ((ctrl[0] & 0xe0) == 0xc0) {
		/* 6.3.3 Unconfirmed Information format - UI */
		pdu->fmt = OSMO_GPRS_LLC_FMT_UI;
		pdu->func = OSMO_GPRS_LLC_FUNC_UI;

		check_len(2, "UI format Control field is too short");
		data_len -= 2;

		pdu->data = ctrl + 2;
		pdu->data_len = data_len;

		pdu->seq_tx  = (ctrl[0] & 0x7) << 6;
		pdu->seq_tx |= (ctrl[1] >> 2);

		if (ctrl[0] & 0x10) {
			check_len(sizeof(pdu->mac), "missing MAC field");
			pdu->data_len -= sizeof(pdu->mac);
			data_len -= sizeof(pdu->mac);

			pdu->mac = osmo_load32le(&pdu->data[data_len]);
			pdu->flags |= OSMO_GPRS_LLC_PDU_F_MAC_PRES;
		}

		if (ctrl[1] & 0x02)
			pdu->flags |= OSMO_GPRS_LLC_PDU_F_ENC_MODE;

		if (~ctrl[1] & 0x01) /* FCS covers hdr + N202 octets */
			pdu->flags &= ~OSMO_GPRS_LLC_PDU_F_PROT_MODE;
	} else {
		/* 6.3.4 Unnumbered format - U */
		pdu->fmt = OSMO_GPRS_LLC_FMT_U;

		check_len(1, "U format Control field is too short");
		data_len -= 1;

		pdu->data = NULL;
		pdu->data_len = 0;

		if (ctrl[0] & 0x10)
			pdu->flags |= OSMO_GPRS_LLC_PDU_F_FOLL_FIN;

		switch (ctrl[0] & 0x0f) {
		case GPRS_LLC_U_NULL_CMD:
			pdu->func = OSMO_GPRS_LLC_FUNC_NULL;
			break;
		case GPRS_LLC_U_DM_RESP:
			pdu->func = OSMO_GPRS_LLC_FUNC_DM;
			break;
		case GPRS_LLC_U_DISC_CMD:
			pdu->func = OSMO_GPRS_LLC_FUNC_DISC;
			break;
		case GPRS_LLC_U_UA_RESP:
			pdu->func = OSMO_GPRS_LLC_FUNC_UA;
			break;
		case GPRS_LLC_U_SABM_CMD:
			pdu->func = OSMO_GPRS_LLC_FUNC_SABM;
			break;
		case GPRS_LLC_U_FRMR_RESP:
			pdu->func = OSMO_GPRS_LLC_FUNC_FRMR;
			break;
		case GPRS_LLC_U_XID:
			pdu->func = OSMO_GPRS_LLC_FUNC_XID;
			pdu->data = ctrl + 1;
			pdu->data_len = data_len;
			break;
		default:
			LOGP(g_log_cat, LOGL_ERROR, "Unknown U func=0x%02x\n", ctrl[0] & 0x0f);
			return -ENOTSUP;
		}
	}

#undef check_len

	return 0;
}
