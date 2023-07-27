/* GPRS QoS definitions from 3GPP TS 24.008 sec 10.5.6.5 */
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

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include "qos.h"

#define GPRS_QOS_FALLTHROUGH __attribute__ ((fallthrough))

static uint32_t dec_mbr_kbps(uint8_t mbr_byte, const uint8_t *extended_mbr_byte, const uint8_t *extended2_mbr_byte)
{
	uint8_t mbr, embr1, embr2;
	mbr = mbr_byte;
	embr1 = extended_mbr_byte ? *extended_mbr_byte : 0;
	embr2 = extended2_mbr_byte ? *extended2_mbr_byte : 0;

	if (mbr == 0)
		return 0;
	if (mbr == 0xff)
		return UINT32_MAX;
	if (mbr == 0xfe) { /* Check extended field */
		if (extended_mbr_byte == NULL || embr1 == 0)
			return 8640;
		if (embr1 == 0xfa) { /* Check extended2 field */
			if (extended2_mbr_byte == NULL || embr2 == 0)
				return 256 * 1000;
			if (embr2 == 0xf6)
				return 10 * 1000 * 1000; /* TODO: check "extended quality of service" IE */
			if (embr2 >= 0xa2 && embr2 <= 0xf6)
				return (1500 + (embr2 - (0xa2 - 1)) * 100) * 1000;
			if (embr2 >= 0x3e && embr2 <= 0xa1)
				return (500 + (embr2 - (0x3e - 1)) * 10) * 1000;
			return (256 + embr2 * 4) * 1000;
		}
		if (embr1 >= 0xbb && embr1 <= 0xfa)
			return (128 + (embr1 - (0xbb - 1)) * 2) * 1000;
		if (embr1 >= 0x4b && embr1 <= 0xba)
			return (16 + (embr1 - (0x4b - 1)) * 1) * 1000;
		return 8600 + embr1 * 100;
	}
	if (mbr & 0x80) {
		mbr &= ~0x80;
		return 576 + mbr_byte * 64;
	}
	if (mbr & 0x40) {
		mbr &= ~0x40;
		return 64 + mbr * 8;
	}
	return mbr;
}

static uint16_t dec_transfer_delay_ms(uint8_t transfer_delay_byte)
{
	transfer_delay_byte &= 0x3f; /* 6 bits */
	if (transfer_delay_byte <= 0x0f)
		return transfer_delay_byte;
	if (transfer_delay_byte <= 0x1f)
		return 200 + (transfer_delay_byte - 0x10) * 50;
	return 1000 + (transfer_delay_byte - 0x20) * 100;
}

/* TS 29.060 7.7.34 Quality of Service (QoS) Profile */
/* TS 24.008 10.5.6.5 Quality of service */
int16_t gprs_qos_parse_qos_profile(
	struct osmo_gprs_sm_qos_profile_decoded *decoded, const uint8_t *data, size_t data_len)
{
	struct osmo_gprs_sm_qos_profile *source = (struct osmo_gprs_sm_qos_profile *)data;

	OSMO_ASSERT(decoded);
	OSMO_ASSERT(data);

	memset(decoded, 0, sizeof(struct osmo_gprs_sm_qos_profile_decoded));
	switch (data_len) {
	case 20: /* octet 3 + octet 3-22 */
		decoded->bit_rate_uplink_extended2_present = true;
		GPRS_QOS_FALLTHROUGH;
	case 18: /* octet 3 + octet 3-20 */
		decoded->bit_rate_downlink_extended2_present = true;
		GPRS_QOS_FALLTHROUGH;
	case 16: /* octet 3 + octet 3-18 */
		decoded->bit_rate_uplink_extended_present = true;
		GPRS_QOS_FALLTHROUGH;
	case 14: /* octet 3 + octet 3-16 */
		decoded->bit_rate_downlink_extended_present = true;
		GPRS_QOS_FALLTHROUGH;
	case 12: /* octet 3-14 */
		decoded->data_octet14_present = true;
		GPRS_QOS_FALLTHROUGH;
	case 11: /* octet 3-13 */
		decoded->data_octet6_to_13_present = true;
		GPRS_QOS_FALLTHROUGH;
	case 3: /* octet 3 + octet 4 + octet 5 */
		break;
	default:
		LOGP(DLGLOBAL, LOGL_ERROR, "Qos Profile wrong length %zu\n", data_len);
		return -1;
	}
	memcpy(&decoded->qos_profile, source, data_len);

	/* Calculate resulting MBRs in kbps: */
	if (decoded->data_octet6_to_13_present) {
		decoded->dec_transfer_delay = dec_transfer_delay_ms(source->data.transfer_delay);
		decoded->dec_mbr_kbps_dl = dec_mbr_kbps(source->data.max_bit_rate_downlink,
							decoded->bit_rate_downlink_extended_present ?
								&source->data.extended.max_bit_rate_downlink : NULL,
							decoded->bit_rate_downlink_extended2_present ?
								&source->data.extended2.max_bit_rate_downlink : NULL);
		decoded->dec_mbr_kbps_ul = dec_mbr_kbps(source->data.max_bit_rate_uplink,
							decoded->bit_rate_uplink_extended_present ?
								&source->data.extended.max_bit_rate_uplink : NULL,
							decoded->bit_rate_uplink_extended2_present ?
								&source->data.extended2.max_bit_rate_uplink : NULL);
	  /* GBR is encoded the same way as MBR: */
	  decoded->dec_gbr_kbps_dl = dec_mbr_kbps(source->data.guaranteed_bit_rate_downlink,
						  decoded->bit_rate_downlink_extended_present ?
							&source->data.extended.guaranteed_bit_rate_downlink : NULL,
						  decoded->bit_rate_downlink_extended2_present ?
							&source->data.extended2.guaranteed_bit_rate_downlink : NULL);
	  decoded->dec_gbr_kbps_ul = dec_mbr_kbps(source->data.guaranteed_bit_rate_uplink,
						  decoded->bit_rate_uplink_extended_present ?
							&source->data.extended.guaranteed_bit_rate_uplink : NULL,
						  decoded->bit_rate_uplink_extended2_present ?
							&source->data.extended2.guaranteed_bit_rate_uplink : NULL);
	}

	return data_len;
}

static uint8_t enc_transfer_delay_ms(uint16_t transfer_delay_ms)
{
	if (transfer_delay_ms >= 4000)
		return 0x3e;
	if (transfer_delay_ms >= 1000) {
		transfer_delay_ms -= 1000;
		return 0x20 + (transfer_delay_ms / 100);
	}
	if (transfer_delay_ms >= 200) {
		transfer_delay_ms -= 200;
		return 0x10 + (transfer_delay_ms / 50);
	}
	if (transfer_delay_ms > 150)
		transfer_delay_ms = 150;
	if (transfer_delay_ms >= 10)
		return transfer_delay_ms / 10;
	return 1; /* 0 is "Reserved" Network->MS */
}

#define CHECK_EXT1 0xfe
#define CHECK_EXT2 0xfa
static uint32_t enc_mbr_kbps(uint32_t mbr_kbps, uint8_t *mbr_byte, uint8_t *extended_mbr_byte, uint8_t *extended2_mbr_byte)
{
	/* up to EXT2 byte: */
	if (mbr_kbps > 10*1000*1000) {
		*extended2_mbr_byte = 0xf6; /* TODO: need to set the real value somewhere else */
		goto ret_check_ext2;
	}
	if (mbr_kbps >= 1600*1000) {
		mbr_kbps -= 1500*1000;
		*extended2_mbr_byte = 0xa1 + mbr_kbps/(100*1000);
		goto ret_check_ext2;
	}
	if (mbr_kbps >= 510*1000) {
		mbr_kbps -= 500*1000;
		*extended2_mbr_byte = 0x2d + mbr_kbps/(10*1000);
		goto ret_check_ext2;
	}
	if (mbr_kbps >= 260*1000) {
		mbr_kbps -= 256*1000;
		*extended2_mbr_byte = 0x00 + mbr_kbps/(4*1000);
		goto ret_check_ext2;
	}

	/* up to EXT1 byte: */
	if (mbr_kbps >= 130*1000) {
		mbr_kbps -= 128*1000;
		*extended_mbr_byte = 0xba +  mbr_kbps/(2*1000);
		goto ret_check_ext1;
	}
	if (mbr_kbps >= 17*1000) {
		mbr_kbps -= 16*1000;
		*extended_mbr_byte = 0x4a +  mbr_kbps/(1*1000);
		goto ret_check_ext1;
	}
	if (mbr_kbps >= 8700) {
		mbr_kbps -= 8600;
		*extended_mbr_byte = 0x00 +  mbr_kbps/(100);
		goto ret_check_ext1;
	}

	/* Only MBR byte: */
	if (mbr_kbps >= 576) {
		mbr_kbps -= 576;
		*mbr_byte = 0x80 +  mbr_kbps/(64);
		goto ret_mbr;
	}
	if (mbr_kbps >= 64) {
		mbr_kbps -= 64;
		*mbr_byte = 0x40 + mbr_kbps/(8);
		goto ret_mbr;
	}
	if (mbr_kbps > 0) {
		*mbr_byte = mbr_kbps;
		goto ret_mbr;
	}
	/* if (mbr_kpbs == 0) */
	*mbr_byte = 0xff;
	goto ret_mbr;

ret_check_ext2:
	*extended_mbr_byte = CHECK_EXT2;
	*mbr_byte = CHECK_EXT1;
	return 2;
ret_check_ext1:
	*extended2_mbr_byte = 0;
	*mbr_byte = CHECK_EXT1;
	return 1;
ret_mbr:
	*extended2_mbr_byte = 0;
	*extended_mbr_byte = 0;
	return 0;
}

int16_t gprs_qos_build_qos_profile(const struct osmo_gprs_sm_qos_profile_decoded *decoded, void *data, int data_len)
{
	struct osmo_gprs_sm_qos_profile *target;
	int mbr_extended_dl, mbr_extended_ul;
	int gbr_extended_dl, gbr_extended_ul;
	int extended_dl, extended_ul;
	unsigned int enc_len = 0;

	OSMO_ASSERT(decoded);
	OSMO_ASSERT(data);
	OSMO_ASSERT((size_t)data_len >= sizeof(struct osmo_gprs_sm_qos_profile));

	target = (struct osmo_gprs_sm_qos_profile *)data;

	/* First, copy the encoded buffer as it is: */
	memcpy(target, &decoded->qos_profile, sizeof(struct osmo_gprs_sm_qos_profile));

	/* Avoid setting Traffic Handling to 0=Reserved even if ignored based on
	 * Interactive/Background Traffic Class: */
	if (target->data.traffic_handling_priority == 0)
		target->data.traffic_handling_priority = 1;

	/* Then, encode in the target position the decoded-provided fields: */
	if (decoded->data_octet6_to_13_present)
		target->data.transfer_delay = enc_transfer_delay_ms(decoded->dec_transfer_delay);

	mbr_extended_dl = enc_mbr_kbps(decoded->dec_mbr_kbps_dl,
				       &target->data.max_bit_rate_downlink,
				       &target->data.extended.max_bit_rate_downlink,
				       &target->data.extended2.max_bit_rate_downlink);
	mbr_extended_ul = enc_mbr_kbps(decoded->dec_mbr_kbps_ul,
				       &target->data.max_bit_rate_uplink,
				       &target->data.extended.max_bit_rate_uplink,
				       &target->data.extended2.max_bit_rate_uplink);
	/* GBR is encoded the same way as MBR: */
	gbr_extended_dl = enc_mbr_kbps(decoded->dec_gbr_kbps_dl,
				       &target->data.guaranteed_bit_rate_downlink,
				       &target->data.extended.guaranteed_bit_rate_downlink,
				       &target->data.extended2.guaranteed_bit_rate_downlink);
	gbr_extended_ul = enc_mbr_kbps(decoded->dec_gbr_kbps_ul,
				       &target->data.guaranteed_bit_rate_uplink,
				       &target->data.extended.guaranteed_bit_rate_uplink,
				       &target->data.extended2.guaranteed_bit_rate_uplink);
	extended_dl = OSMO_MAX(mbr_extended_dl, gbr_extended_dl);
	extended_ul = OSMO_MAX(mbr_extended_ul, gbr_extended_ul);

	/* Finally, set len based on the required octets to encode the fields: */
	if (extended_ul == 2)
		enc_len = 20;
	else if (extended_dl == 2)
		enc_len = 18;
	else if (extended_ul == 1)
		enc_len = 16;
	else if (extended_dl == 1)
		enc_len = 14;
	else if (decoded->data_octet14_present)
		enc_len = 12;
	else if (decoded->data_octet6_to_13_present)
		enc_len = 11;
	else
		enc_len = 5;
	return enc_len;
}
