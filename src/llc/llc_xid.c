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

#include <errno.h>
#include <stdint.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/gprs/llc/llc.h>

const struct value_string osmo_gprs_llc_xid_type_names[] = {
	{ OSMO_GPRS_LLC_XID_T_VERSION,		"LLC-Version" },
	{ OSMO_GPRS_LLC_XID_T_IOV_UI,		"IOV-UI" },
	{ OSMO_GPRS_LLC_XID_T_IOV_I,		"IOV-I" },
	{ OSMO_GPRS_LLC_XID_T_T200,		"T200" },
	{ OSMO_GPRS_LLC_XID_T_N200,		"N200" },
	{ OSMO_GPRS_LLC_XID_T_N201_U,		"N201-U" },
	{ OSMO_GPRS_LLC_XID_T_N201_I,		"N201-I" },
	{ OSMO_GPRS_LLC_XID_T_mD,		"mD" },
	{ OSMO_GPRS_LLC_XID_T_mU,		"mU" },
	{ OSMO_GPRS_LLC_XID_T_kD,		"kD" },
	{ OSMO_GPRS_LLC_XID_T_kU,		"kU" },
	{ OSMO_GPRS_LLC_XID_T_L3_PAR,		"L3-Params" },
	{ OSMO_GPRS_LLC_XID_T_RESET,		"Reset" },
	{ OSMO_GPRS_LLC_XID_T_IIOV_UI,		"i-IOV-UI" },
	{ OSMO_GPRS_LLC_XID_T_IIOV_UI_CNT,	"i-IOV-UI-cnt" },
	{ OSMO_GPRS_LLC_XID_T_MAC_IOV_UI,	"MAC-IOV-UI" },
	{ 0, NULL }
};

/* Table 6: LLC layer parameter negotiation */
static const struct {
	bool var_len;
	uint8_t len;
	unsigned int min;
	unsigned int max;
	bool allow_zero;
} gprs_llc_xid_desc[] = {
	[OSMO_GPRS_LLC_XID_T_VERSION] = { .len = 1, .min = 0, .max = 15 },
	[OSMO_GPRS_LLC_XID_T_IOV_UI] = { .len = 4, .min = 0, .max = UINT32_MAX },
	[OSMO_GPRS_LLC_XID_T_IOV_I] = { .len = 4, .min = 0, .max = UINT32_MAX },
	[OSMO_GPRS_LLC_XID_T_T200] = { .len = 2, .min = 0, .max = 4095 },
	[OSMO_GPRS_LLC_XID_T_N200] = { .len = 1, .min = 1, .max = 15 },
	[OSMO_GPRS_LLC_XID_T_N201_U] = { .len = 2, .min = 140, .max = 1520 },
	[OSMO_GPRS_LLC_XID_T_N201_I] = { .len = 2, .min = 140, .max = 1520 },
	[OSMO_GPRS_LLC_XID_T_mD] = { .len = 2, .min = 9, .max = 24320, .allow_zero = true },
	[OSMO_GPRS_LLC_XID_T_mU] = { .len = 2, .min = 9, .max = 24320, .allow_zero = true },
	[OSMO_GPRS_LLC_XID_T_kD] = { .len = 1, .min = 1, .max = 255 },
	[OSMO_GPRS_LLC_XID_T_kU] = { .len = 1, .min = 1, .max = 255 },
	[OSMO_GPRS_LLC_XID_T_L3_PAR] = { .var_len = true },
	[OSMO_GPRS_LLC_XID_T_RESET] = { .len = 0 },
	[OSMO_GPRS_LLC_XID_T_IIOV_UI] = { .len = 4, .min = 0, .max = UINT32_MAX },
	[OSMO_GPRS_LLC_XID_T_IIOV_UI_CNT] = { .len = 1, .min = 1, .max = 255 },
	[OSMO_GPRS_LLC_XID_T_MAC_IOV_UI] = { .len = 4, .min = 0, .max = UINT32_MAX },
};

bool osmo_gprs_llc_xid_field_is_valid(const struct osmo_gprs_llc_xid_field *field)
{
	if (field->type >= ARRAY_SIZE(gprs_llc_xid_desc)) {
		LOGLLC(LOGL_ERROR,
		       "Unknown XID field type 0x%02x\n", field->type);
		return false;
	}

	if (gprs_llc_xid_desc[field->type].var_len)
		return true;

	/* For mU and mD, the value range (9 .. 24320) also includes 0 */
	if (gprs_llc_xid_desc[field->type].allow_zero && field->val == 0)
		return true;

	if (field->val < gprs_llc_xid_desc[field->type].min) {
		LOGLLC(LOGL_ERROR,
		       "XID field %s value=%u < min=%u\n",
		       osmo_gprs_llc_xid_type_name(field->type),
		       field->val, gprs_llc_xid_desc[field->type].min);
		return false;
	}

	if (field->val > gprs_llc_xid_desc[field->type].max) {
		LOGLLC(LOGL_ERROR,
		       "XID field %s value=%u > max=%u\n",
		       osmo_gprs_llc_xid_type_name(field->type),
		       field->val, gprs_llc_xid_desc[field->type].max);
		return false;
	}

	return true;
}

int osmo_gprs_llc_xid_encode(struct msgb *msg,
			     const struct osmo_gprs_llc_xid_field *fields,
			     unsigned int num_fields)
{
	for (unsigned int i = 0; i < num_fields; i++) {
		const struct osmo_gprs_llc_xid_field *field = &fields[i];
		uint8_t *hdr, len;

		if (!osmo_gprs_llc_xid_field_is_valid(field))
			return -EINVAL;

		/* XID field type */
		hdr = msgb_put(msg, 1);
		hdr[0] = (field->type & 0x1f) << 2;

		/* XID field length */
		if (gprs_llc_xid_desc[field->type].var_len)
			len = field->var.val_len;
		else
			len = gprs_llc_xid_desc[field->type].len;

		if (len == 0)
			continue;
		if (len < 4) {
			hdr[0] |= len;
		} else {
			msgb_put(msg, 1);
			hdr[0] |= (1 << 7); /* XL=1 */
			hdr[0] |= (len >> 6) & 0x03;
			hdr[1]  = (len << 2) & 0xff;
		}

		/* XID field value (variable length) */
		if (gprs_llc_xid_desc[field->type].var_len) {
			memcpy(msgb_put(msg, len), field->var.val, len);
		} else {
			switch (len) {
			case 1:
				msgb_put_u8(msg, field->val);
				break;
			case 2:
				osmo_store16be(field->val, msgb_put(msg, 2));
				break;
			case 4:
				osmo_store32be(field->val, msgb_put(msg, 4));
				break;
			default:
				/* Shall not happen */
				OSMO_ASSERT(0);
			}
		}
	}

	return 0;
}

int osmo_gprs_llc_xid_decode(struct osmo_gprs_llc_xid_field *fields,
			     unsigned int max_fields,
			     const uint8_t *data, size_t data_len)
{
	const uint8_t *ptr = &data[0];
	unsigned int num_fields = 0;

#define check_len(len, text) \
	do { \
		if (data_len < (len)) { \
			LOGLLC(LOGL_ERROR, "Failed to parse XID: %s\n", text); \
			return -EINVAL; \
		} \
	} while (0)

	while (data_len > 0) {
		struct osmo_gprs_llc_xid_field *field = &fields[num_fields++];
		uint8_t len;

		if (num_fields > max_fields) {
			LOGLLC(LOGL_ERROR,
			       "Failed to parse XID: too many fields\n");
			return -ENOMEM;
		}

		check_len(1, "short read at XID header");
		data_len -= 1;

		/* XID field type */
		field->type = (*ptr >> 2) & 0x1f;
		if (field->type >= ARRAY_SIZE(gprs_llc_xid_desc)) {
			LOGLLC(LOGL_ERROR,
			       "Failed to parse XID: unknown field type 0x%02x\n", field->type);
			return -EINVAL;
		}

		/* XID field length */
		if (*ptr & (1 << 7)) {
			check_len(1, "short read");
			data_len -= 1;
			len  = (*(ptr++) & 0x07) << 6;
			len |= (*(ptr++) >> 2);
		} else {
			len = *(ptr++) & 0x03;
		}

		check_len(len, "short read at XID payload");
		data_len -= len;

		/* XID field value (variable length) */
		if (gprs_llc_xid_desc[field->type].var_len) {
			field->var.val = len ? ptr : NULL;
			field->var.val_len = len;
		} else {
			if (len != gprs_llc_xid_desc[field->type].len) {
				LOGLLC(LOGL_NOTICE,
				       "XID field %s has unusual length=%u (expected %u)\n",
				       osmo_gprs_llc_xid_type_name(field->type),
				       len, gprs_llc_xid_desc[field->type].len);
			}

			switch (len) {
			case 0:
				field->val = 0;
				break;
			case 1:
				field->val = *ptr;
				break;
			case 2:
				field->val = osmo_load16be(ptr);
				break;
			case 4:
				field->val = osmo_load32be(ptr);
				break;
			default:
				LOGLLC(LOGL_ERROR,
				       "Failed to parse XID: unsupported field (%s) length=%u\n",
				       osmo_gprs_llc_xid_type_name(field->type), len);
				return -EINVAL;
			}

			if (!osmo_gprs_llc_xid_field_is_valid(field))
				return -EINVAL;
		}

		ptr += len;
	}

#undef check_len

	return num_fields;
}
