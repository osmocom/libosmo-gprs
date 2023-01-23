/* GPRS LLC as per 3GPP TS 44.064 7.2.4 */
/*
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/gprs/llc/llc.h>
#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/llc/llc_private.h>

const struct value_string osmo_gprs_llc_bssgp_prim_type_names[] = {
	{ OSMO_GPRS_LLC_BSSGP_DL_UNITDATA,		"DL-UNITDATA" },
	{ OSMO_GPRS_LLC_BSSGP_UL_UNITDATA,		"UL-UNITDATA" },
	{ 0, NULL }
};

/********************************
 * Primitive allocation:
 ********************************/

static inline struct osmo_gprs_llc_prim *llc_prim_bssgp_alloc(enum osmo_gprs_llc_bssgp_prim_type type,
							     enum osmo_prim_operation operation,
							     unsigned int l3_len)
{
	return gprs_llc_prim_alloc(OSMO_GPRS_LLC_SAP_BSSGP, type, operation, l3_len);
}

/* 7.2.4.1 BSSGP-UL-UNITDATA.ind (SGSN):*/
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_bssgp_ul_unitdata_ind(
					uint32_t tlli, uint8_t *ll_pdu,
					size_t ll_pdu_len)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_bssgp_alloc(OSMO_GPRS_LLC_BSSGP_UL_UNITDATA, PRIM_OP_INDICATION, ll_pdu_len);
	llc_prim->bssgp.tlli = tlli;
	llc_prim->bssgp.ll_pdu = ll_pdu;
	llc_prim->bssgp.ll_pdu_len = ll_pdu_len;
	return llc_prim;
}

/* 7.2.4.2 BSSGP-UL-UNITDATA.ind (SGSN):*/
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_bssgp_dl_unitdata_req(
				uint32_t tlli, uint8_t *ll_pdu, size_t ll_pdu_len)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_bssgp_alloc(OSMO_GPRS_LLC_BSSGP_DL_UNITDATA, PRIM_OP_REQUEST, ll_pdu_len);
	llc_prim->bssgp.tlli = tlli;
	llc_prim->bssgp.ll_pdu = ll_pdu;
	llc_prim->bssgp.ll_pdu_len = ll_pdu_len;
	return llc_prim;
}

/********************************
 * Handling from lower layers:
 ********************************/

static int gprs_llc_prim_handle_bssgp_ul_unitdata_ind(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	struct gprs_llc_pdu_decoded pdu_dec = {0};
	const char *llc_pdu_name = NULL;
	struct gprs_llc_lle *lle = NULL;

	rc = gprs_llc_pdu_decode(&pdu_dec, llc_prim->bssgp.ll_pdu, llc_prim->bssgp.ll_pdu_len);
	if (rc < 0) {
		LOGLLC(LOGL_ERROR, "%s: Error parsing LLC header\n", osmo_gprs_llc_prim_name(llc_prim));
		return rc;
	}
	llc_pdu_name = gprs_llc_pdu_hdr_dump(&pdu_dec);

	LOGLLC(LOGL_DEBUG, "Rx %s: %s\n", osmo_gprs_llc_prim_name(llc_prim), llc_pdu_name);

	switch (gprs_tlli_type(llc_prim->bssgp.tlli)) {
	case TLLI_LOCAL:
	case TLLI_FOREIGN:
	case TLLI_RANDOM:
	case TLLI_AUXILIARY:
		break;
	default:
		LOGLLC(LOGL_ERROR, "%s: Discarding frame with strange TLLI type\n", llc_pdu_name);
		return -EINVAL;
	}

	lle = gprs_llc_lle_for_rx_by_tlli_sapi(llc_prim->bssgp.tlli, pdu_dec.sapi, pdu_dec.func);
	if (!lle) {
		switch (pdu_dec.sapi) {
		case OSMO_GPRS_LLC_SAPI_SNDCP3:
		case OSMO_GPRS_LLC_SAPI_SNDCP5:
		case OSMO_GPRS_LLC_SAPI_SNDCP9:
		case OSMO_GPRS_LLC_SAPI_SNDCP11:
#if 0
/* TODO: probaby send some primitive to the upper layers (GMM) */
			/* Ask an upper layer for help. */
			return gsm0408_gprs_force_reattach_oldmsg(msg, NULL);
#endif
		default:
			break;
		}
		return 0;
	}
	rc = gprs_llc_lle_rx_unitdata_ind(lle, llc_prim->bssgp.ll_pdu, llc_prim->bssgp.ll_pdu_len, &pdu_dec);

	return rc;
}

int gprs_llc_prim_lower_up_bssgp(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;

	switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_LLC_BSSGP_UL_UNITDATA, PRIM_OP_INDICATION):
		rc = gprs_llc_prim_handle_bssgp_ul_unitdata_ind(llc_prim);
		break;
	default:
		rc = -ENOTSUP;
	}
	return rc;
}
