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

/* encrypt information field + FCS, if needed! */
static int apply_gea(const struct gprs_llc_lle *lle, uint16_t crypt_len, uint16_t nu,
		     uint32_t oc, uint8_t sapi, uint8_t *fcs, uint8_t *data)
{
	uint8_t cipher_out[GSM0464_CIPH_MAX_BLOCK];

	if (lle->llme->algo == GPRS_ALGO_GEA0)
		return -EINVAL;

	/* Compute the 'Input' Paraemeter */
	uint32_t fcs_calc, iv = gprs_cipher_gen_input_ui(lle->llme->iov_ui, sapi,
							 nu, oc);
	/* Compute gamma that we need to XOR with the data */
	int r = gprs_cipher_run(cipher_out, crypt_len, lle->llme->algo,
				lle->llme->kc, iv,
				fcs ? GPRS_CIPH_SGSN2MS : GPRS_CIPH_MS2SGSN);
	if (r < 0) {
		LOGLLC(LOGL_ERROR, "Error producing %s gamma for UI "
		     "frame: %d\n", get_value_string(gprs_cipher_names,
						     lle->llme->algo), r);
		return -ENOMSG;
	}

	if (fcs) {
		/* Mark frame as encrypted and update FCS */
		data[2] |= 0x02;
		fcs_calc = gprs_llc_fcs(data, fcs - data);
		fcs[0] = fcs_calc & 0xff;
		fcs[1] = (fcs_calc >> 8) & 0xff;
		fcs[2] = (fcs_calc >> 16) & 0xff;
		data += 3;
	}

	/* XOR the cipher output with the data */
	for (r = 0; r < crypt_len; r++)
		*(data + r) ^= cipher_out[r];

	return 0;
}


static int gprs_llc_prim_handle_bssgp_ul_unitdata_ind(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	struct gprs_llc_hdr *lh = (struct gprs_llc_hdr *) llc_prim->bssgp.ll_pdu;
	struct gprs_llc_pdu_decoded pdu_dec = {0};
	const char *llc_pdu_name = NULL;
	struct gprs_llc_lle *lle = NULL;
	bool drop_cipherable = false;
	struct osmo_gprs_llc_prim *llc_prim_tx;

	rc = gprs_llc_pdu_decode(&pdu_dec, (uint8_t *)lh, llc_prim->bssgp.ll_pdu_len);
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
	/* reset age computation */
	lle->llme->age_timestamp = GPRS_LLME_RESET_AGE;

	/* decrypt information field + FCS, if needed! */
	if (pdu_dec.flags & OSMO_GPRS_LLC_PDU_F_ENC_MODE) {
		if (lle->llme->algo != GPRS_ALGO_GEA0) {
			rc = apply_gea(lle, pdu_dec.data_len + 3, pdu_dec.seq_tx,
				       lle->oc_ui_recv, lle->sapi, NULL,
				       (uint8_t *)pdu_dec.data); /*TODO: either copy buffer or remove "const" from pdu_dec field "data" */
			if (rc < 0)
				return rc;
			pdu_dec.fcs = *(pdu_dec.data + pdu_dec.data_len);
			pdu_dec.fcs |= *(pdu_dec.data + pdu_dec.data_len + 1) << 8;
			pdu_dec.fcs |= *(pdu_dec.data + pdu_dec.data_len + 2) << 16;
		} else {
			LOGLLME(lle->llme, LOGL_NOTICE, "encrypted frame for LLC that "
				"has no KC/Algo! Dropping.\n");
			return 0;
		}
	} else {
		if (lle->llme->algo != GPRS_ALGO_GEA0 &&
		    lle->llme->cksn != GSM_KEY_SEQ_INVAL)
			drop_cipherable = true;
	}

	/* We have to do the FCS check _after_ decryption */
	uint16_t crc_length = llc_prim->bssgp.ll_pdu_len - CRC24_LENGTH;
	if (~pdu_dec.flags & OSMO_GPRS_LLC_PDU_F_PROT_MODE)
		crc_length = OSMO_MIN(crc_length, UI_HDR_LEN + N202);
	if (pdu_dec.fcs != gprs_llc_fcs((uint8_t *)lh, crc_length)) {
		LOGLLE(lle, LOGL_INFO, "Dropping frame with invalid FCS\n");
		return -EIO;
	}

	/* Receive and Process the actual LLC frame */
	rc = gprs_llc_lle_hdr_rx(lle, &pdu_dec);
	if (rc < 0)
		return rc;

	/* pdu_dec.data is only set when we need to send LL_[UNIT]DATA_IND up */
	if (pdu_dec.func == OSMO_GPRS_LLC_FUNC_UI && pdu_dec.data && pdu_dec.data_len) {
		switch (pdu_dec.sapi) {
		case OSMO_GPRS_LLC_SAPI_GMM:
			/* send LL-UNITDATA-IND to GMM */
			llc_prim_tx = gprs_llc_prim_alloc_ll_unitdata_ind(lle->llme->tlli,
									  pdu_dec.sapi,
									  pdu_dec.data,
									  pdu_dec.data_len);
			llc_prim_tx->ll.unitdata_ind.apply_gea = !drop_cipherable; /* TODO: is this correct? */
			llc_prim_tx->ll.unitdata_ind.apply_gia = false; /* TODO: how to set this? */
			gprs_llc_prim_call_up_cb(llc_prim_tx);
			break;
		case OSMO_GPRS_LLC_SAPI_SNDCP3:
		case OSMO_GPRS_LLC_SAPI_SNDCP5:
		case OSMO_GPRS_LLC_SAPI_SNDCP9:
		case OSMO_GPRS_LLC_SAPI_SNDCP11:
			/* send LL_DATA_IND/LL_UNITDATA_IND to SNDCP */
			llc_prim_tx = gprs_llc_prim_alloc_ll_unitdata_ind(lle->llme->tlli,
									  pdu_dec.sapi,
									  pdu_dec.data,
									  pdu_dec.data_len);
			llc_prim_tx->ll.unitdata_ind.apply_gea = !drop_cipherable; /* TODO: is this correct? */
			llc_prim_tx->ll.unitdata_ind.apply_gia = false; /* TODO: how to set this? */
			gprs_llc_prim_call_up_cb(llc_prim_tx);
			break;
		case OSMO_GPRS_LLC_SAPI_SMS:
			/* FIXME */
		case OSMO_GPRS_LLC_SAPI_TOM2:
		case OSMO_GPRS_LLC_SAPI_TOM8:
			/* FIXME: send LL_DATA_IND/LL_UNITDATA_IND to TOM */
		default:
			LOGLLC(LOGL_NOTICE, "Unsupported SAPI %u\n", pdu_dec.sapi);
			rc = -EINVAL;
			break;
		}
	}

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
