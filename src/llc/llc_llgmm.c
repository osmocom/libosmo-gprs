/* GPRS LLC LLGM SAP as per 3GPP TS 44.064 7.2.1 */
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

const struct value_string osmo_gprs_llc_llgmm_prim_type_names[] = {
	{ OSMO_GPRS_LLC_LLGMM_ASSIGN,		"ASSIGN" },
	{ OSMO_GPRS_LLC_LLGMM_RESET,		"RESET" },
	{ OSMO_GPRS_LLC_LLGMM_TRIGGER,		"TRIGGER" },
	{ OSMO_GPRS_LLC_LLGMM_SUSPEND,		"SUSPEND" },
	{ OSMO_GPRS_LLC_LLGMM_RESUME,		"RESUME" },
	{ OSMO_GPRS_LLC_LLGMM_PAGE,		"PAGE" },
	{ OSMO_GPRS_LLC_LLGMM_IOV,		"IOV" },
	{ OSMO_GPRS_LLC_LLGMM_STATUS,		"STATUS" },
	{ OSMO_GPRS_LLC_LLGMM_PSHO,		"PSHO" },
	{ OSMO_GPRS_LLC_LLGMM_ASSIGN_UP,	"ASSIGN-USERPLANE" },
	{ 0, NULL }
};

/* Generate XID message that will cause the GMM to reset */
static int gprs_llc_lle_generate_xid_for_gmm_reset(struct gprs_llc_lle *lle,
						   uint8_t *bytes,
						   int bytes_len, uint32_t iov_ui)
{

	struct gprs_llc_xid_field *fields;
	const unsigned int fields_len = 2;

	fields = (struct gprs_llc_xid_field *)talloc_zero_size(lle->llme, sizeof(*fields) * fields_len);
	OSMO_ASSERT(fields);

	/* First XID component must be RESET */
	fields[0].type = OSMO_GPRS_LLC_XID_T_RESET;

	fields[1].type = OSMO_GPRS_LLC_XID_T_IOV_UI;
	fields[1].val = iov_ui;

	talloc_free(lle->xid);
	lle->xid = fields;
	lle->xid_len = fields_len;

	return gprs_llc_xid_encode(bytes, bytes_len, fields, fields_len);
}

/********************************
 * Primitive allocation:
 ********************************/

static inline struct osmo_gprs_llc_prim *llc_prim_llgmm_alloc(enum osmo_gprs_llc_llgmm_prim_type type,
							     enum osmo_prim_operation operation,
							     unsigned int l3_len)
{
	return gprs_llc_prim_alloc(OSMO_GPRS_LLC_SAP_LLGM, type, operation, l3_len);
}

/* 7.2.1.1 LLGMM-ASSIGN.req (MS/SGSN):*/
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_llgm_assign_req(uint32_t tlli)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_llgmm_alloc(OSMO_GPRS_LLC_LLGMM_ASSIGN, PRIM_OP_REQUEST, 0);
	llc_prim->llgmm.tlli = tlli;
	return llc_prim;
}

/* 7.2.1.2 LLGMM-RESET.req (SGSN):*/
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_llgm_reset_req(uint32_t tlli)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_llgmm_alloc(OSMO_GPRS_LLC_LLGMM_RESET, PRIM_OP_REQUEST, 0);
	llc_prim->llgmm.tlli = tlli;
	return llc_prim;
}

/* 7.2.1.2 LLGMM-RESET.cnf (SGSN):*/
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_llgm_reset_cnf(uint32_t tlli)
{
	struct osmo_gprs_llc_prim *llc_prim;
	llc_prim = llc_prim_llgmm_alloc(OSMO_GPRS_LLC_LLGMM_RESET, PRIM_OP_CONFIRM, 0);
	llc_prim->llgmm.tlli = tlli;
	return llc_prim;
}

/********************************
 * Handling from upper layers:
 ********************************/

/* 7.2.1.1 LLGMM-ASSIGN.req (MS/SGSN):*/
static int llc_prim_handle_llgm_assign_req(struct osmo_gprs_llc_prim *llc_prim)
{
	uint32_t old_tlli = llc_prim->llgmm.tlli;
	uint32_t new_tlli = llc_prim->llgmm.assign_req.tlli_new;
	int rc = 0;
	bool free = false;
	struct gprs_llc_llme *llme;
	unsigned int i;

	if (old_tlli == TLLI_UNASSIGNED && new_tlli == TLLI_UNASSIGNED) {
		LOGLLC(LOGL_NOTICE, "Rx %s: Wrong input: Both old and new TLLI are unassigned!\n",
		       osmo_gprs_llc_prim_name(llc_prim));
		rc = -EINVAL;
		goto ret_free;
	}

	llme = gprs_llc_find_llme_by_tlli(old_tlli != TLLI_UNASSIGNED ? old_tlli : new_tlli);
	if (!llme) {
		LOGLLC(LOGL_NOTICE, "Rx %s: Unknown TLLI 0x%08x\n",
			osmo_gprs_llc_prim_name(llc_prim), old_tlli);
		rc = -ENOKEY;
		goto ret_free;
	}

	LOGLLME(llme, LOGL_NOTICE, "LLGM Assign pre (%08x => %08x)\n", old_tlli, new_tlli);

	if (old_tlli == TLLI_UNASSIGNED && new_tlli != TLLI_UNASSIGNED) {
		/* TLLI Assignment 8.3.1 */
		/* New TLLI shall be assigned and used when (re)transmitting LLC frames */
		/* If old TLLI != TLLI_UNASSIGNED was assigned to LLME, then TLLI
		 * old is unassigned.  Only TLLI new shall be accepted when
		 * received from peer. */
		if (llme->old_tlli != TLLI_UNASSIGNED) {
			llme->old_tlli = TLLI_UNASSIGNED;
			llme->tlli = new_tlli;
		} else {
			/* If TLLI old == TLLI_UNASSIGNED was assigned to LLME, then this is
			 * TLLI assignmemt according to 8.3.1 */
			llme->old_tlli = TLLI_UNASSIGNED;
			llme->tlli = new_tlli;
			llme->state = OSMO_GPRS_LLC_LLMS_ASSIGNED;
			/* 8.5.3.1 For all LLE's */
			for (i = 0; i < ARRAY_SIZE(llme->lle); i++) {
				struct gprs_llc_lle *l = &llme->lle[i];
				l->vu_send = l->vu_recv = 0;
				l->retrans_ctr = 0;
				l->state = OSMO_GPRS_LLC_LLES_ASSIGNED_ADM;
				/* FIXME Set parameters according to table 9 */
			}
		}
	} else if (old_tlli != TLLI_UNASSIGNED && new_tlli != TLLI_UNASSIGNED) {
		/* TLLI Change 8.3.2 */
		/* Both TLLI Old and TLLI New are assigned; use New when
		 * (re)transmitting.  Accept both Old and New on Rx */
		llme->old_tlli = old_tlli;
		llme->tlli = new_tlli;
		llme->state = OSMO_GPRS_LLC_LLMS_ASSIGNED;
	} else if (old_tlli != TLLI_UNASSIGNED && new_tlli == TLLI_UNASSIGNED) {
		/* TLLI Unassignment 8.3.3) */
		llme->tlli = llme->old_tlli = 0;
		llme->state = OSMO_GPRS_LLC_LLMS_ASSIGNED;
		for (i = 0; i < ARRAY_SIZE(llme->lle); i++) {
			struct gprs_llc_lle *l = &llme->lle[i];
			l->state = OSMO_GPRS_LLC_LLES_UNASSIGNED;
		}
		free = true;
	}

	LOGLLME(llme, LOGL_NOTICE, "LLGM Assign post (%08x => %08x)\n", old_tlli, new_tlli);

	if (free)
		gprs_llc_llme_free(llme);
ret_free:
	msgb_free(llc_prim->oph.msg);
	return rc;
}

/* 7.2.1.2 LLGMM-RESET.req (SGSN):*/
static int llc_prim_handle_llgm_reset_req(struct osmo_gprs_llc_prim *llc_prim)
{
	struct gprs_llc_lle *lle;
	uint8_t xid_bytes[1024];
	int xid_bytes_len;
	int rc = 0;
	struct gprs_llc_llme *llme = gprs_llc_find_llme_by_tlli(llc_prim->llgmm.tlli);

	if (!llme) {
		LOGLLC(LOGL_NOTICE, "Rx %s: Unknown TLLI 0x%08x\n",
			osmo_gprs_llc_prim_name(llc_prim), llc_prim->llgmm.tlli);
		rc = -ENOKEY;
		goto ret_free;
	}
	LOGLLME(llme, LOGL_INFO, "%s\n", osmo_gprs_llc_prim_name(llc_prim));

	lle = gprs_llc_llme_get_lle(llme, OSMO_GPRS_LLC_SAPI_GMM);

	rc = osmo_get_rand_id((uint8_t *) &llme->iov_ui, 4);
	if (rc < 0) {
		LOGLLME(llme, LOGL_ERROR, "osmo_get_rand_id() failed for LLC XID reset: %s\n",
		       strerror(-rc));
		goto ret_free;
	}

	/* Generate XID message */
	xid_bytes_len = gprs_llc_lle_generate_xid_for_gmm_reset(lle, xid_bytes, sizeof(xid_bytes),
							    llme->iov_ui);
	if (xid_bytes_len < 0) {
		rc = -EINVAL;
		goto ret_free;
	}

	/* Reset some of the LLC parameters. See GSM 04.64, 8.5.3.1 */
	lle->vu_recv = 0;
	lle->vu_send = 0;
	lle->oc_ui_send = 0;
	lle->oc_ui_recv = 0;

	rc = gprs_llc_lle_tx_xid(lle, xid_bytes, xid_bytes_len, true);

ret_free:
	msgb_free(llc_prim->oph.msg);
	return rc;
}

/* LLC higher layers push LLC primitive down to LLC layer: */
int gprs_llc_prim_llgmm_upper_down(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_ASSIGN, PRIM_OP_REQUEST):
		OSMO_ASSERT(g_ctx->location == OSMO_GPRS_LLC_LOCATION_MS ||
			    g_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = llc_prim_handle_llgm_assign_req(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_RESET, PRIM_OP_REQUEST):
		OSMO_ASSERT(g_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = llc_prim_handle_llgm_reset_req(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_TRIGGER, PRIM_OP_REQUEST):
		OSMO_ASSERT(g_ctx->location == OSMO_GPRS_LLC_LOCATION_MS);
		rc = gprs_llc_prim_handle_unsupported(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_SUSPEND, PRIM_OP_REQUEST):
		OSMO_ASSERT(g_ctx->location == OSMO_GPRS_LLC_LOCATION_MS ||
			    g_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = gprs_llc_prim_handle_unsupported(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_RESUME, PRIM_OP_REQUEST):
		OSMO_ASSERT(g_ctx->location == OSMO_GPRS_LLC_LOCATION_MS ||
			    g_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = gprs_llc_prim_handle_unsupported(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_IOV, PRIM_OP_REQUEST):
		OSMO_ASSERT(g_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = gprs_llc_prim_handle_unsupported(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_PSHO, PRIM_OP_REQUEST):
		OSMO_ASSERT(g_ctx->location == OSMO_GPRS_LLC_LOCATION_MS ||
			    g_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = gprs_llc_prim_handle_unsupported(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_ASSIGN_UP, PRIM_OP_REQUEST):
		OSMO_ASSERT(g_ctx->location == OSMO_GPRS_LLC_LOCATION_MS ||
			    g_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = gprs_llc_prim_handle_unsupported(llc_prim);
		break;
	default:
		rc = -ENOTSUP;
		msgb_free(llc_prim->oph.msg);
	}
	return rc;
}
