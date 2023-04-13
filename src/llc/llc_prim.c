/* GPRS LLC protocol primitive implementation as per 3GPP TS 44.064 */
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

#include <osmocom/gprs/llc/llc.h>
#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/llc/llc_private.h>

#define LLC_MSGB_HEADROOM 0

const struct value_string osmo_gprs_llc_prim_sap_names[] = {
	{ OSMO_GPRS_LLC_SAP_LLGMM,	"LLGMM" },
	{ OSMO_GPRS_LLC_SAP_LL,		"LL" },
	{ OSMO_GPRS_LLC_SAP_GRR,	"GRR" },
	{ OSMO_GPRS_LLC_SAP_BSSGP,	"BSSGP" },
	{ 0, NULL }
};

const char *osmo_gprs_llc_prim_name(const struct osmo_gprs_llc_prim *llc_prim)
{
	static char name_buf[256];
	const char *sap = osmo_gprs_llc_prim_sap_name(llc_prim->oph.sap);
	const char *op = get_value_string(osmo_prim_op_names, llc_prim->oph.operation);
	const char *type;

	switch (llc_prim->oph.sap) {
	case OSMO_GPRS_LLC_SAP_LLGMM:
		type = osmo_gprs_llc_llgmm_prim_type_name(llc_prim->oph.primitive);
		break;
	case OSMO_GPRS_LLC_SAP_LL:
		type = osmo_gprs_llc_ll_prim_type_name(llc_prim->oph.primitive);
		break;
	case OSMO_GPRS_LLC_SAP_GRR:
		type = osmo_gprs_llc_grr_prim_type_name(llc_prim->oph.primitive);
		break;
	case OSMO_GPRS_LLC_SAP_BSSGP:
		type = osmo_gprs_llc_bssgp_prim_type_name(llc_prim->oph.primitive);
		break;
	default:
		type = "unsupported-llc-sap";
	}

	snprintf(name_buf, sizeof(name_buf), "%s-%s.%s", sap, type, op);
	return name_buf;
}

static int llc_up_cb_dummy(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
{
	LOGLLC(LOGL_INFO, "llc_up_cb_dummy(%s)\n", osmo_gprs_llc_prim_name(llc_prim));
	return 0;
}

static int llc_down_cb_dummy(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
{
	LOGLLC(LOGL_INFO, "llc_down_cb_dummy(%s)\n", osmo_gprs_llc_prim_name(llc_prim));
	return 0;
}

/* Set callback used by LLC layer to push primitives to higher layers in protocol stack */
void osmo_gprs_llc_prim_set_up_cb(osmo_gprs_llc_prim_up_cb up_cb, void *up_user_data)
{
	g_llc_ctx->llc_up_cb = up_cb;
	g_llc_ctx->llc_up_cb_user_data = up_user_data;
}

/* Set callback used by LLC layer to push primitives to lower layers in protocol stack */
void osmo_gprs_llc_prim_set_down_cb(osmo_gprs_llc_prim_down_cb down_cb, void *down_user_data)
{
	g_llc_ctx->llc_down_cb = down_cb;
	g_llc_ctx->llc_down_cb_user_data = down_user_data;
}

/********************************
 * Primitive allocation:
 ********************************/

/* allocate a msgb containing a struct osmo_gprs_llc_prim + optional l3 data */
static struct msgb *gprs_llc_prim_msgb_alloc(unsigned int l3_len)
{
	const int headroom = LLC_MSGB_HEADROOM;
	const int size = headroom + sizeof(struct osmo_gprs_llc_prim) + l3_len;
	struct msgb *msg = msgb_alloc_headroom(size, headroom, "llc_prim");

	if (!msg)
		return NULL;

	msg->l1h = msgb_put(msg, sizeof(struct osmo_gprs_llc_prim));

	return msg;
}

struct osmo_gprs_llc_prim *gprs_llc_prim_alloc(enum osmo_gprs_llc_prim_sap sap, unsigned int type,
					  enum osmo_prim_operation operation,
					  unsigned int l3_len)
{
	struct msgb *msg = gprs_llc_prim_msgb_alloc(l3_len);
	struct osmo_gprs_llc_prim *llc_prim = msgb_llc_prim(msg);

	osmo_prim_init(&llc_prim->oph, sap, type, operation, msg);
	return llc_prim;
}

int gprs_llc_prim_handle_unsupported(struct osmo_gprs_llc_prim *llc_prim)
{
	LOGLLC(LOGL_ERROR, "Unsupported llc_prim! %s\n", osmo_gprs_llc_prim_name(llc_prim));
	msgb_free(llc_prim->oph.msg);
	return -ENOTSUP;
}

/********************************
 * Handling from/to upper layers:
 ********************************/

int gprs_llc_prim_call_up_cb(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	if (g_llc_ctx->llc_up_cb)
		rc = g_llc_ctx->llc_up_cb(llc_prim, g_llc_ctx->llc_up_cb_user_data);
	else
		rc = llc_up_cb_dummy(llc_prim, g_llc_ctx->llc_up_cb_user_data);
	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(llc_prim->oph.msg);
	return rc;
}

/* LLC higher layers push LLC primitive down to LLC layer: */
int osmo_gprs_llc_prim_upper_down(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	OSMO_ASSERT(g_llc_ctx);

	LOGLLC(LOGL_INFO, "Rx from upper layers: %s\n", osmo_gprs_llc_prim_name(llc_prim));

	switch (llc_prim->oph.sap) {
	case OSMO_GPRS_LLC_SAP_LLGMM:
		rc = gprs_llc_prim_llgmm_upper_down(llc_prim);
		break;
	case OSMO_GPRS_LLC_SAP_LL:
		rc = gprs_llc_prim_ll_upper_down(llc_prim);
		break;
	default:
		rc = gprs_llc_prim_handle_unsupported(llc_prim);
	}
	return rc;
}

/********************************
 * Handling from/to lower layers:
 ********************************/

int gprs_llc_prim_call_down_cb(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	if (g_llc_ctx->llc_down_cb)
		rc = g_llc_ctx->llc_down_cb(llc_prim, g_llc_ctx->llc_down_cb_user_data);
	else
		rc = llc_down_cb_dummy(llc_prim, g_llc_ctx->llc_down_cb_user_data);
	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(llc_prim->oph.msg);
	else
		rc = 0;
	return rc;
}

/* LLC lower layers push LLC primitive up to LLC layer: */
int osmo_gprs_llc_prim_lower_up(struct osmo_gprs_llc_prim *llc_prim)
{
	OSMO_ASSERT(g_llc_ctx);
	OSMO_ASSERT(llc_prim);
	struct msgb *msg = llc_prim->oph.msg;
	int rc;

	LOGLLC(LOGL_INFO, "Rx from lower layers: %s\n", osmo_gprs_llc_prim_name(llc_prim));

	switch (llc_prim->oph.sap) {
	case OSMO_GPRS_LLC_SAP_GRR:
		OSMO_ASSERT(g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_MS);
		rc = gprs_llc_prim_lower_up_grr(llc_prim);
		break;
	case OSMO_GPRS_LLC_SAP_BSSGP:
		OSMO_ASSERT(g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN);
		rc = gprs_llc_prim_lower_up_bssgp(llc_prim);
		break;
	default:
		rc = -EINVAL;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);
	else
		rc = 0;
	return rc;
}
