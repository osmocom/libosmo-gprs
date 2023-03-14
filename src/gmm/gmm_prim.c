/* GMM service primitive implementation as per 3GPP TS 44.065 */
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

#include <stdint.h>
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/gprs/gmm/gmm.h>
#include <osmocom/gprs/gmm/gmm_prim.h>
#include <osmocom/gprs/gmm/gmm_private.h>

#define GMM_MSGB_HEADROOM 0

const struct value_string osmo_gprs_gmm_prim_sap_names[] = {
	{ OSMO_GPRS_GMM_SAP_GMMREG,	"GMMREG" },
	{ OSMO_GPRS_GMM_SAP_GMMRR,	"GMRR" },
	{ OSMO_GPRS_GMM_SAP_GMMAS,	"GMMAS" },
	{ OSMO_GPRS_GMM_SAP_LLGMM,	"LLGMM" },
	{ OSMO_GPRS_GMM_SAP_GMMSM,	"GMMSM" },
	{ OSMO_GPRS_GMM_SAP_GMMSMS,	"GMMSMS" },
	{ OSMO_GPRS_GMM_SAP_GMMRABM,	"GMMRABM" },
	{ OSMO_GPRS_GMM_SAP_GMMSS,	"GMMSS" },
	{ OSMO_GPRS_GMM_SAP_GMMSS2,	"GMMSS2" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_gmm_gmmreg_prim_type_names[] = {
	{ OSMO_GPRS_GMM_GMMREG_ATTACH, "ATTACH" },
	{ OSMO_GPRS_GMM_GMMREG_DETACH, "DETACH" },
	{ 0, NULL }
};


const char *osmo_gprs_gmm_prim_name(const struct osmo_gprs_gmm_prim *gmm_prim)
{
	static char name_buf[256];
	const char *sap = osmo_gprs_gmm_prim_sap_name(gmm_prim->oph.sap);
	const char *op = get_value_string(osmo_prim_op_names, gmm_prim->oph.operation);
	const char *type;

	switch (gmm_prim->oph.sap) {
	case OSMO_GPRS_GMM_SAP_GMMREG:
		type = osmo_gprs_gmm_gmmreg_prim_type_name(gmm_prim->oph.primitive);
		break;
	default:
		type = "unsupported-gmm-sap";
	}

	snprintf(name_buf, sizeof(name_buf), "%s-%s.%s", sap, type, op);
	return name_buf;
}

static int gmm_up_cb_dummy(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	LOGGMM(LOGL_INFO, "gmm_up_cb_dummy(%s)\n", osmo_gprs_gmm_prim_name(gmm_prim));
	return 0;
}

static int gmm_down_cb_dummy(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	LOGGMM(LOGL_INFO, "gmm_down_cb_dummy(%s)\n", osmo_gprs_gmm_prim_name(gmm_prim));
	return 0;
}

/* Set callback used by GMM layer to push primitives to higher layers in protocol stack */
void osmo_gprs_gmm_prim_set_up_cb(osmo_gprs_gmm_prim_up_cb up_cb, void *up_user_data)
{
	g_ctx->gmm_up_cb = up_cb;
	g_ctx->gmm_up_cb_user_data = up_user_data;
}

/* Set callback used by GMM layer to push primitives to lower layers in protocol stack */
void osmo_gprs_gmm_prim_set_down_cb(osmo_gprs_gmm_prim_down_cb down_cb, void *down_user_data)
{
	g_ctx->gmm_down_cb = down_cb;
	g_ctx->gmm_down_cb_user_data = down_user_data;
}

/********************************
 * Primitive allocation:
 ********************************/

/* allocate a msgb containing a struct osmo_gprs_gmm_prim + optional l3 data */
static struct msgb *gprs_gmm_prim_msgb_alloc(unsigned int npdu_len)
{
	const int headroom = GMM_MSGB_HEADROOM;
	const int size = headroom + sizeof(struct osmo_gprs_gmm_prim) + npdu_len;
	struct msgb *msg = msgb_alloc_headroom(size, headroom, "gmm_prim");

	if (!msg)
		return NULL;

	msg->l1h = msgb_put(msg, sizeof(struct osmo_gprs_gmm_prim));

	return msg;
}

struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc(unsigned int sap, unsigned int type,
						   enum osmo_prim_operation operation,
						   unsigned int extra_size)
{
	struct msgb *msg = gprs_gmm_prim_msgb_alloc(extra_size);
	struct osmo_gprs_gmm_prim *gmm_prim = msgb_gmm_prim(msg);

	osmo_prim_init(&gmm_prim->oph, sap, type, operation, msg);
	return gmm_prim;
}

/*** SN ***/

static inline struct osmo_gprs_gmm_prim *gmm_prim_gmmreg_alloc(enum osmo_gprs_gmm_gmmreg_prim_type type,
							   enum osmo_prim_operation operation,
							   unsigned int extra_size)
{
	return gprs_gmm_prim_alloc(OSMO_GPRS_GMM_SAP_GMMREG, type, operation, extra_size);
}

/* TS 24.007 6.6.1.1 GMMREG-ATTACH.request */
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmreg_attach_req(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmreg_alloc(OSMO_GPRS_GMM_GMMREG_ATTACH, PRIM_OP_REQUEST, 0);
	return gmm_prim;
}


/* 6.6.1.2 GMMREG-ATTACH.cnf */
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmreg_attach_cnf(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmreg_alloc(OSMO_GPRS_GMM_GMMREG_ATTACH, PRIM_OP_CONFIRM, 0);
	gmm_prim->gmmreg.attach_cnf.accepted = true;
	/* TODO: gmm_prim->gmmreg.attach_cnf.acc.* */
	return gmm_prim;
}
/* TODO: 6.6.1.3 GMMREG-ATTACH.rej */

/* TS 24.007 6.6.1.4 GMMREG-DETACH.request */
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_detach_req(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmreg_alloc(OSMO_GPRS_GMM_GMMREG_DETACH, PRIM_OP_REQUEST, 0);
	return gmm_prim;
}

/* TS 24.007 6.6.1.5 GMMREG-DETACH.cnf */
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmreg_detach_cnf(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmreg_alloc(OSMO_GPRS_GMM_GMMREG_DETACH, PRIM_OP_CONFIRM, 0);
	return gmm_prim;
}

/* TS 24.007 6.6.1.6 GMMREG-DETACH.cnf */
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmreg_detach_ind(void)
{
	struct osmo_gprs_gmm_prim *gmm_prim;
	gmm_prim = gmm_prim_gmmreg_alloc(OSMO_GPRS_GMM_GMMREG_DETACH, PRIM_OP_INDICATION, 0);
	return gmm_prim;
}

static int gprs_gmm_prim_handle_unsupported(struct osmo_gprs_gmm_prim *gmm_prim)
{
	LOGGMM(LOGL_ERROR, "Unsupported gmm_prim! %s\n", osmo_gprs_gmm_prim_name(gmm_prim));
	msgb_free(gmm_prim->oph.msg);
	return -ENOTSUP;
}

/********************************
 * Handling from/to upper layers:
 ********************************/

int gprs_gmm_prim_call_up_cb(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;
	if (g_ctx->gmm_up_cb)
		rc = g_ctx->gmm_up_cb(gmm_prim, g_ctx->gmm_up_cb_user_data);
	else
		rc = gmm_up_cb_dummy(gmm_prim, g_ctx->gmm_up_cb_user_data);
	msgb_free(gmm_prim->oph.msg);
	return rc;
}

/* TS 24.007 6.6.1.1 GMMREG-Attach.request:*/
static int gprs_gmm_prim_handle_gmmreg_attach_req(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;

	rc = gprs_gmm_prim_handle_unsupported(gmm_prim);

	msgb_free(gmm_prim->oph.msg);
	return rc;
}

/* TS 24.007 6.6.1.4 GMMREG-Detach.request:*/
static int gprs_gmm_prim_handle_gmmreg_detach_req(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;

	rc = gprs_gmm_prim_handle_unsupported(gmm_prim);

	msgb_free(gmm_prim->oph.msg);
	return rc;
}

/* GMM higher layers push GMM primitive down to GMM layer: */
int osmo_gprs_gmm_prim_upper_down(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;
	OSMO_ASSERT(g_ctx);

	LOGGMM(LOGL_INFO, "Rx from upper layers: %s\n", osmo_gprs_gmm_prim_name(gmm_prim));

	if (gmm_prim->oph.sap != OSMO_GPRS_GMM_SAP_GMMREG)
		return gprs_gmm_prim_handle_unsupported(gmm_prim);

	switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_GMM_GMMREG_ATTACH, PRIM_OP_REQUEST):
		rc = gprs_gmm_prim_handle_gmmreg_attach_req(gmm_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_GMM_GMMREG_DETACH, PRIM_OP_REQUEST):
		rc = gprs_gmm_prim_handle_gmmreg_detach_req(gmm_prim);
		break;
	default:
		rc = gprs_gmm_prim_handle_unsupported(gmm_prim);
	}
	return rc;
}

/********************************
 * Handling from/to lower layers:
 ********************************/

int gprs_gmm_prim_call_down_cb(struct osmo_gprs_gmm_prim *gmm_prim)
{
	int rc;
	if (g_ctx->gmm_down_cb)
		rc = g_ctx->gmm_down_cb(gmm_prim, g_ctx->gmm_down_cb_user_data);
	else
		rc = gmm_down_cb_dummy(gmm_prim, g_ctx->gmm_down_cb_user_data);
	msgb_free(gmm_prim->oph.msg);
	return rc;
}

/* GMM lower layers (LLC) push GMM primitive up to GMM layer: */
int osmo_gprs_gmm_prim_lower_up(struct osmo_gprs_gmm_prim *gmm_prim)
{
	OSMO_ASSERT(g_ctx);
	OSMO_ASSERT(gmm_prim);
	struct msgb *msg = gmm_prim->oph.msg;
	int rc;

	LOGGMM(LOGL_INFO, "Rx from lower layers: %s\n", osmo_gprs_gmm_prim_name(gmm_prim));

	switch (gmm_prim->oph.sap) {
	case OSMO_GPRS_GMM_SAP_LLGMM:
		rc = gprs_gmm_prim_handle_unsupported(gmm_prim);
		rc = 1;
		break;
	default:
		rc = gprs_gmm_prim_handle_unsupported(gmm_prim);
		rc = 1;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);
	else
		rc = 0;
	return rc;
}
