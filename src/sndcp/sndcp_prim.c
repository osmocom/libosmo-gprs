/* SNDCP service primitive implementation as per 3GPP TS 44.065 */
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

#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/sndcp/sndcp.h>
#include <osmocom/gprs/sndcp/sndcp_prim.h>
#include <osmocom/gprs/sndcp/sndcp_private.h>

#define SNDCP_MSGB_HEADROOM 0

const struct value_string osmo_gprs_sndcp_prim_sap_names[] = {
	{ OSMO_GPRS_SNDCP_SAP_SN,	"SN" },
	{ OSMO_GPRS_SNDCP_SAP_SNSM,	"SNSM" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_sndcp_sn_prim_type_names[] = {
	{ OSMO_GPRS_SNDCP_SN_DATA, "DATA" },
	{ OSMO_GPRS_SNDCP_SN_UNITDATA, "UNITDATA" },
	{ OSMO_GPRS_SNDCP_SN_XID, "XID" },
	{ 0, NULL }
};

const struct value_string osmo_gprs_sndcp_snsm_prim_type_names[] = {
	{ OSMO_GPRS_SNDCP_SNSM_ACTIVATE,	"ACTIVATE" },
	{ OSMO_GPRS_SNDCP_SNSM_DEACTIVATE,	"DEACTIVATE" },
	{ OSMO_GPRS_SNDCP_SNSM_MODIFY,		"MODIFY" },
	{ OSMO_GPRS_SNDCP_SNSM_STATUS,		"STATUS" },
	{ OSMO_GPRS_SNDCP_SNSM_SEQUENCE,	"SEQUENCE" },
	{ OSMO_GPRS_SNDCP_SNSM_STOP_ASSIGN,	"STOP-ASSIGN" },
	{ 0, NULL }
};

const char *osmo_gprs_sndcp_prim_name(const struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	static char name_buf[256];
	const char *sap = osmo_gprs_sndcp_prim_sap_name(sndcp_prim->oph.sap);
	const char *op = get_value_string(osmo_prim_op_names, sndcp_prim->oph.operation);
	const char *type;

	switch (sndcp_prim->oph.sap) {
	case OSMO_GPRS_SNDCP_SAP_SN:
		type = osmo_gprs_sndcp_sn_prim_type_name(sndcp_prim->oph.primitive);
		break;
	case OSMO_GPRS_SNDCP_SAP_SNSM:
		type = osmo_gprs_sndcp_snsm_prim_type_name(sndcp_prim->oph.primitive);
		break;
	default:
		type = "unsupported-sndcp-sap";
	}

	snprintf(name_buf, sizeof(name_buf), "%s-%s.%s", sap, type, op);
	return name_buf;
}

static int sndcp_up_cb_dummy(struct osmo_gprs_sndcp_prim *sndcp_prim, void *user_data)
{
	LOGSNDCP(LOGL_INFO, "sndcp_up_cb_dummy(%s)\n", osmo_gprs_sndcp_prim_name(sndcp_prim));
	return 0;
}

static int sndcp_down_cb_dummy(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
{
	LOGSNDCP(LOGL_INFO, "sndcp_down_cb_dummy(%s)\n", osmo_gprs_llc_prim_name(llc_prim));
	return 0;
}

static int sndcp_snsm_cb_dummy(struct osmo_gprs_sndcp_prim *sndcp_prim, void *user_data)
{
	LOGSNDCP(LOGL_INFO, "sndcp_snsm_cb_dummy(%s)\n", osmo_gprs_sndcp_prim_name(sndcp_prim));
	return 0;
}

/* Set callback used by SNDCP layer to push primitives to higher layers in protocol stack */
void osmo_gprs_sndcp_prim_set_up_cb(osmo_gprs_sndcp_prim_up_cb up_cb, void *up_user_data)
{
	g_ctx->sndcp_up_cb = up_cb;
	g_ctx->sndcp_up_cb_user_data = up_user_data;
}

/* Set callback used by SNDCP layer to push primitives to lower layers in protocol stack */
void osmo_gprs_sndcp_prim_set_down_cb(osmo_gprs_sndcp_prim_down_cb down_cb, void *down_user_data)
{
	g_ctx->sndcp_down_cb = down_cb;
	g_ctx->sndcp_down_cb_user_data = down_user_data;
}

/* Set callback used by SNDCP layer to push primitives to SM sublayer */
void osmo_gprs_sndcp_prim_set_snsm_cb(osmo_gprs_sndcp_prim_snsm_cb snsm_cb, void *snsm_user_data)
{
	g_ctx->sndcp_snsm_cb = snsm_cb;
	g_ctx->sndcp_snsm_cb_user_data = snsm_user_data;
}

/********************************
 * Primitive allocation:
 ********************************/

/* allocate a msgb containing a struct osmo_gprs_sndcp_prim + optional l3 data */
static struct msgb *gprs_sndcp_prim_msgb_alloc(unsigned int npdu_len)
{
	const int headroom = SNDCP_MSGB_HEADROOM;
	const int size = headroom + sizeof(struct osmo_gprs_sndcp_prim) + npdu_len;
	struct msgb *msg = msgb_alloc_headroom(size, headroom, "sndcp_prim");

	if (!msg)
		return NULL;

	msg->l1h = msgb_put(msg, sizeof(struct osmo_gprs_sndcp_prim));

	return msg;
}

struct osmo_gprs_sndcp_prim *gprs_sndcp_prim_alloc(unsigned int sap, unsigned int type,
						   enum osmo_prim_operation operation,
						   unsigned int extra_size)
{
	struct msgb *msg = gprs_sndcp_prim_msgb_alloc(extra_size);
	struct osmo_gprs_sndcp_prim *sndcp_prim = msgb_sndcp_prim(msg);

	osmo_prim_init(&sndcp_prim->oph, sap, type, operation, msg);
	return sndcp_prim;
}

/*** SN ***/

static inline struct osmo_gprs_sndcp_prim *sndcp_prim_sn_alloc(enum osmo_gprs_sndcp_sn_prim_type type,
							   enum osmo_prim_operation operation,
							   unsigned int extra_size)
{
	return gprs_sndcp_prim_alloc(OSMO_GPRS_SNDCP_SAP_SN, type, operation, extra_size);
}

/* 5.1.1.1 SN-DATA.request */
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_sn_data_req(uint32_t tlli, uint8_t sapi, uint8_t nsapi, uint8_t *npdu, size_t npdu_len)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	sndcp_prim = sndcp_prim_sn_alloc(OSMO_GPRS_SNDCP_SN_DATA, PRIM_OP_REQUEST, npdu_len);
	sndcp_prim->sn.tlli = tlli;
	sndcp_prim->sn.sapi = sapi;
	sndcp_prim->sn.data_req.nsapi = nsapi;
	sndcp_prim->sn.data_req.npdu = npdu;
	sndcp_prim->sn.data_req.npdu_len = npdu_len;
	return sndcp_prim;
}

/* 5.1.1.3 SN-UNITDATA.request */
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_sn_unitdata_req(uint32_t tlli, uint8_t sapi, uint8_t nsapi, uint8_t *npdu, size_t npdu_len)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	sndcp_prim = sndcp_prim_sn_alloc(OSMO_GPRS_SNDCP_SN_UNITDATA, PRIM_OP_REQUEST, npdu_len);
	sndcp_prim->sn.tlli = tlli;
	sndcp_prim->sn.sapi = sapi;
	sndcp_prim->sn.unitdata_req.nsapi = nsapi;
	sndcp_prim->sn.unitdata_req.npdu = npdu;
	sndcp_prim->sn.unitdata_req.npdu_len = npdu_len;
	return sndcp_prim;
}

/* 5.1.1.3 SN-UNITDATA.ind */
struct osmo_gprs_sndcp_prim *gprs_sndcp_prim_alloc_sn_unitdata_ind(uint32_t tlli, uint8_t sapi, uint8_t nsapi, uint8_t *npdu, size_t npdu_len)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	sndcp_prim = sndcp_prim_sn_alloc(OSMO_GPRS_SNDCP_SN_UNITDATA, PRIM_OP_INDICATION, npdu_len);
	sndcp_prim->sn.tlli = tlli;
	sndcp_prim->sn.sapi = sapi;
	sndcp_prim->sn.unitdata_req.nsapi = nsapi;
	sndcp_prim->sn.unitdata_req.npdu = npdu;
	sndcp_prim->sn.unitdata_req.npdu_len = npdu_len;
	return sndcp_prim;
}

/* 5.1.1.5 SN-XID.request */
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_sn_xid_req(uint32_t tlli, uint8_t sapi, uint8_t nsapi)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	sndcp_prim = sndcp_prim_sn_alloc(OSMO_GPRS_SNDCP_SN_XID, PRIM_OP_REQUEST, 0);
	sndcp_prim->sn.tlli = tlli;
	sndcp_prim->sn.sapi = sapi;
	sndcp_prim->sn.xid_req.nsapi = nsapi;
	return sndcp_prim;
}

/* 5.1.1.5 SN-XID.indication */
struct osmo_gprs_sndcp_prim *gprs_sndcp_prim_alloc_sn_xid_ind(uint32_t tlli, uint8_t sapi, uint8_t nsapi)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	sndcp_prim = sndcp_prim_sn_alloc(OSMO_GPRS_SNDCP_SN_XID, PRIM_OP_INDICATION, 0);
	sndcp_prim->sn.tlli = tlli;
	sndcp_prim->sn.sapi = sapi;
	sndcp_prim->sn.xid_ind.nsapi = nsapi;
	return sndcp_prim;
}

/* 5.1.1.7 SN-XID.response */
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_sn_xid_rsp(uint32_t tlli, uint8_t sapi, uint8_t nsapi)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	sndcp_prim = sndcp_prim_sn_alloc(OSMO_GPRS_SNDCP_SN_XID, PRIM_OP_RESPONSE, 0);
	sndcp_prim->sn.tlli = tlli;
	sndcp_prim->sn.sapi = sapi;
	sndcp_prim->sn.xid_rsp.nsapi = nsapi;
	return sndcp_prim;
}

/*** SN SM ***/

static inline struct osmo_gprs_sndcp_prim *sndcp_prim_snsm_alloc(enum osmo_gprs_sndcp_snsm_prim_type type,
							   enum osmo_prim_operation operation,
							   unsigned int extra_size)
{
	return gprs_sndcp_prim_alloc(OSMO_GPRS_SNDCP_SAP_SNSM, type, operation, extra_size);
}

/* 5.1.2.19 SNSM-ACTIVATE.indication */
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_snsm_activate_ind(uint32_t tlli, uint8_t nsapi, uint8_t sapi)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	sndcp_prim = sndcp_prim_snsm_alloc(OSMO_GPRS_SNDCP_SNSM_ACTIVATE, PRIM_OP_INDICATION, 0);
	sndcp_prim->snsm.tlli = tlli;
	sndcp_prim->snsm.activate_ind.nsapi = nsapi;
	sndcp_prim->snsm.activate_ind.sapi = sapi;
	return sndcp_prim;
}

/* 5.1.2.20 SNSM-ACTIVATE.response */
struct osmo_gprs_sndcp_prim *gprs_sndcp_prim_alloc_snsm_activate_rsp(uint32_t tlli, uint8_t nsapi)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	sndcp_prim = sndcp_prim_snsm_alloc(OSMO_GPRS_SNDCP_SNSM_ACTIVATE, PRIM_OP_RESPONSE, 0);
	sndcp_prim->snsm.tlli = tlli;
	sndcp_prim->snsm.activate_rsp.nsapi = nsapi;
	return sndcp_prim;
}

/* 5.1.2.21 SNSM-DEACTIVATE.indication */
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_snsm_deactivate_ind(uint32_t tlli, uint8_t nsapi)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	sndcp_prim = sndcp_prim_snsm_alloc(OSMO_GPRS_SNDCP_SNSM_DEACTIVATE, PRIM_OP_INDICATION, 0);
	sndcp_prim->snsm.tlli = tlli;
	sndcp_prim->snsm.deactivate_ind.nsapi = nsapi;
	return sndcp_prim;
}

static int gprs_sndcp_prim_handle_unsupported(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	LOGSNDCP(LOGL_ERROR, "Unsupported sndcp_prim! %s\n", osmo_gprs_sndcp_prim_name(sndcp_prim));
	msgb_free(sndcp_prim->oph.msg);
	return -ENOTSUP;
}

static int gprs_sndcp_prim_handle_llc_ll_unsupported(struct osmo_gprs_llc_prim *llc_prim)
{
	LOGSNDCP(LOGL_ERROR, "Unsupported sndcp_prim! %s\n", osmo_gprs_llc_prim_name(llc_prim));
	msgb_free(llc_prim->oph.msg);
	return -ENOTSUP;
}

/********************************
 * Handling from/to upper layers:
 ********************************/

int gprs_sndcp_prim_call_up_cb(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;
	if (g_ctx->sndcp_up_cb)
		rc = g_ctx->sndcp_up_cb(sndcp_prim, g_ctx->sndcp_up_cb_user_data);
	else
		rc = sndcp_up_cb_dummy(sndcp_prim, g_ctx->sndcp_up_cb_user_data);
	msgb_free(sndcp_prim->oph.msg);
	return rc;
}

/* 5.1.1.1 SN-DATA.request:*/
static int gprs_sndcp_prim_handle_sndcp_sn_data_req(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;
	struct gprs_sndcp_entity *sne;
	OSMO_ASSERT(sndcp_prim->sn.data_req.npdu);
	OSMO_ASSERT(sndcp_prim->sn.data_req.npdu_len > 0);

	sne = gprs_sndcp_sne_by_dlci_nsapi(sndcp_prim->sn.tlli, sndcp_prim->sn.sapi,
					   sndcp_prim->sn.data_req.nsapi);
	if (!sne) {
		LOGSNDCP(LOGL_ERROR, "Message for non-existing SNDCP Entity "
			 "(TLLI=%08x, SAPI=%u, NSAPI=%u)\n",
			 sndcp_prim->sn.tlli, sndcp_prim->sn.sapi,
			 sndcp_prim->sn.data_req.nsapi);
		rc = -EIO;
		goto ret_free;
	}

	rc = gprs_sndcp_prim_handle_unsupported(sndcp_prim);
ret_free:
	msgb_free(sndcp_prim->oph.msg);
	return rc;
}

/* 5.1.1.3 SN-UNITDATA.request:*/
static int gprs_sndcp_prim_handle_sndcp_sn_unitdata_req(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;
	struct gprs_sndcp_entity *sne;
	OSMO_ASSERT(sndcp_prim->sn.unitdata_req.npdu);
	OSMO_ASSERT(sndcp_prim->sn.unitdata_req.npdu_len > 0);

	sne = gprs_sndcp_sne_by_dlci_nsapi(sndcp_prim->sn.tlli, sndcp_prim->sn.sapi,
					   sndcp_prim->sn.unitdata_req.nsapi);
	if (!sne) {
		LOGSNDCP(LOGL_ERROR, "Message for non-existing SNDCP Entity "
			 "(TLLI=%08x, SAPI=%u, NSAPI=%u)\n",
			 sndcp_prim->sn.tlli, sndcp_prim->sn.sapi,
			 sndcp_prim->sn.unitdata_req.nsapi);
		rc = -EIO;
		goto ret_free;
	}
	rc = gprs_sndcp_sne_handle_sn_unitdata_req(sne, sndcp_prim->sn.unitdata_req.npdu,
						   sndcp_prim->sn.unitdata_req.npdu_len);
ret_free:
	msgb_free(sndcp_prim->oph.msg);
	return rc;
}

/* 5.1.1.5 SN-XID.request:*/
static int gprs_sndcp_prim_handle_sndcp_sn_xid_req(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;
	struct gprs_sndcp_entity *sne;

	sne = gprs_sndcp_sne_by_dlci_nsapi(sndcp_prim->sn.tlli, sndcp_prim->sn.sapi,
					   sndcp_prim->sn.xid_req.nsapi);
	if (!sne) {
		LOGSNDCP(LOGL_ERROR, "Message for non-existing SNDCP Entity "
			 "(TLLI=%08x, SAPI=%u, NSAPI=%u)\n",
			 sndcp_prim->sn.tlli, sndcp_prim->sn.sapi,
			 sndcp_prim->sn.xid_req.nsapi);
		rc = -EIO;
		goto ret_free;
	}
	rc = gprs_sndcp_sne_handle_sn_xid_req(sne, sndcp_prim);
ret_free:
	msgb_free(sndcp_prim->oph.msg);
	return rc;
}

/* 5.1.1.7 SN-XID.response:*/
static int gprs_sndcp_prim_handle_sndcp_sn_xid_rsp(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;
	struct gprs_sndcp_entity *sne;

	sne = gprs_sndcp_sne_by_dlci_nsapi(sndcp_prim->sn.tlli, sndcp_prim->sn.sapi,
					   sndcp_prim->sn.xid_rsp.nsapi);
	if (!sne) {
		LOGSNDCP(LOGL_ERROR, "Message for non-existing SNDCP Entity "
			 "(TLLI=%08x, SAPI=%u, NSAPI=%u)\n",
			 sndcp_prim->sn.tlli, sndcp_prim->sn.sapi,
			 sndcp_prim->sn.xid_rsp.nsapi);
		rc = -EIO;
		goto ret_free;
	}
	rc = gprs_sndcp_sne_handle_sn_xid_rsp(sne, sndcp_prim);
ret_free:
	msgb_free(sndcp_prim->oph.msg);
	return rc;
}

/* SNDCP higher layers push SNDCP primitive down to SNDCP layer: */
int osmo_gprs_sndcp_prim_upper_down(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;
	OSMO_ASSERT(g_ctx);

	LOGSNDCP(LOGL_INFO, "Rx from upper layers: %s\n", osmo_gprs_sndcp_prim_name(sndcp_prim));

	if (sndcp_prim->oph.sap != OSMO_GPRS_SNDCP_SAP_SN)
		return gprs_sndcp_prim_handle_unsupported(sndcp_prim);

	switch (OSMO_PRIM_HDR(&sndcp_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SN_DATA, PRIM_OP_REQUEST):
		rc = gprs_sndcp_prim_handle_sndcp_sn_data_req(sndcp_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SN_UNITDATA, PRIM_OP_REQUEST):
		rc = gprs_sndcp_prim_handle_sndcp_sn_unitdata_req(sndcp_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SN_XID, PRIM_OP_REQUEST):
		rc = gprs_sndcp_prim_handle_sndcp_sn_xid_req(sndcp_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SN_XID, PRIM_OP_RESPONSE):
		rc = gprs_sndcp_prim_handle_sndcp_sn_xid_rsp(sndcp_prim);
		break;
	default:
		rc = gprs_sndcp_prim_handle_unsupported(sndcp_prim);
	}
	return rc;
}

/********************************
 * Handling from/to lower layers:
 ********************************/

int gprs_sndcp_prim_call_down_cb(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	if (g_ctx->sndcp_down_cb)
		rc = g_ctx->sndcp_down_cb(llc_prim, g_ctx->sndcp_down_cb_user_data);
	else
		rc = sndcp_down_cb_dummy(llc_prim, g_ctx->sndcp_down_cb_user_data);
	msgb_free(llc_prim->oph.msg);
	return rc;
}

static int gprs_sndcp_prim_handle_llc_ll_unitdata_ind(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	struct gprs_sndcp_entity *sne;
	struct sndcp_common_hdr *sch = (struct sndcp_common_hdr *)llc_prim->ll.l3_pdu;
	OSMO_ASSERT(sch);
	OSMO_ASSERT(llc_prim->ll.l3_pdu_len > 0);

	sne = gprs_sndcp_sne_by_dlci_nsapi(llc_prim->ll.tlli, llc_prim->ll.sapi, sch->nsapi);
	if (!sne) {
		LOGSNDCP(LOGL_ERROR, "Message for non-existing SNDCP Entity "
			 "(TLLI=%08x, SAPI=%u, NSAPI=%u)\n",
			 llc_prim->ll.tlli, llc_prim->ll.sapi, sch->nsapi);
		return -EIO;
	}

	rc = gprs_sndcp_sne_handle_llc_ll_unitdata_ind(sne, sch, llc_prim->ll.l3_pdu_len);
	return rc;
}

static int gprs_sndcp_prim_handle_llc_ll_xid_ind(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	struct gprs_sndcp_mgmt_entity *snme;

	snme = gprs_sndcp_snme_find_by_tlli(llc_prim->ll.tlli);
	if (!snme) {
		LOGSNDCP(LOGL_ERROR, "SNDCP-LL-XID.ind: Message for non-existing SNDCP Entity "
			 "(TLLI=%08x, SAPI=%u)\n",
			 llc_prim->ll.tlli, llc_prim->ll.sapi);
		return -EIO;
	}

	rc = gprs_sndcp_snme_handle_llc_ll_xid_ind(snme, llc_prim->ll.sapi,
						   llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len);
	return rc;
}

static int gprs_sndcp_prim_handle_llc_ll_xid_cnf(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	struct gprs_sndcp_mgmt_entity *snme;

	snme = gprs_sndcp_snme_find_by_tlli(llc_prim->ll.tlli);
	if (!snme) {
		LOGSNDCP(LOGL_ERROR, "SNDCP-LL-XID.cnf: Message for non-existing SNDCP Entity "
			 "(TLLI=%08x, SAPI=%u)\n",
			 llc_prim->ll.tlli, llc_prim->ll.sapi);
		return -EIO;
	}

	rc = gprs_sndcp_snme_handle_llc_ll_xid_cnf(snme, llc_prim->ll.sapi,
						   llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len);
	return rc;
}

int gprs_sndcp_prim_lower_up_llc_ll(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;

	switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_UNITDATA, PRIM_OP_INDICATION):
		rc = gprs_sndcp_prim_handle_llc_ll_unitdata_ind(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_XID, PRIM_OP_INDICATION):
		rc = gprs_sndcp_prim_handle_llc_ll_xid_ind(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_XID, PRIM_OP_CONFIRM):
		rc = gprs_sndcp_prim_handle_llc_ll_xid_cnf(llc_prim);
		break;
	default:
		rc = gprs_sndcp_prim_handle_llc_ll_unsupported(llc_prim);
	}
	return rc;
}

/* SNDCP lower layers (LLC) push SNDCP primitive up to SNDCP layer: */
int osmo_gprs_sndcp_prim_lower_up(struct osmo_gprs_llc_prim *llc_prim)
{
	OSMO_ASSERT(g_ctx);
	OSMO_ASSERT(llc_prim);
	struct msgb *msg = llc_prim->oph.msg;
	int rc;

	LOGSNDCP(LOGL_INFO, "Rx from lower layers: %s\n", osmo_gprs_llc_prim_name(llc_prim));

	switch (llc_prim->oph.sap) {
	case OSMO_GPRS_LLC_SAP_LL:
		rc = gprs_sndcp_prim_lower_up_llc_ll(llc_prim);
		break;
	default:
		rc = gprs_sndcp_prim_handle_llc_ll_unsupported(llc_prim);
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);
	else
		rc = 0;
	return rc;
}

/********************************
 * Handling from/to SM sublayer:
 ********************************/

int gprs_sndcp_prim_call_snsm_cb(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;
	if (g_ctx->sndcp_snsm_cb)
		rc = g_ctx->sndcp_snsm_cb(sndcp_prim, g_ctx->sndcp_snsm_cb_user_data);
	else
		rc = sndcp_snsm_cb_dummy(sndcp_prim, g_ctx->sndcp_snsm_cb_user_data);
	msgb_free(sndcp_prim->oph.msg);
	return rc;
}

/* 5.1.2.19 SNSM-ACTIVATE.indication: */
static int gprs_sndcp_prim_handle_sndcp_snsm_activate_ind(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc = 0;
	uint32_t tlli = sndcp_prim->snsm.tlli;
	uint8_t sapi = sndcp_prim->snsm.activate_ind.sapi;
	uint8_t nsapi = sndcp_prim->snsm.activate_ind.nsapi;
	struct gprs_sndcp_mgmt_entity *snme;

	LOGSNDCP(LOGL_INFO, "SNSM-ACTIVATE.ind (TLLI=%08x, SAPI=%u, NSAPI=%u)\n",
		 tlli, sapi, nsapi);

	snme = gprs_sndcp_snme_find_by_tlli(tlli);
	if (!snme) {
		snme = gprs_sndcp_snme_alloc(tlli);
	} else if (gprs_sndcp_snme_get_sne(snme, nsapi)) {
		LOGSNDCP(LOGL_ERROR, "Trying to ACTIVATE already-existing entity "
			 "(TLLI=%08x, SAPI=%u, NSAPI=%u)\n",
			 tlli, sapi, nsapi);
		return -EEXIST;
	}

	if (!snme) {
		LOGSNDCP(LOGL_ERROR, "Out of memory during ACTIVATE\n");
		return -ENOMEM;
	}

	if (!gprs_sndcp_sne_alloc(snme, sapi, nsapi)) {
		LOGSNDCP(LOGL_ERROR, "Out of memory during ACTIVATE\n");
		return -ENOMEM;
	}

	return rc;
}

/* 5.1.2.21 SNSM-DEACTIVATE.indication: */
static int gprs_sndcp_prim_handle_sndcp_snsm_deactivate_ind(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc = 0;
	struct gprs_sndcp_mgmt_entity *snme;
	struct gprs_sndcp_entity *sne;
	uint32_t tlli = sndcp_prim->snsm.tlli;
	uint8_t nsapi = sndcp_prim->snsm.deactivate_ind.nsapi;

	snme = gprs_sndcp_snme_find_by_tlli(tlli);
	if (!snme) {
		LOGSNDCP(LOGL_ERROR, "SNSM-DEACTIVATE.ind: Message for non-existing SNDCP Management Entity "
		 "(TLLI=%08x, NSAPI=%u)\n", tlli, nsapi);
		return -EIO;
	}

	sne = gprs_sndcp_snme_get_sne(snme, nsapi);
	if (!sne) {
		LOGSNDCP(LOGL_ERROR, "SNSM-DEACTIVATE.ind: Message for non-existing SNDCP Entity "
		 "(TLLI=%08x, NSAPI=%u)\n", tlli, nsapi);
		return -EIO;
	}

	gprs_sndcp_sne_free(sne);
	return rc;
}

/* 5.1.2.23 SNSM-MODIFY.indication: */
static int gprs_sndcp_prim_handle_sndcp_snsm_modify_ind(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc = 0;

	rc = gprs_sndcp_prim_handle_unsupported(sndcp_prim);
	return rc;
}

/* 5.1.2.26 SNSM-SEQUENCE.indication: */
static int gprs_sndcp_prim_handle_sndcp_snsm_sequence_ind(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc = 0;

	rc = gprs_sndcp_prim_handle_unsupported(sndcp_prim);
	return rc;
}

/* 5.1.2.28 SNSM-STOP-ASSIGN.indication: */
static int gprs_sndcp_prim_handle_sndcp_snsm_stop_assign_ind(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc = 0;

	rc = gprs_sndcp_prim_handle_unsupported(sndcp_prim);
	return rc;
}

/* SNDCP higher layers push SNDCP primitive down to SNDCP layer: */
int osmo_gprs_sndcp_prim_dispatch_snsm(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;
	OSMO_ASSERT(g_ctx);
	OSMO_ASSERT(sndcp_prim);
	struct msgb *msg = sndcp_prim->oph.msg;

	LOGSNDCP(LOGL_INFO, "Rx from SNDCP SM sublayer: %s\n", osmo_gprs_sndcp_prim_name(sndcp_prim));

	if (sndcp_prim->oph.sap != OSMO_GPRS_SNDCP_SAP_SNSM)
		return gprs_sndcp_prim_handle_unsupported(sndcp_prim);

	switch (OSMO_PRIM_HDR(&sndcp_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_ACTIVATE, PRIM_OP_INDICATION):
		rc = gprs_sndcp_prim_handle_sndcp_snsm_activate_ind(sndcp_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_DEACTIVATE, PRIM_OP_INDICATION):
		rc = gprs_sndcp_prim_handle_sndcp_snsm_deactivate_ind(sndcp_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_MODIFY, PRIM_OP_INDICATION):
		rc = gprs_sndcp_prim_handle_sndcp_snsm_modify_ind(sndcp_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_SEQUENCE, PRIM_OP_INDICATION):
		rc = gprs_sndcp_prim_handle_sndcp_snsm_sequence_ind(sndcp_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SNSM_STOP_ASSIGN, PRIM_OP_INDICATION):
		rc = gprs_sndcp_prim_handle_sndcp_snsm_stop_assign_ind(sndcp_prim);
		break;
	default:
		rc = gprs_sndcp_prim_handle_unsupported(sndcp_prim);
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);
	else
		rc = 0;
	return rc;
}
