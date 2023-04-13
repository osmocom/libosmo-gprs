/* GPRS SNDCP as per 3GPP TS 44.065 */
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
#include <arpa/inet.h>

#include <osmocom/core/talloc.h>

#include <osmocom/gprs/sndcp/sndcp.h>
#include <osmocom/gprs/sndcp/dcomp.h>
#include <osmocom/gprs/sndcp/pcomp.h>
#include <osmocom/gprs/sndcp/sndcp_prim.h>
#include <osmocom/gprs/sndcp/sndcp_private.h>
#include <osmocom/gprs/llc/llc_prim.h>

struct gprs_sndcp_ctx *g_sndcp_ctx;

int osmo_gprs_sndcp_init(void)
{
	if (g_sndcp_ctx)
		talloc_free(g_sndcp_ctx);

	g_sndcp_ctx = talloc_zero(NULL, struct gprs_sndcp_ctx);
	INIT_LLIST_HEAD(&g_sndcp_ctx->snme_list);
	return 0;
}

struct gprs_sndcp_mgmt_entity *gprs_sndcp_snme_alloc(uint32_t tlli)
{
	struct gprs_sndcp_mgmt_entity *snme;

	snme = talloc_zero(g_sndcp_ctx, struct gprs_sndcp_mgmt_entity);
	if (!snme)
		return NULL;

	snme->tlli = tlli;
	llist_add(&snme->list, &g_sndcp_ctx->snme_list);

	return snme;
}

static void gprs_sndcp_snme_free(struct gprs_sndcp_mgmt_entity *snme)
{
	if (!snme)
		return;

	LOGSNME(snme, LOGL_DEBUG, "free()\n");
	llist_del(&snme->list);
	talloc_free(snme);
}

/* lookup SNDCP Management Entity based on TLLI */
struct gprs_sndcp_mgmt_entity *gprs_sndcp_snme_find_by_tlli(uint32_t tlli)
{
	struct gprs_sndcp_mgmt_entity *snme;

	llist_for_each_entry(snme, &g_sndcp_ctx->snme_list, list) {
		if (snme->tlli == tlli)
			return snme;
	}
	return NULL;
}

static void gprs_sndcp_snme_attach_sne(struct gprs_sndcp_mgmt_entity *snme, struct gprs_sndcp_entity *sne)
{
	if (snme->sne[sne->nsapi])
		osmo_panic("Trying to attach already existing SNDCP entity!\n");

	snme->sne[sne->nsapi] = sne;
}

/* snme may become freed upon return (returns bool freed) */
static bool gprs_sndcp_snme_detach_sne(struct gprs_sndcp_mgmt_entity *snme, struct gprs_sndcp_entity *sne)
{
	unsigned int i;
	if (!snme->sne[sne->nsapi])
		osmo_panic("Trying to detach already non-existing SNDCP entity!\n");

	OSMO_ASSERT(sne->snme->sne[sne->nsapi] == sne);
	snme->sne[sne->nsapi] = NULL;

	for (i = 0; i < ARRAY_SIZE(snme->sne); i++) {
		if (snme->sne[i])
			return false;
	}
	LOGSNME(snme, LOGL_DEBUG, "No SNDCP Entities left activate, freeing SNME\n");
	gprs_sndcp_snme_free(snme);
	return true;
}

struct gprs_sndcp_entity *gprs_sndcp_sne_alloc(struct gprs_sndcp_mgmt_entity *snme, uint8_t llc_sapi, uint8_t nsapi)
{
	struct gprs_sndcp_entity *sne;

	sne = talloc_zero(g_sndcp_ctx, struct gprs_sndcp_entity);
	if (!sne)
		return NULL;

	sne->llc_sapi = llc_sapi;
	sne->nsapi = nsapi;
	sne->defrag.timer.data = sne;
	//sne->fqueue.timer.cb = FIXME;
	sne->rx_state = GPRS_SNDCP_RX_S_FIRST;
	INIT_LLIST_HEAD(&sne->defrag.frag_list);

	sne->snme = snme;
	gprs_sndcp_snme_attach_sne(snme, sne);

	return sne;
}

void gprs_sndcp_sne_free(struct gprs_sndcp_entity *sne)
{
	if (!sne)
		return;

	LOGSNE(sne, LOGL_DEBUG, "free()\n");
	gprs_sndcp_snme_detach_sne(sne->snme, sne);
	sne->snme = NULL;
	talloc_free(sne);
}

struct gprs_sndcp_entity *gprs_sndcp_sne_by_dlci_nsapi(uint32_t tlli, uint8_t llc_sapi, uint8_t nsapi)
{
	struct gprs_sndcp_mgmt_entity *snme = gprs_sndcp_snme_find_by_tlli(tlli);
	struct gprs_sndcp_entity *sne;

	if (!snme)
		return NULL;

	sne = gprs_sndcp_snme_get_sne(snme, nsapi);
	if (sne->llc_sapi != llc_sapi)
		return NULL;
	return sne;
}

/* Check if any compression parameters are set in the sgsn configuration */
static inline int any_pcomp_or_dcomp_active(const struct gprs_sndcp_ctx *sgsn)
{
#if 0
	/* TODO: */
	if (sgsn->cfg.pcomp_rfc1144.active || sgsn->cfg.pcomp_rfc1144.passive ||
	    sgsn->cfg.dcomp_v42bis.active || sgsn->cfg.dcomp_v42bis.passive)
		return true;
	//else
#endif
		return false;
}

/* Enqueue a fragment into the defragment queue */
static int defrag_enqueue(struct gprs_sndcp_entity *sne, uint8_t seg_nr,
			  uint8_t *data, uint32_t data_len)
{
	struct defrag_queue_entry *dqe;

	dqe = talloc_zero(g_sndcp_ctx, struct defrag_queue_entry);
	if (!dqe)
		return -ENOMEM;
	dqe->data = talloc_zero_size(dqe, data_len);
	if (!dqe->data) {
		talloc_free(dqe);
		return -ENOMEM;
	}
	dqe->seg_nr = seg_nr;
	dqe->data_len = data_len;

	llist_add(&dqe->list, &sne->defrag.frag_list);

	if (seg_nr > sne->defrag.highest_seg)
		sne->defrag.highest_seg = seg_nr;

	sne->defrag.seg_have |= (1 << seg_nr);
	sne->defrag.tot_len += data_len;

	memcpy(dqe->data, data, data_len);

	return 0;
}

/* return if we have all segments of this N-PDU */
static int defrag_have_all_segments(const struct gprs_sndcp_entity *sne)
{
	uint32_t seg_needed = 0;
	unsigned int i;

	/* create a bitmask of needed segments */
	for (i = 0; i <= sne->defrag.highest_seg; i++)
		seg_needed |= (1 << i);

	if (seg_needed == sne->defrag.seg_have)
		return 1;

	return 0;
}

static struct defrag_queue_entry *defrag_get_seg(const struct gprs_sndcp_entity *sne,
						 uint32_t seg_nr)
{
	struct defrag_queue_entry *dqe;

	llist_for_each_entry(dqe, &sne->defrag.frag_list, list) {
		if (dqe->seg_nr == seg_nr) {
			llist_del(&dqe->list);
			return dqe;
		}
	}
	return NULL;
}

/* Returns talloced buffer containing decompressed data, NULL on error. */
static uint8_t *decompress_segment(struct gprs_sndcp_entity *sne, void *ctx,
				   const uint8_t *compressed_data, unsigned int compressed_data_len,
				   unsigned int *decompressed_data_len)
{
	int rc;
	uint8_t *expnd = NULL;
	*decompressed_data_len = 0;

#if DEBUG_IP_PACKETS == 1
	LOGSNE(sne, "\n");
	LOGSNE(sne, ":::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	LOGSNE(sne, "===================================================\n");
#endif

	expnd = talloc_zero_size(ctx, compressed_data_len * MAX_DATADECOMPR_FAC +
					 MAX_HDRDECOMPR_INCR);
	memcpy(expnd, compressed_data, compressed_data_len);

	/* Apply data decompression */
	rc = gprs_sndcp_dcomp_expand(expnd, compressed_data_len, sne->defrag.dcomp,
				     sne->defrag.data);
	if (rc < 0) {
		LOGSNE(sne, LOGL_ERROR,
		       "Data decompression failed!\n");
		talloc_free(expnd);
		return NULL;
	}

	/* Apply header decompression */
	rc = gprs_sndcp_pcomp_expand(expnd, rc, sne->defrag.pcomp, sne->defrag.proto);
	if (rc < 0) {
		LOGSNE(sne, LOGL_ERROR,
		       "TCP/IP Header decompression failed!\n");
		talloc_free(expnd);
		return NULL;
	}

	*decompressed_data_len = rc;

#if DEBUG_IP_PACKETS == 1
	debug_ip_packet(expnd, *decompressed_data_len, 1, "defrag_segments()");
	LOGSNE(sne, "===================================================\n");
	LOGSNE(sne, ":::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	LOGSNE(sne, "\n");
#endif
	return expnd;
}

/* Perform actual defragmentation and create an output packet */
static int defrag_segments(struct gprs_sndcp_entity *sne)
{
	struct msgb *msg;
	unsigned int seg_nr;
	uint8_t *npdu;
	unsigned int npdu_len;
	int rc;
	uint8_t *expnd = NULL;
	struct osmo_gprs_sndcp_prim *sndcp_prim_tx;

	LOGSNE(sne, LOGL_DEBUG, "TLLI=0x%08x NSAPI=%u: Defragment output PDU %u "
		"num_seg=%u tot_len=%u\n", sne->snme->tlli, sne->nsapi,
		sne->defrag.npdu, sne->defrag.highest_seg, sne->defrag.tot_len);
	msg = msgb_alloc_headroom(sne->defrag.tot_len+256, 128, "SNDCP Defrag");
	if (!msg)
		return -ENOMEM;

	/* FIXME: message headers + identifiers */

	npdu = msg->data;

	for (seg_nr = 0; seg_nr <= sne->defrag.highest_seg; seg_nr++) {
		struct defrag_queue_entry *dqe;
		uint8_t *data;

		dqe = defrag_get_seg(sne, seg_nr);
		if (!dqe) {
			LOGSNE(sne, LOGL_ERROR, "Segment %u missing\n", seg_nr);
			msgb_free(msg);
			return -EIO;
		}
		/* actually append the segment to the N-PDU */
		data = msgb_put(msg, dqe->data_len);
		memcpy(data, dqe->data, dqe->data_len);

		/* release memory for the fragment queue entry */
		talloc_free(dqe);
	}

	npdu_len = sne->defrag.tot_len;

	/* FIXME: cancel timer */

	/* actually send the N-PDU to the SGSN core code, which then
	 * hands it off to the correct GTP tunnel + GGSN via gtp_data_req() */

	/* Decompress packet */
	if (any_pcomp_or_dcomp_active(g_sndcp_ctx)) {
		expnd = decompress_segment(sne, msg, npdu, npdu_len, &npdu_len);
		if (!expnd) {
			rc = -EIO;
			goto ret_free;
		}
	} else {
		expnd = npdu;
	}

	/* Trigger SN-UNITDATA.ind to upper layers: */
	sndcp_prim_tx = gprs_sndcp_prim_alloc_sn_unitdata_ind(sne->snme->tlli, sne->llc_sapi, sne->nsapi, expnd, npdu_len);
	rc = gprs_sndcp_prim_call_up_cb(sndcp_prim_tx);

ret_free:
	/* we must free the memory we allocated above; ownership is not transferred
	 * downwards in the call above */
	msgb_free(msg);
	return rc;
}

static int defrag_input(struct gprs_sndcp_entity *sne, uint8_t *hdr, unsigned int len)
{
	struct sndcp_common_hdr *sch;
	struct sndcp_udata_hdr *suh;
	uint16_t npdu_num;
	uint8_t *data;
	int rc;

	sch = (struct sndcp_common_hdr *) hdr;
	if (sch->first) {
		suh = (struct sndcp_udata_hdr *) (hdr + 1 + sizeof(struct sndcp_common_hdr));
	} else
		suh = (struct sndcp_udata_hdr *) (hdr + sizeof(struct sndcp_common_hdr));

	data = (uint8_t *)suh + sizeof(struct sndcp_udata_hdr);

	npdu_num = (suh->npdu_high << 8) | suh->npdu_low;

	LOGSNE(sne, LOGL_DEBUG, "TLLI=0x%08x NSAPI=%u: Input PDU %u Segment %u "
		"Length %u %s %s\n", sne->snme->tlli, sne->nsapi, npdu_num,
		suh->seg_nr, len, sch->first ? "F " : "", sch->more ? "M" : "");

	if (sch->first) {
		/* first segment of a new packet.  Discard all leftover fragments of
		 * previous packet */
		if (!llist_empty(&sne->defrag.frag_list)) {
			struct defrag_queue_entry *dqe, *dqe2;
			LOGSNE(sne, LOGL_INFO, "TLLI=0x%08x NSAPI=%u: Dropping "
			     "SN-PDU %u due to insufficient segments (%04x)\n",
			     sne->snme->tlli, sne->nsapi, sne->defrag.npdu,
			     sne->defrag.seg_have);
			llist_for_each_entry_safe(dqe, dqe2, &sne->defrag.frag_list, list) {
				llist_del(&dqe->list);
				talloc_free(dqe);
			}
		}
		/* store the currently de-fragmented PDU number */
		sne->defrag.npdu = npdu_num;

		/* Re-set fragmentation state */
		sne->defrag.no_more = sne->defrag.highest_seg = sne->defrag.seg_have = 0;
		sne->defrag.tot_len = 0;
		/* FIXME: (re)start timer */
	}

	if (sne->defrag.npdu != npdu_num) {
		LOGSNE(sne, LOGL_INFO, "Segment for different SN-PDU "
			"(%u != %u)\n", npdu_num, sne->defrag.npdu);
		/* FIXME */
	}

	/* FIXME: check if seg_nr already exists */
	/* make sure to subtract length of SNDCP header from 'len' */
	rc = defrag_enqueue(sne, suh->seg_nr, data, len - (data - hdr));
	if (rc < 0)
		return rc;

	if (!sch->more) {
		/* this is suppsed to be the last segment of the N-PDU, but it
		 * might well be not the last to arrive */
		sne->defrag.no_more = 1;
	}

	if (sne->defrag.no_more) {
		/* we have already received the last segment before, let's check
		 * if all the previous segments exist */
		if (defrag_have_all_segments(sne))
			return defrag_segments(sne);
	}

	return 0;
}

/* Fragmenter state */
struct sndcp_frag_state {
	uint8_t frag_nr;
	struct msgb *msg;	/* original message */
	uint8_t *next_byte;	/* first byte of next fragment */

	struct gprs_sndcp_entity *sne;
};

/* returns '1' if there are more fragments to send, '0' if none */
static int gprs_sndcp_send_ud_frag(struct sndcp_frag_state *fs,
			      uint8_t pcomp, uint8_t dcomp)
{
	struct gprs_sndcp_entity *sne = fs->sne;
	struct sndcp_common_hdr *sch;
	struct sndcp_comp_hdr *scomph;
	struct sndcp_udata_hdr *suh;
	struct msgb *fmsg;
	unsigned int max_payload_len;
	unsigned int len;
	uint8_t *data;
	int rc, more;
	struct osmo_gprs_llc_prim *llc_prim_tx;

	fmsg = msgb_alloc_headroom(sne->n201_u+256, 128, "SNDCP Frag");
	if (!fmsg) {
		msgb_free(fs->msg);
		return -ENOMEM;
	}

	/* prepend common SNDCP header */
	sch = (struct sndcp_common_hdr *) msgb_put(fmsg, sizeof(*sch));
	sch->nsapi = sne->nsapi;
	/* Set FIRST bit if we are the first fragment in a series */
	if (fs->frag_nr == 0)
		sch->first = 1;
	sch->type = 1;

	/* append the compression header for first fragment */
	if (sch->first) {
		scomph = (struct sndcp_comp_hdr *)
				msgb_put(fmsg, sizeof(*scomph));
		scomph->pcomp = pcomp;
		scomph->dcomp = dcomp;
	}

	/* append the user-data header */
	suh = (struct sndcp_udata_hdr *) msgb_put(fmsg, sizeof(*suh));
	suh->npdu_low = sne->tx_npdu_nr & 0xff;
	suh->npdu_high = (sne->tx_npdu_nr >> 8) & 0xf;
	suh->seg_nr = fs->frag_nr % 0xf;

	/* calculate remaining length to be sent */
	len = (fs->msg->data + fs->msg->len) - fs->next_byte;
	/* how much payload can we actually send via LLC? */
	max_payload_len = sne->n201_u - (sizeof(*sch) + sizeof(*suh));
	if (sch->first)
		max_payload_len -= sizeof(*scomph);
	/* check if we're exceeding the max */
	if (len > max_payload_len)
		len = max_payload_len;

	/* copy the actual fragment data into our fmsg */
	data = msgb_put(fmsg, len);
	memcpy(data, fs->next_byte, len);

	/* Increment fragment number and data pointer to next fragment */
	fs->frag_nr++;
	fs->next_byte += len;

	/* determine if we have more fragemnts to send */
	if ((fs->msg->data + fs->msg->len) <= fs->next_byte)
		more = 0;
	else
		more = 1;

	/* set the MORE bit of the SNDCP header accordingly */
	sch->more = more;

	/* Send down the stack SNDCP->LLC as LL-UNITDATA.req: */
	llc_prim_tx = osmo_gprs_llc_prim_alloc_ll_unitdata_req(sne->snme->tlli, sne->llc_sapi, fmsg->data, fmsg->len);
	OSMO_ASSERT(llc_prim_tx);
	rc = gprs_sndcp_prim_call_down_cb(llc_prim_tx);
	msgb_free(fmsg);
	/* abort in case of error, do not advance frag_nr / next_byte */
	if (rc < 0) {
		msgb_free(fs->msg);
		return rc;
	}

	if (!more) {
		/* we've sent all fragments */
		msgb_free(fs->msg);
		memset(fs, 0, sizeof(*fs));
		/* increment NPDU number for next frame */
		sne->tx_npdu_nr = (sne->tx_npdu_nr + 1) % 0xfff;
		return 0;
	}

	/* default: more fragments to send */
	return 1;
}

/* 5.1.1.3 SN-UNITDATA.request */
int gprs_sndcp_sne_handle_sn_unitdata_req(struct gprs_sndcp_entity *sne, uint8_t *npdu, unsigned int npdu_len)
{
	struct sndcp_common_hdr *sch;
	struct sndcp_comp_hdr *scomph;
	struct sndcp_udata_hdr *suh;
	struct sndcp_frag_state fs;
	uint8_t pcomp = 0;
	uint8_t dcomp = 0;
	int rc;
	struct msgb *msg = msgb_alloc_headroom(npdu_len + 256, 128, "sndcp-tx");
	struct osmo_gprs_llc_prim *llc_prim_tx;

	memcpy(msgb_put(msg, npdu_len), npdu, npdu_len);

	/* Compress packet */
#if DEBUG_IP_PACKETS == 1
	LOGSNE(sne, "\n");
	LOGSNE(sne, ":::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	LOGSNE(sne, "===================================================\n");
	debug_ip_packet(npdu, npdu_len, 0, __func__ "()");
#endif
	if (any_pcomp_or_dcomp_active(g_sndcp_ctx)) {

		/* Apply header compression */
		rc = gprs_sndcp_pcomp_compress(msg->data, msg->len, &pcomp,
					       sne->snme->comp.proto, sne->nsapi);
		if (rc < 0) {
			LOGSNE(sne, LOGL_ERROR, "TCP/IP Header compression failed!\n");
			rc = -EIO;
			goto free_ret;
		}

		/* Fixup pointer locations and sizes in message buffer to match
		 * the new, compressed buffer size */
		msgb_get(msg, msg->len);
		msgb_put(msg, rc);

		/* Apply data compression */
		rc = gprs_sndcp_dcomp_compress(msg->data, msg->len, &dcomp,
					       sne->snme->comp.data, sne->nsapi);
		if (rc < 0) {
			LOGSNE(sne, LOGL_ERROR, "Data compression failed!\n");
			rc = -EIO;
			goto free_ret;
		}

		/* Fixup pointer locations and sizes in message buffer to match
		 * the new, compressed buffer size */
		msgb_get(msg, msg->len);
		msgb_put(msg, rc);
	}
#if DEBUG_IP_PACKETS == 1
	LOGSNE(sne, "===================================================\n");
	DLOGSNE(sne, ":::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	LOGSNE(sne, "\n");
#endif

	/* Check if we need to fragment this N-PDU into multiple SN-PDUs */
	if (msg->len > sne->n201_u -
			(sizeof(*sch) + sizeof(*suh) + sizeof(*scomph))) {
		/* initialize the fragmenter state */
		fs.msg = msg;
		fs.frag_nr = 0;
		fs.next_byte = msg->data;
		fs.sne = sne;

		/* call function to generate and send fragments until all
		 * of the N-PDU has been sent */
		while (1) {
			int rc = gprs_sndcp_send_ud_frag(&fs, pcomp, dcomp);
			if (rc == 0)
				return 0;
			if (rc < 0)
				return rc;
		}
		/* not reached */
		return 0;
	}

	/* this is the non-fragmenting case where we only build 1 SN-PDU */

	/* prepend the user-data header */
	suh = (struct sndcp_udata_hdr *) msgb_push(msg, sizeof(*suh));
	suh->npdu_low = sne->tx_npdu_nr & 0xff;
	suh->npdu_high = (sne->tx_npdu_nr >> 8) & 0xf;
	suh->seg_nr = 0;
	sne->tx_npdu_nr = (sne->tx_npdu_nr + 1) % 0xfff;

	scomph = (struct sndcp_comp_hdr *) msgb_push(msg, sizeof(*scomph));
	scomph->pcomp = pcomp;
	scomph->dcomp = dcomp;

	/* prepend common SNDCP header */
	sch = (struct sndcp_common_hdr *) msgb_push(msg, sizeof(*sch));
	sch->first = 1;
	sch->type = 1;
	sch->nsapi = sne->nsapi;

	/* Send down the stack SNDCP->LLC as LL-UNITDATA.req: */
	llc_prim_tx = osmo_gprs_llc_prim_alloc_ll_unitdata_req(sne->snme->tlli, sne->llc_sapi, msg->data, msg->len);
	OSMO_ASSERT(llc_prim_tx);
	rc = gprs_sndcp_prim_call_down_cb(llc_prim_tx);
free_ret:
	msgb_free(msg);
	return rc;
}


/* Generate SNDCP-XID message (5.1.1.5 SN-XID.request) */
static int gprs_sndcp_sne_gen_sndcp_xid(struct gprs_sndcp_entity *sne, uint8_t *bytes, int bytes_len, const struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int entity = 0;
	LLIST_HEAD(comp_fields);
	struct gprs_sndcp_pcomp_rfc1144_params rfc1144_params;
	struct gprs_sndcp_comp_field rfc1144_comp_field;
	struct gprs_sndcp_dcomp_v42bis_params v42bis_params;
	struct gprs_sndcp_comp_field v42bis_comp_field;

	memset(&rfc1144_comp_field, 0, sizeof(struct gprs_sndcp_comp_field));
	memset(&v42bis_comp_field, 0, sizeof(struct gprs_sndcp_comp_field));

	/* Setup rfc1144 */
	if (sndcp_prim->sn.xid_req.pcomp_rfc1144.active) {
		rfc1144_params.nsapi[0] = sne->nsapi;
		rfc1144_params.nsapi_len = 1;
		rfc1144_params.s01 = sndcp_prim->sn.xid_req.pcomp_rfc1144.s01;
		rfc1144_comp_field.p = 1;
		rfc1144_comp_field.entity = entity;
		rfc1144_comp_field.algo.pcomp = RFC_1144;
		rfc1144_comp_field.comp[RFC1144_PCOMP1] = 1;
		rfc1144_comp_field.comp[RFC1144_PCOMP2] = 2;
		rfc1144_comp_field.comp_len = RFC1144_PCOMP_NUM;
		rfc1144_comp_field.rfc1144_params = &rfc1144_params;
		entity++;
		llist_add(&rfc1144_comp_field.list, &comp_fields);
	}

	/* Setup V.42bis */
	if (sndcp_prim->sn.xid_req.dcomp_v42bis.active) {
		v42bis_params.nsapi[0] = sne->nsapi;
		v42bis_params.nsapi_len = 1;
		v42bis_params.p0 = sndcp_prim->sn.xid_req.dcomp_v42bis.p0;
		v42bis_params.p1 = sndcp_prim->sn.xid_req.dcomp_v42bis.p1;
		v42bis_params.p2 = sndcp_prim->sn.xid_req.dcomp_v42bis.p2;
		v42bis_comp_field.p = 1;
		v42bis_comp_field.entity = entity;
		v42bis_comp_field.algo.dcomp = V42BIS;
		v42bis_comp_field.comp[V42BIS_DCOMP1] = 1;
		v42bis_comp_field.comp_len = V42BIS_DCOMP_NUM;
		v42bis_comp_field.v42bis_params = &v42bis_params;
		entity++;
		llist_add(&v42bis_comp_field.list, &comp_fields);
	}

	LOGSNE(sne, LOGL_DEBUG, "SN-XID.req comp_fields:\n");
	gprs_sndcp_dump_comp_fields(&comp_fields, LOGL_DEBUG);

	/* Do not attempt to compile anything if there is no data in the list */
	if (llist_empty(&comp_fields))
		return 0;

	/* Compile bytestream */
	return gprs_sndcp_compile_xid(bytes, bytes_len, &comp_fields,
				      DEFAULT_SNDCP_VERSION);
}

/* 5.1.1.5 SN-XID.request */
int gprs_sndcp_sne_handle_sn_xid_req(struct gprs_sndcp_entity *sne, const struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	int rc;
	uint8_t l3params[1024];
	struct osmo_gprs_llc_prim *llc_prim_tx;

	/* Wipe off all compression entities and their states to
	 * get rid of possible leftovers from a previous session */
	gprs_sndcp_comp_free(sne->snme->comp.proto);
	gprs_sndcp_comp_free(sne->snme->comp.data);
	sne->snme->comp.proto = gprs_sndcp_comp_alloc(sne);
	sne->snme->comp.data = gprs_sndcp_comp_alloc(sne);

	/* Generate compression parameter bytestream */
	sne->l3xid_req_len = gprs_sndcp_sne_gen_sndcp_xid(sne, l3params, sizeof(l3params), sndcp_prim);
	if (sne->l3xid_req_len > 0) {
		talloc_free(sne->l3xid_req);
		sne->l3xid_req = talloc_size(sne, sne->l3xid_req_len);
		memcpy(sne->l3xid_req, l3params, sne->l3xid_req_len);
	} else {
		talloc_free(sne->l3xid_req);
		sne->l3xid_req = NULL;
	}

	llc_prim_tx = osmo_gprs_llc_prim_alloc_ll_xid_req(sne->snme->tlli, sne->llc_sapi,
							  sne->l3xid_req, sne->l3xid_req_len);
	OSMO_ASSERT(llc_prim_tx);
	rc = gprs_sndcp_prim_call_down_cb(llc_prim_tx);

	return rc;
}

/* 5.1.1.7 SN-XID.response */
/* FIXME: This is currently uses comp_fields stored from gprs_sndcp_snme_handle_llc_ll_xid_ind().
* It should use info provided by upper layers in the prim instead */
int gprs_sndcp_sne_handle_sn_xid_rsp(struct gprs_sndcp_entity *sne, const struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	struct osmo_gprs_llc_prim *llc_prim_tx;
	struct msgb *msg;
	int rc;

	if (!sne->l3_xid_comp_fields_req_from_peer) {
		LOGSNE(sne, LOGL_DEBUG, "SN-XID.rsp origianted comp_fields not found!\n");
		return -EINVAL;
	}

	LOGSNE(sne, LOGL_DEBUG, "SN-XID.rsp comp_fields:\n");
	gprs_sndcp_dump_comp_fields(sne->l3_xid_comp_fields_req_from_peer, LOGL_DEBUG);

	llc_prim_tx = osmo_gprs_llc_prim_alloc_ll_xid_resp(sne->snme->tlli, sne->llc_sapi, NULL, 256);
	OSMO_ASSERT(llc_prim_tx);
	msg = llc_prim_tx->oph.msg;
	llc_prim_tx->ll.l3_pdu = msg->tail;
	/* Compile modified SNDCP-XID bytes */
	rc = gprs_sndcp_compile_xid(msg->tail,
				    msgb_tailroom(msg),
				    sne->l3_xid_comp_fields_req_from_peer, 0);
	if (rc < 0) {
		msgb_free(msg);
		return -EINVAL;
	}
	msgb_put(msg, rc);
	llc_prim_tx->ll.l3_pdu_len = rc;

	/* Transmit LL-XID.rsp to lower layers (LLC): */
	rc = gprs_sndcp_prim_call_down_cb(llc_prim_tx);
	return rc;
}

/* Section 5.1.2.17 LL-UNITDATA.ind, see osmo-sgsn sndcp_llunitdata_ind() */
int gprs_sndcp_sne_handle_llc_ll_unitdata_ind(struct gprs_sndcp_entity *sne, struct sndcp_common_hdr *sch, uint16_t len)
{
	struct sndcp_comp_hdr *scomph = NULL;
	struct sndcp_udata_hdr *suh;
	uint8_t *npdu;
	uint16_t npdu_num __attribute__((unused));
	int npdu_len;
	int rc = 0;
	uint8_t *expnd = NULL;
	uint8_t *hdr = (uint8_t *)sch;
	struct osmo_gprs_sndcp_prim *sndcp_prim_tx;

	if (sch->first) {
		scomph = (struct sndcp_comp_hdr *) (hdr + 1);
		suh = (struct sndcp_udata_hdr *) (hdr + 1 + sizeof(struct sndcp_common_hdr));
	} else
		suh = (struct sndcp_udata_hdr *) (hdr + sizeof(struct sndcp_common_hdr));

	if (sch->type == 0) {
		LOGSNE(sne, LOGL_ERROR, "SN-DATA PDU at unitdata_ind() function\n");
		return -EINVAL;
	}

	if (len < sizeof(*sch) + sizeof(*suh)) {
		LOGSNE(sne, LOGL_ERROR, "SN-UNITDATA PDU too short (%u)\n", len);
		return -EIO;
	}

	if (scomph) {
		sne->defrag.pcomp = scomph->pcomp;
		sne->defrag.dcomp = scomph->dcomp;
		sne->defrag.proto = sne->snme->comp.proto;
		sne->defrag.data = sne->snme->comp.data;
	}

	/* any non-first segment is by definition something to defragment
	 * as is any segment that tells us there are more segments */
	if (!sch->first || sch->more)
		return defrag_input(sne, hdr, len);

	npdu_num = (suh->npdu_high << 8) | suh->npdu_low;
	npdu = (uint8_t *)suh + sizeof(*suh);
	npdu_len = (hdr + len) - npdu;

	if (npdu_len <= 0) {
		LOGSNE(sne, LOGL_ERROR, "Short SNDCP N-PDU: %d\n", npdu_len);
		return -EIO;
	}
	/* actually send the N-PDU to the SGSN core code, which then
	 * hands it off to the correct GTP tunnel + GGSN via gtp_data_req() */

	/* Decompress packet */
	if (any_pcomp_or_dcomp_active(g_sndcp_ctx)) {
		expnd = decompress_segment(sne, g_sndcp_ctx, npdu, npdu_len, (unsigned int *)&npdu_len);
		if (!expnd) {
			rc = -EIO;
			goto ret_free;
		}
	} else {
		expnd = npdu;
	}

	/* Trigger SN-UNITDATA.ind to upper layers: */
	sndcp_prim_tx = gprs_sndcp_prim_alloc_sn_unitdata_ind(sne->snme->tlli, sne->llc_sapi, sne->nsapi, expnd, npdu_len);
	rc = gprs_sndcp_prim_call_up_cb(sndcp_prim_tx);

ret_free:
	if (any_pcomp_or_dcomp_active(g_sndcp_ctx))
		talloc_free(expnd);
	return rc;
}

/* Handle header compression entities */
static int gprs_sndcp_snme_handle_pcomp_entities(struct gprs_sndcp_mgmt_entity *snme,
						 uint32_t sapi,
						 struct gprs_sndcp_comp_field *comp_field)
{
	/* Note: This functions also transforms the comp_field into its
	 * echo form (strips comp values, resets propose bit etc...)
	 * the processed comp_fields can then be sent back as XID-
	 * Response without further modification. */

	/* Delete propose bit */
	comp_field->p = 0;

	/* Process proposed parameters */
	switch (comp_field->algo.pcomp) {
	case RFC_1144:
		if (g_sndcp_ctx->cfg.pcomp_rfc1144_passive_accept
		    && comp_field->rfc1144_params->nsapi_len > 0) {
			LOGSNME(snme, LOGL_DEBUG, "Accepting RFC1144 header compression...\n");
			gprs_sndcp_comp_add(snme, snme->comp.proto, comp_field);
		} else {
			LOGSNME(snme, LOGL_DEBUG, "Rejecting RFC1144 header compression...\n");
			gprs_sndcp_comp_delete(snme->comp.proto, comp_field->entity);
			comp_field->rfc1144_params->nsapi_len = 0;
		}
		break;
	case RFC_2507:
		/* RFC 2507 is not yet supported,
		 * so we set applicable nsapis to zero */
		LOGSNME(snme, LOGL_DEBUG, "Rejecting RFC2507 header compression...\n");
		comp_field->rfc2507_params->nsapi_len = 0;
		gprs_sndcp_comp_delete(snme->comp.proto, comp_field->entity);
		break;
	case ROHC:
		/* ROHC is not yet supported,
		 * so we set applicable nsapis to zero */
		LOGSNME(snme, LOGL_DEBUG, "Rejecting ROHC header compression...\n");
		comp_field->rohc_params->nsapi_len = 0;
		gprs_sndcp_comp_delete(snme->comp.proto, comp_field->entity);
		break;
	}

	return 0;
}

/* Hanle data compression entities */
static int gprs_sndcp_snme_handle_dcomp_entities(struct gprs_sndcp_mgmt_entity *snme,
						 uint32_t sapi,
						 struct gprs_sndcp_comp_field *comp_field)
{
	/* See note in handle_pcomp_entities() */

	/* Delete propose bit */
	comp_field->p = 0;

	/* Process proposed parameters */
	switch (comp_field->algo.dcomp) {
	case V42BIS:
		if (g_sndcp_ctx->cfg.dcomp_v42bis_passive_accept &&
		    comp_field->v42bis_params->nsapi_len > 0) {
			LOGSNME(snme, LOGL_DEBUG, "Accepting V.42bis data compression...\n");
			gprs_sndcp_comp_add(snme, snme->comp.data, comp_field);
		} else {
			LOGSNME(snme, LOGL_DEBUG, "Rejecting V.42bis data compression...\n");
			gprs_sndcp_comp_delete(snme->comp.data, comp_field->entity);
			comp_field->v42bis_params->nsapi_len = 0;
		}
		break;
	case V44:
		/* V44 is not yet supported,
		 * so we set applicable nsapis to zero */
		LOGSNME(snme, LOGL_DEBUG, "Rejecting V.44 data compression...\n");
		comp_field->v44_params->nsapi_len = 0;
		gprs_sndcp_comp_delete(snme->comp.data, comp_field->entity);
		break;
	}

	return 0;

}

/* 5.1.2.10 SN-XID.indication */
int gprs_sndcp_snme_handle_llc_ll_xid_ind(struct gprs_sndcp_mgmt_entity *snme, uint32_t sapi, uint8_t *l3params, unsigned int l3params_len)
{
	int rc;
	int compclass;
	int version;
	struct llist_head *comp_fields;
	struct gprs_sndcp_comp_field *comp_field;
	struct gprs_sndcp_entity *sne = NULL;
	struct osmo_gprs_sndcp_prim *sndcp_prim_tx;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(snme->sne); i++) {
		struct gprs_sndcp_entity *sne_i = snme->sne[i];
		if (!sne_i)
			continue;
		if (sne_i->llc_sapi != sapi)
			continue;
		LOGSNE(sne_i, LOGL_DEBUG, "LL-XID.ind: Found SNE SAPI=%u\n", sapi);
		sne = sne_i;
		break;
	}
	if (!sne) {
		LOGSNME(snme, LOGL_ERROR, "LL-XID.ind: No SNDCP entity found having sent a LL-XID.ind (SAPI=%u)\n", sapi);
		return -EINVAL;
	}

	/* Some phones send zero byte length SNDCP frames
	 * and do require a confirmation response. */
	if (l3params_len == 0) {
		/* TODO: send empty (len=0) SN-XID.response? */
		return 0;
	}


	/* Parse SNDCP-CID XID-Field */
	comp_fields = gprs_sndcp_parse_xid(&version, sne,
					   l3params,
					   l3params_len,
					   NULL);
	if (!comp_fields) {
		LOGSNME(snme, LOGL_NOTICE, "LL-XID.ind: parse failed\n");
		return -EINVAL;
	}

	/* Handle compression entities */
	LOGSNME(snme, LOGL_DEBUG, "LL-XID.cnf requested comp_fields:\n");
	gprs_sndcp_dump_comp_fields(comp_fields, LOGL_DEBUG);

	llist_for_each_entry(comp_field, comp_fields, list) {
		compclass = gprs_sndcp_get_compression_class(comp_field);
		if (compclass == SNDCP_XID_PROTOCOL_COMPRESSION)
			rc = gprs_sndcp_snme_handle_pcomp_entities(snme, sapi, comp_field);
		else if (compclass == SNDCP_XID_DATA_COMPRESSION)
			rc = gprs_sndcp_snme_handle_dcomp_entities(snme, sapi, comp_field);
		else {
			gprs_sndcp_comp_delete(snme->comp.proto, comp_field->entity);
			gprs_sndcp_comp_delete(snme->comp.data, comp_field->entity);
			rc = 0;
		}

		if (rc < 0) {
			talloc_free(comp_fields);
			return -EINVAL;
		}
	}

	TALLOC_FREE(sne->l3_xid_comp_fields_req_from_peer);
	sne->l3_xid_comp_fields_req_from_peer = comp_fields;

	/* Trigger SN-XID.ind to upper layers: */
	sndcp_prim_tx = gprs_sndcp_prim_alloc_sn_xid_ind(sne->snme->tlli, sne->llc_sapi, sne->nsapi);
	rc = gprs_sndcp_prim_call_up_cb(sndcp_prim_tx);
	return rc;
}

/* 5.1.2.12 SN-XID.confirm
 * (See also: TS 144 065, Section 6.8 XID parameter negotiation)
 */
int gprs_sndcp_snme_handle_llc_ll_xid_cnf(struct gprs_sndcp_mgmt_entity *snme, uint32_t sapi, uint8_t *l3params, unsigned int l3params_len)
{
	/* Note: This function handles an incoming SNDCP-XID confirmation.
	 * Since the confirmation fields may lack important parameters we
	 * will reconstruct these missing fields using the original request
	 * we have sent. After that we will create (or delete) the
	 * compression entities */

	struct llist_head *comp_fields_req;
	struct llist_head *comp_fields_conf;
	struct gprs_sndcp_comp_field *comp_field;
	int rc = 0;
	int compclass;
	unsigned int i;
	struct gprs_sndcp_entity *sne = NULL;

	/* We need both, the confirmation that is sent back by the ms,
	 * and the original request we have sent. If one of this is missing
	 * we can not process the confirmation, the caller must check if
	 * request and confirmation fields are available. */
	for (i = 0; i < ARRAY_SIZE(snme->sne); i++) {
		struct gprs_sndcp_entity *sne_i = snme->sne[i];
		if (!sne_i)
			continue;
		if (sne_i->llc_sapi != sapi)
			continue;
		LOGSNE(sne_i, LOGL_DEBUG, "LL-XID.cnf: Found SNE SAPI=%u\n", sapi);
		if (!sne_i->l3xid_req || sne_i->l3xid_req_len == 0)
			continue;
		sne = sne_i;
		break;
	}
	if (!sne) {
		LOGSNME(snme, LOGL_ERROR, "LL-XID.cnf: No SNDCP entity found having sent a LL-XID.req (SAPI=%u)\n", sapi);
		return -EINVAL;
	}

	/* Parse SNDCP-CID XID-Field */
	comp_fields_req = gprs_sndcp_parse_xid(NULL, sne, sne->l3xid_req, sne->l3xid_req_len, NULL);
	if (!comp_fields_req)
		return -EINVAL;

	/* Parse SNDCP-CID XID-Field */
	comp_fields_conf = gprs_sndcp_parse_xid(NULL, sne, l3params, l3params_len, comp_fields_req);
	if (!comp_fields_conf) {
		talloc_free(comp_fields_req);
		return -EINVAL;
	}

	LOGSNDCP(LOGL_DEBUG, "LL-XID.cnf response comp_fields:\n");
	gprs_sndcp_dump_comp_fields(comp_fields_conf, LOGL_DEBUG);

	/* Handle compression entities */
	llist_for_each_entry(comp_field, comp_fields_conf, list) {
		compclass = gprs_sndcp_get_compression_class(comp_field);
		if (compclass == SNDCP_XID_PROTOCOL_COMPRESSION)
			rc = gprs_sndcp_snme_handle_pcomp_entities(snme, sapi, comp_field);
		else if (compclass == SNDCP_XID_DATA_COMPRESSION)
			rc = gprs_sndcp_snme_handle_dcomp_entities(snme, sapi, comp_field);
		else {
			gprs_sndcp_comp_delete(snme->comp.proto, comp_field->entity);
			gprs_sndcp_comp_delete(snme->comp.data, comp_field->entity);
			rc = 0;
		}
		if (rc < 0)
			break;
	}

	talloc_free(comp_fields_req);
	talloc_free(comp_fields_conf);
	return rc;
}
