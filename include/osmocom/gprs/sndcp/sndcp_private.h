#pragma once

/* 3GPP TS 44.065, private header */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/endian.h>

#include <osmocom/gprs/llc/llc.h>
#include <osmocom/gprs/sndcp/sndcp.h>
#include <osmocom/gprs/sndcp/sndcp_prim.h>
#include <osmocom/gprs/sndcp/comp.h>
#include <osmocom/gprs/sndcp/pcomp.h>
#include <osmocom/gprs/sndcp/dcomp.h>

extern int g_sndcp_log_cat[_OSMO_GPRS_SNDCP_LOGC_MAX];

#define LOGSNDCP(lvl, fmt, args...) LOGP(g_sndcp_log_cat[OSMO_GPRS_SNDCP_LOGC_SNDCP], lvl, fmt, ## args)

#define msgb_sndcp_prim(msg) ((struct osmo_gprs_sndcp_prim *)(msg)->l1h)

/* Chapter 7.2: SN-PDU Formats */
struct sndcp_common_hdr {
#if OSMO_IS_LITTLE_ENDIAN
	/* octet 1 */
	uint8_t nsapi:4;
	uint8_t more:1;
	uint8_t type:1;
	uint8_t first:1;
	uint8_t spare:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t spare:1, first:1, type:1, more:1, nsapi:4;
#endif
} __attribute__((packed));

/* PCOMP / DCOMP only exist in first fragment */
struct sndcp_comp_hdr {
#if OSMO_IS_LITTLE_ENDIAN
	/* octet 2 */
	uint8_t pcomp:4;
	uint8_t dcomp:4;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t dcomp:4, pcomp:4;
#endif
} __attribute__((packed));

struct sndcp_udata_hdr {
#if OSMO_IS_LITTLE_ENDIAN
	/* octet 3 */
	uint8_t npdu_high:4;
	uint8_t seg_nr:4;
	/* octet 4 */
	uint8_t npdu_low;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t seg_nr:4, npdu_high:4;
	uint8_t npdu_low;
#endif
} __attribute__((packed));

/* A fragment queue entry, containing one framgent of a N-PDU */
struct defrag_queue_entry {
	struct llist_head list;
	/* segment number of this fragment */
	uint32_t seg_nr;
	/* length of the data area of this fragment */
	uint32_t data_len;
	/* pointer to the data of this fragment */
	uint8_t *data;
};

/* TODO: this needs to be set through API or VTY: */
struct gprs_sndcp_ctx_cfg {
	bool pcomp_rfc1144_passive_accept;
	bool dcomp_v42bis_passive_accept;
};

struct gprs_sndcp_ctx {
	osmo_gprs_sndcp_prim_up_cb sndcp_up_cb;
	void *sndcp_up_cb_user_data;

	osmo_gprs_sndcp_prim_down_cb sndcp_down_cb;
	void *sndcp_down_cb_user_data;

	osmo_gprs_sndcp_prim_snsm_cb sndcp_snsm_cb;
	void *sndcp_snsm_cb_user_data;

	struct llist_head snme_list; /* list of struct gprs_sndcp_mgmt_entity->list */

	struct gprs_sndcp_ctx_cfg cfg;
};

extern struct gprs_sndcp_ctx *g_ctx;


/* A fragment queue header, maintaining list of fragments for one N-PDU */
struct gprs_sndcp_defrag_state {
	/* PDU number for which the defragmentation state applies */
	uint16_t npdu;
	/* highest segment number we have received so far */
	uint8_t highest_seg;
	/* bitmask of the segments we already have */
	uint32_t seg_have;
	/* do we still expect more segments? */
	unsigned int no_more;
	/* total length of all segments together */
	unsigned int tot_len;

	/* linked list of defrag_queue_entry: one for each fragment  */
	struct llist_head frag_list;

	struct osmo_timer_list timer;

	/* Holds state to know which compression mode is used
	 * when the packet is re-assembled */
	uint8_t pcomp;
	uint8_t dcomp;

	/* Holds the pointers to the compression entity list
	 * that is used when the re-assembled packet is decompressed */
	struct llist_head *proto;
	struct llist_head *data;
};

/* See 6.7.1.2 Reassembly */
enum gprs_sndcp_rx_state {
	GPRS_SNDCP_RX_S_FIRST,
	GPRS_SNDCP_RX_S_SUBSEQ,
	GPRS_SNDCP_RX_S_DISCARD,
};

#define GPRS_SNDCP_NUM_NSAPIS	16

/* SNDCP entity: One per TLLI + NSAPI */
struct gprs_sndcp_mgmt_entity;
struct gprs_sndcp_entity {
	struct gprs_sndcp_mgmt_entity *snme; /* backpointer */

	/* FIXME: move this RA_ID up to the LLME or even higher */
	//struct gprs_ra_id ra_id;
	/* reference to the LLC Entity below this SNDCP entity */
	uint8_t llc_sapi;
	/* The NSAPI we shall use on top of LLC */
	uint8_t nsapi;

	/* NPDU number for the GTP->SNDCP side */
	uint16_t tx_npdu_nr;
	/* SNDCP eeceiver state */
	enum gprs_sndcp_rx_state rx_state;
	/* The defragmentation queue */
	struct gprs_sndcp_defrag_state defrag;

	/* Copy of the XID fields array we have sent with the last
	 * originated XID-Request. NULL if not existing (and l3xid_req_len = 0) */
	uint8_t *l3xid_req;
	unsigned int l3xid_req_len;

	/* Copy of the requested XID fields array we have received with the last
	 * originated XID-Request from peer. NULL if not existing (and l3xid_req_len = 0) */
	struct llist_head *l3_xid_comp_fields_req_from_peer;

	/* TODO: taken from lle.params and not yet set ever in code! */
	uint16_t n201_u;
	uint16_t n201_i;
};

/* SNDCP management entity: One per TLLI */
struct gprs_sndcp_mgmt_entity {
	struct llist_head list; /* item in (struct gprs_sndcp_ctx)->snme_list */
	uint32_t tlli;
	struct gprs_sndcp_entity *sne[GPRS_SNDCP_NUM_NSAPIS];

	/* Compression entities */
	struct {
		/* In these two list_heads we will store the
		 * data and protocol compression entities,
		 * together with their compression states */
		struct llist_head *proto;
		struct llist_head *data;
	} comp;
};

static inline struct gprs_sndcp_entity *gprs_sndcp_snme_get_sne(struct gprs_sndcp_mgmt_entity *snme,
							 uint8_t nsapi) {
	OSMO_ASSERT(nsapi < GPRS_SNDCP_NUM_NSAPIS);
	return snme->sne[nsapi];
}

/* sndcp_prim.c: */
struct osmo_gprs_sndcp_prim *gprs_sndcp_prim_alloc_sn_unitdata_ind(uint32_t tlli, uint8_t sapi, uint8_t nsapi, uint8_t *npdu, size_t npdu_len);
struct osmo_gprs_sndcp_prim *gprs_sndcp_prim_alloc_sn_xid_ind(uint32_t tlli, uint8_t sapi, uint8_t nsapi);
struct osmo_gprs_sndcp_prim *gprs_sndcp_prim_alloc_snsm_activate_rsp(uint32_t tlli, uint8_t nsapi);
int gprs_sndcp_prim_call_up_cb(struct osmo_gprs_sndcp_prim *sndcp_prim);
int gprs_sndcp_prim_call_down_cb(struct osmo_gprs_llc_prim *llc_prim);

/* sndcp.c: */
struct gprs_sndcp_mgmt_entity *gprs_sndcp_snme_alloc(uint32_t tlli);
struct gprs_sndcp_mgmt_entity *gprs_sndcp_snme_find_by_tlli(uint32_t tlli);
struct gprs_sndcp_entity *gprs_sndcp_sne_alloc(struct gprs_sndcp_mgmt_entity *snme, uint8_t llc_sapi, uint8_t nsapi);
void gprs_sndcp_sne_free(struct gprs_sndcp_entity *sne);
struct gprs_sndcp_entity *gprs_sndcp_sne_by_dlci_nsapi(uint32_t tlli, uint8_t llc_sapi, uint8_t nsapi);
int gprs_sndcp_sne_handle_llc_ll_unitdata_ind(struct gprs_sndcp_entity *sne,
					  struct sndcp_common_hdr *sch, uint16_t len);
int gprs_sndcp_snme_handle_llc_ll_xid_ind(struct gprs_sndcp_mgmt_entity *snme, uint32_t sapi, uint8_t *l3params, unsigned int l3params_len);
int gprs_sndcp_snme_handle_llc_ll_xid_cnf(struct gprs_sndcp_mgmt_entity *snme, uint32_t sapi, uint8_t *l3params, unsigned int l3params_len);
int gprs_sndcp_sne_handle_sn_unitdata_req(struct gprs_sndcp_entity *sne, uint8_t *npdu, unsigned int npdu_len);
int gprs_sndcp_sne_handle_sn_xid_req(struct gprs_sndcp_entity *sne, const struct osmo_gprs_sndcp_prim *sndcp_prim);
int gprs_sndcp_sne_handle_sn_xid_rsp(struct gprs_sndcp_entity *sne, const struct osmo_gprs_sndcp_prim *sndcp_prim);

#define LOGSNME(snme, level, fmt, args...) \
	LOGSNDCP(level, "SNME(%08x) " fmt, \
		 (snme)->tlli, \
		 ## args)

#define LOGSNE(sne, level, fmt, args...) \
	LOGSNDCP(level, "SNE(%08x,%s,%u) " fmt, \
		 (sne)->snme->tlli, \
		 osmo_gprs_llc_sapi_name((sne)->llc_sapi), \
		 (sne)->nsapi, \
		 ## args)
