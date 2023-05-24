#pragma once

/* RLCMAC private header */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/gsm48_rest_octets.h>

#include <osmocom/gprs/rlcmac/rlcmac_prim.h>
#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/coding_scheme.h>
#include <osmocom/gprs/rlcmac/csn1_defs.h>

/* 3GPP TS 44.064 § 8.3 TLLI assignment procedures */
#define GPRS_RLCMAC_TLLI_UNASSIGNED (0xffffffff)

#define GPRS_RLCMAC_USF_UNUSED 0x07

#define GPRS_RLCMAC_LLC_PDU_MAX_LEN 1543

struct gprs_rlcmac_ul_tbf_allocation_ts {
	bool allocated;
	uint8_t usf;
};

struct gprs_rlcmac_ul_tbf_allocation {
	uint8_t ul_tfi;
	uint8_t num_ts; /* number of allocated TS */
	struct gprs_rlcmac_ul_tbf_allocation_ts ts[8];
};

struct gprs_rlcmac_dl_tbf_allocation_ts {
	bool allocated;
};

struct gprs_rlcmac_dl_tbf_allocation {
	uint8_t dl_tfi;
	uint8_t num_ts; /* number of allocated TS */
	struct gprs_rlcmac_dl_tbf_allocation_ts ts[8];
};

extern int g_rlcmac_log_cat[_OSMO_GPRS_RLCMAC_LOGC_MAX];

#define LOGRLCMAC(lvl, fmt, args...) LOGP(g_rlcmac_log_cat[OSMO_GPRS_RLCMAC_LOGC_RLCMAC], lvl, fmt, ## args)
#define LOGRLCMACC(lvl, fmt, args...) LOGPC(g_rlcmac_log_cat[OSMO_GPRS_RLCMAC_LOGC_RLCMAC], lvl, fmt, ## args)

#define msgb_rlcmac_prim(msg) ((struct osmo_gprs_rlcmac_prim *)(msg)->l1h)

struct gprs_rlcmac_ctx {
	struct {
		enum osmo_gprs_rlcmac_location location;
		struct {
			bool use;
			uint32_t interval_msec;
		} codel;
		enum gprs_rlcmac_egprs_arq_type egprs_arq_type;
		bool ul_tbf_preemptive_retransmission;
	} cfg;
	osmo_gprs_rlcmac_prim_up_cb rlcmac_up_cb;
	void *rlcmac_up_cb_user_data;

	osmo_gprs_rlcmac_prim_down_cb rlcmac_down_cb;
	void *rlcmac_down_cb_user_data;

	struct osmo_tdef *T_defs; /* timers controlled by RLC/MAC layer */

	struct llist_head gre_list; /* contains (struct gprs_rlcmac_entity)->entry */

	uint8_t next_ul_tbf_nr;
	uint8_t next_dl_tbf_nr;

	struct {
		struct gprs_rlcmac_pdch_ulc *ulc[8];
	} sched;

	/* Last SI13 received from BCCH: */
	bool si13_available;
	uint8_t si13[GSM_MACBLOCK_LEN];
	SI13_RestOctets_t si13ro;
};

extern struct gprs_rlcmac_ctx *g_rlcmac_ctx;

/* rlcmac.c */
struct gprs_rlcmac_entity *gprs_rlcmac_find_entity_by_tlli(uint32_t tlli);
struct gprs_rlcmac_entity *gprs_rlcmac_find_entity_by_ptmsi(uint32_t ptmsi);
struct gprs_rlcmac_entity *gprs_rlcmac_find_entity_by_imsi(const char *imsi);
struct gprs_rlcmac_dl_tbf *gprs_rlcmac_find_dl_tbf_by_tfi(uint8_t dl_tfi);
struct gprs_rlcmac_ul_tbf *gprs_rlcmac_find_ul_tbf_by_tfi(uint8_t ul_tfi);
int gprs_rlcmac_handle_ccch_imm_ass(const struct gsm48_imm_ass *ia, uint32_t fn);
int gprs_rlcmac_handle_ccch_pag_req1(const struct gsm48_paging1 *pag);
int gprs_rlcmac_handle_ccch_pag_req2(const struct gsm48_paging2 *pag);
int gprs_rlcmac_handle_bcch_si13(const struct gsm48_system_information_type_13 *si13);
int gprs_rlcmac_handle_gprs_dl_block(const struct osmo_gprs_rlcmac_prim *rlcmac_prim,
				     enum gprs_rlcmac_coding_scheme cs);

/* rlcmac_prim.c */
int gprs_rlcmac_prim_call_up_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim);
int gprs_rlcmac_prim_call_down_cb(struct osmo_gprs_rlcmac_prim *rlcmac_prim);

struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_grr_unitdata_ind(
				uint32_t tlli, uint8_t *ll_pdu, size_t ll_pdu_len);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_gmmrr_page_ind(uint32_t tlli);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_gmmrr_llc_transmitted_ind(uint32_t tlli);

struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_rach8_req(uint8_t ra);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_rach11_req(uint16_t ra11, uint8_t synch_seq);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_pdch_data_req(uint8_t ts_nr, uint32_t fn,
									uint8_t *data, uint8_t data_len);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_cfg_dl_tbf_req(uint8_t dl_tbf_nr, uint8_t dl_slotmask, uint8_t dl_tfi);
struct osmo_gprs_rlcmac_prim *gprs_rlcmac_prim_alloc_l1ctl_cfg_ul_tbf_req(uint8_t ul_tbf_nr, uint8_t ul_slotmask);
