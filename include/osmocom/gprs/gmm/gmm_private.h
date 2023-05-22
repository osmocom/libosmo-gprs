#pragma once

/* 3GPP TS 24.008, private header */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/endian.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/gmm/gmm.h>
#include <osmocom/gprs/gmm/gmm_prim.h>
#include <osmocom/gprs/gmm/gmm_ms_fsm.h>

/* 3GPP TS 44.064 § 8.3 TLLI assignment procedures */
#define GPRS_GMM_TLLI_UNASSIGNED (0xffffffff)

#define GPRS_GMM_SESS_ID_UNASSIGNED (0xffffffff)

extern int g_gmm_log_cat[_OSMO_GPRS_GMM_LOGC_MAX];

#define LOGGMM(lvl, fmt, args...) LOGP(g_gmm_log_cat[OSMO_GPRS_GMM_LOGC_GMM], lvl, fmt, ## args)

#define msgb_gmm_prim(msg) ((struct osmo_gprs_gmm_prim *)(msg)->l1h)

struct gprs_gmm_ctx {
	enum osmo_gprs_gmm_location location;
	osmo_gprs_gmm_prim_up_cb gmm_up_cb;
	void *gmm_up_cb_user_data;

	osmo_gprs_gmm_prim_down_cb gmm_down_cb;
	void *gmm_down_cb_user_data;

	osmo_gprs_gmm_prim_llc_down_cb gmm_llc_down_cb;
	void *gmm_llc_down_cb_user_data;

	/* GPRS enabled in the system: 3GPP TS 24.008 Figure 4.1b,
	 * transition GMM-NULL<->GMM-DEREGISTERED */
	bool gprs_enabled;

	struct osmo_tdef *T_defs; /* timers controlled by GMM layer */

	struct llist_head gmme_list; /* list of struct gprs_gmm_entity->list */
};

extern struct gprs_gmm_ctx *g_gmm_ctx;

/* GMM Entity: */
struct gprs_gmm_entity {
	struct llist_head list; /* item in (struct gprs_gmm_ctx)->gmme_list */

	struct gprs_gmm_ms_fsm_ctx ms_fsm;
	uint32_t sess_id; /* Used to identify the GMME in GMMSM SAP */
	uint32_t ptmsi_sig; /* 3 bytes */
	uint32_t ptmsi;
	uint32_t old_ptmsi;
	uint32_t tlli;
	uint32_t old_tlli;
	char imsi[OSMO_IMSI_BUF_SIZE];
	char imei[GSM23003_IMEI_NUM_DIGITS + 1];
	char imeisv[GSM23003_IMEISV_NUM_DIGITS+1];

	uint8_t ra_upd_timer;	/* TS 24.008 10.5.7.3 */
	uint8_t radio_prio;	/* TS 24.008 10.5.7.2 */
	struct gprs_ra_id ra; /* TS 24.008  10.5.5.15 (decoded) */

	struct {
		/* Input params received from network: */
		struct {
			uint8_t ac_ref_nr;
			uint8_t key_seq;
			uint8_t rand[16]; /* max 16 * 8 = 128 bits */
			bool imeisv_requested;
		} req;
		uint8_t gea; /* GEA/0 = 0, GEA/1 = 1, ... */
		uint8_t kc[16]; /* max 16 * 8 = 128 bits */
	} auth_ciph;

	unsigned long t3302;
	unsigned long t3346;
};

/* gmm_prim.c: */
int gprs_gmm_prim_call_up_cb(struct osmo_gprs_gmm_prim *gmm_prim);
int gprs_gmm_prim_call_down_cb(struct osmo_gprs_gmm_prim *gmm_prim);
int gprs_gmm_prim_call_llc_down_cb(struct osmo_gprs_llc_prim *llc_prim);

struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmreg_attach_cnf(void);
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmreg_detach_cnf(void);
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmreg_sim_auth_ind(void);

struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmrr_assign_req(uint32_t old_tlli, uint32_t new_tlli);

struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmsm_establish_cnf(uint32_t id, uint8_t cause);
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmrr_release_ind(uint32_t id);
struct osmo_gprs_gmm_prim *gprs_gmm_prim_alloc_gmmsm_unitdata_ind(uint32_t id, uint8_t *smpdu, unsigned int smpdu_len);

/* gmm.c: */
struct gprs_gmm_entity *gprs_gmm_gmme_alloc(uint32_t ptmsi, const char *imsi);
void gprs_gmm_gmme_free(struct gprs_gmm_entity *gmme);
struct gprs_gmm_entity *gprs_gmm_gmme_find_or_create_by_ptmsi_imsi(uint32_t ptmsi, const char *imsi);
struct gprs_gmm_entity *gprs_gmm_find_gmme_by_ptmsi(uint32_t ptmsi);
struct gprs_gmm_entity *gprs_gmm_find_gmme_by_imsi(const char *imsi);
struct gprs_gmm_entity *gprs_gmm_find_gmme_by_tlli(uint32_t tlli);
struct gprs_gmm_entity *gprs_gmm_find_gmme_by_sess_id(uint32_t id);
uint32_t gprs_gmm_alloc_rand_tlli(void);
int gprs_gmm_rx(struct gprs_gmm_entity *gmme, struct gsm48_hdr *gh, unsigned int len);
int gprs_gmm_tx_att_req(struct gprs_gmm_entity *gmme,
			enum osmo_gprs_gmm_attach_type attach_type,
			bool attach_with_imsi);
int gprs_gmm_tx_detach_req(struct gprs_gmm_entity *gmme,
			   enum osmo_gprs_gmm_detach_ms_type detach_type,
			   enum osmo_gprs_gmm_detach_poweroff_type poweroff_type);
int gprs_gmm_tx_ciph_auth_resp(const struct gprs_gmm_entity *gmme, const uint8_t *sres);

int gprs_gmm_submit_gmmreg_attach_cnf(struct gprs_gmm_entity *gmme, bool accepted, uint8_t cause);
int gprs_gmm_submit_gmmsm_establish_cnf(struct gprs_gmm_entity *gmme, bool accepted, uint8_t cause);
int gprs_gmm_submit_llgmm_assing_req(const struct gprs_gmm_entity *gmme);

/* misc.c */
int gprs_gmm_gprs_tmr_to_secs(uint8_t gprs_tmr);
uint8_t gprs_gmm_secs_to_gprs_tmr_floor(int secs);

#define LOGGMME(gmme, level, fmt, args...) \
	LOGGMM(level, "GMME(IMSI-%s:PTMSI-%08x:TLLI-%08x) " fmt, \
		 gmme->imsi, \
		 gmme->ptmsi, \
		 gmme->tlli, \
		 ## args)
