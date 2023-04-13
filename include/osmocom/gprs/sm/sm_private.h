#pragma once

/* 3GPP TS 24.007, private header */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/endian.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/gprs/gmm/gmm_prim.h>
#include <osmocom/gprs/sm/sm.h>
#include <osmocom/gprs/sm/sm_prim.h>
#include <osmocom/gprs/sm/sm_ms_fsm.h>

extern int g_sm_log_cat[_OSMO_GPRS_SM_LOGC_MAX];

#define LOGSM(lvl, fmt, args...) LOGP(g_sm_log_cat[OSMO_GPRS_SM_LOGC_SM], lvl, fmt, ## args)

#define msgb_sm_prim(msg) ((struct osmo_gprs_sm_prim *)(msg)->l1h)

/* 10.5.6.4 Packet data protocol address */
enum gprs_sm_pdp_addr_org {
	GPRS_SM_PDP_ADDR_ORG_ETSI = 0x00,
	GPRS_SM_PDP_ADDR_ORG_IETF = 0x01,
	GPRS_SM_PDP_ADDR_ORG_EMPTY = 0x0f,
	/* All other values are reserved. */
};

/* 10.5.6.4 Packet data protocol address */
enum gprs_sm_pdp_addr_etsi_type {
	GPRS_SM_PDP_ADDR_ETSI_RESERVED = 00, /* used in earlier version of this protocol */
	GPRS_SM_PDP_ADDR_ETSI_PPP = 0x01,
	GPRS_SM_PDP_ADDR_ETSI_NON_IP = 0x02,
	/* All other values are reserved in this version of the protocol. */
};

struct gprs_sm_pdp_addr {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t spare:4,
		organization:4; /* enum gprs_sm_pdp_addr_org */
	uint8_t type; /* osmo_gprs_sm_pdp_addr_{etsi,ietf}_type */
	union {
		/* IPv4 */
		uint32_t addr;

		/* IPv6 */
		uint8_t addr6[16];

		/* IPv4v6 */
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t organization:4, spare:4;
	uint8_t type;
	union {
		uint32_t addr;
		uint8_t addr6[16];
#endif
		struct {
			uint32_t addr;
			uint8_t addr6[16];
		} __attribute__ ((packed)) both;
	};
} __attribute__ ((packed));

struct gprs_sm_ms;

struct gprs_sm_ctx {
	enum osmo_gprs_sm_location location;
	osmo_gprs_sm_prim_up_cb sm_up_cb;
	void *sm_up_cb_user_data;

	osmo_gprs_sm_prim_down_cb sm_down_cb;
	void *sm_down_cb_user_data;

	osmo_gprs_sm_prim_gmm_down_cb sm_gmm_down_cb;
	void *sm_gmm_down_cb_user_data;

	struct osmo_tdef *T_defs; /* timers controlled by SM layer */

	struct llist_head ms_list; /* list of struct gprs_sm_ms->list */

	uint32_t next_sess_id;
};

extern struct gprs_sm_ctx *g_sm_ctx;

/* SM Entity, PDP CTX */
struct gprs_sm_entity {
	struct gprs_sm_ms *ms; /* backpointer */

	uint32_t sess_id;

	uint8_t nsapi;
	enum osmo_gprs_sm_llc_sapi llc_sapi;

	enum osmo_gprs_sm_pdp_addr_ietf_type pdp_addr_ietf_type;
	struct osmo_sockaddr pdp_addr_v4;
	struct osmo_sockaddr pdp_addr_v6;

	uint8_t qos[OSMO_GPRS_SM_QOS_MAXLEN];
	uint8_t qos_len;

	char apn[OSMO_GPRS_SM_APN_MAXLEN];

	uint8_t pco[OSMO_GPRS_SM_MBIFORM_MAXLEN];
	uint8_t pco_len;

	uint8_t ti; /* transaction identifier */

	struct gprs_sm_ms_fsm_ctx ms_fsm;
};

/* Mobile Station: */
struct gprs_sm_ms {
	struct llist_head list; /* item in (struct gprs_sm_ctx)->ms_list */

	uint32_t ms_id;

	struct gprs_sm_entity *pdp[OSMO_GPRS_SM_PDP_MAXNSAPI];

	struct {
		uint32_t ptmsi;
		char imsi[OSMO_IMSI_BUF_SIZE];
		char imei[GSM23003_IMEI_NUM_DIGITS + 1];
		char imeisv[GSM23003_IMEISV_NUM_DIGITS+1];
	} gmm;
};

/* 10.5.6.2 Network service access point identifier */
static inline bool gprs_sm_nsapi_is_valid(uint8_t nsapi)
{
	return nsapi >= 5 && nsapi <= 15;
}

static inline struct gprs_sm_entity *gprs_sm_ms_get_pdp_ctx(struct gprs_sm_ms *ms,
							      uint8_t nsapi) {
	OSMO_ASSERT(gprs_sm_nsapi_is_valid(nsapi));
	return ms->pdp[nsapi];
}

/* sm_prim.c: */
int gprs_sm_prim_call_up_cb(struct osmo_gprs_sm_prim *sm_prim);
int gprs_sm_prim_call_down_cb(struct osmo_gprs_sm_prim *sm_prim);
int gprs_sm_prim_call_gmm_down_cb(struct osmo_gprs_gmm_prim *gmm_prim);

struct osmo_gprs_sm_prim *gprs_sm_prim_alloc_smreg_pdp_act_cnf(void);
struct osmo_gprs_sm_prim *gprs_sm_prim_alloc_smreg_pdp_act_ind(void);

/* sm.c: */
struct gprs_sm_ms *gprs_sm_ms_alloc(uint32_t ms_id);
void gprs_sm_ms_free(struct gprs_sm_ms *ms);
struct gprs_sm_ms *gprs_sm_find_ms_by_id(uint32_t ms_id);

struct gprs_sm_entity *gprs_sm_entity_alloc(struct gprs_sm_ms *ms, uint32_t nsapi);
void gprs_sm_entity_free(struct gprs_sm_entity *sme);
struct gprs_sm_entity *gprs_sm_find_sme_by_sess_id(uint32_t sess_id);

int gprs_sm_submit_gmmsm_assign_req(const struct gprs_sm_entity *sme);
int gprs_sm_submit_smreg_pdp_act_cnf(const struct gprs_sm_entity *sme, enum gsm48_gsm_cause cause);
int gprs_sm_tx_act_pdp_ctx_req(struct gprs_sm_entity *sme);
int gprs_sm_rx(struct gprs_sm_entity *sme, struct gsm48_hdr *gh, unsigned int len);


#define LOGMS(ms, level, fmt, args...) \
	LOGSM(level, "MS(ID-%u) " fmt, \
	      ms->ms_id, \
	      ## args)

#define LOGSME(sme, level, fmt, args...) \
	LOGSM(level, "PDP(ID-%u:NSAPI-%u) " fmt, \
	      sme->ms->ms_id, \
	      sme->nsapi, \
	      ## args)
