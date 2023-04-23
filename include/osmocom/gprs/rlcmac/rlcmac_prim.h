#pragma once

/* GPRS Radio Resource SAP as per:
 * 3GPP TS 44.060 4.3
 * 3GPP TS 24.007 9.3
 * 3GPP TS 44.064 7.2.3
 */

#include <osmocom/core/prim.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gprs/rlcmac/rlcmac.h>

/* TS 24.007 Section 9.3 */
enum osmo_gprs_rlcmac_prim_sap {
	OSMO_GPRS_RLCMAC_SAP_GRR,
	OSMO_GPRS_RLCMAC_SAP_GMMRR,
	OSMO_GPRS_RLCMAC_SAP_L1CTL,
};

extern const struct value_string osmo_gprs_rlcmac_prim_sap_names[];
static inline const char *osmo_gprs_rlcmac_prim_sap_name(enum osmo_gprs_rlcmac_prim_sap val)
{
	return get_value_string(osmo_gprs_rlcmac_prim_sap_names, val);
}

/* TS 24.007 Section 9.3.1 "Service primitives for GRR-SAP (GSM only)"
 * TS 04.64 Section 7.2.3 "LLE - RLC/MAC primitives" (MS side) */
enum osmo_gprs_rlcmac_grr_prim_type {
	OSMO_GPRS_RLCMAC_GRR_DATA,	/* Req/Ind: TLLI, LL-PDU, SAPI, Cause, QoS, Radio Prio */
	OSMO_GPRS_RLCMAC_GRR_UNITDATA,	/* Req/Ind: TLLI, LL-PDU, SAPI, QoS, Radio Prio */
};

extern const struct value_string osmo_gprs_rlcmac_grr_prim_type_names[];
static inline const char *osmo_gprs_rlcmac_grr_prim_type_name(enum osmo_gprs_rlcmac_grr_prim_type val)
{
	return get_value_string(osmo_gprs_rlcmac_grr_prim_type_names, val);
}

/* Parameters for OSMO_GPRS_RLCMAC_GRR_* prims */
struct osmo_gprs_rlcmac_grr_prim {
	/* Common fields */
	uint32_t tlli;
	uint8_t *ll_pdu;
	size_t ll_pdu_len;
	/* Specific fields */
	union {
		/* OSMO_GPRS_RLCMAC_GRR_DATA | Req */
		struct {
			uint8_t sapi;
			uint8_t radio_prio;
			uint8_t qos_params[3];
		} data_req;
		/* OSMO_GPRS_RLCMAC_GRR_UNITDATA | Req */
		struct {
			uint8_t sapi;
			uint8_t radio_prio;
			uint8_t qos_params[3];
			uint8_t cause;
		} unitdata_req;
	};
};

/* TS 24.007 Section 9.3.2 "Service primitives for GMMRR-SAP (GSM only)"
 * Same as enum osmo_gprs_gmm_gmmrr_prim_type.
 */
enum osmo_gprs_rlcmac_gmmrr_prim_type {
	OSMO_GPRS_RLCMAC_GMMRR_ASSIGN,	/* Req: newTLLI  */
	OSMO_GPRS_RLCMAC_GMMRR_PAGE,	/* Ind: TLLI */
};

extern const struct value_string osmo_gprs_rlcmac_gmmrr_prim_type_names[];
static inline const char *osmo_gprs_rlcmac_gmmrr_prim_type_name(enum osmo_gprs_rlcmac_gmmrr_prim_type val)
{
	return get_value_string(osmo_gprs_rlcmac_gmmrr_prim_type_names, val);
}

/* Parameters for OSMO_GPRS_RLCMAC_GRR_* prims.
 * Same as struct osmo_gprs_gmm_gmmrr_prim.
 */
struct osmo_gprs_rlcmac_gmmrr_prim {
	/* Common fields (none) */
	union {
		/* OSMO_GPRS_RLCMAC_GMMRR_ASSIGN | Req */
		struct {
			uint32_t new_tlli;
		} assign_req;
		/* OSMO_GPRS_RLCMAC_GMMRR_PAGE | Ind */
		struct {
			uint32_t tlli;
		} page_ind;
	};
};

/* From/Towards lower layers */
enum osmo_gprs_rlcmac_l1ctl_prim_type {
	OSMO_GPRS_RLCMAC_L1CTL_RACH,
	OSMO_GPRS_RLCMAC_L1CTL_CCCH_DATA,
	OSMO_GPRS_RLCMAC_L1CTL_PDCH_DATA,
	OSMO_GPRS_RLCMAC_L1CTL_PDCH_RTS,
	OSMO_GPRS_RLCMAC_L1CTL_CFG_UL_TBF,
	OSMO_GPRS_RLCMAC_L1CTL_CFG_DL_TBF,
};

extern const struct value_string osmo_gprs_rlcmac_l1ctl_prim_type_names[];
static inline const char *osmo_gprs_rlcmac_l1ctl_prim_type_name(enum osmo_gprs_rlcmac_l1ctl_prim_type val)
{
	return get_value_string(osmo_gprs_rlcmac_l1ctl_prim_type_names, val);
}

/* Parameters for OSMO_GPRS_RLCMAC_L1CTL_* prims */
struct osmo_gprs_rlcmac_l1ctl_prim {
	/* Common fields (none) */
	union {
		/* OSMO_GPRS_RLCMAC_L1CTL_RACH | Req */
		struct {
			bool is_11bit;
			union {
				uint8_t ra;
				struct {
					uint16_t ra11;
					uint8_t synch_seq;
				};
			};
		} rach_req;
		/* OSMO_GPRS_RLCMAC_L1CTL_CCCH_DATA | Ind */
		struct {
			uint32_t fn;
			uint8_t *data; /* data_len = GSM_MACBLOCK_LEN */
		} ccch_data_ind;
		/* OSMO_GPRS_RLCMAC_L1CTL_PDCH_DATA | Req */
		struct {
			uint32_t fn;
			uint8_t ts_nr;
			uint8_t data_len;
			uint8_t *data;
		} pdch_data_req;
		/* OSMO_GPRS_RLCMAC_L1CTL_PDCH_DATA | Ind */
		struct {
			uint32_t fn;
			uint8_t ts_nr;
			uint8_t rx_lev;
			uint16_t ber10k;
			int16_t ci_cb;
			uint8_t data_len; /* data_len = 0 if decoding fails or filtered by lower layer based on DL TFI */
			uint8_t *data;
		} pdch_data_ind;
		/* OSMO_GPRS_RLCMAC_L1CTL_PDCH_RTS | Ind */
		struct {
			uint32_t fn;
			uint8_t ts_nr;
			uint8_t usf;
		} pdch_rts_ind;
		/* OSMO_GPRS_RLCMAC_L1CTL_CFG_UL_TBF | Req */
		struct {
			uint8_t ul_tbf_nr;
			uint8_t ul_slotmask;
			uint8_t ul_usf[8]; /* USF for each PDCH indicated in the slotmask */
		} cfg_ul_tbf_req;
		/* OSMO_GPRS_RLCMAC_L1CTL_CFG_DL_TBF | Req */
		struct {
			uint8_t dl_tbf_nr;
			uint8_t dl_slotmask;
			uint8_t dl_tfi; /* DL TFI for all PDCHs indicated in the slotmask */
		} cfg_dl_tbf_req;
	};
};

struct osmo_gprs_rlcmac_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_gprs_rlcmac_grr_prim grr;
		struct osmo_gprs_rlcmac_gmmrr_prim gmmrr;
		struct osmo_gprs_rlcmac_l1ctl_prim l1ctl;
	};
};

typedef int (*osmo_gprs_rlcmac_prim_up_cb)(struct osmo_gprs_rlcmac_prim *rlcmac_prim, void *up_user_data);
void osmo_gprs_rlcmac_prim_set_up_cb(osmo_gprs_rlcmac_prim_up_cb up_cb, void *up_user_data);

typedef int (*osmo_gprs_rlcmac_prim_down_cb)(struct osmo_gprs_rlcmac_prim *rlcmac_prim, void *down_user_data);
void osmo_gprs_rlcmac_prim_set_down_cb(osmo_gprs_rlcmac_prim_down_cb down_cb, void *down_user_data);

int osmo_gprs_rlcmac_prim_upper_down(struct osmo_gprs_rlcmac_prim *rlcmac_prim);
int osmo_gprs_rlcmac_prim_lower_up(struct osmo_gprs_rlcmac_prim *rlcmac_prim);

const char *osmo_gprs_rlcmac_prim_name(const struct osmo_gprs_rlcmac_prim *rlcmac_prim);

/* Alloc primitive for GRR SAP: */
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_grr_unitdata_req(
				uint32_t tlli, uint8_t *ll_pdu, size_t ll_pdu_len);

/* Alloc primitive for GMMRR SAP: */
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_gmmrr_assign_req(
				uint32_t new_tlli);

/* Alloc primitive for L1CTL SAP: */
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_l1ctl_ccch_data_ind(uint32_t fn, uint8_t *data);
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_data_ind(uint8_t ts_nr, uint32_t fn,
				uint8_t rx_lev, uint16_t ber10k, int16_t ci_cb,
				uint8_t *data, uint8_t data_len);
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_l1ctl_pdch_rts_ind(uint8_t ts_nr, uint32_t fn, uint8_t usf);
