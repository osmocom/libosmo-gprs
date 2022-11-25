#pragma once

/* 3GPP TS 44.064, section 7.1 "Definition of service primitives and parameters" */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/prim.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gprs/llc/llc.h>

/* Section 7.1.0 */
enum osmo_gprs_llc_prim_sap {
	OSMO_GPRS_LLC_SAP_LLGM,
	OSMO_GPRS_LLC_SAP_LL,
	OSMO_GPRS_LLC_SAP_GRR,
	OSMO_GPRS_LLC_SAP_BSSGP,
};

extern const struct value_string osmo_gprs_llc_prim_sap_names[];
static inline const char *osmo_gprs_llc_prim_sap_name(enum osmo_gprs_llc_prim_sap val)
{
	return get_value_string(osmo_gprs_llc_prim_sap_names, val);
}

/* TS 04.64 Section 7.1.2 Table 7: LLC layer primitives (GMM/SNDCP/SMS/TOM) */
/* TS 04.65 Section 5.1.2 Table 2: Service primitives used by SNDCP */

/* TS 04.65 Section 7.2.1 GMM - LLME primitives */
enum osmo_gprs_llc_llgmm_prim_type {
	OSMO_GPRS_LLC_LLGMM_ASSIGN,	/* Req: TLLI old, TLLI new, Kc, CiphAlg */
	OSMO_GPRS_LLC_LLGMM_RESET,	/* Req/Cnf: TLLI */
	OSMO_GPRS_LLC_LLGMM_TRIGGER,	/* Req: TLLI, Cause */
	OSMO_GPRS_LLC_LLGMM_SUSPEND,	/* Req: TLLI, Page */
	OSMO_GPRS_LLC_LLGMM_RESUME,	/* Req: TLLI */
	OSMO_GPRS_LLC_LLGMM_PAGE,	/* Ind: TLLI */
	OSMO_GPRS_LLC_LLGMM_IOV,	/* Req: TLLI */
	OSMO_GPRS_LLC_LLGMM_STATUS,	/* Ind: TLLI, Cause */
	OSMO_GPRS_LLC_LLGMM_PSHO,	/* Req/Ind/Cnf: TLLI, Ciph, IOV-UI, Old XID */
	OSMO_GPRS_LLC_LLGMM_ASSIGN_UP,	/* Req: TLLI */
};

extern const struct value_string osmo_gprs_llc_llgmm_prim_type_names[];
static inline const char *osmo_gprs_llc_llgmm_prim_type_name(enum osmo_gprs_llc_llgmm_prim_type val)
{
	return get_value_string(osmo_gprs_llc_llgmm_prim_type_names, val);
}

/* TS 04.65 Section 7.2.2 "Layer 3 - LLE primitives" */
enum osmo_gprs_llc_ll_prim_type {
	OSMO_GPRS_LLC_LL_RESET,		/* Ind: TLLI */
	OSMO_GPRS_LLC_LL_ESTABLISH,	/* Req/Ind/Rsp/Cnf: TLLI, XID Req/Neg, N201-I, N201-U */
	OSMO_GPRS_LLC_LL_RELEASE,	/* Req/Ind/Cnf: TLLI, Local, Cause */
	OSMO_GPRS_LLC_LL_XID,		/* Req/Ind/Rsp/Cnf: TLLI, XID Req/Neg, N201-I, N201-U */
	OSMO_GPRS_LLC_LL_DATA,		/* Req/Ind/Cnf: TLLI, L3-PDU, Ref, QoS, Radio Prio */
	OSMO_GPRS_LLC_LL_UNITDATA,	/* Req/Ind: TLLI, L3-PDU, QoS, Radio Prio, Ciph, ... */
	OSMO_GPRS_LLC_LL_STATUS,	/* Ind: TLLI, Cause */
};

extern const struct value_string osmo_gprs_llc_ll_prim_type_names[];
static inline const char *osmo_gprs_llc_ll_prim_type_name(enum osmo_gprs_llc_ll_prim_type val)
{
	return get_value_string(osmo_gprs_llc_ll_prim_type_names, val);
}

/* TS 04.65 Section 7.2.3 "LLE - RLC/MAC primitives" (MS side) */
enum osmo_gprs_llc_grr_prim_type {
	OSMO_GPRS_LLC_GRR_DATA,		/* Req/Ind: TLLI, LL-PDU, SAPI, Cause, QoS, Radio Prio */
	OSMO_GPRS_LLC_GRR_UNITDATA,	/* Req/Ind: TLLI, LL-PDU, SAPI, QoS, Radio Prio */
};

extern const struct value_string osmo_gprs_llc_grr_prim_type_names[];
static inline const char *osmo_gprs_llc_grr_prim_type_name(enum osmo_gprs_llc_grr_prim_type val)
{
	return get_value_string(osmo_gprs_llc_grr_prim_type_names, val);
}

/* TS 04.65 Section 7.2.4 "LLE - BSSGP primitives" (SGSN side) */
enum osmo_gprs_llc_bssgp_prim_type {
	OSMO_GPRS_LLC_BSSGP_DL_UNITDATA,	/* Req: TLLI, LL-PDU, Cell Id, QoS, RLC Confirm, SAPI, ... */
	OSMO_GPRS_LLC_BSSGP_UL_UNITDATA,	/* Ind: TLLI, LL-PDU, Cell Id, edirect attempt, IMSI, V(U) for redirect, ... */
};

extern const struct value_string osmo_gprs_llc_bssgp_prim_type_names[];
static inline const char *osmo_gprs_llc_bssgp_prim_type_name(enum osmo_gprs_llc_bssgp_prim_type val)
{
	return get_value_string(osmo_gprs_llc_bssgp_prim_type_names, val);
}


/* Parameters for OSMO_GPRS_LLC_LLGMM_* prims */
struct osmo_gprs_llc_llgmm_prim {
	/* Common fields */
	uint32_t tlli;
	/* Specific fields */
	union {
		/* OSMO_GPRS_LLC_LLGMM_ASSIGN | Req */
		struct {
			uint32_t tlli_new;
			uint8_t gea; /* GEA/0 = 0, GEA/1 = 1, ... */
			uint8_t kc[16]; /* max 16 * 8 = 128 bits */
			/* TODO: Integrity Key & Algo */
		} assign_req;
		/* OSMO_GPRS_LLC_LLGMM_TRIGGER | Req */
		struct {
			uint8_t cause;
		} trigger_req;
		/* OSMO_GPRS_LLC_LLGMM_SUSPEND | Req */
		struct {
			uint8_t page;
		} suspend_req;
		/* OSMO_GPRS_LLC_LLGMM_STATUS | Ind */
		struct {
			uint8_t cause;
		} status_ind;
		/* OSMO_GPRS_LLC_LLGMM_PSHO | Ind */
		struct {
			uint8_t gea; /* GEA/0 = 0, GEA/1 = 1, ... */
		} psho_ind;
		/* OSMO_GPRS_LLC_LLGMM_PSHO | Req */
		struct {
			uint8_t gea; /* GEA/0 = 0, GEA/1 = 1, ... */
			uint8_t kc[16]; /* max 16 * 8 = 128 bits */
		} psho_req;
		/* OSMO_GPRS_LLC_LLGMM_PSHO | Cnf */
		struct {
			uint32_t iov_ui;
			/* TODO: old XID indicator */
		} psho_cnf;
	};
};

/* Parameters for OSMO_GPRS_LLC_LL_* prims */
struct osmo_gprs_llc_ll_prim {
	/* Common fields */
	uint32_t tlli;
	enum osmo_gprs_llc_sapi sapi;
	/* OSMO_GPRS_LLC_LL_[UNIT]DATA, OSMO_GPRS_LLC_LL_XID */
	uint8_t *l3_pdu;
	size_t l3_pdu_len;
	/* Specific fields */
	union {
		/* OSMO_GPRS_LLC_LL_RESET | Ind */
		struct {
			/* TODO: old XID indicator */
		} reset_ind;
		/* OSMO_GPRS_LLC_LL_ESTABLISH | { Req, Ind, Rsp, Cnf } */
		struct {
			/* TODO: XID Req/Neg */
			uint16_t n201_i; /* only for Ind & Cnf */
			uint16_t n201_u; /* only for Ind & Cnf */
		} establish;
		/* OSMO_GPRS_LLC_LL_RELEASE | Req */
		struct {
			uint8_t local;
		} release_req;
		/* OSMO_GPRS_LLC_LL_RELEASE | Ind */
		struct {
			uint8_t cause;
		} release_ind;
		/* OSMO_GPRS_LLC_LL_XID | { Req, Ind, Rsp, Cnf } */
		struct {
			/* XID Req/Neg are encoded as buffer in l3_pdu + l3_pdu_len */
			uint16_t n201_i; /* only for Ind & Cnf */
			uint16_t n201_u; /* only for Ind & Cnf */
		} xid;
		/* OSMO_GPRS_LLC_LL_DATA | Req */
		struct {
			uint8_t qos_params[3];
			uint8_t reference; /* TODO: confirm type */
			uint8_t radio_prio; /* only for the MS side */
		} data_req;
		/* OSMO_GPRS_LLC_LL_DATA | Cnf */
		struct {
			uint8_t reference; /* TODO: confirm type */
		} data_cnf;
		/* OSMO_GPRS_LLC_LL_UNITDATA | Req */
		struct {
			uint8_t qos_params[3];
			uint8_t radio_prio; /* only for the MS side */
			bool apply_gea; /* Cipher */
			bool apply_gia; /* Integrity Protection */
		} unitdata_req;
		/* OSMO_GPRS_LLC_LL_UNITDATA | Ind */
		struct {
			bool apply_gea; /* Cipher */
			bool apply_gia; /* Integrity Protection */
			/* TODO: MAC Verified */
			/* TODO: LLC MAC */
		} unitdata_ind;
		/* OSMO_GPRS_LLC_LL_STATUS | Ind */
		struct {
			uint8_t cause;
		} status_ind;
	};
};

/* Parameters for OSMO_GPRS_LLC_GRR_* prims */
struct osmo_gprs_llc_grr_prim {
	/* Common fields */
	uint32_t tlli;
	uint8_t *ll_pdu;
	size_t ll_pdu_len;
	/* Specific fields */
	union {
		/* OSMO_GPRS_LLC_GRR_[UNIT]DATA | Req */
		struct {
			uint8_t qos_params[3];
			uint8_t radio_prio;
			uint8_t cause; /* only for OSMO_GPRS_LLC_GRR_UNITDATA | Req */
			uint8_t sapi;
		} data_req;
	};
};

/* Parameters for OSMO_GPRS_LLC_BSSGP_* prims */
struct osmo_gprs_llc_bssgp_prim {
	/* Common fields */
	uint32_t tlli;
	uint8_t *ll_pdu;
	size_t ll_pdu_len;
	/* Specific fields */
	union {
		/* OSMO_GPRS_LLC_BSSGP_DL_UNITDATA | Req */
		struct {
			uint8_t qos_params[3];
			bool rlc_confirm;
			uint8_t sapi;
			/* TODO: MOCN specific parameters:
			 * - Redirect indication
			 * - IMSI
			 * - GMM cause
			 * - V(U) for redirect
			 * - Redirect complete */
		} dl_unitdata_req;
		/* OSMO_GPRS_LLC_BSSGP_UL_UNITDATA | Ind */
		struct {
			struct gsm0808_cell_id cell_id;
			/* TODO: MOCN specific parameters:
			 * - Redirect attempt
			 * - IMSI
			 * - V(U) for redirect */
		} ul_unitdata_ind;
	};
};

struct osmo_gprs_llc_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_gprs_llc_llgmm_prim llgmm;
		struct osmo_gprs_llc_ll_prim ll;
		struct osmo_gprs_llc_grr_prim grr;
		struct osmo_gprs_llc_bssgp_prim bssgp;
	};
};

typedef int (*osmo_gprs_llc_prim_up_cb)(struct osmo_gprs_llc_prim *llc_prim, void *up_user_data);
void osmo_gprs_llc_prim_set_up_cb(osmo_gprs_llc_prim_up_cb up_cb, void *up_user_data);

typedef int (*osmo_gprs_llc_prim_down_cb)(struct osmo_gprs_llc_prim *llc_prim, void *down_user_data);
void osmo_gprs_llc_prim_set_down_cb(osmo_gprs_llc_prim_down_cb down_cb, void *down_user_data);

int osmo_gprs_llc_prim_upper_down(struct osmo_gprs_llc_prim *llc_prim);
int osmo_gprs_llc_prim_lower_up(struct osmo_gprs_llc_prim *llc_prim);

const char *osmo_gprs_llc_prim_name(const struct osmo_gprs_llc_prim *llc_prim);

/* Alloc primitive for LLGMM SAP: */
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_llgm_assign_req(uint32_t tlli);
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_llgm_reset_req(uint32_t tlli);

/* Alloc primitive for LL SAP: */
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_ll_xid_req(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi,
							       uint8_t *l3_par, unsigned int l3_par_len);
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_ll_xid_resp(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi,
								uint8_t *l3_par, unsigned int l3_par_len);
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_ll_unitdata_req(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi,
								    uint8_t *l3_pdu, size_t l3_pdu_len);

/* Alloc primitive for BSSGP SAP: */
struct osmo_gprs_llc_prim *osmo_gprs_llc_prim_alloc_bssgp_ul_unitdata_ind(
				uint32_t tlli, uint8_t *ll_pdu, size_t ll_pdu_len);
