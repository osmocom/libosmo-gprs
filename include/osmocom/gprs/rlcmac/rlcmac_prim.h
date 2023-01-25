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

/* TS 24.007 Section 9.3.2 "Service primitives for GMMRR-SAP (GSM only)" */
enum osmo_gprs_rlcmac_gmmrr_prim_type {
	OSMO_GPRS_RLCMAC_GMMRR_ASSIGN,	/* Req: newTLLI  */
	OSMO_GPRS_RLCMAC_GMMRR_PAGE,	/* Ind: TLLI */
};

extern const struct value_string osmo_gprs_rlcmac_gmmrr_prim_type_names[];
static inline const char *osmo_gprs_rlcmac_gmmrr_prim_type_name(enum osmo_gprs_rlcmac_gmmrr_prim_type val)
{
	return get_value_string(osmo_gprs_rlcmac_gmmrr_prim_type_names, val);
}

/* Parameters for OSMO_GPRS_RLCMAC_GRR_* prims */
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

struct osmo_gprs_rlcmac_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_gprs_rlcmac_grr_prim grr;
		struct osmo_gprs_rlcmac_gmmrr_prim gmmrr;
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
struct osmo_gprs_rlcmac_prim *osmo_gprs_rlcmac_prim_alloc_gmmrr_asign_req(
				uint32_t new_tlli);
