#pragma once

/* 3GPP TS 44.065, section 5 "Service primitives and functions" */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/prim.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gprs/sndcp/sndcp.h>

struct osmo_gprs_llc_prim;

/* Section 5.1 "Service primitives" */
enum osmo_gprs_sndcp_prim_sap {
	OSMO_GPRS_SNDCP_SAP_SN,
	OSMO_GPRS_SNDCP_SAP_SNSM,
};
extern const struct value_string osmo_gprs_sndcp_prim_sap_names[];
static inline const char *osmo_gprs_sndcp_prim_sap_name(enum osmo_gprs_sndcp_prim_sap val)
{
	return get_value_string(osmo_gprs_sndcp_prim_sap_names, val);
}

/* Table 1: SNDCP layer service primitives */
enum osmo_gprs_sndcp_sn_prim_type {
	OSMO_GPRS_SNDCP_SN_DATA,	/* Req/Ind: N-PDU, NSAPI, N-PDU Number*/
	OSMO_GPRS_SNDCP_SN_UNITDATA,	/* Req/Ind: N-PDU, NSAPI */
	OSMO_GPRS_SNDCP_SN_XID,		/* Req/Ind/Resp/Cnf: Req/Neg SNDCP XID Parameters */
};
extern const struct value_string osmo_gprs_sndcp_sn_prim_type_names[];
static inline const char *osmo_gprs_sndcp_sn_prim_type_name(enum osmo_gprs_sndcp_sn_prim_type val)
{
	return get_value_string(osmo_gprs_sndcp_sn_prim_type_names, val);
}

/* Table 2: Service primitives used by the SNDCP entity */
enum osmo_gprs_sndcp_snsm_prim_type {
	OSMO_GPRS_SNDCP_SNSM_ACTIVATE,		/* Ind/Resp: TLLI, NSAPI, QoS profile, SAPI, Radio Priority */
	OSMO_GPRS_SNDCP_SNSM_DEACTIVATE,	/* Ind/Resp: TLLI, NSAPI(s), LLC Release Indicator, XID Negotiation Indicator */
	OSMO_GPRS_SNDCP_SNSM_MODIFY,		/* Ind/Resp: TLLI, NSAPI, QoS Profile, SAPI, Radio Priority, Send N-PDU Number, Receive N-PDU Number */
	OSMO_GPRS_SNDCP_SNSM_STATUS,		/* Req: TLLI, SAPI, Cause */
	OSMO_GPRS_SNDCP_SNSM_SEQUENCE,		/* Ind/Resp: TLLI, NSAPI, Receive N-PDU Number */
	OSMO_GPRS_SNDCP_SNSM_STOP_ASSIGN,	/* Ind/Resp: TLLI, NSAPI */
};
extern const struct value_string osmo_gprs_sndcp_snsm_prim_type_names[];
static inline const char *osmo_gprs_sndcp_snsm_prim_type_name(enum osmo_gprs_sndcp_snsm_prim_type val)
{
	return get_value_string(osmo_gprs_sndcp_snsm_prim_type_names, val);
}

/* Parameters for OSMO_GPRS_SNDCP_SN_* prims */
struct osmo_gprs_sndcp_sn_prim {
	/* Common fields */
	uint32_t tlli;
	uint8_t sapi; /* llc */
	/* Specific fields */
	union {
		/* OSMO_GPRS_SNDCP_SN_DATA | Req */
		struct {
			uint8_t nsapi;
			uint8_t *npdu;
			size_t npdu_len;
			uint32_t npdu_number;
		} data_req;
		/* OSMO_GPRS_SNDCP_SN_DATA | Ind */
		struct {
			uint8_t nsapi;
			uint8_t *npdu;
			size_t npdu_len;
		} data_ind;
		/* OSMO_GPRS_SNDCP_SN_UNITDATA | Req */
		struct {
			uint8_t nsapi;
			uint8_t *npdu;
			size_t npdu_len;
		} unitdata_req;
		/* OSMO_GPRS_SNDCP_SN_UNITDATA | Ind */
		struct {
			uint8_t nsapi;
			uint8_t *npdu;
			size_t npdu_len;
		} unitdata_ind;
		/* OSMO_GPRS_SNDCP_SN_XID | Req */
		struct {
			uint8_t nsapi;
			struct {
				bool active;
				bool passive;
				int s01;
			} pcomp_rfc1144;
			struct {
				bool active;
				bool passive;
				int p0;
				int p1;
				int p2;
			} dcomp_v42bis;
		} xid_req;
		/* OSMO_GPRS_SNDCP_SN_XID | Ind */
		struct {
			uint8_t nsapi;
			uint8_t *req_xid; /* TODO: theses need to be passed already decoded as in xid_req above */
			uint32_t req_xid_len;
		} xid_ind;
		/* OSMO_GPRS_SNDCP_SN_XID | Rsp */
		struct {
			uint8_t nsapi;
		} xid_rsp;
		/* OSMO_GPRS_SNDCP_SN_XID | Cnf */
		struct {
			uint8_t *neg_xid;
			uint32_t neg_xid_len;
		} xid_cnf;
	};
};

/* Parameters for OSMO_GPRS_SNDCP_SNSM_* prims */
struct osmo_gprs_sndcp_snsm_prim {
	/* Common fields */
	uint32_t tlli;
	/* Specific fields */
	union {
		/* OSMO_GPRS_SNDCP_SNSM_ACTIVATE | Ind */
		struct {
			uint8_t nsapi;
			uint8_t sapi;
			uint8_t qos_profile[OSMO_GPRS_SNDCP_QOS_MAXLEN];
			uint8_t qos_profile_len;
			uint8_t radio_prio;
		} activate_ind;
		/* OSMO_GPRS_SNDCP_SNSM_ACTIVATE | Rsp */
		struct {
			uint8_t nsapi;
		} activate_rsp;
		/* OSMO_GPRS_SNDCP_SNSM_DEACTIVATE | Req */
		struct {
			uint8_t nsapi;
			/* TODO: LLC Release Indicator,
				 XID Negotiation Indicator
			*/
		} deactivate_ind;
		/* OSMO_GPRS_SNDCP_SNSM_DEACTIVATE | Rsp */
		struct {
			uint8_t nsapi;
		} deactivate_rsp;
		/* OSMO_GPRS_SNDCP_SNSM_MODIFY | Ind */
		struct {
			uint8_t nsapi;
			uint8_t sapi;
			uint8_t qos_profile[OSMO_GPRS_SNDCP_QOS_MAXLEN];
			uint8_t qos_profile_len;
			uint8_t radio_prio;
			unsigned int tx_npdu_nr;
			unsigned int rx_npdu_nr;
		} modify_ind;
		/* OSMO_GPRS_SNDCP_SNSM_MODIFY | Rsp */
		struct {
			uint8_t nsapi;
		} modify_rsp;
		/* OSMO_GPRS_SNDCP_SNSM_STATUS| Req */
		struct {
			uint8_t sapi;
			uint8_t cause;
		} status_req;

		/* OSMO_GPRS_SNDCP_SNSM_SEQUENCE | Ind */
		struct {
			uint8_t nsapi;
			unsigned int rx_npdu_nr;
		} sequence_ind;
		/* OSMO_GPRS_SNDCP_SNSM_SEQUENCE | Rsp */
		struct {
			uint8_t nsapi;
		} sequence_rsp;

		/* OSMO_GPRS_SNDCP_SNSM_STOP_ASSIGN | Ind */
		struct {
			uint8_t nsapi;
		} stop_assign_ind;
	};
};

struct osmo_gprs_sndcp_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_gprs_sndcp_sn_prim sn;
		struct osmo_gprs_sndcp_snsm_prim snsm;
	};
};

typedef int (*osmo_gprs_sndcp_prim_up_cb)(struct osmo_gprs_sndcp_prim *sndcp_prim, void *up_user_data);
void osmo_gprs_sndcp_prim_set_up_cb(osmo_gprs_sndcp_prim_up_cb up_cb, void *up_user_data);

typedef int (*osmo_gprs_sndcp_prim_down_cb)(struct osmo_gprs_llc_prim *llc_prim, void *down_user_data);
void osmo_gprs_sndcp_prim_set_down_cb(osmo_gprs_sndcp_prim_down_cb down_cb, void *down_user_data);

typedef int (*osmo_gprs_sndcp_prim_snsm_cb)(struct osmo_gprs_sndcp_prim *sndcp_prim, void *snsm_user_data);
void osmo_gprs_sndcp_prim_set_snsm_cb(osmo_gprs_sndcp_prim_snsm_cb snsm_cb, void *snsm_user_data);

int osmo_gprs_sndcp_prim_upper_down(struct osmo_gprs_sndcp_prim *sndcp_prim);
int osmo_gprs_sndcp_prim_lower_up(struct osmo_gprs_llc_prim *llc_prim);
int osmo_gprs_sndcp_prim_dispatch_snsm(struct osmo_gprs_sndcp_prim *sndcp_prim);

const char *osmo_gprs_sndcp_prim_name(const struct osmo_gprs_sndcp_prim *sndcp_prim);

/* Alloc primitive for SN SAP: */
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_sn_data_req(uint32_t tlli, uint8_t sapi, uint8_t nsapi, uint8_t *npdu, size_t npdu_len);
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_sn_unitdata_req(uint32_t tlli, uint8_t sapi, uint8_t nsapi, uint8_t *npdu, size_t npdu_len);
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_sn_xid_req(uint32_t tlli, uint8_t sapi, uint8_t nsapi);
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_sn_xid_rsp(uint32_t tlli, uint8_t sapi, uint8_t nsapi);

/* Alloc primitive for SNSM SAP: */
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_snsm_activate_ind(uint32_t tlli, uint8_t nsapi, uint8_t sapi);
struct osmo_gprs_sndcp_prim *osmo_gprs_sndcp_prim_alloc_snsm_deactivate_ind(uint32_t tlli, uint8_t nsapi);
