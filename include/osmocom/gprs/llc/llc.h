#pragma once

/* LLC (Logical Link Control) definitions from 3GPP TS 44.064 */

#include <stdint.h>

/* Section 6.2.3 Service Access Point Identifier (SAPI) */
enum osmo_gprs_llc_sapi {
	OSMO_GPRS_LLC_SAPI_GMM		= 1,
	OSMO_GPRS_LLC_SAPI_TOM2		= 2,
	OSMO_GPRS_LLC_SAPI_SNDCP3	= 3,
	OSMO_GPRS_LLC_SAPI_SNDCP5	= 5,
	OSMO_GPRS_LLC_SAPI_SMS		= 7,
	OSMO_GPRS_LLC_SAPI_TOM8		= 8,
	OSMO_GPRS_LLC_SAPI_SNDCP9	= 9,
	OSMO_GPRS_LLC_SAPI_SNDCP12	= 11,
};

/* Section 6.4.1.6 / Table 6 */
enum osmo_gprs_llc_xid_type {
	OSMO_GPRS_LLC_XID_T_VERSION	= 0,
	OSMO_GPRS_LLC_XID_T_IOV_UI	= 1,
	OSMO_GPRS_LLC_XID_T_IOV_I	= 2,
	OSMO_GPRS_LLC_XID_T_T200	= 3,
	OSMO_GPRS_LLC_XID_T_N200	= 4,
	OSMO_GPRS_LLC_XID_T_N201_U	= 5,
	OSMO_GPRS_LLC_XID_T_N201_I	= 6,
	OSMO_GPRS_LLC_XID_T_mD		= 7,
	OSMO_GPRS_LLC_XID_T_mU		= 8,
	OSMO_GPRS_LLC_XID_T_kD		= 9,
	OSMO_GPRS_LLC_XID_T_kU		= 10,
	OSMO_GPRS_LLC_XID_T_L3_PAR	= 11,
	OSMO_GPRS_LLC_XID_T_RESET	= 12,
};

/* TS 04.64 Section 7.1.2 Table 7: LLC layer primitives (GMM/SNDCP/SMS/TOM) */
/* TS 04.65 Section 5.1.2 Table 2: Service primitives used by SNDCP */
enum osmo_gprs_llc_primitive {
	/* GMM <-> LLME */
	OSMO_GPRS_LLC_LLGMM_ASSIGN_REQ,		/* GMM tells us new TLLI: TLLI old, TLLI new, Kc, CiphAlg */
	OSMO_GPRS_LLC_LLGMM_RESET_REQ,		/* GMM tells us to perform XID negotiation: TLLI */
	OSMO_GPRS_LLC_LLGMM_RESET_CNF,		/* LLC informs GMM that XID has completed: TLLI */
	OSMO_GPRS_LLC_LLGMM_SUSPEND_REQ,	/* GMM tells us MS has suspended: TLLI, Page */
	OSMO_GPRS_LLC_LLGMM_RESUME_REQ,		/* GMM tells us MS has resumed: TLLI */
	OSMO_GPRS_LLC_LLGMM_PAGE_IND,		/* LLC asks GMM to page MS: TLLI */
	OSMO_GPRS_LLC_LLGMM_IOV_REQ,		/* GMM tells us to perform XID: TLLI */
	OSMO_GPRS_LLC_LLGMM_STATUS_IND,		/* LLC informs GMM about error: TLLI, Cause */
	/* LLE <-> (GMM/SNDCP/SMS/TOM) */
	OSMO_GPRS_LLC_LL_RESET_IND,		/* TLLI */
	OSMO_GPRS_LLC_LL_ESTABLISH_REQ,		/* TLLI, XID Req */
	OSMO_GPRS_LLC_LL_ESTABLISH_IND,		/* TLLI, XID Req, N201-I, N201-U */
	OSMO_GPRS_LLC_LL_ESTABLISH_RESP,	/* TLLI, XID Negotiated */
	OSMO_GPRS_LLC_LL_ESTABLISH_CONF,	/* TLLI, XID Neg, N201-i, N201-U */
	OSMO_GPRS_LLC_LL_RELEASE_REQ,		/* TLLI, Local */
	OSMO_GPRS_LLC_LL_RELEASE_IND,		/* TLLI, Cause */
	OSMO_GPRS_LLC_LL_RELEASE_CONF,		/* TLLI */
	OSMO_GPRS_LLC_LL_XID_REQ,		/* TLLI, XID Requested */
	OSMO_GPRS_LLC_LL_XID_IND,		/* TLLI, XID Req, N201-I, N201-U */
	OSMO_GPRS_LLC_LL_XID_RESP,		/* TLLI, XID Negotiated */
	OSMO_GPRS_LLC_LL_XID_CONF,		/* TLLI, XID Neg, N201-I, N201-U */
	OSMO_GPRS_LLC_LL_DATA_REQ,		/* TLLI, SN-PDU, Ref, QoS, Radio Prio, Ciph */
	OSMO_GPRS_LLC_LL_DATA_IND,		/* TLLI, SN-PDU */
	OSMO_GPRS_LLC_LL_DATA_CONF,		/* TLLI, Ref */
	OSMO_GPRS_LLC_LL_UNITDATA_REQ,		/* TLLI, SN-PDU, Ref, QoS, Radio Prio, Ciph */
	OSMO_GPRS_LLC_LL_UNITDATA_IND,		/* TLLI, SN-PDU */
	OSMO_GPRS_LLC_LL_STATUS_IND,		/* TLLI, Cause */
};

/* Section 4.5.2 Logical Link States + Annex C.2 */
enum osmo_gprs_llc_lle_state {
	OSMO_GPRS_LLC_LLES_UNASSIGNED	= 1,	/* No TLLI yet */
	OSMO_GPRS_LLC_LLES_ASSIGNED_ADM	= 2,	/* TLLI assigned */
	OSMO_GPRS_LLC_LLES_LOCAL_EST	= 3,	/* Local Establishment */
	OSMO_GPRS_LLC_LLES_REMOTE_EST	= 4,	/* Remote Establishment */
	OSMO_GPRS_LLC_LLES_ABM		= 5,
	OSMO_GPRS_LLC_LLES_LOCAL_REL	= 6,	/* Local Release */
	OSMO_GPRS_LLC_LLES_TIMER_REC	= 7,	/* Timer Recovery */
};

enum osmo_gprs_llc_llme_state {
	OSMO_GPRS_LLC_LLMS_UNASSIGNED	= 1,	/* No TLLI yet */
	OSMO_GPRS_LLC_LLMS_ASSIGNED	= 2,	/* TLLI assigned */
};

/* Section 8.9.9 LLC layer parameter default values */
struct osmo_gprs_llc_params {
	uint16_t iov_i_exp;
	uint16_t t200_201;
	uint16_t n200;
	uint16_t n201_u;
	uint16_t n201_i;
	uint16_t mD;
	uint16_t mU;
	uint16_t kD;
	uint16_t kU;
};
