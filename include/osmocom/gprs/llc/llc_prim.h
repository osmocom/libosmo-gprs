#pragma once

/* TS 04.64 Section 7.1.2 Table 7: LLC layer primitives (GMM/SNDCP/SMS/TOM) */
/* TS 04.65 Section 5.1.2 Table 2: Service primitives used by SNDCP */
enum osmo_gprs_llc_prim_type {
	/* GMM <-> LLME */
	OSMO_GPRS_LLC_LLGMM_ASSIGN,		/* Req: TLLI old, TLLI new, Kc, CiphAlg */
	OSMO_GPRS_LLC_LLGMM_RESET,		/* Req/Cnf: TLLI */
	OSMO_GPRS_LLC_LLGMM_TRIGGER,		/* Req: TLLI, Cause */
	OSMO_GPRS_LLC_LLGMM_SUSPEND,		/* Req: TLLI, Page */
	OSMO_GPRS_LLC_LLGMM_RESUME,		/* Req: TLLI */
	OSMO_GPRS_LLC_LLGMM_PAGE,		/* Ind: TLLI */
	OSMO_GPRS_LLC_LLGMM_IOV,		/* Req: TLLI */
	OSMO_GPRS_LLC_LLGMM_STATUS,		/* Ind: TLLI, Cause */
	OSMO_GPRS_LLC_LLGMM_PSHO,		/* Req/Ind/Cnf: TLLI, Ciph, IOV-UI, Old XID */
	OSMO_GPRS_LLC_LLGMM_ASSIGN_UP,		/* Req: TLLI */
	/* LLE <-> (GMM/SNDCP/SMS/TOM) */
	OSMO_GPRS_LLC_LL_RESET,			/* Ind: TLLI */
	OSMO_GPRS_LLC_LL_ESTABLISH,		/* Req/Ind/Rsp/Cnf: TLLI, XID Req/Neg, N201-I, N201-U */
	OSMO_GPRS_LLC_LL_RELEASE,		/* Req/Ind/Cnf: TLLI, Local, Cause */
	OSMO_GPRS_LLC_LL_XID,			/* Req/Ind/Rsp/Cnf: TLLI, XID Req/Neg, N201-I, N201-U */
	OSMO_GPRS_LLC_LL_DATA,			/* Req/Ind/Cnf: TLLI, L3-PDU, Ref, QoS, Radio Prio */
	OSMO_GPRS_LLC_LL_UNITDATA,		/* Req/Ind: TLLI, L3-PDU, QoS, Radio Prio, Ciph, ... */
	OSMO_GPRS_LLC_LL_STATUS,		/* Ind: TLLI, Cause */
	/* LLE <-> RLC/MAC (MS side) */
	OSMO_GPRS_LLC_GRR_DATA,			/* Req/Ind: TLLI, LL-PDU, SAPI, Cause, QoS, Radio Prio */
	OSMO_GPRS_LLC_GRR_UNITDATA,		/* Req/Ind: TLLI, LL-PDU, SAPI, QoS, Radio Prio */
	/* LLE <-> BSSGP (SGSN side) */
	OSMO_GPRS_LLC_BSSGP_UNITDATA,		/* Req/Ind: TLLI, LL-PDU, Cell Id, QoS, RLC Confirm, SAPI, ... */
};
