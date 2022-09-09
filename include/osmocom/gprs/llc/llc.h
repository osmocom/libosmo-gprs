#pragma once

/* LLC (Logical Link Control) definitions from 3GPP TS 44.064 */

#include <stdint.h>
#include <stddef.h>

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

/* Section 6.3.0 Control field formats */
enum osmo_gprs_llc_frame_fmt {
	OSMO_GPRS_LLC_FMT_I,			/* 6.3.1 Information transfer format - I */
	OSMO_GPRS_LLC_FMT_S,			/* 6.3.2 Supervisory format - S */
	OSMO_GPRS_LLC_FMT_UI,			/* 6.3.3 Unconfirmed Information format - UI */
	OSMO_GPRS_LLC_FMT_U,			/* 6.3.4 Unnumbered format - U */
};

extern const struct value_string osmo_gprs_llc_frame_fmt_names[];

#define osmo_gprs_llc_frame_fmt_name(val) \
	get_value_string(osmo_gprs_llc_frame_fmt_names, val)

/* Section 6.4 Commands and responses */
enum osmo_gprs_llc_frame_func {
	/* 6.4.1 Unnumbered (U) frames */
	OSMO_GPRS_LLC_FUNC_SABM,		/* 6.4.1.1 */
	OSMO_GPRS_LLC_FUNC_DISC,		/* 6.4.1.2 */
	OSMO_GPRS_LLC_FUNC_UA,			/* 6.4.1.3 */
	OSMO_GPRS_LLC_FUNC_DM,			/* 6.4.1.4 */
	OSMO_GPRS_LLC_FUNC_FRMR,		/* 6.4.1.5 */
	OSMO_GPRS_LLC_FUNC_XID,			/* 6.4.1.6 */
	OSMO_GPRS_LLC_FUNC_NULL,		/* 6.4.1.7 */
	/* 6.4.2 Unconfirmed Information (UI) frame */
	OSMO_GPRS_LLC_FUNC_UI,			/* 6.4.2.1 */
	OSMO_GPRS_LLC_FUNC_UI_DUMMY,		/* 6.4.2.2 */
	/* 6.4.3 Combined Information (I) and Supervisory (S) frames */
	OSMO_GPRS_LLC_FUNC_RR,			/* 6.4.3.1 */
	OSMO_GPRS_LLC_FUNC_ACK,			/* 6.4.3.2 */
	OSMO_GPRS_LLC_FUNC_SACK,		/* 6.4.3.3 */
	OSMO_GPRS_LLC_FUNC_RNR,			/* 6.4.3.4 */
};

extern const struct value_string osmo_gprs_llc_frame_func_names[];

#define osmo_gprs_llc_frame_func_name(val) \
	get_value_string(osmo_gprs_llc_frame_func_names, val)

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

#define OSMO_GPRS_LLC_PDU_F_CMD_RSP	(1 << 0)	/* 6.2.2 Commmand/Response bit (C/R) */
#define OSMO_GPRS_LLC_PDU_F_FOLL_FIN	(1 << 1)	/* 6.3.5.1 Poll/Final bit (P/F) */
#define OSMO_GPRS_LLC_PDU_F_ACK_REQ	(1 << 2)	/* 6.3.5.2 Acknowledgement request bit (A) */
#define OSMO_GPRS_LLC_PDU_F_MAC_PRES	(1 << 3)	/* 6.3.5.2a Integrity Protection bit (IP) */
#define OSMO_GPRS_LLC_PDU_F_ENC_MODE	(1 << 4)	/* 6.3.5.5.1 Encryption mode bit (E) */
#define OSMO_GPRS_LLC_PDU_F_PROT_MODE	(1 << 5)	/* 6.3.5.5.2 Protected Mode bit (PM) */

struct osmo_gprs_llc_pdu_decoded {
	enum osmo_gprs_llc_sapi sapi;
	enum osmo_gprs_llc_frame_fmt fmt;
	enum osmo_gprs_llc_frame_func func;
	uint32_t flags; /* see OSMO_GPRS_LLC_PDU_F_* above */
	uint32_t seq_rx; /* 6.3.5.4.5 Receive sequence number N(R) */
	uint32_t seq_tx; /* 6.3.5.4.3 Send sequence number N(S) */
	uint32_t fcs; /* 5.5 Frame Check Sequence (FCS) field */
	uint32_t mac; /* 5.5a Message Authentication Code (MAC) field */
	struct {
		uint8_t len; /* Indicates the number of octets in the bitmap */
		uint8_t r[32]; /* The R(n) bitmap */
	} sack; /* 6.3.5.4.6 SACK bitmap R(n) */
	size_t data_len;
	const uint8_t *data;
};

void osmo_gprs_llc_pdu_hdr_dump_buf(char *buf, size_t buf_size,
				    const struct osmo_gprs_llc_pdu_decoded *pdu);
const char *osmo_gprs_llc_pdu_hdr_dump(const struct osmo_gprs_llc_pdu_decoded *pdu);

int osmo_gprs_llc_pdu_decode(struct osmo_gprs_llc_pdu_decoded *pdu,
			     const uint8_t *data, size_t data_len);
int osmo_gprs_llc_pdu_encode(struct msgb *msg, const struct osmo_gprs_llc_pdu_decoded *pdu);

uint32_t osmo_gprs_llc_fcs(const uint8_t *data, size_t len);
