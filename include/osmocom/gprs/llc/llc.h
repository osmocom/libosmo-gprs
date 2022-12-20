#pragma once

/* LLC (Logical Link Control) definitions from 3GPP TS 44.064 */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/msgb.h>

/* Section 7.1.2 LLC layer service primitives */
enum osmo_gprs_llc_location {
	OSMO_GPRS_LLC_LOCATION_UNSET,
	OSMO_GPRS_LLC_LOCATION_MS,
	OSMO_GPRS_LLC_LOCATION_SGSN,
};

/* Section 6.2.3 Service Access Point Identifier (SAPI) */
enum osmo_gprs_llc_sapi {
	OSMO_GPRS_LLC_SAPI_GMM		= 1,
	OSMO_GPRS_LLC_SAPI_TOM2		= 2,
	OSMO_GPRS_LLC_SAPI_SNDCP3	= 3,
	OSMO_GPRS_LLC_SAPI_SNDCP5	= 5,
	OSMO_GPRS_LLC_SAPI_SMS		= 7,
	OSMO_GPRS_LLC_SAPI_TOM8		= 8,
	OSMO_GPRS_LLC_SAPI_SNDCP9	= 9,
	OSMO_GPRS_LLC_SAPI_SNDCP11	= 11,
};

extern const struct value_string osmo_gprs_llc_sapi_names[];

static inline const char *osmo_gprs_llc_sapi_name(enum osmo_gprs_llc_sapi val)
{
	return get_value_string(osmo_gprs_llc_sapi_names, val);
}

/* Section 6.3.0 Control field formats */
enum osmo_gprs_llc_frame_fmt {
	OSMO_GPRS_LLC_FMT_I,			/* 6.3.1 Information transfer format - I */
	OSMO_GPRS_LLC_FMT_S,			/* 6.3.2 Supervisory format - S */
	OSMO_GPRS_LLC_FMT_UI,			/* 6.3.3 Unconfirmed Information format - UI */
	OSMO_GPRS_LLC_FMT_U,			/* 6.3.4 Unnumbered format - U */
};

extern const struct value_string osmo_gprs_llc_frame_fmt_names[];

static inline const char *osmo_gprs_llc_frame_fmt_name(enum osmo_gprs_llc_frame_fmt val)
{
	return get_value_string(osmo_gprs_llc_frame_fmt_names, val);
}

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

static inline const char *osmo_gprs_llc_frame_func_name(enum osmo_gprs_llc_frame_func val)
{
	return get_value_string(osmo_gprs_llc_frame_func_names, val);
}

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
	OSMO_GPRS_LLC_XID_T_IIOV_UI	= 13,
	OSMO_GPRS_LLC_XID_T_IIOV_UI_CNT	= 14,
	OSMO_GPRS_LLC_XID_T_MAC_IOV_UI	= 15,
};

extern const struct value_string osmo_gprs_llc_xid_type_names[];

static inline const char *osmo_gprs_llc_xid_type_name(enum osmo_gprs_llc_xid_type val)
{
	return get_value_string(osmo_gprs_llc_xid_type_names, val);
}

struct osmo_gprs_llc_xid_field {
	enum osmo_gprs_llc_xid_type type;
	/* Fixed-length value */
	uint32_t val;
	/* Variable-length value */
	struct {
		const uint8_t *val;
		uint8_t val_len;
	} var;
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

bool osmo_gprs_llc_xid_field_is_valid(const struct osmo_gprs_llc_xid_field *field);
int osmo_gprs_llc_xid_decode(struct osmo_gprs_llc_xid_field *fields,
			     unsigned int max_fields,
			     const uint8_t *data, size_t data_len);
int osmo_gprs_llc_xid_encode(struct msgb *msg,
			     const struct osmo_gprs_llc_xid_field *fields,
			     unsigned int num_fields);

enum osmo_gprs_llc_log_cat {
	OSMO_GPRS_LLC_LOGC_LLC,
	_OSMO_GPRS_LLC_LOGC_MAX,
};

void osmo_gprs_llc_set_log_cat(enum osmo_gprs_llc_log_cat logc, int logc_num);

/* TODO: move to llc_private.h */
extern int g_llc_log_cat[_OSMO_GPRS_LLC_LOGC_MAX];

#define LOGLLC(lvl, fmt, args...) LOGP(g_llc_log_cat[OSMO_GPRS_LLC_LOGC_LLC], lvl, fmt, ## args)
