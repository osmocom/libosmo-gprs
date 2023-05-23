#pragma once

/* 3GPP TS 44.064, private header */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/msgb.h>
#include <osmocom/crypt/gprs_cipher.h>

#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/llc/llc.h>

extern int g_llc_log_cat[_OSMO_GPRS_LLC_LOGC_MAX];

#define LOGLLC(lvl, fmt, args...) LOGP(g_llc_log_cat[OSMO_GPRS_LLC_LOGC_LLC], lvl, fmt, ## args)

#define GPRS_LLME_RESET_AGE (0)

/* 3GPP TS 44.064 § 8.3 TLLI assignment procedures */
#define TLLI_UNASSIGNED (0xffffffff)

/* GSM 04.08 - 10.5.1.2 */
#define GSM_KEY_SEQ_INVAL 7

#define CRC24_LENGTH	3
#define UI_HDR_LEN	3
#define N202		4

#define msgb_llc_prim(msg) ((struct osmo_gprs_llc_prim *)(msg)->l1h)


/* Section 6.3.0 Control field formats */
enum gprs_llc_frame_fmt {
	OSMO_GPRS_LLC_FMT_I,			/* 6.3.1 Information transfer format - I */
	OSMO_GPRS_LLC_FMT_S,			/* 6.3.2 Supervisory format - S */
	OSMO_GPRS_LLC_FMT_UI,			/* 6.3.3 Unconfirmed Information format - UI */
	OSMO_GPRS_LLC_FMT_U,			/* 6.3.4 Unnumbered format - U */
};

extern const struct value_string gprs_llc_frame_fmt_names[];

static inline const char *gprs_llc_frame_fmt_name(enum gprs_llc_frame_fmt val)
{
	return get_value_string(gprs_llc_frame_fmt_names, val);
}

/* Section 6.4 Commands and responses */
enum gprs_llc_frame_func {
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

extern const struct value_string gprs_llc_frame_func_names[];

static inline const char *gprs_llc_frame_func_name(enum gprs_llc_frame_func val)
{
	return get_value_string(gprs_llc_frame_func_names, val);
}

/* Section 6.4.1.6 / Table 6 */
enum gprs_llc_xid_type {
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

extern const struct value_string gprs_llc_xid_type_names[];

static inline const char *gprs_llc_xid_type_name(enum gprs_llc_xid_type val)
{
	return get_value_string(gprs_llc_xid_type_names, val);
}

struct gprs_llc_xid_field {
	enum gprs_llc_xid_type type;
	/* Fixed-length value */
	uint32_t val;
	/* Variable-length value */
	struct {
		uint8_t *val;
		uint8_t val_len;
	} var;
};

/* Section 4.5.2 Logical Link States + Annex C.2 */
enum gprs_llc_lle_state {
	OSMO_GPRS_LLC_LLES_UNASSIGNED	= 1,	/* No TLLI yet */
	OSMO_GPRS_LLC_LLES_ASSIGNED_ADM	= 2,	/* TLLI assigned */
	OSMO_GPRS_LLC_LLES_LOCAL_EST	= 3,	/* Local Establishment */
	OSMO_GPRS_LLC_LLES_REMOTE_EST	= 4,	/* Remote Establishment */
	OSMO_GPRS_LLC_LLES_ABM		= 5,
	OSMO_GPRS_LLC_LLES_LOCAL_REL	= 6,	/* Local Release */
	OSMO_GPRS_LLC_LLES_TIMER_REC	= 7,	/* Timer Recovery */
};
extern const struct value_string gprs_llc_lle_state_names[];
static inline const char *gprs_llc_lle_state_name(enum gprs_llc_lle_state val)
{
	return get_value_string(gprs_llc_lle_state_names, val);
}

enum gprs_llc_llme_state {
	OSMO_GPRS_LLC_LLMS_UNASSIGNED	= 1,	/* No TLLI yet */
	OSMO_GPRS_LLC_LLMS_ASSIGNED	= 2,	/* TLLI assigned */
};

extern const struct value_string gprs_llc_llme_state_names[];
static inline const char *gprs_llc_llme_state_name(enum gprs_llc_llme_state val)
{
	return get_value_string(gprs_llc_llme_state_names, val);
}

/* Section 8.9.9 LLC layer parameter default values */
struct gprs_llc_params {
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

struct gprs_llc_pdu_decoded {
	enum osmo_gprs_llc_sapi sapi;
	enum gprs_llc_frame_fmt fmt;
	enum gprs_llc_frame_func func;
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
	uint8_t *data;
};

struct gprs_llc_llme;

/* 3GPP TS 44.064 § 4.7.1: Logical Link Entity: One per DLCI (TLLI + SAPI) */
struct gprs_llc_lle {
	struct llist_head list;

	uint32_t sapi;

	struct gprs_llc_llme *llme; /* backpointer to the Logical Link Management Entity */

	enum gprs_llc_lle_state state;

	struct osmo_timer_list t200;
	struct osmo_timer_list t201;	/* wait for acknowledgement */

	uint16_t v_sent;
	uint16_t v_ack;
	uint16_t v_recv;

	uint16_t vu_send;
	uint16_t vu_recv;

	/* non-standard LLC state */
	uint16_t vu_recv_last;
	uint16_t vu_recv_duplicates;

	/* Overflow Counter for ABM */
	uint32_t oc_i_send;
	uint32_t oc_i_recv;

	/* Overflow Counter for unconfirmed transfer */
	uint32_t oc_ui_send;
	uint32_t oc_ui_recv;

	unsigned int retrans_ctr;

	struct gprs_llc_params params;

	/* Copy of the XID fields array we have sent with the last
	 * network originated XID-Request. Since the phone
	 * may strip the optional fields in the confirmation
	 * we need to remeber those fields in order to be
	 * able to create the compression entity. */
	struct gprs_llc_xid_field *xid;
	unsigned int xid_len;

	/* Copy of last XID-Request fields array received from the peer: We need
	to remember it to be able to send an Xid-Response back when SNDCP
	provides us with layer3 XID field */
	struct gprs_llc_xid_field *rx_xid;
	unsigned int rx_xid_len;

};

#define NUM_SAPIS	16

/* 3GPP TS 44.064 § 4.7.3: Logical Link Management Entity: One per TLLI */
struct gprs_llc_llme {
	struct llist_head list;

	enum gprs_llc_llme_state state;

	uint32_t tlli;
	uint32_t old_tlli;

	/* Crypto parameters */
	enum gprs_ciph_algo algo;
	uint8_t kc[16];
	uint8_t cksn;
	/* 3GPP TS 44.064 § 8.9.2: */
	uint32_t iov_ui;

	/* over which BSSGP BTS ctx do we need to transmit */
	uint16_t bvci;
	uint16_t nsei;
	struct gprs_llc_lle lle[NUM_SAPIS];

	/* Internal management */
	uint32_t age_timestamp;

	/* TS 44.064 § C.2: "In addition, all states should observe the suspended
	 * operation (reception of LLGMM-SUSPEND-REQ) restrictions" */
	bool suspended;
};

static inline struct gprs_llc_lle *gprs_llc_llme_get_lle(struct gprs_llc_llme *llme,
							 enum osmo_gprs_llc_sapi sapi) {
	OSMO_ASSERT(sapi < NUM_SAPIS);
	return &llme->lle[sapi];
}

struct gprs_llc_ctx {
	enum osmo_gprs_llc_location location;
	osmo_gprs_llc_prim_up_cb llc_up_cb;
	void *llc_up_cb_user_data;

	osmo_gprs_llc_prim_down_cb llc_down_cb;
	void *llc_down_cb_user_data;

	struct llist_head llme_list;
};

extern struct gprs_llc_ctx *g_llc_ctx;

/* llc_bssgp.c */
int gprs_llc_prim_lower_up_bssgp(struct osmo_gprs_llc_prim *llc_prim);
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_bssgp_dl_unitdata_req(
				uint32_t tlli, uint8_t *ll_pdu, size_t ll_pdu_len);

/* llc_grr.c */
int gprs_llc_prim_lower_up_grr(struct osmo_gprs_llc_prim *llc_prim);
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_grr_unitdata_req(
				uint32_t tlli, uint8_t *ll_pdu, size_t ll_pdu_len);

/* llc_ll.c */
int gprs_llc_prim_ll_upper_down(struct osmo_gprs_llc_prim *llc_prim);
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_ll_establish_cnf(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi,
								uint8_t *l3_par, unsigned int l3_par_len);
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_ll_xid_ind(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi,
							  uint8_t *l3_par, unsigned int l3_par_len);
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_ll_xid_cnf(uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi,
							  uint8_t *l3_par, unsigned int l3_par_len);
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc_ll_unitdata_ind(
				uint32_t tlli, enum osmo_gprs_llc_sapi ll_sapi,
				uint8_t *l3_pdu, size_t l3_pdu_len);
int gprs_llc_lle_submit_prim_ll_xid_ind(struct gprs_llc_lle *lle,
					const struct gprs_llc_xid_field *xid_field_request_l3);
int gprs_llc_lle_submit_prim_ll_xid_cnf(struct gprs_llc_lle *lle,
					const struct gprs_llc_xid_field *xid_field_response_l3,
					const struct gprs_llc_xid_field *xid_field_request_l3);

/* llc_llgmm.c */
int gprs_llc_prim_llgmm_upper_down(struct osmo_gprs_llc_prim *llc_prim);

/* llc.c */
struct gprs_llc_llme *gprs_llc_llme_alloc(uint32_t tlli);
struct gprs_llc_llme *gprs_llc_find_llme_by_tlli(uint32_t tlli);
struct gprs_llc_lle *gprs_llc_find_lle_by_tlli_sapi(uint32_t tlli, uint8_t sapi);
struct gprs_llc_lle *gprs_llc_lle_for_rx_by_tlli_sapi(const uint32_t tlli,
					uint8_t sapi, enum gprs_llc_frame_func cmd);
int gprs_llc_lle_rx_unitdata_ind(struct gprs_llc_lle *lle, uint8_t *ll_pdu, size_t ll_pdu_len,
				 struct gprs_llc_pdu_decoded *pdu_dec);
void gprs_llc_llme_free(struct gprs_llc_llme *llme);
int gprs_llc_lle_tx_sabm(struct gprs_llc_lle *lle, uint8_t *l3par, unsigned int l3par_len);
int gprs_llc_lle_tx_xid(const struct gprs_llc_lle *lle, uint8_t *xid_payload, unsigned int xid_payload_len, bool is_cmd);
int gprs_llc_lle_tx_xid_req(struct gprs_llc_lle *lle, uint8_t *l3par, unsigned int l3par_len);
int gprs_llc_lle_tx_xid_resp(struct gprs_llc_lle *lle, uint8_t *l3par, unsigned int l3par_len);
int gprs_llc_lle_tx_ui(struct gprs_llc_lle *lle, uint8_t *l3_pdu, size_t l3_pdu_len, bool encryptable);

/* llc_prim.c: */
struct osmo_gprs_llc_prim *gprs_llc_prim_alloc(enum osmo_gprs_llc_prim_sap sap, unsigned int type,
					  enum osmo_prim_operation operation,
					  unsigned int l3_len);
int gprs_llc_prim_handle_unsupported(struct osmo_gprs_llc_prim *llc_prim);
int gprs_llc_prim_call_down_cb(struct osmo_gprs_llc_prim *llc_prim);
int gprs_llc_prim_call_up_cb(struct osmo_gprs_llc_prim *llc_prim);

/* llc_xid.c: */
bool gprs_llc_xid_field_is_valid(const struct gprs_llc_xid_field *field);
int gprs_llc_xid_decode(struct gprs_llc_xid_field *fields,
			unsigned int max_fields,
			uint8_t *data, size_t data_len);
int gprs_llc_xid_encode(uint8_t *data, size_t data_len,
			     const struct gprs_llc_xid_field *fields,
			     unsigned int num_fields);
struct gprs_llc_xid_field *gprs_llc_xid_deepcopy(void *ctx,
						      const struct gprs_llc_xid_field *src_xid,
						      size_t src_xid_len);

/* llc_pdu.c: */
int gprs_llc_pdu_decode(struct gprs_llc_pdu_decoded *pdu,
			     uint8_t *data, size_t data_len);
int gprs_llc_pdu_encode(struct msgb *msg, const struct gprs_llc_pdu_decoded *pdu);
void gprs_llc_pdu_hdr_dump_buf(char *buf, size_t buf_size,
				    const struct gprs_llc_pdu_decoded *pdu);
const char *gprs_llc_pdu_hdr_dump(const struct gprs_llc_pdu_decoded *pdu);
uint32_t gprs_llc_fcs(const uint8_t *data, size_t len);



/**
 * \short Check if N(U) should be considered a retransmit
 *
 * Implements the range check as of GSM 04.64 8.4.2
 * Receipt of unacknowledged information.
 *
 * @returns Returns 1 if  (V(UR)-32) <= N(U) < V(UR)
 * @param nu N(U) unconfirmed sequence number of the UI frame
 * @param vur V(UR) unconfirmend received state variable
 */
static inline int gprs_llc_is_retransmit(uint16_t nu, uint16_t vur)
{
	int delta = (vur - nu) & 0x1ff;
	return 0 < delta && delta < 32;
}

/* 6.2.2 Command/Response bit (C/R) */
static inline bool gprs_llc_received_cr_is_cmd(uint8_t cr)
{
	if (g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN)
		return !cr; /*received from MS */
	else
		return !!cr; /*received from SGSN */

}

static inline void gprs_llc_encode_is_cmd_as_cr(bool is_cmd, uint32_t *flags)
{
	if (g_llc_ctx->location == OSMO_GPRS_LLC_LOCATION_SGSN)
		*flags |= OSMO_GPRS_LLC_PDU_F_CMD_RSP; /*Transmit to MS */
	else
		*flags &= ~OSMO_GPRS_LLC_PDU_F_CMD_RSP; /* Transmit to SGSN */

}

#define LOGLLME(llme, level, fmt, args...) \
	LOGLLC(level, "LLME(%08x/%08x){%s} " fmt, (llme)->old_tlli, \
	     (llme)->tlli, gprs_llc_llme_state_name((llme)->state), ## args)
#define LOGLLE(lle, level, fmt, args...) \
	LOGLLC(level, "LLE(%08x/%08x,%s){%s} " fmt, \
	       (lle)->llme->old_tlli,  (lle)->llme->tlli, \
	       osmo_gprs_llc_sapi_name((lle)->sapi), \
	       gprs_llc_lle_state_name((lle)->state), ## args)
