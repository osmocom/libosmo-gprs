/* RLC block manipulation, 3GPP TS 44.060 */
#pragma once

#include <stdint.h>

#include <osmocom/core/endian.h>
#include <osmocom/gprs/rlcmac/coding_scheme.h>

#define RLC_GPRS_SNS	128 /* GPRS, must be power of 2 */
#define RLC_EGPRS_SNS	2048 /* EGPRS, must be power of 2 */
#define RLC_EGPRS_MAX_BSN_DELTA	512
#define RLC_MAX_SNS	RLC_EGPRS_SNS
#define RLC_MAX_LEN	74 /* MCS-9 data unit */

struct gprs_rlcmac_rlc_li_field {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t	e:1,
		 m:1,
		 li:6;
	uint8_t ll_pdu[0];
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t	li:6, m:1, e:1;
	uint8_t ll_pdu[0];
#endif
} __attribute__ ((packed));

/* TS 44.060  10.2.2 Uplink RLC data block */
struct gprs_rlcmac_rlc_ul_data_header {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t	r:1,
		si:1,
		cv:4,
		pt:2;
	uint8_t	ti:1,
		tfi:5,
		pi:1,
		spare:1;
	uint8_t	e:1,
		bsn:7;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t	pt:2, cv:4, si:1, r:1;
	uint8_t	spare:1, pi:1, tfi:5, ti:1;
	uint8_t	bsn:7, e:1;
#endif
} __attribute__ ((packed));

/* TS 44.060 10.2.1 Downlink RLC data block */
struct gprs_rlcmac_rlc_dl_data_header {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t	usf:3,
		s_p:1,
		rrbp:2,
		pt:2;
	uint8_t	fbi:1,
		tfi:5,
		pr:2;
	uint8_t	e:1,
		bsn:7;
	struct gprs_rlcmac_rlc_li_field lime[0];
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t	pt:2, rrbp:2, s_p:1, usf:3;
	uint8_t	pr:2, tfi:5, fbi:1;
	uint8_t	bsn:7, e:1;
	struct gprs_rlcmac_rlc_li_field lime[0];
#endif
} __attribute__ ((packed));

struct gprs_rlcmac_rlc_li_field_egprs {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t	e:1,
		 li:7;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t	li:7, e:1;
#endif
} __attribute__ ((packed));

static inline uint16_t mod_sns_half(void)
{
	return (RLC_MAX_SNS / 2) - 1;
}

struct gprs_rlcmac_rlc_block_info {
	unsigned int data_len; /* EGPRS: N2, GPRS: N2-2, N-2 */
	unsigned int bsn;
	unsigned int ti;
	unsigned int e;
	unsigned int cv; /* FBI == 1 <=> CV == 0 */
	unsigned int pi;
	unsigned int spb;
};
void gprs_rlcmac_rlc_block_info_init(struct gprs_rlcmac_rlc_block_info *rdbi, enum gprs_rlcmac_coding_scheme cs, bool with_padding, const unsigned int spb);

struct gprs_rlcmac_rlc_data_info {
	enum gprs_rlcmac_coding_scheme cs;
	unsigned int r;
	unsigned int si;
	unsigned int tfi;
	unsigned int cps;
	unsigned int rsb;
	unsigned int usf;
	unsigned int es_p;
	unsigned int rrbp;
	unsigned int pr;
	unsigned int fbi;
	uint8_t num_data_blocks; /* this can actually be only 0, 1, 2: enforced in gprs_rlcmac_rlc_data_header_init() */
	unsigned int with_padding;
	unsigned int data_offs_bits[2];
	struct gprs_rlcmac_rlc_block_info block_info[2];
};
void gprs_rlcmac_rlc_data_info_init_ul(struct gprs_rlcmac_rlc_data_info *rlc,
				       enum gprs_rlcmac_coding_scheme cs,
				       bool with_padding, unsigned int spb);
void gprs_rlcmac_rlc_data_info_init_dl(struct gprs_rlcmac_rlc_data_info *rlc,
				       enum gprs_rlcmac_coding_scheme cs,
				       bool with_padding);

/*
 * EGPRS resegment status information for UL
 * When only first split block is received bsn state
 * will be set to EGPRS_RESEG_FIRST_SEG_RXD and when
 * only second segment is received the state will be
 * set to EGPRS_RESEG_SECOND_SEG_RXD. When both Split
 * blocks are received the state will be set to
 * EGPRS_RESEG_DEFAULT
 * The EGPRS resegmentation feature allows MS to retransmit
 * RLC blocks of HeaderType1, HeaderType2 by segmenting
 * them to 2 HeaderType3 blocks(Example MCS5 will be
 * retransmitted as 2 MCS2 blocks). Table 10.4.8b.1 of 44.060
 * explains the possible values of SPB in HeadrType3 for UL
 * direction. When the MCS is changed at the PCU, PCU directs the
 * changed MCS to MS by PUAN or UPLINK ASSIGNMENT message along
 * with RESEGMENT flag, Then MS may decide to retransmit the
 * blocks by resegmenting it based on Table 8.1.1.1 of 44.060.
 * The retransmission MCS is calculated based on current MCS of
 * the Block and demanded MCS by PCU. Section 10.3a.4.3 of 44.060
 * shows the HeadrType3 with SPB field present in it
*/
enum gprs_rlcmac_rlc_egprs_dl_reseg_bsn_state {
	GPRS_RLCMAC_EGPRS_RESEG_DEFAULT = 0,
	GPRS_RLCMAC_EGPRS_RESEG_FIRST_SEG_RXD = 0x01,
	GPRS_RLCMAC_EGPRS_RESEG_SECOND_SEG_RXD = 0x02,
	GPRS_RLCMAC_EGPRS_RESEG_INVALID = 0x04
};

/*
 * EGPRS resegment status information for DL
 * When only first segment is sent, bsn state
 * will be set to EGPRS_RESEG_FIRST_SEG_SENT and when
 * second segment is sent the state will be
 * set to EGPRS_RESEG_SECOND_SEG_SENT.
 * EGPRS_RESEG_DL_INVALID is set to 8 considering there is a scope for
 * 3rd segment according to Table 10.4.8b.2 of 44.060
 * The EGPRS resegmentation feature allows PCU to retransmit
 * RLC blocks of HeaderType1, HeaderType2 by segmenting
 * them to 2 HeaderType3 blocks(Example MCS5 will be
 * retransmitted as 2 MCS2 blocks). Table 10.4.8b.2 of 44.060
 * explains the possible values of SPB in HeadrType3 for DL
 * direction.The PCU decides to retransmit the
 * blocks by resegmenting it based on Table 8.1.1.1 of 44.060.
 * The retransmission MCS is calculated based on current MCS of
 * the Block and demanded MCS by PCU. Section 10.3a.3.3 of 44.060
 * shows the HeadrType3 with SPB field present in it
 */
enum gprs_rlcmac_rlc_egprs_ul_reseg_bsn_state {
	GPRS_RLCMAC_EGPRS_RESEG_UL_DEFAULT = 0,
	GPRS_RLCMAC_EGPRS_RESEG_FIRST_SEG_SENT = 0x01,
	GPRS_RLCMAC_EGPRS_RESEG_SECOND_SEG_SENT = 0x02,
	GPRS_RLCMAC_EGPRS_RESEG_UL_INVALID = 0x08
};

/* holds the current status of the block w.r.t UL/DL split blocks */
union split_block_status {
	enum gprs_rlcmac_rlc_egprs_ul_reseg_bsn_state block_status_ul;
	enum gprs_rlcmac_rlc_egprs_dl_reseg_bsn_state block_status_dl;
};

/* Table 10.4.8b.2 of 44.060 */
enum gprs_rlcmac_rlc_egprs_ul_spb {
	GPRS_RLCMAC_EGPRS_UL_SPB_NO_RETX = 0,
	GPRS_RLCMAC_EGPRS_UL_SPB_FIRST_SEG_10PAD = 1,
	GPRS_RLCMAC_EGPRS_UL_SPB_FIRST_SEG_6NOPAD = 2,
	GPRS_RLCMAC_EGPRS_UL_SPB_SEC_SEG = 3,
};

#if 0
/* Table 10.4.8b.2 of 44.060 */
enum gprs_rlcmac_rlc_egprs_dl_spb {
	GPRS_RLCMAC_EGPRS_DL_SPB_NO_RETX = 0,
	GPRS_RLCMAC_EGPRS_DL_SPB_FIRST_SEG = 2,
	GPRS_RLCMAC_EGPRS_DL_SPB_SEC_SEG = 3,
};
#endif

/*
 * Valid puncturing scheme values
 * TS 44.060 10.4.8a.3.1, 10.4.8a.2.1, 10.4.8a.1.1
 */
enum gprs_rlcmac_egprs_puncturing_values {
	GPRS_RLCMAC_EGPRS_PS_1,
	GPRS_RLCMAC_EGPRS_PS_2,
	GPRS_RLCMAC_EGPRS_PS_3,
	GPRS_RLCMAC_EGPRS_PS_INVALID,
};

/*
 * EGPRS_MAX_PS_NUM_2 is valid for MCS 1,2,5,6.
 * And EGPRS_MAX_PS_NUM_3 is valid for MCS 3,4,7,8,9
 * TS 44.060 10.4.8a.3.1, 10.4.8a.2.1, 10.4.8a.1.1
 */
enum gprs_rlcmac_egprs_puncturing_types {
	GPRS_RLCMAC_EGPRS_MAX_PS_NUM_2 = 2,
	GPRS_RLCMAC_EGPRS_MAX_PS_NUM_3,
	GPRS_RLCMAC_EGPRS_MAX_PS_NUM_INVALID,
};

struct gprs_rlcmac_rlc_block {
	/* block data including LI headers */
	uint8_t buf[RLC_MAX_LEN];
	/* block data len including LI headers*/
	uint8_t len;

	struct gprs_rlcmac_rlc_block_info block_info;
	/*
	 * cs_current_trans is variable to hold the cs_last value for
	 * current transmission. cs_current_trans is same as cs_last during
	 * transmission case. during retransmission cs_current_trans is
	 * fetched from egprs_mcs_retx_tbl table based on
	 * cs and demanded cs.reference is 44.060 Table
	 * 8.1.1.1 and Table 8.1.1.2
	 * For UL. cs_last shall be used everywhere.
	 */
	enum gprs_rlcmac_coding_scheme cs_current_trans;
	enum gprs_rlcmac_coding_scheme cs_last;

	/*
	 * The MCS of initial transmission of a BSN
	 * This variable is used for split block
	 * processing in DL
	 */
	enum gprs_rlcmac_coding_scheme cs_init;

	/* puncturing scheme value to be used for next transmission*/
	enum gprs_rlcmac_egprs_puncturing_values next_ps;

	/* holds the status of the block w.r.t UL/DL split blocks*/
	union split_block_status spb_status;
};
uint8_t *gprs_rlcmac_rlc_block_prepare(struct gprs_rlcmac_rlc_block *blk, size_t block_data_len);

/*
 * I hold the currently transferred blocks and will provide
 * the routines to manipulate these arrays.
 */
struct gprs_rlcmac_rlc_block_store {
	struct gprs_rlcmac_rlc_block blocks[RLC_MAX_SNS/2];
};

struct gprs_rlcmac_rlc_block_store *gprs_rlcmac_rlc_block_store_alloc(void *ctx);
void gprs_rlcmac_rlc_block_store_free(struct gprs_rlcmac_rlc_block_store *blkst);

struct gprs_rlcmac_rlc_block *gprs_rlcmac_rlc_block_store_get_block(struct gprs_rlcmac_rlc_block_store *blkst, int bsn);

unsigned int gprs_rlcmac_rlc_mcs_cps(enum gprs_rlcmac_coding_scheme cs,
			      enum gprs_rlcmac_egprs_puncturing_values punct,
			      enum gprs_rlcmac_egprs_puncturing_values punct2,
			      bool with_padding);
enum gprs_rlcmac_egprs_puncturing_values gprs_rlcmac_get_punct_scheme(enum gprs_rlcmac_egprs_puncturing_values punct,
							 enum gprs_rlcmac_coding_scheme cs,
							 enum gprs_rlcmac_coding_scheme cs_current_trans,
							 enum gprs_rlcmac_rlc_egprs_ul_spb spb);
void gprs_rlcmac_update_punct_scheme(enum gprs_rlcmac_egprs_puncturing_values *punct,
				     enum gprs_rlcmac_coding_scheme cs);
