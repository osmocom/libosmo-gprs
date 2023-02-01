/* RLC Window (common for both UL/DL TBF), 3GPP TS 44.060 */
#pragma once

#include <stdint.h>

#include <osmocom/core/bitvec.h>

#include <osmocom/gprs/rlcmac/rlc.h>
#include <osmocom/gprs/rlcmac/rlc_window.h>

struct gprs_rlcmac_ul_tbf;

enum gprs_rlcmac_rlc_ul_bsn_state {
	GPRS_RLCMAC_RLC_UL_BSN_INVALID,
	GPRS_RLCMAC_RLC_UL_BSN_NACKED,
	GPRS_RLCMAC_RLC_UL_BSN_ACKED,
	GPRS_RLCMAC_RLC_UL_BSN_UNACKED,
	GPRS_RLCMAC_RLC_UL_BSN_RESEND,
	GPRS_RLCMAC_RLC_UL_BSN_MAX,
};

struct gprs_rlcmac_rlc_v_b {
	enum gprs_rlcmac_rlc_ul_bsn_state v_b[RLC_MAX_SNS/2]; /* acknowledge state array */
};

void gprs_rlcmac_rlc_v_b_reset(struct gprs_rlcmac_rlc_v_b *v_b);
/* Check for an individual frame */
bool gprs_rlcmac_rlc_v_b_is_unacked(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn);
bool gprs_rlcmac_rlc_v_b_is_nacked(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn);
bool gprs_rlcmac_rlc_v_b_is_acked(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn);
bool gprs_rlcmac_rlc_v_b_is_resend(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn);
bool gprs_rlcmac_rlc_v_b_is_invalid(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn);
enum gprs_rlcmac_rlc_ul_bsn_state gprs_rlcmac_rlc_v_b_get_state(const struct gprs_rlcmac_rlc_v_b *v_b, int bsn);

/* Mark a RLC frame for something */
void gprs_rlcmac_rlc_v_b_mark_unacked(struct gprs_rlcmac_rlc_v_b *v_b, int bsn);
void gprs_rlcmac_rlc_v_b_mark_nacked(struct gprs_rlcmac_rlc_v_b *v_b, int bsn);
void gprs_rlcmac_rlc_v_b_mark_acked(struct gprs_rlcmac_rlc_v_b *v_b, int bsn);
void gprs_rlcmac_rlc_v_b_mark_resend(struct gprs_rlcmac_rlc_v_b *v_b, int bsn);
void gprs_rlcmac_rlc_v_b_mark_invalid(struct gprs_rlcmac_rlc_v_b *v_b, int bsn);


struct gprs_rlcmac_rlc_ul_window {
	struct gprs_rlcmac_rlc_window window; /* parent */
	struct gprs_rlcmac_ul_tbf *ul_tbf; /* backpointer */

	uint16_t v_s;	/* send state */
	uint16_t v_a;	/* ack state */
	struct gprs_rlcmac_rlc_v_b v_b;
};

struct gprs_rlcmac_rlc_ul_window *gprs_rlcmac_rlc_ul_window_alloc(struct gprs_rlcmac_ul_tbf *ul_tbf);
void gprs_rlcmac_rlc_ul_window_free(struct gprs_rlcmac_rlc_ul_window *ulw);

void gprs_rlcmac_rlc_ul_window_reset(struct gprs_rlcmac_rlc_ul_window *ulw);

bool gprs_rlcmac_rlc_ul_window_window_stalled(const struct gprs_rlcmac_rlc_ul_window *ulw);
bool gprs_rlcmac_rlc_ul_window_window_empty(const struct gprs_rlcmac_rlc_ul_window *ulw);

void gprs_rlcmac_rlc_ul_window_increment_send(struct gprs_rlcmac_rlc_ul_window *ulw);
void gprs_rlcmac_rlc_ul_window_raise(struct gprs_rlcmac_rlc_ul_window *ulw, int moves);

uint16_t gprs_rlcmac_rlc_ul_window_v_s(const struct gprs_rlcmac_rlc_ul_window *ulw);
uint16_t gprs_rlcmac_rlc_ul_window_v_s_mod(const struct gprs_rlcmac_rlc_ul_window *ulw, int offset);
uint16_t gprs_rlcmac_rlc_ul_window_v_a(const struct gprs_rlcmac_rlc_ul_window *ulw);
uint16_t gprs_rlcmac_rlc_ul_window_distance(const struct gprs_rlcmac_rlc_ul_window *ulw);

/* Methods to manage reception */
int gprs_rlcmac_rlc_ul_window_resend_needed(const struct gprs_rlcmac_rlc_ul_window *ulw);
unsigned int gprs_rlcmac_rlc_ul_window_mark_for_resend(struct gprs_rlcmac_rlc_ul_window *ulw);
void gprs_rlcmac_rlc_ul_window_update_ssn(struct gprs_rlcmac_rlc_ul_window *ulw, char *show_rbb,
					  uint16_t ssn, uint16_t *lost, uint16_t *received);
void gprs_rlcmac_rlc_ul_window_update(struct gprs_rlcmac_rlc_ul_window *ulw, const struct bitvec *rbb,
				      uint16_t first_bsn, uint16_t *lost, uint16_t *received);
unsigned int gprs_rlcmac_rlc_ul_window_move_window(struct gprs_rlcmac_rlc_ul_window *ulw);
void gprs_rlcmac_rlc_ul_window_show_state(const struct gprs_rlcmac_rlc_ul_window *ulw, char *show_v_b);
unsigned int gprs_rlcmac_rlc_ul_window_count_unacked(const struct gprs_rlcmac_rlc_ul_window *ulw);


static inline struct gprs_rlcmac_rlc_window *rlc_ulw_as_w(struct gprs_rlcmac_rlc_ul_window *ulw)
{
	return &ulw->window;
}

static inline const struct gprs_rlcmac_rlc_window *rlc_ulw_as_w_const(const struct gprs_rlcmac_rlc_ul_window *ulw)
{
	return &ulw->window;
}

static inline struct gprs_rlcmac_rlc_ul_window *rlc_w_as_ulw(struct gprs_rlcmac_rlc_window *w)
{
	return (struct gprs_rlcmac_rlc_ul_window *)w;
}

static inline const struct gprs_rlcmac_rlc_ul_window *rcl_w_as_ulw_const(struct gprs_rlcmac_rlc_window *w)
{
	return (const struct gprs_rlcmac_rlc_ul_window *)w;
}
