/* RLC Window (common for both UL/DL TBF), 3GPP TS 44.060 */
#pragma once

#include <stdint.h>

#include <osmocom/core/bitvec.h>

#include <osmocom/gprs/rlcmac/rlc.h>
#include <osmocom/gprs/rlcmac/rlc_window.h>

struct gprs_rlcmac_dl_tbf;

enum gprs_rlcmac_rlc_dl_bsn_state {
	GPRS_RLCMAC_RLC_DL_BSN_INVALID,
	GPRS_RLCMAC_RLC_DL_BSN_RECEIVED,
	GPRS_RLCMAC_RLC_DL_BSN_MISSING,
	GPRS_RLCMAC_RLC_DL_BSN_MAX,
};

struct gprs_rlcmac_rlc_v_n {
	enum gprs_rlcmac_rlc_dl_bsn_state v_n[RLC_MAX_SNS/2]; /* receive state array */
};

void gprs_rlcmac_rlc_v_n_reset(struct gprs_rlcmac_rlc_v_n *v_n);
enum gprs_rlcmac_rlc_dl_bsn_state gprs_rlcmac_rlc_v_n_get_state(const struct gprs_rlcmac_rlc_v_n *v_n, int bsn);
bool gprs_rlcmac_rlc_v_n_is_received(const struct gprs_rlcmac_rlc_v_n *v_n, int bsn);

/* Mark a RLC frame for something */
void gprs_rlcmac_rlc_v_n_mark_received(struct gprs_rlcmac_rlc_v_n *v_n, int bsn);
void gprs_rlcmac_rlc_v_n_mark_missing(struct gprs_rlcmac_rlc_v_n *v_n, int bsn);


struct gprs_rlcmac_rlc_dl_window {
	struct gprs_rlcmac_rlc_window window; /* parent */
	struct gprs_rlcmac_dl_tbf *dl_tbf; /* backpointer */

	uint16_t v_r;	/* send state */
	uint16_t v_q;	/* ack state */
	struct gprs_rlcmac_rlc_v_n v_n;
};

struct gprs_rlcmac_rlc_dl_window *gprs_rlcmac_rlc_dl_window_alloc(struct gprs_rlcmac_dl_tbf *dl_tbf);
void gprs_rlcmac_rlc_dl_window_free(struct gprs_rlcmac_rlc_dl_window *dlw);

void gprs_rlcmac_rlc_dl_window_reset(struct gprs_rlcmac_rlc_dl_window *dlw);

uint16_t gprs_rlcmac_rlc_dl_window_v_r(const struct gprs_rlcmac_rlc_dl_window *dlw);
uint16_t gprs_rlcmac_rlc_dl_window_v_q(const struct gprs_rlcmac_rlc_dl_window *dlw);

void gprs_rlcmac_rlc_dl_window_set_v_r(struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t v_r);
void gprs_rlcmac_rlc_dl_window_set_v_q(struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t v_q);

bool gprs_rlcmac_rlc_dl_window_is_in_window(const struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t bsn);
bool gprs_rlcmac_rlc_dl_window_is_received(const struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t bsn);

void gprs_rlcmac_rlc_dl_window_update_rbb(const struct gprs_rlcmac_rlc_dl_window *dlw, char *rbb);
uint16_t gprs_rlcmac_rlc_dl_window_update_rbb_egprs(const struct gprs_rlcmac_rlc_dl_window *dlw, uint8_t *rbb);

void gprs_rlcmac_rlc_dl_window_raise_v_r_to(struct gprs_rlcmac_rlc_dl_window *dlw, int moves);
void gprs_rlcmac_rlc_dl_window_raise_v_q_to(struct gprs_rlcmac_rlc_dl_window *dlw, int incr);
void gprs_rlcmac_rlc_dl_window_raise_v_r(struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t bsn);
uint16_t gprs_rlcmac_rlc_dl_window_raise_v_q(struct gprs_rlcmac_rlc_dl_window *dlw);

void gprs_rlcmac_rlc_dl_window_receive_bsn(struct gprs_rlcmac_rlc_dl_window *dlw, uint16_t bsn);

static inline uint16_t gprs_rlcmac_rlc_dl_window_ssn(const struct gprs_rlcmac_rlc_dl_window *dlw)
{
	return gprs_rlcmac_rlc_dl_window_v_r(dlw);
}

static inline struct gprs_rlcmac_rlc_window *rlc_dlw_as_w(struct gprs_rlcmac_rlc_dl_window *dlw)
{
	return &dlw->window;
}

static inline const struct gprs_rlcmac_rlc_window *rlc_dlw_as_w_const(const struct gprs_rlcmac_rlc_dl_window *dlw)
{
	return &dlw->window;
}

static inline struct gprs_rlcmac_rlc_dl_window *rlc_w_as_dlw(struct gprs_rlcmac_rlc_window *w)
{
	return (struct gprs_rlcmac_rlc_dl_window *)w;
}

static inline const struct gprs_rlcmac_rlc_dl_window *rcl_w_as_dlw_const(struct gprs_rlcmac_rlc_window *w)
{
	return (const struct gprs_rlcmac_rlc_dl_window *)w;
}
