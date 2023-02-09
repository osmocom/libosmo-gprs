/* Downlink TBF, 3GPP TS 44.060 */
#pragma once

#include <inttypes.h>

#include <osmocom/core/msgb.h>

#include <osmocom/gprs/rlcmac/tbf.h>
#include <osmocom/gprs/rlcmac/tbf_dl_fsm.h>
#include <osmocom/gprs/rlcmac/coding_scheme.h>
#include <osmocom/gprs/rlcmac/sched.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>

struct gprs_rlcmac_dl_tbf {
	struct gprs_rlcmac_tbf tbf;
	struct gprs_rlcmac_tbf_dl_fsm_ctx state_fsm;

	/* Current TS/TFI/USF allocated by the PCU: */
	struct gprs_rlcmac_dl_tbf_allocation cur_alloc;
};

struct gprs_rlcmac_dl_tbf *gprs_rlcmac_dl_tbf_alloc(struct gprs_rlcmac_entity *gre);
void gprs_rlcmac_dl_tbf_free(struct gprs_rlcmac_dl_tbf *dl_tbf);

int gprs_rlcmac_dl_tbf_configure_l1ctl(struct gprs_rlcmac_dl_tbf *dl_tbf);

static inline struct gprs_rlcmac_tbf *dl_tbf_as_tbf(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	return &dl_tbf->tbf;
}

static inline const struct gprs_rlcmac_tbf *dl_tbf_as_tbf_const(const struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	return &dl_tbf->tbf;
}

static inline struct gprs_rlcmac_dl_tbf *tbf_as_dl_tbf(struct gprs_rlcmac_tbf *tbf)
{
	OSMO_ASSERT(tbf->direction == GPRS_RLCMAC_TBF_DIR_DL);
	return (struct gprs_rlcmac_dl_tbf *)tbf;
}

static inline const struct gprs_rlcmac_dl_tbf *tbf_as_dl_tbf_const(struct gprs_rlcmac_tbf *tbf)
{
	OSMO_ASSERT(tbf->direction == GPRS_RLCMAC_TBF_DIR_DL);
	return (const struct gprs_rlcmac_dl_tbf *)tbf;
}

#define LOGPTBFDL(dl_tbf, lvl, fmt, args...) \
	LOGP(g_rlcmac_log_cat[OSMO_GPRS_RLCMAC_LOGC_TBFUL], lvl, "TBF(DL:NR-%" PRIu8 ":TLLI-%08x) " fmt, \
	(dl_tbf)->tbf.nr, (dl_tbf)->tbf.gre->tlli, \
	## args)
