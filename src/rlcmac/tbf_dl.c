/* Downlink TBF as per 3GPP TS 44.064 */
/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <osmocom/core/logging.h>

#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/gre.h>

struct gprs_rlcmac_dl_tbf *gprs_rlcmac_dl_tbf_alloc(struct gprs_rlcmac_entity *gre)
{
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	int rc;

	dl_tbf = talloc_zero(gre, struct gprs_rlcmac_dl_tbf);
	if (!dl_tbf)
		return NULL;

	gprs_rlcmac_tbf_constructor(dl_tbf_as_tbf(dl_tbf), GPRS_RLCMAC_TBF_DIR_DL, gre);

	rc = gprs_rlcmac_tbf_dl_fsm_constructor(dl_tbf);
	if (rc < 0)
		goto err_tbf_destruct;

	dl_tbf->tbf.nr = g_ctx->next_dl_tbf_nr++;

	return dl_tbf;
err_tbf_destruct:
	gprs_rlcmac_tbf_destructor(dl_tbf_as_tbf(dl_tbf));
	talloc_free(dl_tbf);
	return NULL;
}

void gprs_rlcmac_dl_tbf_free(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	if (!dl_tbf)
		return;

	//gprs_rlcmac_tbf_dl_fsm_destructor(dl_tbf);

	gprs_rlcmac_tbf_destructor(dl_tbf_as_tbf(dl_tbf));
	talloc_free(dl_tbf);
}


static uint8_t dl_tbf_dl_slotmask(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	uint8_t i;
	uint8_t dl_slotmask = 0;

	for (i = 0; i < 8; i++) {
		if (dl_tbf->cur_alloc.ts[i].allocated)
			dl_slotmask |= (1 << i);
	}

	return dl_slotmask;
}

int gprs_rlcmac_dl_tbf_configure_l1ctl(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	struct osmo_gprs_rlcmac_prim *rlcmac_prim;
	uint8_t dl_slotmask = dl_tbf_dl_slotmask(dl_tbf);

	 LOGPTBFDL(dl_tbf, LOGL_INFO, "Send L1CTL-CF_DL_TBF.req dl_slotmask=0x%02x dl_tfi=%u\n",
		   dl_slotmask, dl_tbf->cur_alloc.dl_tfi);
	rlcmac_prim = gprs_rlcmac_prim_alloc_l1ctl_cfg_dl_tbf_req(dl_tbf->tbf.nr,
								  dl_slotmask,
								  dl_tbf->cur_alloc.dl_tfi);
	return gprs_rlcmac_prim_call_down_cb(rlcmac_prim);
}
