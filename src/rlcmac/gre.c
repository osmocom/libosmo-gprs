/* GPRS RLC/MAC Entity (one per MS) */
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

#include <stdbool.h>

#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/rlcmac_prim.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/tbf_ul_fsm.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/gre.h>

struct gprs_rlcmac_entity *gprs_rlcmac_entity_alloc(uint32_t tlli)
{
	struct gprs_rlcmac_entity *gre;

	gre = talloc_zero(g_ctx, struct gprs_rlcmac_entity);
	if (!gre)
		return NULL;

	gre->llc_queue = gprs_rlcmac_llc_queue_alloc(gre);
	if (!gre->llc_queue)
		goto err_free_gre;
	gprs_rlcmac_llc_queue_set_codel_params(gre->llc_queue,
					       g_ctx->cfg.codel.use,
					       g_ctx->cfg.codel.interval_msec);

	gre->tlli = tlli;
	llist_add_tail(&gre->entry, &g_ctx->gre_list);

	return gre;

err_free_gre:
	talloc_free(gre);
	return NULL;
}

void gprs_rlcmac_entity_free(struct gprs_rlcmac_entity *gre)
{
	if (!gre)
		return;

	gprs_rlcmac_dl_tbf_free(gre->dl_tbf);
	gprs_rlcmac_ul_tbf_free(gre->ul_tbf);
	gprs_rlcmac_llc_queue_free(gre->llc_queue);
	llist_del(&gre->entry);
	talloc_free(gre);
}

int gprs_rlcmac_entity_llc_enqueue(struct gprs_rlcmac_entity *gre, uint8_t *ll_pdu, unsigned int ll_pdu_len,
				   enum osmo_gprs_rlcmac_llc_sapi sapi, uint8_t radio_prio)
{
	int rc;
	rc = gprs_rlcmac_llc_queue_enqueue(gre->llc_queue, ll_pdu, ll_pdu_len,
					   sapi, radio_prio);
	if (rc < 0)
		return rc;

	if (!gre->ul_tbf) {
		/* We have new data in the queue but we have no ul_tbf. Allocate one and start UL Assignment. */
		gre->ul_tbf = gprs_rlcmac_ul_tbf_alloc(gre);
		if (!gre->ul_tbf)
			return -ENOMEM;
		/* We always use 1phase for now... */
		rc = gprs_rlcmac_tbf_ul_ass_start(gre->ul_tbf, GPRS_RLCMAC_TBF_UL_ASS_TYPE_1PHASE);
	}

	return rc;
}
