/* TBF as per 3GPP TS 44.064 */
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

#include <osmocom/gprs/rlcmac/tbf.h>
#include <osmocom/gprs/rlcmac/tbf_ul.h>
#include <osmocom/gprs/rlcmac/tbf_dl.h>
#include <osmocom/gprs/rlcmac/gre.h>
#include <osmocom/gprs/rlcmac/pdch_ul_controller.h>

void gprs_rlcmac_tbf_constructor(struct gprs_rlcmac_tbf *tbf,
				 enum gprs_rlcmac_tbf_direction direction,
				 struct gprs_rlcmac_entity *gre)
{
	tbf->gre = gre;
	tbf->direction = direction;
}

void gprs_rlcmac_tbf_destructor(struct gprs_rlcmac_tbf *tbf)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(g_rlcmac_ctx->sched.ulc); i++)
		gprs_rlcmac_pdch_ulc_release_tbf(g_rlcmac_ctx->sched.ulc[i], tbf);
}

/* Comodity function to call required ul/dl tbf function: */
void gprs_rlcmac_tbf_free(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->direction == GPRS_RLCMAC_TBF_DIR_UL)
		gprs_rlcmac_ul_tbf_free(tbf_as_ul_tbf(tbf));
	else
		gprs_rlcmac_dl_tbf_free(tbf_as_dl_tbf(tbf));
}
