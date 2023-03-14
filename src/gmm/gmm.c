/* GPRS GMM as per 3GPP TS 24.008, TS 24.007 */
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

#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>

#include <osmocom/core/talloc.h>

#include <osmocom/gprs/gmm/gmm.h>
#include <osmocom/gprs/gmm/gmm_prim.h>
#include <osmocom/gprs/gmm/gmm_private.h>

struct gprs_gmm_ctx *g_ctx;

int osmo_gprs_gmm_init(enum osmo_gprs_gmm_location location)
{
	if (g_ctx)
		talloc_free(g_ctx);

	g_ctx = talloc_zero(NULL, struct gprs_gmm_ctx);
	g_ctx->location = location;
	INIT_LLIST_HEAD(&g_ctx->gmme_list);
	return 0;
}

struct gprs_gmm_entity *gprs_gmm_gmme_alloc(void)
{
	struct gprs_gmm_entity *gmme;

	gmme = talloc_zero(g_ctx, struct gprs_gmm_entity);
	if (!gmme)
		return NULL;

	llist_add(&gmme->list, &g_ctx->gmme_list);

	return gmme;
}

void gprs_gmm_gmme_free(struct gprs_gmm_entity *gmme)
{
	if (!gmme)
		return;

	LOGGMME(gmme, LOGL_DEBUG, "free()\n");
	llist_del(&gmme->list);
	talloc_free(gmme);
}
