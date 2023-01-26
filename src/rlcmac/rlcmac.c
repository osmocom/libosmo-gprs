/* GPRS RLCMAC as per 3GPP TS 44.060 */
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
#include <osmocom/gprs/rlcmac/gre.h>

#define GPRS_CODEL_SLOW_INTERVAL_MS 4000

struct gprs_rlcmac_ctx *g_ctx;

int osmo_gprs_rlcmac_init(enum osmo_gprs_rlcmac_location location)
{
	OSMO_ASSERT(location == OSMO_GPRS_RLCMAC_LOCATION_MS || location == OSMO_GPRS_RLCMAC_LOCATION_PCU)

	if (g_ctx)
		talloc_free(g_ctx);

	g_ctx = talloc_zero(NULL, struct gprs_rlcmac_ctx);
	g_ctx->cfg.location = location;
	g_ctx->cfg.codel.use = true;
	g_ctx->cfg.codel.interval_msec = GPRS_CODEL_SLOW_INTERVAL_MS;
	INIT_LLIST_HEAD(&g_ctx->gre_list);

	return 0;
}

/*! Set CoDel parameters used in the Tx queue of LLC PDUs waiting to be transmitted.
 *  \param[in] use Whether to enable or disable use of CoDel algo.
 *  \param[in] interval_msec Interval at which CoDel triggers, in milliseconds. (0 = use default interval value)
 *  \returns 0 on success; negative on error.
 */
int osmo_gprs_rlcmac_set_codel_params(bool use, unsigned int interval_msec)
{
	if (interval_msec == 0)
		interval_msec = GPRS_CODEL_SLOW_INTERVAL_MS;

	g_ctx->cfg.codel.use = use;
	g_ctx->cfg.codel.interval_msec = interval_msec;
	return 0;
}

struct gprs_rlcmac_entity *gprs_rlcmac_find_entity_by_tlli(uint32_t tlli)
{
	struct gprs_rlcmac_entity *gre;

	llist_for_each_entry(gre, &g_ctx->gre_list, entry) {
		if (gre->tlli == tlli)
			return gre;
	}
	return NULL;
}
