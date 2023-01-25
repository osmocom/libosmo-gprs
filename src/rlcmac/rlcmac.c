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

#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/rlcmac_prim.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>

struct gprs_rlcmac_ctx *g_ctx;

int osmo_gprs_rlcmac_init(enum osmo_gprs_rlcmac_location location)
{
	OSMO_ASSERT(location == OSMO_GPRS_RLCMAC_LOCATION_MS || location == OSMO_GPRS_RLCMAC_LOCATION_PCU)

	if (g_ctx)
		talloc_free(g_ctx);

	g_ctx = talloc_zero(NULL, struct gprs_rlcmac_ctx);
	g_ctx->location = location;

	return 0;
}
