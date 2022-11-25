/* GPRS LLC LLGM SAP as per 3GPP TS 44.064 7.2.3 */
/*
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/gprs/llc/llc.h>
#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/llc/llc_private.h>

const struct value_string osmo_gprs_llc_grr_prim_type_names[] = {
	{ OSMO_GPRS_LLC_GRR_DATA,		"DATA" },
	{ OSMO_GPRS_LLC_GRR_UNITDATA,		"UNITDATA" },
	{ 0, NULL }
};

static int llc_prim_handle_grr_data_ind(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc = gprs_llc_prim_handle_unsupported(llc_prim);
	return rc;
}

static int llc_prim_handle_grr_unitdata_ind(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc = gprs_llc_prim_handle_unsupported(llc_prim);
	return rc;
}


int gprs_llc_prim_lower_up_grr(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;

	switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_LLC_GRR_DATA, PRIM_OP_INDICATION):
		rc = llc_prim_handle_grr_data_ind(llc_prim);
		break;
	case OSMO_PRIM(OSMO_GPRS_LLC_GRR_UNITDATA, PRIM_OP_INDICATION):
		rc = llc_prim_handle_grr_unitdata_ind(llc_prim);
		break;
	default:
		rc = -ENOTSUP;
	}
	return rc;
}
