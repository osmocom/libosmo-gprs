/* GPRS QoS definitions from 3GPP TS 24.008 sec 10.5.6.5 */
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

#include <osmocom/gprs/sm/sm_qos.h>
#include "../common/qos.h"

int16_t osmo_gprs_sm_qos_parse_qos_profile(
	struct osmo_gprs_sm_qos_profile_decoded *decoded, const uint8_t *data, size_t data_len)
{
	return gprs_qos_parse_qos_profile(decoded, data, data_len);
}

int16_t osmo_gprs_sm_qos_build_qos_profile(const struct osmo_gprs_sm_qos_profile_decoded *decoded, void *data, int data_len)
{
	return gprs_qos_build_qos_profile(decoded, data, data_len);
}
