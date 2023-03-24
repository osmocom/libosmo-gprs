#pragma once

/* GPRS Session Management (SM) definitions from 3GPP TS 24.008 */

#include <stdint.h>
#include <stddef.h>

/* 3GPP TS 24.008 10.5.6.1 */
#define OSMO_GPRS_SM_APN_MAXLEN	100

/* Max number of NSAPI */
#define OSMO_GPRS_SM_PDP_MAXNSAPI 16

/* 3GPP TS 24.008 10.5.6.3 Protocol configuration options */
#define OSMO_GPRS_SM_PCO_MAXLEN 253

/* 3GPP TS 24.008 10.5.6.5 Quality of service */
#define OSMO_GPRS_SM_QOS_MAXLEN 22

/* 3GPP TS 24.008 10.5.6.21 NBIFOM container (T=1,L=1,V=255 => 257) */
#define OSMO_GPRS_SM_MBIFORM_MAXLEN 255

/* TS 24.008 10.5.6.9 "LLC service access point identifier" */
enum osmo_gprs_sm_llc_sapi {
	OSMO_GPRS_SM_LLC_SAPI_UNASSIGNED = 0,
	OSMO_GPRS_SM_LLC_SAPI_SAPI3 = 3,
	OSMO_GPRS_SM_LLC_SAPI_SAPI5 = 5,
	OSMO_GPRS_SM_LLC_SAPI_SAPI9 = 9,
	OSMO_GPRS_SM_LLC_SAPI_SAPI11 = 11,
};

/* 10.5.6.4 Packet data protocol address */
enum osmo_gprs_sm_pdp_addr_ietf_type {
	OSMO_GPRS_SM_PDP_ADDR_IETF_IPV4 = 0x21, /* used in earlier version of this protocol */
	OSMO_GPRS_SM_PDP_ADDR_IETF_IPV6 = 0x57,
	OSMO_GPRS_SM_PDP_ADDR_IETF_IPV4V6 = 0x8D,
	/* All other values shall be interpreted as IPv4 address in this version of the protocol */
};

/* Use stack as MS or as network? */
enum osmo_gprs_sm_location {
	OSMO_GPRS_SM_LOCATION_UNSET,
	OSMO_GPRS_SM_LOCATION_MS,
	OSMO_GPRS_SM_LOCATION_NETWORK,
};

int osmo_gprs_sm_init(enum osmo_gprs_sm_location location);

enum osmo_gprs_sm_log_cat {
	OSMO_GPRS_SM_LOGC_SM,
	_OSMO_GPRS_SM_LOGC_MAX,
};

void osmo_gprs_sm_set_log_cat(enum osmo_gprs_sm_log_cat logc, int logc_num);
