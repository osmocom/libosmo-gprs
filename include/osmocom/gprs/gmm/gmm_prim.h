#pragma once

/* 3GPP TS 44.065, section 5 "Service primitives and functions" */

/* 3GPP TS 24.007:
 * section 6.6 "Registration Services for GPRS-Services"
 * section 9.4 "Services provided by the LLC entity for GPRS services (GSM only)"
 * section 9.5 "Services provided by the GMM for GPRS services"
 */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/prim.h>
#include <osmocom/gprs/gmm/gmm.h>

/* 3GPP TS 24.007 (index, "GMMR") */
enum osmo_gprs_gmm_prim_sap {
	OSMO_GPRS_GMM_SAP_GMMREG, /* 6.6 */
	OSMO_GPRS_GMM_SAP_GMMRR, /* GSM only */
	OSMO_GPRS_GMM_SAP_GMMAS, /* UMTS only */
	OSMO_GPRS_GMM_SAP_LLGMM,
	OSMO_GPRS_GMM_SAP_GMMSM,
	OSMO_GPRS_GMM_SAP_GMMSMS,
	OSMO_GPRS_GMM_SAP_GMMRABM, /* UMTS only */
	OSMO_GPRS_GMM_SAP_GMMSS,
	OSMO_GPRS_GMM_SAP_GMMSS2,
};
extern const struct value_string osmo_gprs_gmm_prim_sap_names[];
static inline const char *osmo_gprs_gmm_prim_sap_name(enum osmo_gprs_gmm_prim_sap val)
{
	return get_value_string(osmo_gprs_gmm_prim_sap_names, val);
}

/* 6.6 Registration Services for GPRS-Services */
enum osmo_gprs_gmm_gmmreg_prim_type {
	OSMO_GPRS_GMM_GMMREG_ATTACH,	/* Req/Cnf/Rej */
	OSMO_GPRS_GMM_GMMREG_DETACH,	/* Req/Cnf/Ind */
};
extern const struct value_string osmo_gprs_gmm_gmmreg_prim_type_names[];
static inline const char *osmo_gprs_gmm_gmmreg_prim_type_name(enum osmo_gprs_gmm_gmmreg_prim_type val)
{
	return get_value_string(osmo_gprs_gmm_gmmreg_prim_type_names, val);
}

/* Parameters for OSMO_GPRS_GMM_GMMREG_* prims */
struct osmo_gprs_gmm_gmmreg_prim {
	/* Common fields */
	/* Specific fields */
	union {
		/* OSMO_GPRS_GMM_GMMREG_ATTACH | Req, 6.6.1.1 */
		struct {
			/* attach-type, READY-timer, STANDBY-timer */
		} attach_req;
		/* OSMO_GPRS_GMM_GMMREG_ATTACH | Cnf 6.6.1.2 / Rej 6.6.1.3 */
		struct {
			bool accepted;
			union {
				struct {
					/* PLMNs MT-caps, attach-type. */
				} acc;
				struct {
					uint8_t cause;
				} rej;
			};
		} attach_cnf;
		/* OSMO_GPRS_GMM_GMMREG_DETACH | Req, 6.6.1.4 */
		struct {
			/* detach-type, power-off/normal-detach  */
		} detach_req;
		/* OSMO_GPRS_GMM_GMMREG_DETACH | Cnf, 6.6.1.5 */
		struct {
			/* detach-type */
		} detach_cnf;
		/* OSMO_GPRS_GMM_GMMREG_DETACH | Ind, , 6.6.1.6 */
		struct {
			/* detach-type */
		} detach_ind;
	};
};

struct osmo_gprs_gmm_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_gprs_gmm_gmmreg_prim gmmreg;
	};
};

typedef int (*osmo_gprs_gmm_prim_up_cb)(struct osmo_gprs_gmm_prim *gmm_prim, void *up_user_data);
void osmo_gprs_gmm_prim_set_up_cb(osmo_gprs_gmm_prim_up_cb up_cb, void *up_user_data);

typedef int (*osmo_gprs_gmm_prim_down_cb)(struct osmo_gprs_gmm_prim *gmm_prim, void *down_user_data);
void osmo_gprs_gmm_prim_set_down_cb(osmo_gprs_gmm_prim_down_cb down_cb, void *down_user_data);

int osmo_gprs_gmm_prim_upper_down(struct osmo_gprs_gmm_prim *gmm_prim);
int osmo_gprs_gmm_prim_lower_up(struct osmo_gprs_gmm_prim *gmm_prim);

const char *osmo_gprs_gmm_prim_name(const struct osmo_gprs_gmm_prim *gmm_prim);

/* Alloc primitive for GMMREG SAP: */
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmreg_attach_req(void);
