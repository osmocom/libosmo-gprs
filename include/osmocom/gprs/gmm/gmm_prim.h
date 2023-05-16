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
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gprs/gmm/gmm.h>

struct osmo_gprs_llc_prim;

/* 3GPP TS 24.007 (index, "GMMR") */
enum osmo_gprs_gmm_prim_sap {
	OSMO_GPRS_GMM_SAP_GMMREG, /* 6.6 */
	OSMO_GPRS_GMM_SAP_GMMRR, /* 9.3.2, GSM only */
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

/* 3GPP TS 24.007 Section 6.6 Registration Services for GPRS-Services */
enum osmo_gprs_gmm_gmmreg_prim_type {
	OSMO_GPRS_GMM_GMMREG_ATTACH,	/* Req/Cnf/Rej */
	OSMO_GPRS_GMM_GMMREG_DETACH,	/* Req/Cnf/Ind */
	OSMO_GPRS_GMM_GMMREG_SIM_AUTH,	/* Ind/Rsp, Osmocom specific primitive */
};
extern const struct value_string osmo_gprs_gmm_gmmreg_prim_type_names[];
static inline const char *osmo_gprs_gmm_gmmreg_prim_type_name(enum osmo_gprs_gmm_gmmreg_prim_type val)
{
	return get_value_string(osmo_gprs_gmm_gmmreg_prim_type_names, val);
}

/* Attach type 10.5.5.2 */
enum osmo_gprs_gmm_attach_type {
	/* 0 is reserved */
	OSMO_GPRS_GMM_ATTACH_TYPE_GPRS = 1,
	OSMO_GPRS_GMM_ATTACH_TYPE_COMBINED_OLD = 2, /* Table 10.5.135b NOTE 1 */
	OSMO_GPRS_GMM_ATTACH_TYPE_COMBINED = 3,
	OSMO_GPRS_GMM_ATTACH_TYPE_EMERGENCY = 4,
	/* others: reserved, interpreted as OSMO_GPRS_GMM_ATTACH_TYPE_GPRS */
};
extern const struct value_string osmo_gprs_gmm_attach_type_names[];
static inline const char *osmo_gprs_gmm_attach_ms_type_name(enum osmo_gprs_gmm_attach_type val)
{
	return get_value_string(osmo_gprs_gmm_attach_type_names, val);
}

/* Detach type 10.5.5.5 */
enum osmo_gprs_gmm_detach_poweroff_type {
	/* 0 is reserved */
	OSMO_GPRS_GMM_DETACH_POWEROFF_TYPE_NORMAL = 0,
	OSMO_GPRS_GMM_DETACH_POWEROFF_TYPE_POWEROFF = 1,
};
enum osmo_gprs_gmm_detach_ms_type {
	/* 0 is reserved */
	OSMO_GPRS_GMM_DETACH_MS_TYPE_GPRS = 1,
	OSMO_GPRS_GMM_DETACH_MS_TYPE_IMSI = 2,
	OSMO_GPRS_GMM_DETACH_MS_TYPE_COMBINED = 3,
	/* others: reserved, interpreted as OSMO_GPRS_GMM_DETACH_TYPE_COMBINED */
};
extern const struct value_string osmo_gprs_gmm_detach_ms_type_names[];
static inline const char *osmo_gprs_gmm_detach_ms_type_name(enum osmo_gprs_gmm_detach_ms_type val)
{
	return get_value_string(osmo_gprs_gmm_detach_ms_type_names, val);
}

enum osmo_gprs_gmm_detach_network_type {
	/* 0 is reserved */
	OSMO_GPRS_GMM_DETACH_NETWORK_TYPE_REATTACH_REQUIRED = 1,
	OSMO_GPRS_GMM_DETACH_NETWORK_TYPE_REATTACH_NOT_REQUIRED = 2,
	OSMO_GPRS_GMM_DETACH_NETWORK_TYPE_IMSI = 3,
	/* others: reserved, interpreted as OSMO_GPRS_GMM_DETACH_TYPE_REATTACH_NOT_REQUIRED */
};
extern const struct value_string osmo_gprs_gmm_detach_network_type_names[];
static inline const char *osmo_gprs_gmm_detach_network_type_name(enum osmo_gprs_gmm_detach_network_type val)
{
	return get_value_string(osmo_gprs_gmm_detach_network_type_names, val);
}

/* Parameters for OSMO_GPRS_GMM_GMMREG_* prims */
struct osmo_gprs_gmm_gmmreg_prim {
	/* Common fields */
	/* Specific fields */
	union {
		/* OSMO_GPRS_GMM_GMMREG_ATTACH | Req, 6.6.1.1 */
		struct {
			enum osmo_gprs_gmm_attach_type attach_type;
			uint32_t ptmsi;
			bool attach_with_imsi;
			char imsi[OSMO_IMSI_BUF_SIZE];
			char imei[GSM23003_IMEI_NUM_DIGITS + 1];
			char imeisv[GSM23003_IMEISV_NUM_DIGITS+1];
			struct gprs_ra_id old_rai;
			/* READY-timer, STANDBY-timer */
		} attach_req;
		/* OSMO_GPRS_GMM_GMMREG_ATTACH | Cnf 6.6.1.2 / Rej 6.6.1.3 */
		struct {
			bool accepted;
			union {
				struct {
					/* PLMNs MT-caps, attach-type. */
					uint32_t allocated_ptmsi;
					uint32_t allocated_tlli;
				} acc;
				struct {
					uint8_t cause; /* See enum gsm48_gsm_cause */
				} rej;
			};
		} attach_cnf;
		/* OSMO_GPRS_GMM_GMMREG_DETACH | Req, 6.6.1.4 */
		struct {
			uint32_t ptmsi;
			enum osmo_gprs_gmm_detach_ms_type detach_type;
			enum osmo_gprs_gmm_detach_poweroff_type poweroff_type;
		} detach_req;
		/* OSMO_GPRS_GMM_GMMREG_DETACH | Cnf, 6.6.1.5 */
		struct {
			enum osmo_gprs_gmm_detach_ms_type detach_type;
		} detach_cnf;
		/* OSMO_GPRS_GMM_GMMREG_DETACH | Ind, 6.6.1.6 */
		struct {
			enum osmo_gprs_gmm_detach_ms_type detach_type;
		} detach_ind;
		/* OSMO_GPRS_GMM_GMMREG_SIM_AUTH | Ind, Osmocom specific */
		struct {
			uint8_t ac_ref_nr;
			uint8_t key_seq;
			uint8_t rand[16];
		} sim_auth_ind;
		/* OSMO_GPRS_GMM_GMMREG_SIM_AUTH | Rsp, Osmocom specific */
		struct {
			uint8_t ac_ref_nr; /* from ind originating rsp */
			uint8_t key_seq; /* from ind originating rsp */
			uint8_t rand[16]; /* from ind originating rsp */
			uint8_t sres[4]; /* result */
			uint8_t kc[16]; /* result */
		} sim_auth_rsp;
	};
};

/* TS 24.007 Section 9.3.2 "Service primitives for GMMRR-SAP (GSM only)"
 * Same as enum osmo_gprs_rlcmac_gmmrr_prim_type.
 */
enum osmo_gprs_gmm_gmmrr_prim_type {
	OSMO_GPRS_GMM_GMMRR_ASSIGN,	/* Req: newTLLI  */
	OSMO_GPRS_GMM_GMMRR_PAGE,	/* Ind: TLLI */
};
extern const struct value_string osmo_gprs_gmm_gmmrr_prim_type_names[];
static inline const char *osmo_gprs_gmm_gmmrr_prim_type_name(enum osmo_gprs_gmm_gmmrr_prim_type val)
{
	return get_value_string(osmo_gprs_gmm_gmmrr_prim_type_names, val);
}

/* Parameters for OSMO_GPRS_GMM_GMMRR_* prims
 * Same as struct osmo_gprs_rlcmac_gmmrr_prim.
 */
struct osmo_gprs_gmm_gmmrr_prim {
	/* Common fields */
	uint32_t tlli;
	union {
		/* OSMO_GPRS_GMM_GMMRR_ASSIGN | Req */
		struct {
			uint32_t new_tlli;
		} assign_req;
		/* OSMO_GPRS_GMM_GMMRR_PAGE | Ind */
		struct {
		} page_ind;
	};
};

/* TS 24.007 Section 9.5.1 "Service primitives for GMMSM-SAP"
 */
enum osmo_gprs_gmm_gmmsm_prim_type {
	OSMO_GPRS_GMM_GMMSM_ESTABLISH,	/* Req, Cnf/Rej */
	OSMO_GPRS_GMM_GMMSM_RELEASE,	/* Ind */
	OSMO_GPRS_GMM_GMMSM_UNITDATA,	/* Req, Ind */
};
extern const struct value_string osmo_gprs_gmm_gmmsm_prim_type_names[];
static inline const char *osmo_gprs_gmm_gmmsm_prim_type_name(enum osmo_gprs_gmm_gmmsm_prim_type val)
{
	return get_value_string(osmo_gprs_gmm_gmmsm_prim_type_names, val);
}

/* Parameters for OSMO_GPRS_GMM_GMMSM_* prims
 */
struct osmo_gprs_gmm_gmmsm_prim {
	/* Common fields */
	uint32_t sess_id;
	union {
		/* OSMO_GPRS_GMM_GMMSM_ESTABLISH | Req */
		struct {
			enum osmo_gprs_gmm_attach_type attach_type;
			uint32_t ptmsi;
			bool attach_with_imsi;
			char imsi[OSMO_IMSI_BUF_SIZE];
			char imei[GSM23003_IMEI_NUM_DIGITS + 1];
			char imeisv[GSM23003_IMEISV_NUM_DIGITS+1];
			struct gprs_ra_id old_rai;
			/* READY-timer, STANDBY-timer */
		} establish_req;
		/* OSMO_GPRS_GMM_GMMSM_ESTABLISH | Cnf/Rej */
		struct {
			bool accepted;
			union {
				struct {
					/* PLMNs MT-caps, attach-type. */
					uint32_t allocated_ptmsi;
					uint32_t allocated_tlli;
				} acc;
				struct {
					uint8_t cause;
				} rej;
			};
		} establish_cnf;
		/* OSMO_GPRS_GMM_GMMSM_RELEASE | Ind */
		struct {
		} release_ind;
		/* OSMO_GPRS_GMM_GMMSM_UNITDATA | Req */
		struct {
			uint8_t *smpdu;
			uint16_t smpdu_len;
		} unitdata_req;
		/* OSMO_GPRS_GMM_GMMSM_UNITDATA | Ind */
		struct {
			uint8_t *smpdu;
			uint16_t smpdu_len;
		} unitdata_ind;
	};
};

struct osmo_gprs_gmm_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_gprs_gmm_gmmreg_prim gmmreg;
		struct osmo_gprs_gmm_gmmrr_prim gmmrr;
		struct osmo_gprs_gmm_gmmsm_prim gmmsm;
	};
};

typedef int (*osmo_gprs_gmm_prim_up_cb)(struct osmo_gprs_gmm_prim *gmm_prim, void *up_user_data);
void osmo_gprs_gmm_prim_set_up_cb(osmo_gprs_gmm_prim_up_cb up_cb, void *up_user_data);

typedef int (*osmo_gprs_gmm_prim_down_cb)(struct osmo_gprs_gmm_prim *gmm_prim, void *down_user_data);
void osmo_gprs_gmm_prim_set_down_cb(osmo_gprs_gmm_prim_down_cb down_cb, void *down_user_data);


typedef int (*osmo_gprs_gmm_prim_llc_down_cb)(struct osmo_gprs_llc_prim *llc_prim, void *llc_down_user_data);
void osmo_gprs_gmm_prim_set_llc_down_cb(osmo_gprs_gmm_prim_llc_down_cb llc_down_cb, void *llc_down_user_data);

int osmo_gprs_gmm_prim_upper_down(struct osmo_gprs_gmm_prim *gmm_prim);
int osmo_gprs_gmm_prim_lower_up(struct osmo_gprs_gmm_prim *gmm_prim);
int osmo_gprs_gmm_prim_llc_lower_up(struct osmo_gprs_llc_prim *llc_prim);

const char *osmo_gprs_gmm_prim_name(const struct osmo_gprs_gmm_prim *gmm_prim);

/* Alloc primitive for GMMREG SAP: */
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmreg_attach_req(void);
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmreg_detach_req(void);
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmreg_sim_auth_rsp(void);

/* Alloc primitive for GMMRR SAP: */
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmrr_page_ind(uint32_t tlli);

/* Alloc primitive for GMMSM SAP: */
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmsm_establish_req(uint32_t id);
struct osmo_gprs_gmm_prim *osmo_gprs_gmm_prim_alloc_gmmsm_unitdata_req(uint32_t id, uint8_t *smpdu, unsigned int smpdu_len);
