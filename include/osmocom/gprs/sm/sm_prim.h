#pragma once

/* 3GPP TS 24.007:
 * section 6.5 "Session Management Services for GPRS-Services"
 * section 9.4 "Services provided by the LLC entity for GPRS services (GSM only)"
 * section 9.5 "Services provided by the SM for GPRS services"
 */

#include <stdint.h>
#include <stddef.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/prim.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

#include <osmocom/gprs/sm/sm.h>


struct osmo_gprs_gmm_prim;
struct osmo_gprs_sndcp_prim;

/* 3GPP TS 24.007 */
enum osmo_gprs_sm_prim_sap {
	OSMO_GPRS_SM_SAP_SMREG, /* 6.5.1 */
};
extern const struct value_string osmo_gprs_sm_prim_sap_names[];
static inline const char *osmo_gprs_sm_prim_sap_name(enum osmo_gprs_sm_prim_sap val)
{
	return get_value_string(osmo_gprs_sm_prim_sap_names, val);
}

/* 3GPP TS 24.007 Section 6.6 Registration Services for GPRS-Services */
enum osmo_gprs_sm_smreg_prim_type {
	OSMO_GPRS_SM_SMREG_PDP_ACTIVATE,	/* Req/Cnf/Rej/Ind/Rsp */
	OSMO_GPRS_SM_SMREG_PDP_DEACTIVATE,	/* Req/Cnf/Ind */
	OSMO_GPRS_SM_SMREG_PDP_MODIFY,		/* Req/Ind/Cnf/Rej */
	OSMO_GPRS_SM_SMREG_PDP_ACTIVATE_SEC,	/* Req/Cnf/Rej */
	OSMO_GPRS_SM_SMREG_MBMS_ACTIVATE,	/* Req/Cnf/Rej/Ind */
};
extern const struct value_string osmo_gprs_sm_smreg_prim_type_names[];
static inline const char *osmo_gprs_sm_smreg_prim_type_name(enum osmo_gprs_sm_smreg_prim_type val)
{
	return get_value_string(osmo_gprs_sm_smreg_prim_type_names, val);
}

/* Parameters for OSMO_GPRS_SM_SMREG_* prims */
struct osmo_gprs_sm_smreg_prim {
	/* Common fields */
	uint32_t ms_id;
	/* Specific fields */
	union {
		/* OSMO_GPRS_SM_SMREG_PDP_ACTIVATE | Req, 6.5.1.1 */
		struct {
			uint8_t nsapi;
			enum osmo_gprs_sm_llc_sapi llc_sapi;
			enum osmo_gprs_sm_pdp_addr_ietf_type pdp_addr_ietf_type;
			struct osmo_sockaddr pdp_addr_v4;
			struct osmo_sockaddr pdp_addr_v6;
			uint8_t qos[OSMO_GPRS_SM_QOS_MAXLEN];
			uint8_t qos_len;
			char apn[OSMO_GPRS_SM_APN_MAXLEN];
			uint8_t pco[OSMO_GPRS_SM_PCO_MAXLEN];
			uint8_t pco_len;
			struct {
				uint32_t ptmsi;
				bool attach_with_imsi;
				char imsi[OSMO_IMSI_BUF_SIZE];
				char imei[GSM23003_IMEI_NUM_DIGITS + 1];
				char imeisv[GSM23003_IMEISV_NUM_DIGITS+1];
			} gmm;
		} pdp_act_req;

		/* OSMO_GPRS_SM_SMREG_PDP_ACTIVATE | Cnf 6.5.1.2 / Rej 6.5.1.3 */
		struct {
			bool accepted;
			uint8_t nsapi;
			uint8_t pco[OSMO_GPRS_SM_PCO_MAXLEN];
			uint8_t pco_len;
			union {
				struct {
					enum osmo_gprs_sm_pdp_addr_ietf_type pdp_addr_ietf_type;
					struct osmo_sockaddr pdp_addr_v4;
					struct osmo_sockaddr pdp_addr_v6;
					uint8_t radio_prio;	/* TS 24.008 10.5.7.2 */
					uint8_t qos[OSMO_GPRS_SM_QOS_MAXLEN];
					uint8_t qos_len;
				} acc;
				struct {
					uint8_t cause;
				} rej;
			};
		} pdp_act_cnf;

		/* OSMO_GPRS_SM_SMREG_PDP_ACTIVATE | Ind, 6.5.1.4 */
		struct {
			struct osmo_sockaddr pdp_addr;
			char apn[OSMO_GPRS_SM_APN_MAXLEN];
			uint8_t pco[OSMO_GPRS_SM_PCO_MAXLEN];
			uint8_t pco_len;
		} pdp_act_ind;

		/* OSMO_GPRS_SM_SMREG_PDP_ACTIVATE | Rsp, 6.5.1.14 */
		struct {
			uint8_t cause;
			struct osmo_sockaddr pdp_addr;
			char apn[OSMO_GPRS_SM_APN_MAXLEN];
			uint8_t pco[OSMO_GPRS_SM_PCO_MAXLEN];
			uint8_t pco_len;
			/* TODO: MBMS protocol configuration options*/
		} pdp_act_rej_rsp;

		/* OSMO_GPRS_SM_SMREG_PDP_DEACTIVATE, 6.5.1.5 */
		struct {
			uint8_t nsapi[OSMO_GPRS_SM_PDP_MAXNSAPI];
			uint8_t num_nsapi;
			uint8_t tear_down_ind;
			uint8_t cause;
			uint8_t pco[OSMO_GPRS_SM_PCO_MAXLEN];
			uint8_t pco_len;
			/* TODO: MBMS protocol configuration options*/
		} deact_req;


		/* OSMO_GPRS_SM_SMREG_PDP_DEACTIVATE | Cnf, 6.5.1.6 */
		struct {
			uint8_t nsapi[OSMO_GPRS_SM_PDP_MAXNSAPI];
			uint8_t num_nsapi;
			uint8_t pco[OSMO_GPRS_SM_PCO_MAXLEN];
			uint8_t pco_len;
			/* TODO: MBMS protocol configuration options*/
		} deact_cnf;

		/* OSMO_GPRS_SM_SMREG_PDP_DEACTIVATE | Ind, 6.5.1.7 */
		struct {
			uint8_t nsapi[OSMO_GPRS_SM_PDP_MAXNSAPI];
			uint8_t num_nsapi;
			uint8_t tear_down_ind;
			uint8_t cause;
			uint8_t pco[OSMO_GPRS_SM_PCO_MAXLEN];
			uint8_t pco_len;
			/* TODO: MBMS protocol configuration options */
		} deact_ind;

		/* OSMO_GPRS_SM_SMREG_PDP_MODIFY | Ind, 6.5.1.8 */
		struct {
			uint8_t qos[OSMO_GPRS_SM_QOS_MAXLEN];
			uint8_t qos_len;
			uint8_t nsapi;
			uint8_t pco[OSMO_GPRS_SM_PCO_MAXLEN];
			uint8_t pco_len;
		} pdp_mod_ind;

		/* OSMO_GPRS_SM_SMREG_PDP_MODIFY | Req 6.5.1.18 */
		struct {
			uint8_t qos[OSMO_GPRS_SM_QOS_MAXLEN];
			uint8_t qos_len;
			uint8_t nsapi;
			uint8_t tft; /* TODO */
			uint8_t pco[OSMO_GPRS_SM_PCO_MAXLEN];
			uint8_t pco_len;
		} pdp_mod_req;

		/* OSMO_GPRS_SM_SMREG_PDP_MODIFY | Cnf 6.5.1.19 / Rej 6.5.1.20 */
		struct {
			bool accepted;
			uint8_t nsapi;
			uint8_t pco[OSMO_GPRS_SM_PCO_MAXLEN];
			union {
				struct {
					uint8_t qos[OSMO_GPRS_SM_QOS_MAXLEN];
					uint8_t qos_len;
				} acc;
				struct {
					uint8_t cause;
				} rej;
			};
		} pdp_mod_cnf;

		/* TODO:
		* OSMO_GPRS_SM_SMREG_PDP_ACTIVATE_SEC
		* OSMO_GPRS_SM_SMREG_MBMS_ACTIVATE
		*/
	};
};


struct osmo_gprs_sm_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_gprs_sm_smreg_prim smreg;
	};
};

typedef int (*osmo_gprs_sm_prim_up_cb)(struct osmo_gprs_sm_prim *sm_prim, void *up_user_data);
void osmo_gprs_sm_prim_set_up_cb(osmo_gprs_sm_prim_up_cb up_cb, void *up_user_data);

typedef int (*osmo_gprs_sm_prim_sndcp_up_cb)(struct osmo_gprs_sndcp_prim *sndcp_prim, void *sndcp_up_user_data);
void osmo_gprs_sm_prim_set_sndcp_up_cb(osmo_gprs_sm_prim_sndcp_up_cb sndcp_up_cb, void *sndcp_up_user_data);

typedef int (*osmo_gprs_sm_prim_down_cb)(struct osmo_gprs_sm_prim *sm_prim, void *down_user_data);
void osmo_gprs_sm_prim_set_down_cb(osmo_gprs_sm_prim_down_cb down_cb, void *down_user_data);

typedef int (*osmo_gprs_sm_prim_gmm_down_cb)(struct osmo_gprs_gmm_prim *gmm_prim, void *gmm_down_user_data);
void osmo_gprs_sm_prim_set_gmm_down_cb(osmo_gprs_sm_prim_gmm_down_cb gmm_down_cb, void *gmm_down_user_data);

int osmo_gprs_sm_prim_upper_down(struct osmo_gprs_sm_prim *sm_prim);
int osmo_gprs_sm_prim_sndcp_upper_down(struct osmo_gprs_sndcp_prim *sndcp_prim);
int osmo_gprs_sm_prim_lower_up(struct osmo_gprs_sm_prim *sm_prim);
int osmo_gprs_sm_prim_gmm_lower_up(struct osmo_gprs_gmm_prim *gmm_prim);

const char *osmo_gprs_sm_prim_name(const struct osmo_gprs_sm_prim *sm_prim);

/* Alloc primitive for SMREG SAP: */
struct osmo_gprs_sm_prim *osmo_gprs_sm_prim_alloc_smreg_pdp_act_req(void);
