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
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/gprs/gmm/gmm.h>
#include <osmocom/gprs/gmm/gmm_prim.h>
#include <osmocom/gprs/gmm/gmm_private.h>
#include <osmocom/gprs/gmm/gmm_ms_fsm.h>
#include <osmocom/gprs/gmm/gmm_pdu.h>


struct gprs_gmm_ctx *g_gmm_ctx;

/* Section 11.2.2 / Table 11.3 GPRS Mobility management timers - MS side */
#define GSM0408_T3310_SECS	15
#define GSM0408_T3311_SECS	15
#define GSM0408_T3316_SECS	30
#define GSM0408_T3318_SECS	20
#define GSM0408_T3320_SECS	15
#define GSM0408_T3321_SECS	15
#define GSM0408_T3330_SECS	15
#define GSM0408_T3340_SECS	10

/* Section 11.2.2 / Table 11.3a GPRS Mobility management timers – MS side */
#define GSM0408_T3302_SECS	(12 * 60)
#define GSM0408_T3312_SECS	(54 * 60)
#define GSM0408_T3314_SECS	44
#define GSM0408_T3317_SECS	15
#define GSM0408_T3319_SECS	30
#define GSM0408_T3323_SECS	GSM0408_T3312_SECS /* NOTE 6 */
#define GSM0408_T3325_SECS	60
#define GSM0408_T3346_SECS	(15*60)

/* TS 24.008 */
static struct osmo_tdef T_defs_gmm[] = {
	{ .T=3302, .default_val=GSM0408_T3302_SECS, .desc = "" },
	{ .T=3310, .default_val=GSM0408_T3310_SECS, .desc = "Tattach" },
	{ .T=3311, .default_val=GSM0408_T3311_SECS, .desc = "" },
	{ .T=3312, .default_val=GSM0408_T3312_SECS, .desc = "Periodic RA Update timer (s)" },
	{ .T=3314, .default_val=GSM0408_T3314_SECS, .desc = "READY timer. Forced to STANDBY on expiry timer (s)" },
	{ .T=3316, .default_val=GSM0408_T3316_SECS, .desc = "AA-Ready timer (s)" },
	{ .T=3317, .default_val=GSM0408_T3317_SECS, .desc = "" },
	{ .T=3318, .default_val=GSM0408_T3318_SECS, .desc = "" },
	{ .T=3319, .default_val=GSM0408_T3319_SECS, .desc = "" },
	{ .T=3320, .default_val=GSM0408_T3320_SECS, .desc = "" },
	{ .T=3321, .default_val=GSM0408_T3321_SECS, .desc = "" },
	{ .T=3323, .default_val=GSM0408_T3323_SECS, .desc = "" },
	{ .T=3324, .default_val=0 /* provided by the network */, .desc = "" },
	{ .T=3325, .default_val=GSM0408_T3323_SECS, .desc = "" },
	{ .T=3330, .default_val=GSM0408_T3330_SECS, .desc = "" },
	{ .T=3340, .default_val=GSM0408_T3340_SECS, .desc = "" },
	{ .T=3346, .default_val=GSM0408_T3346_SECS /* updated by netowrk */, .desc = "" },
	{ 0 } /* empty item at the end */
};

const struct value_string gprs_gmm_upd_type_names[] = {
	{ GPRS_GMM_UPD_TYPE_RA,	"RA updating" },
	{ GPRS_GMM_UPD_TYPE_COMBINED_RA_LA, "Combined RA/LA updating" },
	{ GPRS_GMM_UPD_TYPE_COMBINED_RA_LA_IMSI, "Combined RA/LA updating with IMSI attac" },
	{ GPRS_GMM_UPD_TYPE_PERIODIC,	"Periodic updating" },
	{ 0, NULL }
};

static void t3314_ready_timer_cb(void *data);
static void t3312_periodic_rau_timer_cb(void *data);

static void gprs_gmm_ctx_free(void)
{
	struct gprs_gmm_entity *gmme;

	while ((gmme = llist_first_entry_or_null(&g_gmm_ctx->gmme_list, struct gprs_gmm_entity, list)))
		gprs_gmm_gmme_free(gmme);

	talloc_free(g_gmm_ctx);
}

int osmo_gprs_gmm_init(enum osmo_gprs_gmm_location location)
{
	bool first_init = true;
	int rc;
	OSMO_ASSERT(location == OSMO_GPRS_GMM_LOCATION_MS || location == OSMO_GPRS_GMM_LOCATION_NETWORK)

	if (g_gmm_ctx) {
		first_init = false;
		gprs_gmm_ctx_free();
	}

	g_gmm_ctx = talloc_zero(NULL, struct gprs_gmm_ctx);
	g_gmm_ctx->location = location;
	g_gmm_ctx->T_defs = T_defs_gmm;
	INIT_LLIST_HEAD(&g_gmm_ctx->gmme_list);

	osmo_tdefs_reset(g_gmm_ctx->T_defs);

	if (first_init) {
		rc = gprs_gmm_ms_fsm_init();
		if (rc != 0) {
			TALLOC_FREE(g_gmm_ctx);
			return rc;
		}
	}
	return 0;
}

/* Whether GPRS is enabled on the phone.
 * See transition GMM-NULL <-> GMM-* in
 * "Figure 4.1b/3GPP TS 24.008:GMM main states in the MS" */
void osmo_gprs_gmm_enable_gprs(bool enable_gprs)
{
	struct gprs_gmm_entity *gmme;
	int ev;

	if (g_gmm_ctx->gprs_enabled == enable_gprs)
		return;

	g_gmm_ctx->gprs_enabled = enable_gprs;

	/* Inform all existing MS: */
	ev = enable_gprs ? GPRS_GMM_MS_EV_ENABLE_GPRS_MODE :
			   GPRS_GMM_MS_EV_DISABLE_GPRS_MODE;
	llist_for_each_entry(gmme, &g_gmm_ctx->gmme_list, list)
		osmo_fsm_inst_dispatch(gmme->ms_fsm.fi, ev, NULL);
}

struct gprs_gmm_entity *gprs_gmm_gmme_alloc(uint32_t ptmsi, const char *imsi)
{
	struct gprs_gmm_entity *gmme;

	gmme = talloc_zero(g_gmm_ctx, struct gprs_gmm_entity);
	if (!gmme)
		return NULL;

	if (gprs_gmm_ms_fsm_ctx_init(&gmme->ms_fsm, gmme) < 0) {
		talloc_free(gmme);
		return NULL;
	}

	gmme->sess_id = GPRS_GMM_SESS_ID_UNASSIGNED;
	gmme->ptmsi_sig = GSM_RESERVED_TMSI;
	gmme->ptmsi = ptmsi;
	gmme->old_ptmsi = GSM_RESERVED_TMSI;
	gmme->old_tlli = GPRS_GMM_TLLI_UNASSIGNED;
	gmme->auth_ciph.req.ac_ref_nr = 0xff; /* invalid value */
	OSMO_STRLCPY_ARRAY(gmme->imsi, imsi);

	/* TS 24.008 4.7.1.4.1:
	 * - If the MS has stored a valid P-TMSI, the MS shall derive a foreign TLLI
	 *   from that P-TMSI
	 * - When the MS has not stored a valid P-TMSI, i.e. the MS is not
	 *   attached to GPRS, the MS shall use a randomly selected random TLLI
	 */
	if (gmme->ptmsi == GSM_RESERVED_TMSI)
		gmme->tlli = gprs_gmm_alloc_rand_tlli();
	else
		gmme->tlli = gprs_tmsi2tlli(gmme->ptmsi, TLLI_FOREIGN);

	/* Initialize timers to default values. They may be overwritten by the
	 * network later on: */
	gmme->t3302 = osmo_tdef_get(g_gmm_ctx->T_defs, 3302, OSMO_TDEF_S, -1);
	gmme->t3346 = osmo_tdef_get(g_gmm_ctx->T_defs, 3346, OSMO_TDEF_S, -1);

	osmo_timer_setup(&gmme->t3314, t3314_ready_timer_cb, gmme);
	osmo_timer_setup(&gmme->t3312, t3312_periodic_rau_timer_cb, gmme);

	llist_add(&gmme->list, &g_gmm_ctx->gmme_list);

	return gmme;
}

void gprs_gmm_gmme_free(struct gprs_gmm_entity *gmme)
{
	if (!gmme)
		return;

	LOGGMME(gmme, LOGL_DEBUG, "free()\n");
	if (osmo_timer_pending(&gmme->t3314))
		osmo_timer_del(&gmme->t3314);
	if (osmo_timer_pending(&gmme->t3312))
		osmo_timer_del(&gmme->t3312);
	gprs_gmm_ms_fsm_ctx_release(&gmme->ms_fsm);
	llist_del(&gmme->list);
	talloc_free(gmme);
}

struct gprs_gmm_entity *gprs_gmm_gmme_find_or_create_by_ptmsi_imsi(uint32_t ptmsi, const char *imsi)
{
	struct gprs_gmm_entity *gmme = NULL;

	if (ptmsi != GSM_RESERVED_TMSI)
		gmme = gprs_gmm_find_gmme_by_ptmsi(ptmsi);
	if (!gmme) {
		gmme = gprs_gmm_find_gmme_by_imsi(imsi);
		if (!gmme)
			gmme = gprs_gmm_gmme_alloc(ptmsi, imsi);
	}
	OSMO_ASSERT(gmme);
	return gmme;
}

struct gprs_gmm_entity *gprs_gmm_find_gmme_by_ptmsi(uint32_t ptmsi)
{
	struct gprs_gmm_entity *gmme;

	llist_for_each_entry(gmme, &g_gmm_ctx->gmme_list, list) {
		if (gmme->ptmsi == ptmsi || gmme->old_ptmsi == ptmsi)
			return gmme;
	}
	return NULL;
}

struct gprs_gmm_entity *gprs_gmm_find_gmme_by_imsi(const char *imsi)
{
	struct gprs_gmm_entity *gmme;

	llist_for_each_entry(gmme, &g_gmm_ctx->gmme_list, list) {
		if (strncmp(gmme->imsi, imsi, ARRAY_SIZE(gmme->imsi)) == 0)
			return gmme;
	}
	return NULL;
}

struct gprs_gmm_entity *gprs_gmm_find_gmme_by_tlli(uint32_t tlli)
{
	struct gprs_gmm_entity *gmme;

	llist_for_each_entry(gmme, &g_gmm_ctx->gmme_list, list) {
		if (gmme->tlli == tlli || gmme->old_tlli == tlli)
			return gmme;
	}
	return NULL;
}

struct gprs_gmm_entity *gprs_gmm_find_gmme_by_sess_id(uint32_t id)
{
	struct gprs_gmm_entity *gmme;

	llist_for_each_entry(gmme, &g_gmm_ctx->gmme_list, list) {
		if (gmme->sess_id == id)
			return gmme;
	}
	return NULL;
}

uint32_t gprs_gmm_alloc_rand_tlli(void)
{
	/* 3GPP TS 23.003 Table 1: Type of TLLI = Random TLLI_
	 * | 31 | 30 | 29 | 28 | 27 | 26 to 0 |
	 *   0	| 1  | 1  | 1  | 1  | R       | => prefix = 0x78000000
	 */
	uint32_t tlli;
	int max_retries = 134217728; /* 2^27 */
	int rc = 0;

	do {
		rc = osmo_get_rand_id((uint8_t *) &tlli, sizeof(tlli));
		if (rc < 0)
			goto failed;

		/* Remove first bits 27-31: */
		tlli &= ~0xf8000000;
		/* Apply proper prefix: */
		tlli |= 0x78000000;

		if (!gprs_gmm_find_gmme_by_tlli(tlli)) {
			LOGGMM(LOGL_INFO, "Allocated new random TLLI=0x%08x\n", tlli);
			return tlli;
		}
	} while (max_retries--);

	rc = -ERANGE;
failed:
	LOGGMM(LOGL_ERROR, "Failed to allocate a TLLI: %d (%s)\n", rc, strerror(-rc));
	return GPRS_GMM_TLLI_UNASSIGNED;
}

/* TS 24.008 4.7.2.1.1 READY timer behaviour (A/Gb mode only) */
/* Ready timer is started: */
void gprs_gmm_gmme_ready_timer_start(struct gprs_gmm_entity *gmme)
{
	if (gmme->t3314_assigned_sec == 0)
		return;
	LOGGMME(gmme, LOGL_INFO, "READY timer started (expires in %lu seconds)\n", gmme->t3314_assigned_sec);
	osmo_timer_schedule(&gmme->t3314, gmme->t3314_assigned_sec, 0);

	/* "Timer T3312 is stopped and shall be set to its initial value
	 * for the next start when the READY timer is started.": */
	gprs_gmm_gmme_t3312_stop(gmme);
}

/* Ready timer is stopped: */
void gprs_gmm_gmme_ready_timer_stop(struct gprs_gmm_entity *gmme)
{
	if (!osmo_timer_pending(&gmme->t3314))
		return;
	LOGGMME(gmme, LOGL_INFO, "READY timer stopped\n");
	osmo_timer_del(&gmme->t3314);

	/* "In A/Gb mode, the timer T3312 is reset and started with its
	 * initial value, when the READY timer is stopped or expires."
	 */
	gprs_gmm_gmme_t3312_start(gmme);
}

bool gprs_gmm_gmme_ready_timer_running(const struct gprs_gmm_entity *gmme)
{
	return osmo_timer_pending(&gmme->t3314);
}

/* READY timer expiration: */
static void t3314_ready_timer_cb(void *data)
{
	/* "When the READY timer has expired the MS shall perform the routing
	 * area updating procedure when a routing area border is crossed"
	 */
	struct gprs_gmm_entity *gmme = (struct gprs_gmm_entity *)data;
	LOGGMME(gmme, LOGL_INFO, "READY timer expired\n");

	/* "In A/Gb mode, the timer T3312 is reset and started with its
	 * initial value, when the READY timer is stopped or expires.":
	 */
	gprs_gmm_gmme_t3312_start(gmme);
}

/* T3312 (Periodic RAU) is started: */
void gprs_gmm_gmme_t3312_start(struct gprs_gmm_entity *gmme)
{
	if (gmme->t3312_assigned_sec == 0)
		return;

	LOGGMME(gmme, LOGL_INFO, "T3312 started (expires in %lu seconds)\n", gmme->t3312_assigned_sec);
	osmo_timer_schedule(&gmme->t3312, gmme->t3312_assigned_sec, 0);
}

/* T3312 (Periodic RAU) is stopped: */
void gprs_gmm_gmme_t3312_stop(struct gprs_gmm_entity *gmme)
{
	if (!osmo_timer_pending(&gmme->t3312))
		return;

	LOGGMME(gmme, LOGL_INFO, "T3312 stopped\n");
	osmo_timer_del(&gmme->t3312);
}

/* T3312 (Periodic RAU) timer expiration: */
static void t3312_periodic_rau_timer_cb(void *data)
{
	struct gprs_gmm_entity *gmme = (struct gprs_gmm_entity *)data;
	LOGGMME(gmme, LOGL_INFO, "T3312 Periodic RAU timer expired\n");

	/* TODO:
	 * - "Initiation of the Periodic RAU procedure if the MS is not
	 *   attached for emergency bearer services or T3323 started under the
	 *   conditions as specified in subclause 4.7.2.2.
	 * - Implicit detach from network if the MS is attached for emergency
	 *   bearer services."
	 * - "If the MS is in a state other than GMM-REGISTERED.NORMAL-SERVICE
	 *   when timer T3312 expires, the periodic routing area updating procedure
	 *   is delayed until the MS returns to GMM-REGISTERED.NORMAL-SERVICE."
	 *   "If timer T3323 expires, the MS shall memorize that it has to initiate a
	 *   routing area updating procedure when it returns to state
	 *   GMM-REGISTERED.NORMAL-SERVICE."
	 */
	gprs_gmm_ms_fsm_ctx_request_rau(&gmme->ms_fsm, GPRS_GMM_UPD_TYPE_PERIODIC);

}

int gprs_gmm_submit_gmmreg_attach_cnf(struct gprs_gmm_entity *gmme, bool accepted, uint8_t cause)
{
	struct osmo_gprs_gmm_prim *gmm_prim_tx;
	int rc;

	gmm_prim_tx = gprs_gmm_prim_alloc_gmmreg_attach_cnf();
	gmm_prim_tx->gmmreg.attach_cnf.accepted = accepted;
	if (accepted) {
		gmm_prim_tx->gmmreg.attach_cnf.acc.allocated_ptmsi = gmme->ptmsi;
		gmm_prim_tx->gmmreg.attach_cnf.acc.allocated_ptmsi_sig = gmme->ptmsi_sig;
		gmm_prim_tx->gmmreg.attach_cnf.acc.allocated_tlli = gmme->tlli;
		memcpy(&gmm_prim_tx->gmmreg.attach_cnf.acc.rai, &gmme->ra, sizeof(gmme->ra));
	} else {
		gmm_prim_tx->gmmreg.attach_cnf.rej.cause = cause;
	}

	rc = gprs_gmm_prim_call_up_cb(gmm_prim_tx);
	return rc;
}

static int gprs_gmm_submit_gmmreg_detach_cnf(struct gprs_gmm_entity *gmme)
{
	struct osmo_gprs_gmm_prim *gmm_prim_tx;
	int rc;

	gmm_prim_tx = gprs_gmm_prim_alloc_gmmreg_detach_cnf();
	gmm_prim_tx->gmmreg.detach_cnf.detach_type = gmme->ms_fsm.detach.type;

	rc = gprs_gmm_prim_call_up_cb(gmm_prim_tx);
	return rc;
}

static int gprs_gmm_submit_gmmreg_sim_auth_ind(struct gprs_gmm_entity *gmme)
{
	struct osmo_gprs_gmm_prim *gmm_prim_tx;
	int rc;

	gmm_prim_tx = gprs_gmm_prim_alloc_gmmreg_sim_auth_ind();
	gmm_prim_tx->gmmreg.sim_auth_ind.ac_ref_nr = gmme->auth_ciph.req.ac_ref_nr;
	gmm_prim_tx->gmmreg.sim_auth_ind.key_seq = gmme->auth_ciph.req.key_seq;
	memcpy(gmm_prim_tx->gmmreg.sim_auth_ind.rand, gmme->auth_ciph.req.rand,
	       sizeof(gmm_prim_tx->gmmreg.sim_auth_ind.rand));

	rc = gprs_gmm_prim_call_up_cb(gmm_prim_tx);
	return rc;
}

int gprs_gmm_submit_gmmsm_establish_cnf(struct gprs_gmm_entity *gmme, bool accepted, uint8_t cause)
{
	struct osmo_gprs_gmm_prim *gmm_prim_tx;
	int rc;

	gmm_prim_tx = gprs_gmm_prim_alloc_gmmsm_establish_cnf(gmme->sess_id, cause);
	if (accepted) {
		gmm_prim_tx->gmmsm.establish_cnf.acc.allocated_ptmsi = gmme->ptmsi;
		gmm_prim_tx->gmmsm.establish_cnf.acc.allocated_ptmsi_sig = gmme->ptmsi_sig;
		gmm_prim_tx->gmmsm.establish_cnf.acc.allocated_tlli = gmme->tlli;
		memcpy(&gmm_prim_tx->gmmsm.establish_cnf.acc.rai, &gmme->ra, sizeof(gmme->ra));
	}

	rc = gprs_gmm_prim_call_up_cb(gmm_prim_tx);
	return rc;
}

static int gprs_gmm_submit_gmmrr_assing_req(struct gprs_gmm_entity *gmme)
{
	struct osmo_gprs_gmm_prim *gmm_prim_tx;
	int rc;

	gmm_prim_tx = gprs_gmm_prim_alloc_gmmrr_assign_req(gmme->old_tlli, gmme->tlli);
	gmm_prim_tx->gmmrr.assign_req.ptmsi = gmme->ptmsi;
	OSMO_STRLCPY_ARRAY(gmm_prim_tx->gmmrr.assign_req.imsi, gmme->imsi);

	rc = gprs_gmm_prim_call_down_cb(gmm_prim_tx);
	return rc;
}

int gprs_gmm_submit_llgmm_assing_req(const struct gprs_gmm_entity *gmme)
{
	struct osmo_gprs_llc_prim *llc_prim_tx;
	int rc;

	llc_prim_tx = osmo_gprs_llc_prim_alloc_llgmm_assign_req(gmme->old_tlli);
	llc_prim_tx->llgmm.assign_req.tlli_new = gmme->tlli;
	llc_prim_tx->llgmm.assign_req.gea = gmme->auth_ciph.gea;
	memcpy(llc_prim_tx->llgmm.assign_req.kc, gmme->auth_ciph.kc, ARRAY_SIZE(gmme->auth_ciph.kc));

	rc = gprs_gmm_prim_call_llc_down_cb(llc_prim_tx);
	return rc;
}

static void gprs_gmm_gmme_update_allocated_ptmsi(struct gprs_gmm_entity *gmme, uint32_t new_ptmsi)
{
	gmme->old_ptmsi = gmme->ptmsi;
	gmme->ptmsi = new_ptmsi;
	/* TS 24.008 4.7.1.4.1:"Upon receipt of the assigned P-TMSI, the MS
	 * shall derive the local TLLI from this P-TMSI and shall use it for
	 * addressing at lower layers": */
	gmme->old_tlli = gmme->tlli;
	gmme->tlli = gprs_tmsi2tlli(gmme->ptmsi, TLLI_LOCAL);
}

/* Tx Identity Response, 9.2.11 */
static int gprs_gmm_tx_id_resp(struct gprs_gmm_entity *gmme,
			       uint8_t mi_type)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	struct msgb *msg;

	LOGGMME(gmme, LOGL_INFO, "Tx GMM IDENTITY RESPONSE\n");

	llc_prim = osmo_gprs_llc_prim_alloc_ll_unitdata_req(
			gmme->tlli, OSMO_GPRS_LLC_SAPI_GMM, NULL, GPRS_GMM_ALLOC_SIZE);
	msg = llc_prim->oph.msg;
	msg->l3h = msg->tail;
	rc = gprs_gmm_build_identity_resp(gmme, mi_type, msg);
	if (rc < 0) {
		msgb_free(msg);
		return -EBADMSG;
	}
	llc_prim->ll.l3_pdu = msg->l3h;
	llc_prim->ll.l3_pdu_len = msgb_l3len(msg);
	/* TODO:
	llc_prim->ll.qos_params.*;
	llc_prim->ll.radio_prio;
	llc_prim->ll.apply_gea;
	llc_prim->ll.apply_gia;
	*/

	rc = gprs_gmm_prim_call_llc_down_cb(llc_prim);
	if (rc < 0)
		return rc;
	return rc;
}

/* Tx GMM Authentication and ciphering response, 9.4.10
 * sres can be NULL if no authentication was requested. */
int gprs_gmm_tx_ciph_auth_resp(const struct gprs_gmm_entity *gmme, const uint8_t *sres)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	struct msgb *msg;

	LOGGMME(gmme, LOGL_INFO, "Tx GMM GMM AUTHENTICATION AND CIPHERING RESPONSE\n");

	llc_prim = osmo_gprs_llc_prim_alloc_ll_unitdata_req(
			gmme->tlli, OSMO_GPRS_LLC_SAPI_GMM, NULL, GPRS_GMM_ALLOC_SIZE);
	msg = llc_prim->oph.msg;
	msg->l3h = msg->tail;
	rc = gprs_gmm_build_ciph_auth_resp(gmme, sres, msg);
	if (rc < 0) {
		msgb_free(msg);
		return -EBADMSG;
	}
	llc_prim->ll.l3_pdu = msg->l3h;
	llc_prim->ll.l3_pdu_len = msgb_l3len(msg);
	/* TODO:
	llc_prim->ll.qos_params.*;
	llc_prim->ll.radio_prio;
	llc_prim->ll.apply_gea;
	llc_prim->ll.apply_gia;
	*/

	rc = gprs_gmm_prim_call_llc_down_cb(llc_prim);
	if (rc < 0)
		return rc;
	return rc;
}

/* Tx GMM Atach Request, 9.4.1 */
int gprs_gmm_tx_att_req(struct gprs_gmm_entity *gmme,
			enum osmo_gprs_gmm_attach_type attach_type,
			bool attach_with_imsi)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	struct msgb *msg;

	LOGGMME(gmme, LOGL_INFO, "Tx GMM ATTACH REQUEST (new TLLI=0x%08x)\n", gmme->tlli);
	llc_prim = osmo_gprs_llc_prim_alloc_ll_unitdata_req(
			gmme->tlli, OSMO_GPRS_LLC_SAPI_GMM, NULL, GPRS_GMM_ALLOC_SIZE);
	msg = llc_prim->oph.msg;
	msg->l3h = msg->tail;
	rc = gprs_gmm_build_attach_req(gmme,
				       attach_type,
				       attach_with_imsi,
				       msg);
	if (rc < 0) {
		msgb_free(msg);
		return -EBADMSG;
	}
	llc_prim->ll.l3_pdu = msg->l3h;
	llc_prim->ll.l3_pdu_len = msgb_l3len(msg);
	/* TODO:
	llc_prim->ll.qos_params.*;
	llc_prim->ll.radio_prio;
	llc_prim->ll.apply_gea;
	llc_prim->ll.apply_gia;
	*/

	rc = gprs_gmm_prim_call_llc_down_cb(llc_prim);

	return rc;
}

/* Tx GMM Atach Complete, 9.4.3 */
static int gprs_gmm_tx_att_compl(struct gprs_gmm_entity *gmme)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	struct msgb *msg;

	LOGGMME(gmme, LOGL_INFO, "Tx GMM ATTACH COMPL\n");

	llc_prim = osmo_gprs_llc_prim_alloc_ll_unitdata_req(
			gmme->tlli, OSMO_GPRS_LLC_SAPI_GMM, NULL, GPRS_GMM_ALLOC_SIZE);
	msg = llc_prim->oph.msg;
	msg->l3h = msg->tail;
	rc = gprs_gmm_build_attach_compl(gmme, msg);
	if (rc < 0) {
		msgb_free(msg);
		return -EBADMSG;
	}
	llc_prim->ll.l3_pdu = msg->l3h;
	llc_prim->ll.l3_pdu_len = msgb_l3len(msg);
	/* TODO:
	llc_prim->ll.qos_params.*;
	llc_prim->ll.radio_prio;
	llc_prim->ll.apply_gea;
	llc_prim->ll.apply_gia;
	*/

	rc = gprs_gmm_prim_call_llc_down_cb(llc_prim);
	if (rc < 0)
		return rc;
	return rc;
}

/* Tx GMM Detach Request (mobile originating detach), 9.4.5.2 */
int gprs_gmm_tx_detach_req(struct gprs_gmm_entity *gmme,
			   enum osmo_gprs_gmm_detach_ms_type detach_type,
			   enum osmo_gprs_gmm_detach_poweroff_type poweroff_type)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	struct msgb *msg;

	LOGGMME(gmme, LOGL_INFO, "Tx GMM DETACH REQUEST (MO)\n");
	llc_prim = osmo_gprs_llc_prim_alloc_ll_unitdata_req(
			gmme->tlli, OSMO_GPRS_LLC_SAPI_GMM, NULL, GPRS_GMM_ALLOC_SIZE);
	msg = llc_prim->oph.msg;
	msg->l3h = msg->tail;
	rc = gprs_gmm_build_detach_req(gmme, detach_type, poweroff_type, msg);
	if (rc < 0) {
		msgb_free(msg);
		return -EBADMSG;
	}
	llc_prim->ll.l3_pdu = msg->l3h;
	llc_prim->ll.l3_pdu_len = msgb_l3len(msg);
	/* TODO:
	llc_prim->ll.qos_params.*;
	llc_prim->ll.radio_prio;
	llc_prim->ll.apply_gea;
	llc_prim->ll.apply_gia;
	*/

	rc = gprs_gmm_prim_call_llc_down_cb(llc_prim);

	return rc;
}

/* Tx GMM Atach Complete, 9.4.3 */
static int gprs_gmm_tx_ptmsi_realloc_compl(struct gprs_gmm_entity *gmme)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	struct msgb *msg;

	LOGGMME(gmme, LOGL_INFO, "Tx P-TMSI REALLOCATION COMPL\n");

	llc_prim = osmo_gprs_llc_prim_alloc_ll_unitdata_req(
			gmme->tlli, OSMO_GPRS_LLC_SAPI_GMM, NULL, GPRS_GMM_ALLOC_SIZE);
	msg = llc_prim->oph.msg;
	msg->l3h = msg->tail;
	rc = gprs_gmm_build_ptmsi_realloc_compl(gmme, msg);
	if (rc < 0) {
		msgb_free(msg);
		return -EBADMSG;
	}
	llc_prim->ll.l3_pdu = msg->l3h;
	llc_prim->ll.l3_pdu_len = msgb_l3len(msg);
	/* TODO:
	llc_prim->ll.qos_params.*;
	llc_prim->ll.radio_prio;
	llc_prim->ll.apply_gea;
	llc_prim->ll.apply_gia;
	*/

	rc = gprs_gmm_prim_call_llc_down_cb(llc_prim);
	if (rc < 0)
		return rc;
	return rc;
}

/* Tx GMM Routing area update request, 9.4.14 */
int gprs_gmm_tx_rau_req(struct gprs_gmm_entity *gmme,
			enum gprs_gmm_upd_type rau_type)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	struct msgb *msg;

	LOGGMME(gmme, LOGL_INFO, "Tx GMM RAU REQUEST\n");
	llc_prim = osmo_gprs_llc_prim_alloc_ll_unitdata_req(
			gmme->tlli, OSMO_GPRS_LLC_SAPI_GMM, NULL, GPRS_GMM_ALLOC_SIZE);
	msg = llc_prim->oph.msg;
	msg->l3h = msg->tail;
	rc = gprs_gmm_build_rau_req(gmme, rau_type, msg);
	if (rc < 0) {
		msgb_free(msg);
		return -EBADMSG;
	}
	llc_prim->ll.l3_pdu = msg->l3h;
	llc_prim->ll.l3_pdu_len = msgb_l3len(msg);
	/* TODO:
	llc_prim->ll.qos_params.*;
	llc_prim->ll.radio_prio;
	llc_prim->ll.apply_gea;
	llc_prim->ll.apply_gia;
	*/

	rc = gprs_gmm_prim_call_llc_down_cb(llc_prim);

	return rc;
}

/* Tx GMM Routing area update complete, 9.4.16 */
static int gprs_gmm_tx_rau_compl(struct gprs_gmm_entity *gmme)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	struct msgb *msg;

	LOGGMME(gmme, LOGL_INFO, "Tx GMM RAU COMPL\n");

	llc_prim = osmo_gprs_llc_prim_alloc_ll_unitdata_req(
			gmme->tlli, OSMO_GPRS_LLC_SAPI_GMM, NULL, GPRS_GMM_ALLOC_SIZE);
	msg = llc_prim->oph.msg;
	msg->l3h = msg->tail;
	rc = gprs_gmm_build_rau_compl(gmme, msg);
	if (rc < 0) {
		msgb_free(msg);
		return -EBADMSG;
	}
	llc_prim->ll.l3_pdu = msg->l3h;
	llc_prim->ll.l3_pdu_len = msgb_l3len(msg);
	/* TODO:
	llc_prim->ll.qos_params.*;
	llc_prim->ll.radio_prio;
	llc_prim->ll.apply_gea;
	llc_prim->ll.apply_gia;
	*/

	rc = gprs_gmm_prim_call_llc_down_cb(llc_prim);
	if (rc < 0)
		return rc;
	return rc;
}

static int gprs_gmm_rx_att_ack(struct gprs_gmm_entity *gmme, struct gsm48_hdr *gh, unsigned int len)
{
	struct gsm48_attach_ack *aa;
	struct tlv_parsed tp;
	int rc;
	int periodic_rau_sec;

	if (len < sizeof(*gh) + sizeof(*aa)) {
		LOGGMME(gmme, LOGL_ERROR, "Rx GMM ATTACH ACCEPT with wrong size %u\n", len);
		goto rejected;
	}

	LOGGMME(gmme, LOGL_INFO, "Rx GMM ATTACH ACCEPT\n");
	aa = (struct gsm48_attach_ack *)&gh->data[0];

	periodic_rau_sec = gprs_gmm_gprs_tmr_to_secs(aa->ra_upd_timer);
	gmme->radio_prio = aa->radio_prio;
	gmme->t3312_assigned_sec = periodic_rau_sec >= 0 ? periodic_rau_sec : 0;
	if (gmme->t3312_assigned_sec == 0)
		gprs_gmm_gmme_t3312_stop(gmme);
	if (aa->force_stby)
		gprs_gmm_gmme_ready_timer_stop(gmme);
	gsm48_parse_ra(&gmme->ra, (const uint8_t *)&aa->ra_id);

	if (len > sizeof(*gh) + sizeof(*aa)) {
		rc = gprs_gmm_tlv_parse(&tp, &aa->data[0],
					len - (sizeof(*gh) + sizeof(*aa)));
		if (rc < 0) {
			LOGGMME(gmme, LOGL_ERROR, "Rx GMM ATTACH ACCEPT: failed to parse TLVs %d\n", rc);
			goto rejected;
		}

		if (TLVP_PRESENT(&tp, GSM48_IE_GMM_PTMSI_SIG)) {
			const uint8_t *ptmsi_sig = TLVP_VAL(&tp, GSM48_IE_GMM_PTMSI_SIG);
			gmme->ptmsi_sig = (ptmsi_sig[0] << 8) | (ptmsi_sig[1] << 4) | ptmsi_sig[2];
		} else {
			gmme->ptmsi_sig = GSM_RESERVED_TMSI;
		}

		/* 10.5.7.3 Negotiated READY timer value */
		if (TLVP_PRESENT(&tp, GSM48_IE_GMM_TIMER_READY)) {
			int secs = gprs_gmm_gprs_tmr_to_secs(*TLVP_VAL(&tp, GSM48_IE_GMM_TIMER_READY));
			gmme->t3314_assigned_sec = secs >= 0 ? secs : 0;
		} else {
			/* Apply the requested value: */
			gmme->t3314_assigned_sec = osmo_tdef_get(g_gmm_ctx->T_defs, 3314, OSMO_TDEF_S, -1);
		}
		/* "If the negotiated READY timer value is set to zero, the READY timer shall be stopped immediately": */
		if (gmme->t3314_assigned_sec == 0) {
			gprs_gmm_gmme_ready_timer_stop(gmme);
			/* "If after a READY timer negotiation the READY timer
			 * value is set to zero, timer T3312 is reset and started
			 * with its initial value." */
			gprs_gmm_gmme_t3312_start(gmme);
		}

		if (TLVP_PRESENT(&tp, GSM48_IE_GMM_ALLOC_PTMSI)) {
			struct osmo_mobile_identity mi;
			if (osmo_mobile_identity_decode(&mi, TLVP_VAL(&tp, GSM48_IE_GMM_ALLOC_PTMSI),
							TLVP_LEN(&tp, GSM48_IE_GMM_ALLOC_PTMSI), false)
			    || mi.type != GSM_MI_TYPE_TMSI) {
				LOGGMME(gmme, LOGL_ERROR, "Cannot decode P-TMSI\n");
				goto rejected;
			}
			gprs_gmm_gmme_update_allocated_ptmsi(gmme, mi.tmsi);
		}

		if (TLVP_PRES_LEN(&tp, GSM48_IE_GMM_TIMER_T3302, 1))
			gmme->t3302 = *TLVP_VAL(&tp, GSM48_IE_GMM_TIMER_T3302);
	}

	/* Submit LLGMM-ASSIGN-REQ as per TS 24.007 Annex C.1 */
	rc = gprs_gmm_submit_llgmm_assing_req(gmme);
	if (rc < 0)
		goto rejected;

	/* Submit GMMRR-ASSIGN-REQ as per TS 24.007 Annex C.1 */
	rc = gprs_gmm_submit_gmmrr_assing_req(gmme);
	if (rc < 0)
		goto rejected;

	rc = gprs_gmm_tx_att_compl(gmme);
	if (rc < 0)
		goto rejected;

	rc = osmo_fsm_inst_dispatch(gmme->ms_fsm.fi, GPRS_GMM_MS_EV_ATTACH_ACCEPTED, NULL);

	return rc;

rejected:
	return -EINVAL; /* TODO: what to do on error? */
}

/* Rx GMM Attach Reject, 9.4.4 */
static int gprs_gmm_rx_att_rej(struct gprs_gmm_entity *gmme, struct gsm48_hdr *gh, unsigned int len)
{
	uint8_t *arej = &gh->data[0];
	struct tlv_parsed tp;
	uint8_t cause;
	int rc;

	if (len < sizeof(*gh) + 1) {
		LOGGMME(gmme, LOGL_ERROR, "Rx GMM ATTACH REJECT with wrong size %u\n", len);
		goto rejected;
	}

	cause = *arej;
	arej++;

	LOGGMME(gmme, LOGL_NOTICE, "Rx GMM ATTACH REJECT cause='%s' (%u)\n",
		get_value_string(gsm48_gmm_cause_names, cause), cause);

	if (len > sizeof(*gh) + 1) {
		rc = gprs_gmm_tlv_parse(&tp, arej, len - (sizeof(*gh) + 1));
		if (rc < 0) {
			LOGGMME(gmme, LOGL_ERROR, "Rx GMM ATTACH REJECT: failed to parse TLVs %d\n", rc);
			goto rejected;
		}

		if (TLVP_PRES_LEN(&tp, GSM48_IE_GMM_TIMER_T3302, 1))
			gmme->t3302 = *TLVP_VAL(&tp, GSM48_IE_GMM_TIMER_T3302);

		if (TLVP_PRES_LEN(&tp, GSM48_IE_GMM_TIMER_T3302, 1))
			gmme->t3346 = *TLVP_VAL(&tp, GSM48_IE_GMM_TIMER_T3346);
	}

	rc = osmo_fsm_inst_dispatch(gmme->ms_fsm.fi, GPRS_GMM_MS_EV_ATTACH_REJECTED, &cause);

	return rc;

rejected:
	return -EINVAL;
}

/* Rx GMM Detach Accept (mobile originating detach), 9.4.6.2 */
static int gprs_gmm_rx_detach_accept(struct gprs_gmm_entity *gmme, struct gsm48_hdr *gh, unsigned int len)
{
	int rc;

	if (len < sizeof(*gh) + 1) {
		LOGGMME(gmme, LOGL_ERROR, "Rx GMM DETACH ACCEPT (MO) with wrong size %u\n", len);
		goto rejected;
	}

	bool force_standby_indicated = (gh->data[0] >> 4) == 0x01;

	LOGGMME(gmme, LOGL_INFO, "Rx GMM DETACH ACCEPT (MO) force_standby_indicated=%s\n",
		force_standby_indicated ? "true" : "false");

	if (force_standby_indicated)
		gprs_gmm_gmme_ready_timer_stop(gmme);

	/* TODO: submit GMMSM-RELEASE-IND */

	/* Submit LLGMM-ASSIGN-REQ as per TS 24.007 Annex C.3 */
	gmme->old_tlli = gmme->tlli;
	gmme->tlli = GPRS_GMM_TLLI_UNASSIGNED;
	rc = gprs_gmm_submit_llgmm_assing_req(gmme);
	if (rc < 0)
		goto rejected;

	/* Submit GMMREG-DETACH-CNF as per TS 24.007 Annex C.3 */
	rc = gprs_gmm_submit_gmmreg_detach_cnf(gmme);
	if (rc < 0)
		goto rejected;

	rc = osmo_fsm_inst_dispatch(gmme->ms_fsm.fi, GPRS_GMM_MS_EV_DETACH_ACCEPTED, NULL);
	return rc;

rejected:
	return -EINVAL; /* TODO: what to do on error? */
}

/* Rx Routing area update accept, 9.4.15 */
static int gprs_gmm_rx_rau_acc(struct gprs_gmm_entity *gmme, struct gsm48_hdr *gh, unsigned int len)
{
	struct gsm48_ra_upd_ack *raack;
	struct tlv_parsed tp;
	int rc;
	int periodic_rau_sec;

	if (len < sizeof(*gh) + sizeof(*raack)) {
		LOGGMME(gmme, LOGL_ERROR, "Rx GMM RAU ACCEPT with wrong size %u\n", len);
		goto rejected;
	}

	raack = (struct gsm48_ra_upd_ack *)&gh->data[0];
	LOGGMME(gmme, LOGL_INFO, "Rx GMM RAU ACCEPT upd_result=0x%02x\n", raack->upd_result);

	/* TODO: check raack->upd_result */

	periodic_rau_sec = gprs_gmm_gprs_tmr_to_secs(raack->ra_upd_timer);
	gmme->t3312_assigned_sec = periodic_rau_sec >= 0 ? periodic_rau_sec : 0;
	if (gmme->t3312_assigned_sec == 0)
		gprs_gmm_gmme_t3312_stop(gmme);
	if (raack->force_stby)
		gprs_gmm_gmme_ready_timer_stop(gmme);
	gsm48_parse_ra(&gmme->ra, (const uint8_t *)&raack->ra_id);

	if (len > sizeof(*gh) + sizeof(*raack)) {
		rc = gprs_gmm_tlv_parse(&tp, &raack->data[0],
					len - (sizeof(*gh) + sizeof(*raack)));
		if (rc < 0) {
			LOGGMME(gmme, LOGL_ERROR, "Rx GMM RAU ACCEPT: failed to parse TLVs %d\n", rc);
			goto rejected;
		}

		/* 10.5.5.8 P-TMSI signature */
		if (TLVP_PRESENT(&tp, GSM48_IE_GMM_PTMSI_SIG)) {
			const uint8_t *ptmsi_sig = TLVP_VAL(&tp, GSM48_IE_GMM_PTMSI_SIG);
			gmme->ptmsi_sig = (ptmsi_sig[0] << 8) | (ptmsi_sig[1] << 4) | ptmsi_sig[2];
		} else {
			gmme->ptmsi_sig = GSM_RESERVED_TMSI;
		}

		/* 10.5.1.4 Allocated P-TMSI */
		if (TLVP_PRESENT(&tp, GSM48_IE_GMM_ALLOC_PTMSI)) {
			struct osmo_mobile_identity mi;
			if (osmo_mobile_identity_decode(&mi, TLVP_VAL(&tp, GSM48_IE_GMM_ALLOC_PTMSI),
							TLVP_LEN(&tp, GSM48_IE_GMM_ALLOC_PTMSI), false)
			    || mi.type != GSM_MI_TYPE_TMSI) {
				LOGGMME(gmme, LOGL_ERROR, "Cannot decode P-TMSI\n");
				goto rejected;
			}
			gprs_gmm_gmme_update_allocated_ptmsi(gmme, mi.tmsi);
		}
		/* FIXME! what to do it PTMSI changes? probably need to update other layers... Check GPRS ATTACH ACCEPT func */

		/* 10.5.1.4 MS identity */
		if (TLVP_PRESENT(&tp, GSM48_IE_GMM_IMEISV)) {
			struct osmo_mobile_identity mi;
			if (osmo_mobile_identity_decode(&mi, TLVP_VAL(&tp, GSM48_IE_GMM_IMEISV),
							TLVP_LEN(&tp, GSM48_IE_GMM_IMEISV), false)
			    || mi.type != GSM_MI_TYPE_IMEISV) {
				LOGGMME(gmme, LOGL_ERROR, "Cannot decode IMEISV\n");
				goto rejected;
			}
			/* TODO: */
		}

		/* 10.5.5.11 List of Receive N-PDU Numbers: TODO */

		/* 10.5.7.3 Negotiated READY timer value */
		if (TLVP_PRESENT(&tp, GSM48_IE_GMM_TIMER_READY)) {
			int secs = gprs_gmm_gprs_tmr_to_secs(*TLVP_VAL(&tp, GSM48_IE_GMM_TIMER_READY));
			gmme->t3314_assigned_sec = secs >= 0 ? secs : 0;
		} else {
			/* Apply the requested value: */
			gmme->t3314_assigned_sec = osmo_tdef_get(g_gmm_ctx->T_defs, 3314, OSMO_TDEF_S, -1);
		}
		/* "If the negotiated READY timer value is set to zero, the READY timer shall be stopped immediately": */
		if (gmme->t3314_assigned_sec == 0) {
			gprs_gmm_gmme_ready_timer_stop(gmme);
			/* "If after a READY timer negotiation the READY timer
			 * value is set to zero, timer T3312 is reset and started
			 * with its initial value." */
			gprs_gmm_gmme_t3312_start(gmme);
		}

		/* 10.5.5.14 GMM cause: TODO */

		/* 10.5.7.4 T3302 value */
		if (TLVP_PRES_LEN(&tp, GSM48_IE_GMM_TIMER_T3302, 1))
			gmme->t3302 = *TLVP_VAL(&tp, GSM48_IE_GMM_TIMER_T3302);

		/* 10.5.1.13 Equivalent PLMNs: TODO */
		/* 10.5.7.1 PDP context status: TODO */

		/* TODO: lots more Optional IEs */
	}

	/* Submit LLGMM-ASSIGN-REQ as per TS 24.007 Annex C.1 */
	rc = gprs_gmm_submit_llgmm_assing_req(gmme);
	if (rc < 0)
		goto rejected;

	/* Submit GMMRR-ASSIGN-REQ as per TS 24.007 Annex C.1 */
	rc = gprs_gmm_submit_gmmrr_assing_req(gmme);
	if (rc < 0)
		goto rejected;

	rc = gprs_gmm_tx_rau_compl(gmme);
	if (rc < 0)
		goto rejected;

	rc = osmo_fsm_inst_dispatch(gmme->ms_fsm.fi, GPRS_GMM_MS_EV_RAU_ACCEPTED, NULL);

	return rc;

rejected:
	return -EINVAL; /* TODO: what to do on error? */
}

/* Rx GMM Identity Request, 9.2.10 */
static int gprs_gmm_rx_id_req(struct gprs_gmm_entity *gmme, struct gsm48_hdr *gh, unsigned int len)
{
	/* 4.7.8.2: "An MS shall be ready to respond to an IDENTITY REQUEST message at any time."
	 * "Upon receipt of the IDENTITY REQUEST message the MS sends back an IDENTITY RESPONSE message.
	 * The IDENTITY RESPONSE message shall contain the identification parameters as requested by the network"
	 */
	uint8_t id_type;
	bool force_standby_indicated;

	if (len < sizeof(struct gsm48_hdr) + 1) {
		LOGGMME(gmme, LOGL_ERROR, "Rx GMM IDENTITY REQUEST with wrong size %u\n", len);
		return -EINVAL;
	}

	id_type = gh->data[0] & 0xf;
	force_standby_indicated = (gh->data[0] >> 4) == 0x01;
	LOGGMME(gmme, LOGL_INFO, "Rx GMM IDENTITY REQUEST mi_type=%s force_stdby=%u\n",
		gsm48_mi_type_name(id_type), force_standby_indicated);

	if (force_standby_indicated)
		gprs_gmm_gmme_ready_timer_stop(gmme);

	return gprs_gmm_tx_id_resp(gmme, id_type);
}

/* Rx GMM P-TMSI reallocation command, 9.4.7 */
static int gprs_gmm_rx_ptmsi_realloc_cmd(struct gprs_gmm_entity *gmme, const struct gsm48_hdr *gh, unsigned int len)
{
	const uint8_t *buf = &gh->data[0];
	uint8_t mi_len;
	struct osmo_mobile_identity mi;
	bool force_standby_indicated;
	struct tlv_parsed tp;
	int rc;

	if (len != 15) {
		LOGGMME(gmme, LOGL_ERROR, "Rx GMM P-TMSI REALLOCATION COMMAND with wrong size %u\n", len);
		goto rejected;
	}

	mi_len = *buf;
	if (mi_len != 5)
		goto rejected;
	buf++;
	if (osmo_mobile_identity_decode(&mi, buf, mi_len, false) || mi.type != GSM_MI_TYPE_TMSI) {
		LOGGMME(gmme, LOGL_ERROR, "Rx GMM P-TMSI REALLOCATION COMMAND: Cannot decode P-TMSI\n");
		goto rejected;
	}
	gprs_gmm_gmme_update_allocated_ptmsi(gmme, mi.tmsi);
	buf += mi_len;

	gsm48_parse_ra(&gmme->ra, (const uint8_t *)buf);
	buf += 6;

	force_standby_indicated = (*buf >> 4) == 0x01;
	if (force_standby_indicated)
		gprs_gmm_gmme_ready_timer_stop(gmme);
	buf++;

	/* Optional: */
	if (len > (buf - (uint8_t *)gh)) {
		rc = gprs_gmm_tlv_parse(&tp, buf, len - (buf - (uint8_t *)gh));
		if (rc < 0) {
			LOGGMME(gmme, LOGL_ERROR, "Rx GMM P-TMSI REALLOCATION COMMAND: failed to parse TLVs %d\n", rc);
			goto rejected;
		}

		/* 10.5.5.8 P-TMSI signature */
		if (TLVP_PRESENT(&tp, GSM48_IE_GMM_PTMSI_SIG)) {
			const uint8_t *ptmsi_sig = TLVP_VAL(&tp, GSM48_IE_GMM_PTMSI_SIG);
			gmme->ptmsi_sig = (ptmsi_sig[0] << 8) | (ptmsi_sig[1] << 4) | ptmsi_sig[2];
		} else {
			gmme->ptmsi_sig = GSM_RESERVED_TMSI;
		}

		/* TODO: 10.5.5.35 DCN-ID */
	}

	/* Submit LLGMM-ASSIGN-REQ as per TS 24.007 Annex C.1 */
	rc = gprs_gmm_submit_llgmm_assing_req(gmme);
	if (rc < 0)
		goto rejected;

	/* Submit GMMRR-ASSIGN-REQ as per TS 24.007 Annex C.1 */
	rc = gprs_gmm_submit_gmmrr_assing_req(gmme);
	if (rc < 0)
		goto rejected;

	return gprs_gmm_tx_ptmsi_realloc_compl(gmme);

rejected:
	return -EINVAL; /* TODO: what to do on error? */
}

/* Rx GMM Authentication and ciphering request, 9.4.9 */
static int gprs_gmm_rx_auth_ciph_req(struct gprs_gmm_entity *gmme, struct gsm48_hdr *gh, unsigned int len)
{
	struct gsm48_auth_ciph_req *acreq;
	struct tlv_parsed tp;
	int rc;
	uint8_t *rand = NULL;
	uint8_t cksn = 0xff;

	if (len < sizeof(*gh) + sizeof(*acreq)) {
		LOGGMME(gmme, LOGL_ERROR, "Rx GMM AUTHENTICATION AND CIPHERING REQUEST with wrong size %u\n", len);
		return -EINVAL;
	}

	LOGGMME(gmme, LOGL_INFO, "Rx GMM AUTHENTICATION AND CIPHERING REQUEST\n");
	acreq = (struct gsm48_auth_ciph_req *)&gh->data[0];

	if (len > sizeof(*gh) + sizeof(*acreq)) {
		rc = gprs_gmm_tlv_parse(&tp, &acreq->data[0],
					len - (sizeof(*gh) + sizeof(*acreq)));
		if (rc < 0) {
			LOGGMME(gmme, LOGL_ERROR, "Rx GMM AUTHENTICATION AND CIPHERING REQUEST: failed to parse TLVs %d\n", rc);
			return -EINVAL;
		}
		if (TLVP_PRESENT(&tp, GSM48_IE_GMM_AUTH_RAND)) {
			rand = (uint8_t *)TLVP_VAL(&tp, GSM48_IE_GMM_AUTH_RAND);
			if (TLVP_PRESENT(&tp, GSM48_IE_GMM_CIPH_CKSN)) {
				cksn = *(uint8_t *)TLVP_VAL(&tp, GSM48_IE_GMM_CIPH_CKSN);
				cksn &= 0x0f;
			}
		}
		/* TODO: 9.4.9.3 Authentication Parameter AUTN */
		/* TODO: 9.4.9.4 Replayed MS network capability */
		/* TODO: 9.4.9.5 Integrity algorithm */
		/* TODO: 9.4.9.6 Message authentication code */
		/* TODO: 9.4.9.7 Replayed MS Radio Access Capability */
	}

	if (acreq->force_stby)
		gprs_gmm_gmme_ready_timer_stop(gmme);

	gmme->auth_ciph.gea = acreq->ciph_alg;
	gmme->auth_ciph.req.ac_ref_nr = acreq->ac_ref_nr;
	gmme->auth_ciph.req.imeisv_requested = acreq->imeisv_req;
	gmme->auth_ciph.req.key_seq = cksn;
	if (rand)
		memcpy(gmme->auth_ciph.req.rand, rand, sizeof(gmme->auth_ciph.req.rand));

	if (rand) {
		/* SIM AUTH needed. Answer GMM req asynchronously in GMMREG-SIM_AUTH.rsp: */
		rc = gprs_gmm_submit_gmmreg_sim_auth_ind(gmme);
		/* TODO: if rc < 0, transmit AUTHENTICATION AND CIPHERING FAILURE (9.4.10a) */
	} else {
		/* Submit LLGMM-ASSIGN-REQ as per TS 24.007 Annex C.1 */
		rc = gprs_gmm_submit_llgmm_assing_req(gmme);
		if (rc < 0) {
			/* TODO: if rc < 0, transmit AUTHENTICATION AND CIPHERING FAILURE (9.4.10a) */
			/* invalidate active reference: */
			gmme->auth_ciph.req.ac_ref_nr = 0xff;
			return rc;
		}
		rc = gprs_gmm_tx_ciph_auth_resp(gmme, NULL);
		/* invalidate active reference: */
		gmme->auth_ciph.req.ac_ref_nr = 0xff;
	}
	return rc;
}

/* Rx GPRS Mobility Management. */
int gprs_gmm_rx(struct gprs_gmm_entity *gmme, struct gsm48_hdr *gh, unsigned int len)
{
	int rc = 0;

	switch (gh->msg_type) {
	case GSM48_MT_GMM_ATTACH_ACK:
		rc = gprs_gmm_rx_att_ack(gmme, gh, len);
		break;
	case GSM48_MT_GMM_ATTACH_REJ:
		rc = gprs_gmm_rx_att_rej(gmme, gh, len);
		break;
	case GSM48_MT_GMM_DETACH_ACK:
		rc = gprs_gmm_rx_detach_accept(gmme, gh, len);
		break;
	case GSM48_MT_GMM_RA_UPD_ACK:
		rc = gprs_gmm_rx_rau_acc(gmme, gh, len);
		break;
	case GSM48_MT_GMM_ID_REQ:
		rc = gprs_gmm_rx_id_req(gmme, gh, len);
		break;
	case GSM48_MT_GMM_PTMSI_REALL_CMD:
		rc = gprs_gmm_rx_ptmsi_realloc_cmd(gmme, gh, len);
		break;
	case GSM48_MT_GMM_AUTH_CIPH_REQ:
		rc = gprs_gmm_rx_auth_ciph_req(gmme, gh, len);
		break;
	default:
		LOGGMME(gmme, LOGL_ERROR,
			"Rx GMM message not implemented! type=%u len=%u\n",
			gh->msg_type, len);
		rc = -EINVAL;
	}

	return rc;
}
