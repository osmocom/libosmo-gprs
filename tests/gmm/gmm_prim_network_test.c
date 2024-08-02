/* gmm_prim tests (network side)
 *
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau espin Pedrol <pespin@sysmocom.de>
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
#include <stdio.h>

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>

#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/llc/llc_private.h>
#include <osmocom/gprs/gmm/gmm.h>
#include <osmocom/gprs/gmm/gmm_prim.h>
#include <osmocom/gprs/gmm/gmm_pdu.h>

#include "gmm_prim_test.h"

static void *tall_ctx = NULL;

static uint8_t pdu_gmm_att_req[] = { /* TODO: provide good hexstring, this comes from a att_accept... */
0x08, 0x02, 0x01, 0x2a, 0x44, 0x32, 0xf4, 0x07, 0x00, 0x05, 0x00, 0x17, 0x16, 0x18, 0x05, 0xf4,
0xea, 0x71, 0x1b, 0x41
};

static uint8_t pdu_gmm_id_resp[] = { /* TODO: provide GMM Identification Response here */
};

/* override, requires '-Wl,--wrap=osmo_get_rand_id' */
int __real_osmo_get_rand_id(uint8_t *data, size_t len);
int __wrap_osmo_get_rand_id(uint8_t *data, size_t len)
{
	memset(data, 0x00, len);
	return 0;
}

int test_gmm_prim_up_cb(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_gmm_prim_name(gmm_prim);
	struct osmo_gprs_gmm_prim *gmm_prim_tx;
	int rc;

	switch (gmm_prim->oph.sap) {
	case OSMO_GPRS_GMM_SAP_GMMREG:
		switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMREG_ATTACH, PRIM_OP_CONFIRM):
			if (gmm_prim->gmmreg.attach_cnf.accepted) {
				printf("%s(): Rx %s accepted=%u allocated_ptmsi=0x%08x allocated_ptmsi_sig=0x%06x allocated_tlli=0x%08x\n", __func__, pdu_name,
				       gmm_prim->gmmreg.attach_cnf.accepted,
				       gmm_prim->gmmreg.attach_cnf.acc.allocated_ptmsi,
				       gmm_prim->gmmreg.attach_cnf.acc.allocated_ptmsi_sig,
				       gmm_prim->gmmreg.attach_cnf.acc.allocated_tlli);
			} else {
				printf("%s(): Rx %s accepted=%u rej_cause=%u\n", __func__, pdu_name,
				       gmm_prim->gmmreg.attach_cnf.accepted,
				       gmm_prim->gmmreg.attach_cnf.rej.cause);
			}
			break;
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMREG_DETACH, PRIM_OP_CONFIRM):
			printf("%s(): Rx %s detach_type='%s'\n", __func__, pdu_name,
			       osmo_gprs_gmm_detach_ms_type_name(gmm_prim->gmmreg.detach_cnf.detach_type));
			break;
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMREG_SIM_AUTH, PRIM_OP_INDICATION):
			printf("%s(): Rx %s ac_ref_nr=%u key_seq=%u rand=%s\n",
				__func__, pdu_name,
			       gmm_prim->gmmreg.sim_auth_ind.ac_ref_nr,
			       gmm_prim->gmmreg.sim_auth_ind.key_seq,
			       osmo_hexdump(gmm_prim->gmmreg.sim_auth_ind.rand,
					    sizeof(gmm_prim->gmmreg.sim_auth_ind.rand)));
			/* Emulate SIM, asnwer SRES=0xacacacac, Kc=bdbdbd... */
			gmm_prim_tx = osmo_gprs_gmm_prim_alloc_gmmreg_sim_auth_rsp();
			OSMO_ASSERT(gmm_prim_tx);
			gmm_prim_tx->gmmreg.sim_auth_rsp.ac_ref_nr = gmm_prim->gmmreg.sim_auth_ind.ac_ref_nr;
			gmm_prim_tx->gmmreg.sim_auth_rsp.key_seq  = gmm_prim->gmmreg.sim_auth_ind.key_seq;
			memcpy(gmm_prim_tx->gmmreg.sim_auth_rsp.rand, gmm_prim->gmmreg.sim_auth_ind.rand,
			       sizeof(gmm_prim_tx->gmmreg.sim_auth_rsp.rand));
			memset(gmm_prim_tx->gmmreg.sim_auth_rsp.sres, 0xac,
			       sizeof(gmm_prim_tx->gmmreg.sim_auth_rsp.sres));
			memset(gmm_prim_tx->gmmreg.sim_auth_rsp.kc, 0xbd,
			       sizeof(gmm_prim_tx->gmmreg.sim_auth_rsp.kc));
			rc = osmo_gprs_gmm_prim_upper_down(gmm_prim_tx);
			OSMO_ASSERT(rc == 0);
			break;
		default:
			printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
			OSMO_ASSERT(0)
		}
		break;
	case OSMO_GPRS_GMM_SAP_GMMSM:
		switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_ESTABLISH, PRIM_OP_CONFIRM):
			if (gmm_prim->gmmsm.establish_cnf.accepted)
				printf("%s(): Rx %s sess_id=%u accepted\n", __func__, pdu_name,
				       gmm_prim->gmmsm.sess_id);
			else
				printf("%s(): Rx %s sess_id=%u rejected cause=%u\n", __func__, pdu_name,
				       gmm_prim->gmmsm.sess_id,
				       gmm_prim->gmmsm.establish_cnf.rej.cause);
			break;
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_UNITDATA, PRIM_OP_INDICATION):
			printf("%s(): Rx %s sess_id=%u sm_pdu=%s\n", __func__, pdu_name,
			       gmm_prim->gmmsm.sess_id,
			       osmo_hexdump(gmm_prim->gmmsm.unitdata_ind.smpdu,
					    gmm_prim->gmmsm.unitdata_ind.smpdu_len));
			break;
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_RELEASE, PRIM_OP_INDICATION):
			printf("%s(): Rx %s sess_id=%u\n", __func__, pdu_name,
			       gmm_prim->gmmsm.sess_id);
			break;
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMSM_MODIFY, PRIM_OP_INDICATION):
			printf("%s(): Rx %s sess_id=%u allocated_ptmsi=0x%08x allocated_ptmsi_sig=0x%06x allocated_tlli=0x%08x\n", __func__, pdu_name,
			       gmm_prim->gmmsm.sess_id,
			       gmm_prim->gmmsm.modify_ind.allocated_ptmsi,
			       gmm_prim->gmmsm.modify_ind.allocated_ptmsi_sig,
			       gmm_prim->gmmsm.modify_ind.allocated_tlli);
			break;
		default:
			printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
			OSMO_ASSERT(0)
		}
		break;
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

int test_gmm_prim_down_cb(struct osmo_gprs_gmm_prim *gmm_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_gmm_prim_name(gmm_prim);

	switch (gmm_prim->oph.sap) {
	case OSMO_GPRS_GMM_SAP_GMMBSSGP:
		switch (OSMO_PRIM_HDR(&gmm_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMBSSGP_PAGING, PRIM_OP_REQUEST):
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMBSSGP_RA_CAPABILITY, PRIM_OP_REQUEST):
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMBSSGP_RA_CAPABILITY_UPDATE, PRIM_OP_RESPONSE):
		case OSMO_PRIM(OSMO_GPRS_GMM_GMMBSSGP_MS_REGISTRATION_ENQUIRY, PRIM_OP_RESPONSE):
			printf("%s(): Rx %s\n", __func__, pdu_name);
			break;
		}
		break;
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

int test_gmm_prim_llc_down_cb(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_llc_prim_name(llc_prim);
	struct osmo_gprs_gmm_prim *gmm_prim_tx;

	switch (llc_prim->oph.sap) {
	case OSMO_GPRS_LLC_SAP_LLGMM:
		switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_LLC_LLGMM_ASSIGN, PRIM_OP_REQUEST):
			printf("%s(): Rx %s old_TLLI=0x%08x new_TLLI=0x%08x\n",
			       __func__, pdu_name,
			       llc_prim->llgmm.tlli, llc_prim->llgmm.assign_req.tlli_new);
			break;
		default:
			printf("%s(): Rx %s TLLI=0x%08x\n", __func__, pdu_name, llc_prim->llgmm.tlli);
		}
		break;
	case OSMO_GPRS_LLC_SAP_LL:
		printf("%s(): Rx %s TLLI=0x%08x SAPI=%s l3=[%s]\n", __func__, pdu_name,
		       llc_prim->ll.tlli, osmo_gprs_llc_sapi_name(llc_prim->ll.sapi),
		       osmo_hexdump(llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len));
		switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
		case OSMO_PRIM(OSMO_GPRS_LLC_LL_UNITDATA, PRIM_OP_REQUEST):
			/* Immediately notify GMM that it was transmitted over the air: */
			gmm_prim_tx = (struct osmo_gprs_gmm_prim *)gprs_rlcmac_prim_alloc_gmmrr_llc_transmitted_ind(llc_prim->ll.tlli);
			gmm_prim_tx->oph.sap = OSMO_GPRS_GMM_SAP_GMMRR;
			gmm_prim_tx->oph.primitive = OSMO_GPRS_GMM_GMMRR_LLC_TRANSMITTED;
			osmo_gprs_gmm_prim_lower_up(gmm_prim_tx);
			break;
		}
		break;
	default:
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return 0;
}

/* Test explicit GPRS attach through GMMREG, TS 24.007 Annex C.1 */
static void test_gmm_prim_ms_gmmreg(void)
{
	//struct osmo_gprs_gmm_prim *gmm_prim;
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	uint32_t rand_tlli = 0x80001234;

	printf("==== %s() [start] ====\n", __func__);

	clock_override_set(0, 0);

	rc = osmo_gprs_gmm_init(OSMO_GPRS_GMM_LOCATION_NETWORK);
	OSMO_ASSERT(rc == 0);

	osmo_gprs_gmm_prim_set_up_cb(test_gmm_prim_up_cb, NULL);
	osmo_gprs_gmm_prim_set_down_cb(test_gmm_prim_down_cb, NULL);
	osmo_gprs_gmm_prim_set_llc_down_cb(test_gmm_prim_llc_down_cb, NULL);

	/* MS sends GMM Attach Req */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(rand_tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_att_req, sizeof(pdu_gmm_att_req));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	/* TODO: implement this primitive!
	 * OSMO_ASSERT(rc == 0); */
	/* As a result, Network answers with GMM Identification Request. */

	/* MS sends GMM Identification response */
	llc_prim = gprs_llc_prim_alloc_ll_unitdata_ind(rand_tlli, OSMO_GPRS_LLC_SAPI_GMM, (uint8_t *)pdu_gmm_id_resp, sizeof(pdu_gmm_id_resp));
	OSMO_ASSERT(llc_prim);
	rc = osmo_gprs_gmm_prim_llc_lower_up(llc_prim);
	/* TODO: implement this primitive!
	 * OSMO_ASSERT(rc == 0); */

	/* ... */

	printf("==== %s() [end] ====\n", __func__);
}

static const struct log_info_cat test_log_categories[] = { };
static const struct log_info test_log_info = {
	.cat = test_log_categories,
	.num_cat = ARRAY_SIZE(test_log_categories),
};

int main(int argc, char *argv[])
{
	tall_ctx = talloc_named_const(NULL, 1, __FILE__);

	osmo_init_logging2(tall_ctx, &test_log_info);
	log_parse_category_mask(osmo_stderr_target, "DLGLOBAL,1:");
	osmo_fsm_log_addr(false);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	clock_override_enable(true);

	test_gmm_prim_ms_gmmreg();

	talloc_free(tall_ctx);
}
