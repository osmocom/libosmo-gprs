/* GPRS RLC/MAC Entity (one per MS) */
#pragma once

#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/llc_queue.h>
#include <osmocom/gprs/rlcmac/tbf_dl_ass_fsm.h>

struct gprs_rlcmac_dl_tbf;
struct gprs_rlcmac_ul_tbf;
struct gprs_rlcmac_tbf;

struct gprs_rlcmac_entity {
	struct llist_head entry; /* item in (struct gprs_rlcmac_ctx)->gre_list */
	uint32_t tlli;

	/* Used to match paging requests coming from CS domain: */
	uint32_t ptmsi;
	char imsi[OSMO_IMSI_BUF_SIZE];

	struct gprs_rlcmac_llc_queue *llc_queue;

	/* Manage TBF Starting Time delay during TBF assignment: */
	struct gprs_rlcmac_tbf_dl_ass_fsm_ctx dl_tbf_dl_ass_fsm;

	struct gprs_rlcmac_dl_tbf *dl_tbf;
	struct gprs_rlcmac_ul_tbf *ul_tbf;

	bool freeing; /* Set to true during destructor */
};

struct gprs_rlcmac_entity *gprs_rlcmac_entity_alloc(uint32_t tlli);
void gprs_rlcmac_entity_free(struct gprs_rlcmac_entity *gre);

bool gprs_rlcmac_entity_in_packet_idle_mode(const struct gprs_rlcmac_entity *gre);
bool gprs_rlcmac_entity_in_packet_transfer_mode(const struct gprs_rlcmac_entity *gre);
bool gprs_rlcmac_entity_have_tx_data_queued(const struct gprs_rlcmac_entity *gre);
int gprs_rlcmac_entity_start_ul_tbf_pkt_acc_proc_if_needed(struct gprs_rlcmac_entity *gre);

int gprs_rlcmac_entity_llc_enqueue(struct gprs_rlcmac_entity *gre, uint8_t *ll_pdu, unsigned int ll_pdu_len,
				   enum osmo_gprs_rlcmac_llc_sapi sapi, uint8_t radio_prio);

struct msgb *gprs_rlcmac_gre_create_pkt_ctrl_ack(const struct gprs_rlcmac_entity *gre);

void gprs_rlcmac_entity_dl_tbf_freed(struct gprs_rlcmac_entity *gre, const struct gprs_rlcmac_dl_tbf *ul_tbf);
void gprs_rlcmac_entity_ul_tbf_freed(struct gprs_rlcmac_entity *gre, const struct gprs_rlcmac_ul_tbf *ul_tbf);


#define LOGGRE(gre, level, fmt, args...) \
	LOGRLCMAC(level, "GRE(%08x) " fmt, (gre)->tlli, ## args)
