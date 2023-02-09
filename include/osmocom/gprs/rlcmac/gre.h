/* GPRS RLC/MAC Entity (one per MS) */
#pragma once

#include <osmocom/gprs/rlcmac/rlcmac.h>
#include <osmocom/gprs/rlcmac/llc_queue.h>

struct gprs_rlcmac_dl_tbf;
struct gprs_rlcmac_ul_tbf;

struct gprs_rlcmac_entity {
	struct llist_head entry; /* item in (struct gprs_rlcmac_ctx)->gre_list */
	uint32_t tlli;

	struct gprs_rlcmac_llc_queue *llc_queue;

	struct gprs_rlcmac_dl_tbf *dl_tbf;
	struct gprs_rlcmac_ul_tbf *ul_tbf;
};

struct gprs_rlcmac_entity *gprs_rlcmac_entity_alloc(uint32_t tlli);
void gprs_rlcmac_entity_free(struct gprs_rlcmac_entity *gre);

int gprs_rlcmac_entity_llc_enqueue(struct gprs_rlcmac_entity *gre, uint8_t *ll_pdu, unsigned int ll_pdu_len,
				   enum osmo_gprs_rlcmac_llc_sapi sapi, uint8_t radio_prio);

#define LOGGRE(gre, level, fmt, args...) \
	LOGRLCMAC(level, "GRE(%08x) " fmt, (gre)->tlli, ## args)
