#pragma once

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gprs/rlcmac/codel.h>
#include <osmocom/gprs/rlcmac/rlcmac_prim.h>
#include <osmocom/gprs/rlcmac/types_private.h>
#include <osmocom/gprs/rlcmac/rlcmac.h>

struct gprs_rlcmac_entity;

/* Highet/Lowest radio priority (biggest number) as per 3GPP TS 24.008 version 16.7.0 Release 16 section 10.5.7.2:
 * "All other values are interpreted as priority level 4 by this version of the protocol." */
#define _GPRS_RLCMAC_RADIO_NUM_PRIO 4

enum gprs_rlcmac_llc_queue_sapi_prio { /* lowest value has highest prio */
	GPRS_RLCMAC_LLC_QUEUE_SAPI_PRIO_GMM = 0, /* SAPI 1 */
	GPRS_RLCMAC_LLC_QUEUE_SAPI_PRIO_TOM_SMS, /* SAPI 2,7,8 */
	GPRS_RLCMAC_LLC_QUEUE_SAPI_PRIO_OTHER, /* Other SAPIs */
	_GPRS_RLCMAC_LLC_QUEUE_SAPI_PRIO_SIZE /* used to calculate size of enum */
};

struct gprs_llc_prio_queue {
	enum gprs_rlcmac_radio_priority radio_prio; /* Radio prio of this queue, range (1..4) */
	enum osmo_gprs_rlcmac_llc_sapi sapi; /* LLC SAPI of this queue */
	struct gprs_codel codel_state;
	struct llist_head queue; /* queued LLC DL data. See enum gprs_rlcmac_llc_queue_prio. */
};

struct gprs_rlcmac_llc_queue {
	struct gprs_rlcmac_entity *gre; /* backpointer */
	uint32_t avg_queue_delay; /* Average delay of data going through the queue */
	size_t queue_size;
	size_t queue_octets;
	bool use_codel;
	struct gprs_llc_prio_queue pq[_GPRS_RLCMAC_RADIO_NUM_PRIO][_GPRS_RLCMAC_LLC_QUEUE_SAPI_PRIO_SIZE]; /* queued LLC DL data. See enum gprs_rlcmac_llc_queue_prio. */
};

struct gprs_rlcmac_llc_queue *gprs_rlcmac_llc_queue_alloc(struct gprs_rlcmac_entity *gre);
void gprs_rlcmac_llc_queue_free(struct gprs_rlcmac_llc_queue *q);
void gprs_rlcmac_llc_queue_clear(struct gprs_rlcmac_llc_queue *q);

void gprs_rlcmac_llc_queue_set_codel_params(struct gprs_rlcmac_llc_queue *q, bool use, unsigned int interval_msec);

int gprs_rlcmac_llc_queue_enqueue(struct gprs_rlcmac_llc_queue *q, const uint8_t *ll_pdu, unsigned int ll_pdu_len,
				  enum osmo_gprs_rlcmac_llc_sapi sapi, enum gprs_rlcmac_radio_priority radio_prio);
struct msgb *gprs_rlcmac_llc_queue_dequeue(struct gprs_rlcmac_llc_queue *q, bool can_discard);
enum gprs_rlcmac_radio_priority gprs_rlcmac_llc_queue_highest_radio_prio_pending(struct gprs_rlcmac_llc_queue *q);
enum osmo_gprs_rlcmac_llc_sapi gprs_rlcmac_llc_queue_highest_llc_sapi_pending(struct gprs_rlcmac_llc_queue *q);

void gprs_rlcmac_llc_queue_merge_prepend(struct gprs_rlcmac_llc_queue *q, struct gprs_rlcmac_llc_queue *old_q);

static inline size_t gprs_rlcmac_llc_queue_size(const struct gprs_rlcmac_llc_queue *q)
{
	return q->queue_size;
}

static inline size_t gprs_rlcmac_llc_queue_octets(const struct gprs_rlcmac_llc_queue *q)
{
	return q->queue_octets;
}
