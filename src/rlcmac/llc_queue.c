/* llc_queue.c
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2023 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */


#include <stdio.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/timer_compat.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>
#include <osmocom/gprs/rlcmac/llc_queue.h>
#include <osmocom/gprs/rlcmac/gre.h>

struct llc_queue_entry_hdr {
	struct timespec recv_time;
};

struct gprs_rlcmac_llc_queue *gprs_rlcmac_llc_queue_alloc(struct gprs_rlcmac_entity *gre)
{
	struct gprs_rlcmac_llc_queue *q;
	uint32_t i, j;

	q = talloc_zero(gre, struct gprs_rlcmac_llc_queue);
	if (!q)
		return NULL;

	q->gre = gre;
	q->queue_size = 0;
	q->queue_octets = 0;
	q->avg_queue_delay = 0;
	for (i = 0; i < ARRAY_SIZE(q->pq); i++) {
		for (j = 0; j < ARRAY_SIZE(q->pq[i]); j++) {
			INIT_LLIST_HEAD(&q->pq[i][j].queue);
			gprs_codel_init(&q->pq[i][j].codel_state);
		}
	}

	return q;
}

void gprs_rlcmac_llc_queue_free(struct gprs_rlcmac_llc_queue *q)
{
	talloc_free(q);
}

void gprs_rlcmac_llc_queue_set_codel_params(struct gprs_rlcmac_llc_queue *q, bool use, unsigned int interval_msec)
{
	unsigned int i, j;

	q->use_codel = use;

	if (!q->use_codel)
		return;

	for (i = 0; i < ARRAY_SIZE(q->pq); i++)
		for (j = 0; j < ARRAY_SIZE(q->pq[i]); j++)
			gprs_codel_set_interval(&q->pq[i][j].codel_state, interval_msec);
}

static enum gprs_rlcmac_llc_queue_sapi_prio gprs_rlcmac_llc_sapi2prio(enum osmo_gprs_rlcmac_llc_sapi sapi)
{
	switch (sapi) {
	case OSMO_GPRS_RLCMAC_LLC_SAPI_GMM:
		return GPRS_RLCMAC_LLC_QUEUE_SAPI_PRIO_GMM;
	case OSMO_GPRS_RLCMAC_LLC_SAPI_TOM2:
	case OSMO_GPRS_RLCMAC_LLC_SAPI_SMS:
	case OSMO_GPRS_RLCMAC_LLC_SAPI_TOM8:
		return GPRS_RLCMAC_LLC_QUEUE_SAPI_PRIO_TOM_SMS;
	default:
		return GPRS_RLCMAC_LLC_QUEUE_SAPI_PRIO_OTHER;
	}
}

int gprs_rlcmac_llc_queue_enqueue(struct gprs_rlcmac_llc_queue *q, uint8_t *ll_pdu, unsigned int ll_pdu_len,
				   enum osmo_gprs_rlcmac_llc_sapi sapi, uint8_t radio_prio)
{
	struct llc_queue_entry_hdr *ehdr;
	enum gprs_rlcmac_llc_queue_sapi_prio sapi_prio;
	struct msgb *msg;

	/* Trim to expected values 1..4, (3GPP TS 24.008) 10.5.7.2 */
	if (radio_prio < _GPRS_RLCMAC_RADIO_PRIO_HIGHEST)
		radio_prio = _GPRS_RLCMAC_RADIO_PRIO_HIGHEST;
	else if (radio_prio > _GPRS_RLCMAC_RADIO_PRIO_LOWEST)
		radio_prio = _GPRS_RLCMAC_RADIO_PRIO_LOWEST;

	sapi_prio = gprs_rlcmac_llc_sapi2prio(sapi);

	msg = msgb_alloc_headroom(sizeof(*ehdr) + ll_pdu_len, 0, "llc_queue_msg");
	msg->l1h = msgb_put(msg, sizeof(*ehdr));
	ehdr = (struct llc_queue_entry_hdr *)msg->l1h;

	osmo_clock_gettime(CLOCK_MONOTONIC, &ehdr->recv_time);

	if (ll_pdu_len) {
		msg->l2h = msgb_put(msg, ll_pdu_len);
		memcpy(msg->l2h, ll_pdu, ll_pdu_len);
	} else {
		msg->l2h = NULL;
	}

	msgb_enqueue(&q->pq[RADIO_PRIO_NORM(radio_prio)][sapi_prio].queue, msg);
	q->queue_size += 1;
	q->queue_octets += ll_pdu_len;

	return 0;
}

void gprs_rlcmac_llc_queue_clear(struct gprs_rlcmac_llc_queue *q)
{
	struct msgb *msg;
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(q->pq); i++) {
		for (j = 0; j < ARRAY_SIZE(q->pq[i]); j++) {
			while ((msg = msgb_dequeue(&q->pq[i][j].queue)))
				msgb_free(msg);
		}
	}

	q->queue_size = 0;
	q->queue_octets = 0;
}

#define ALPHA 0.5f

static struct msgb *gprs_rlcmac_llc_queue_pick_msg(struct gprs_rlcmac_llc_queue *q, struct gprs_llc_prio_queue **prioq)
{
	struct msgb *msg;
	struct timespec tv_now, tv_result;
	uint32_t lifetime;
	unsigned int i, j;
	const struct llc_queue_entry_hdr *ehdr;

	for (i = 0; i < ARRAY_SIZE(q->pq); i++) {
		for (j = 0; j < ARRAY_SIZE(q->pq[i]); j++) {
			if ((msg = msgb_dequeue(&q->pq[i][j].queue))) {
				*prioq = &q->pq[i][j];
				goto found;
			}
		}
	}
	return NULL;

found:
	ehdr = msgb_l1(msg);

	q->queue_size -= 1;
	q->queue_octets -= msgb_l2len(msg);

	/* take the second time */
	osmo_clock_gettime(CLOCK_MONOTONIC, &tv_now);
	timespecsub(&tv_now, &ehdr->recv_time, &tv_result);

	lifetime = tv_result.tv_sec*1000 + tv_result.tv_nsec/1000000;
	q->avg_queue_delay = q->avg_queue_delay * ALPHA + lifetime * (1-ALPHA);

	return msg;
}

struct msgb *gprs_rlcmac_llc_queue_dequeue(struct gprs_rlcmac_llc_queue *q)
{
	struct msgb *msg;
	struct timespec tv_now;
	uint32_t octets = 0, frames = 0;
	struct gprs_llc_prio_queue *prioq;
	const struct llc_queue_entry_hdr *ehdr;

	osmo_clock_gettime(CLOCK_MONOTONIC, &tv_now);

	while ((msg = gprs_rlcmac_llc_queue_pick_msg(q, &prioq))) {
		ehdr = msgb_l1(msg);
		if (q->use_codel) {
			int bytes = gprs_rlcmac_llc_queue_octets(q);
			if (gprs_codel_control(&prioq->codel_state, &ehdr->recv_time, &tv_now, bytes)) {
				/* Drop frame: */
				frames++;
				octets += msg->len;
				msgb_free(msg);
				/* rate_ctr_inc(CTR_LLC_FRAME_DROPPED); */
			}
		}

		/* dequeue current msg */
		break;
	}

	if (frames > 0) {
		LOGGRE(q->gre, LOGL_NOTICE, "Discarding %u LLC PDUs (%u octets) due to codel algo, "
		       "new_queue_size=%zu\n", frames, octets, gprs_rlcmac_llc_queue_size(q));
	}

	msgb_pull_to_l2(msg);

	return msg;
}