/*! \file it_msgq.c
 * Osmocom Inter-Thread message queue implementation */
/* (C) 2019 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301, USA.
 */

/*! \addtogroup it_msgq
 *  @{
 *  Inter-Thread Message Queue.
 *
 * This implements a general-purpose message queue between threads. It
 * uses 'struct msgb' as elements in the queue and an eventfd-based notification
 * mechanism.  Hence, it can be used for pretty much anything that can be stored
 * inside msgbs, including msgb-wrapped osmo_prim.
 *
 * The idea is that the sending thread simply calls osmo_it_msgq_enqueue().
 * The receiving thread is woken up from its osmo_select_main() loop by eventfd,
 * and a general osmo_fd callback function for the eventfd will dequeue each msgb
 * and call a queue-specific callback function.
 */

#include "../config.h"

#ifdef HAVE_SYS_EVENTFD_H

#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/eventfd.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/it_msgq.h>

static int eventfd_increment(int fd, uint64_t inc)
{
	int rc;

	rc = write(fd, &inc, sizeof(inc));
	if (rc != sizeof(inc))
		return -1;

	return 0;
}

/* global (for all threads) list of message queues in a program + associated lock */
static LLIST_HEAD(msg_queues);
static pthread_rwlock_t msg_queues_rwlock;

static struct osmo_it_msgq *_osmo_it_msgq_by_name(const char *name)
{
	struct osmo_it_msgq *q;
	llist_for_each_entry(q, &msg_queues, entry) {
		if (!strcmp(q->name, name))
			return q;
	}
	return NULL;
}

struct osmo_it_msgq *osmo_it_msgq_by_name(const char *name)
{
	struct osmo_it_msgq *q;
	pthread_rwlock_rdlock(&msg_queues_rwlock);
	q = _osmo_it_msgq_by_name(name);
	pthread_rwlock_unlock(&msg_queues_rwlock);
	return q;
}

/* osmo_fd call-back when eventfd is readable */
static int osmo_it_msgq_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct osmo_it_msgq *q = (struct osmo_it_msgq *) ofd->data;
	uint64_t val;
	int i, rc;

	if (!(what & OSMO_FD_READ))
		return 0;

	rc = read(ofd->fd, &val, sizeof(val));
	if (rc < sizeof(val))
		return rc;

	for (i = 0; i < val; i++) {
		struct msgb *msg = osmo_it_msgq_dequeue(q);
		/* in case the user might have called osmo_it_msgq_flush() we may
		 * end up in the eventfd-dispatch but witout any messages left in the queue,
		 * otherwise I'd have loved to OSMO_ASSERT(msg) here. */
		if (!msg)
			break;
		q->read_cb(q, msg);
	}

	return 0;
}

/*! Allocate a new inter-thread message queue.
 *  \param[in] ctx talloc context from which to allocate the queue
 *  \param[in] name human-readable string name of the queue; function creates a copy.
 *  \param[in] read_cb call-back function to be called for each de-queued message
 *  \returns a newly-allocated inter-thread message queue; NULL in case of error */
struct osmo_it_msgq *osmo_it_msgq_alloc(void *ctx, const char *name, unsigned int max_length,
					void (*read_cb)(struct osmo_it_msgq *q, struct msgb *msg),
					void *data)
{
	struct osmo_it_msgq *q;
	int fd;

	q = talloc_zero(ctx, struct osmo_it_msgq);
	if (!q)
		return NULL;
	q->data = data;
	q->name = talloc_strdup(q, name);
	q->current_length = 0;
	q->max_length = max_length;
	q->read_cb = read_cb;
	INIT_LLIST_HEAD(&q->list);

	/* create eventfd */
	fd = eventfd(0, 0);
	if (fd < 0) {
		talloc_free(q);
		return NULL;
	}

	/* initialize BUT NOT REGISTER the osmo_fd. The receiving thread must
	 * take are to select/poll/read/... on ot */
	osmo_fd_setup(&q->event_ofd, fd, OSMO_FD_READ, osmo_it_msgq_fd_cb, q, 0);

	/* add to global list of queues, checking for duplicate names */
	pthread_rwlock_wrlock(&msg_queues_rwlock);
	if (_osmo_it_msgq_by_name(q->name)) {
		pthread_rwlock_unlock(&msg_queues_rwlock);
		osmo_fd_close(&q->event_ofd);
		talloc_free(q);
		return NULL;
	}
	llist_add_tail(&q->entry, &msg_queues);
	pthread_rwlock_unlock(&msg_queues_rwlock);

	return q;
}

/*! Flush all messages currently present in queue */
static void _osmo_it_msgq_flush(struct osmo_it_msgq *q)
{
	struct msgb *msg;
	while ((msg = msgb_dequeue_count(&q->list, &q->current_length))) {
		msgb_free(msg);
	}
}

/*! Flush all messages currently present in queue */
void osmo_it_msgq_flush(struct osmo_it_msgq *q)
{
	pthread_mutex_lock(&q->mutex);
	_osmo_it_msgq_flush(q);
	pthread_mutex_unlock(&q->mutex);
}

/*! Destroy a message queue */
void osmo_it_msgq_destroy(struct osmo_it_msgq *q)
{
	/* first remove from global list of queues */
	pthread_rwlock_wrlock(&msg_queues_rwlock);
	llist_del(&q->entry);
	pthread_rwlock_unlock(&msg_queues_rwlock);
	/* next, close the eventfd */
	osmo_fd_close(&q->event_ofd);
	/* flush all messages still present */
	osmo_it_msgq_flush(q);
	/* and finally release memory */
	talloc_free(q);
}

/*! Thread-safe en-queue to an inter-thread message queue.
 *  \param[in] queue Inter-thread queue on which to enqueue
 *  \param[in] msgb Message buffer to enqueue
 *  \returns 0 on success; negative on error */
int osmo_it_msgq_enqueue(struct osmo_it_msgq *queue, struct msgb *msg)
{
	pthread_mutex_lock(&queue->mutex);
	if (queue->current_length+1 > queue->max_length) {
		pthread_mutex_unlock(&queue->mutex);
		return -ENOSPC;
	}
	msgb_enqueue_count(&queue->list, msg, &queue->current_length);
	pthread_mutex_unlock(&queue->mutex);
	/* increment eventfd counter by one */
	eventfd_increment(queue->event_ofd.fd, 1);
	return 0;
}

/*! Thread-safe de-queue from an inter-thread message queue.
 *  \param[in] queue Inter-thread queue from which to dequeue
 *  \returns dequeued message buffer; NULL if none available
 */
struct msgb *osmo_it_msgq_dequeue(struct osmo_it_msgq *queue)
{
	struct msgb *msg;

	pthread_mutex_lock(&queue->mutex);
	msg = msgb_dequeue_count(&queue->list, &queue->current_length);
	pthread_mutex_unlock(&queue->mutex);

	return msg;
}

#endif /* HAVE_SYS_EVENTFD_H */

/*! @} */
