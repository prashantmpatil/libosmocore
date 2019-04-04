#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <pthread.h>

/*! \defgroup it_msgq Inter-ThreadMessage Queue
 *  @{
 *  \file it_msgq.h */

struct osmo_it_msgq {
	/* entry in global list of message queues */
	struct llist_head entry;

	/* the actual list of msgb's. HEAD: first in queue; TAIL: last in queue */
	struct llist_head list;
	/* A pthread mutex to safeguard accesses to the queue. No rwlock as we always write. */
	pthread_mutex_t mutex;
	/* Current count of messages in the queue */
	unsigned int current_length;
	/* osmo-fd wrapped eventfd */
	struct osmo_fd event_ofd;

	/* a user-defined name for this queue */
	const char *name;
	/* maximum permitted length of queue */
	unsigned int max_length;
	/* read call-back, called for each de-queued message */
	void (*read_cb)(struct osmo_it_msgq *q, struct msgb *msg);
	/* opaque data pointer passed through to call-back function */
	void *data;
};

struct osmo_it_msgq *osmo_it_msgq_by_name(const char *name);
int osmo_it_msgq_enqueue(struct osmo_it_msgq *queue, struct msgb *msg);
struct msgb *osmo_it_msgq_dequeue(struct osmo_it_msgq *queue);
struct osmo_it_msgq *osmo_it_msgq_alloc(void *ctx, const char *name, unsigned int max_length,
					void (*read_cb)(struct osmo_it_msgq *q, struct msgb *msg),
					void *data);
void osmo_it_msgq_destroy(struct osmo_it_msgq *q);
void osmo_it_msgq_flush(struct osmo_it_msgq *q);

/*! @} */
