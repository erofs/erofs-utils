// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include "erofs/workqueue.h"

/* Main processing thread */
static void *workqueue_thread(void *arg)
{
	struct erofs_workqueue		*wq = arg;
	struct erofs_work		*wi;

	pthread_mutex_lock(&wq->lock);
	/*
	 * Loop pulling work from the passed in work queue.
	 * Check for notification to exit after every chunk of work.
	 */
	while (1) {
		/*
		 * Wait for work.
		 */
		while (wq->next_item == NULL && !wq->terminate) {
			assert(wq->item_count == 0);
			pthread_cond_wait(&wq->wakeup, &wq->lock);
		}
		if (wq->next_item == NULL && wq->terminate) {
			pthread_mutex_unlock(&wq->lock);
			break;
		}

		/*
		 *  Dequeue work from the head of the list. If the queue was
		 *  full then send a wakeup if we're configured to do so.
		 */
		assert(wq->item_count > 0);
		if (wq->max_queued)
			pthread_cond_broadcast(&wq->queue_full);

		wi = wq->next_item;
		wq->next_item = wi->next;
		wq->item_count--;

		if (wq->max_queued && wq->next_item) {
			/* more work, wake up another worker */
			pthread_cond_signal(&wq->wakeup);
		}
		wi->next = NULL;

		pthread_mutex_unlock(&wq->lock);
		(wi->function)(wq, wi);
		pthread_mutex_lock(&wq->lock);

		//wi->function = NULL;
	}
	return NULL;
}

/* Allocate a work queue and threads.  Returns zero or negative error code. */
int erofs_workqueue_create(struct erofs_workqueue *wq,
			   unsigned int nr_workers, unsigned int max_queue)
{
	unsigned int		i;
	int			err = 0;

	memset(wq, 0, sizeof(*wq));
	err = -pthread_cond_init(&wq->wakeup, NULL);
	if (err)
		return err;
	err = -pthread_cond_init(&wq->queue_full, NULL);
	if (err)
		goto out_wake;
	err = -pthread_mutex_init(&wq->lock, NULL);
	if (err)
		goto out_cond;

	wq->thread_count = nr_workers;
	wq->max_queued = max_queue;
	wq->threads = malloc(nr_workers * sizeof(pthread_t));
	if (!wq->threads) {
		err = -errno;
		goto out_mutex;
	}
	wq->terminate = false;
	wq->terminated = false;

	for (i = 0; i < nr_workers; i++) {
		err = -pthread_create(&wq->threads[i], NULL, workqueue_thread,
				wq);
		if (err)
			break;
	}

	/*
	 * If we encounter errors here, we have to signal and then wait for all
	 * the threads that may have been started running before we can destroy
	 * the workqueue.
	 */
	if (err)
		erofs_workqueue_destroy(wq);
	return err;
out_mutex:
	pthread_mutex_destroy(&wq->lock);
out_cond:
	pthread_cond_destroy(&wq->queue_full);
out_wake:
	pthread_cond_destroy(&wq->wakeup);
	return err;
}

/*
 * Create a work item consisting of a function and some arguments and schedule
 * the work item to be run via the thread pool.  Returns zero or a negative
 * error code.
 */
int erofs_workqueue_add(struct erofs_workqueue	*wq,
			struct erofs_work *wi)
{
	int	ret;

	assert(!wq->terminated);

	if (wq->thread_count == 0) {
		(wi->function)(wq, wi);
		return 0;
	}

	wi->queue = wq;
	wi->next = NULL;

	/* Now queue the new work structure to the work queue. */
	pthread_mutex_lock(&wq->lock);
restart:
	if (wq->next_item == NULL) {
		assert(wq->item_count == 0);
		ret = -pthread_cond_signal(&wq->wakeup);
		if (ret) {
			pthread_mutex_unlock(&wq->lock);
			return ret;
		}
		wq->next_item = wi;
	} else {
		/* throttle on a full queue if configured */
		if (wq->max_queued && wq->item_count == wq->max_queued) {
			pthread_cond_wait(&wq->queue_full, &wq->lock);
			/*
			 * Queue might be empty or even still full by the time
			 * we get the lock back, so restart the lookup so we do
			 * the right thing with the current state of the queue.
			 */
			goto restart;
		}
		wq->last_item->next = wi;
	}
	wq->last_item = wi;
	wq->item_count++;
	pthread_mutex_unlock(&wq->lock);
	return 0;
}

/*
 * Wait for all pending work items to be processed and tear down the
 * workqueue thread pool.  Returns zero or a negative error code.
 */
int erofs_workqueue_terminate(struct erofs_workqueue *wq)
{
	unsigned int		i;
	int			ret;

	pthread_mutex_lock(&wq->lock);
	wq->terminate = true;
	pthread_mutex_unlock(&wq->lock);

	ret = -pthread_cond_broadcast(&wq->wakeup);
	if (ret)
		return ret;

	for (i = 0; i < wq->thread_count; i++) {
		ret = -pthread_join(wq->threads[i], NULL);
		if (ret)
			return ret;
	}

	pthread_mutex_lock(&wq->lock);
	wq->terminated = true;
	pthread_mutex_unlock(&wq->lock);
	return 0;
}

/* Tear down the workqueue. */
void erofs_workqueue_destroy(struct erofs_workqueue *wq)
{
	assert(wq->terminated);

	free(wq->threads);
	pthread_mutex_destroy(&wq->lock);
	pthread_cond_destroy(&wq->wakeup);
	pthread_cond_destroy(&wq->queue_full);
	memset(wq, 0, sizeof(*wq));
}
