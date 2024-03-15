/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_WORKQUEUE_H
#define __EROFS_WORKQUEUE_H

#include "internal.h"

struct erofs_workqueue;

typedef void *(*erofs_wq_func_t)(struct erofs_workqueue *, void *);

struct erofs_work {
	struct erofs_work *next;
	void (*fn)(struct erofs_work *work, void *tlsp);
};

struct erofs_workqueue {
	struct erofs_work *head, *tail;
	pthread_mutex_t lock;
	pthread_cond_t cond_empty;
	pthread_cond_t cond_full;
	pthread_t *workers;
	unsigned int nworker;
	unsigned int max_jobs;
	unsigned int job_count;
	bool shutdown;
	erofs_wq_func_t on_start, on_exit;
};

int erofs_alloc_workqueue(struct erofs_workqueue *wq, unsigned int nworker,
			  unsigned int max_jobs, erofs_wq_func_t on_start,
			  erofs_wq_func_t on_exit);
int erofs_queue_work(struct erofs_workqueue *wq, struct erofs_work *work);
int erofs_destroy_workqueue(struct erofs_workqueue *wq);
#endif
