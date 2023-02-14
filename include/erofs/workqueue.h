/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __EROFS_WORKQUEUE_H
#define __EROFS_WORKQUEUE_H

#include "internal.h"

struct erofs_workqueue;
struct erofs_work;

typedef void erofs_workqueue_func_t(struct erofs_workqueue *wq,
				    struct erofs_work *work);

struct erofs_work {
	struct erofs_workqueue	*queue;
	struct erofs_work	*next;
	erofs_workqueue_func_t	*function;
};

struct erofs_workqueue {
	pthread_t		*threads;
	struct erofs_work	*next_item;
	struct erofs_work	*last_item;
	pthread_mutex_t		lock;
	pthread_cond_t		wakeup;
	unsigned int		item_count;
	unsigned int		thread_count;
	bool			terminate;
	bool			terminated;
	int			max_queued;
	pthread_cond_t		queue_full;
};

int erofs_workqueue_create(struct erofs_workqueue *wq,
			   unsigned int nr_workers, unsigned int max_queue);
int erofs_workqueue_add(struct erofs_workqueue	*wq,
			struct erofs_work *wi);
int erofs_workqueue_terminate(struct erofs_workqueue *wq);
void erofs_workqueue_destroy(struct erofs_workqueue *wq);

#endif
