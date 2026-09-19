/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_COND_H
#define __EROFS_COND_H

#include "lock.h"

#if defined(HAVE_PTHREAD_H) && defined(EROFS_MT_ENABLED)
#include <pthread.h>

typedef pthread_cond_t erofs_cond_t;

static inline void erofs_cond_init(erofs_cond_t *cond)
{
	pthread_cond_init(cond, NULL);
}
#define erofs_cond_wait		pthread_cond_wait
#define erofs_cond_signal	pthread_cond_signal
#define erofs_cond_broadcast	pthread_cond_broadcast
#define erofs_cond_destroy	pthread_cond_destroy

#else
typedef struct {} erofs_cond_t;

static inline void erofs_cond_init(erofs_cond_t *cond) {}
static inline int erofs_cond_wait(erofs_cond_t *cond, erofs_mutex_t *mutex) { return 0; }
static inline int erofs_cond_signal(erofs_cond_t *cond) { return 0; }
static inline int erofs_cond_broadcast(erofs_cond_t *cond) { return 0; }
static inline int erofs_cond_destroy(erofs_cond_t *cond) { return 0; }
#endif

#endif
