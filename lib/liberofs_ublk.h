/* SPDX-License-Identifier: GPL-2.0+ OR MIT */
/*
 * Copyright (C) 2026 Tencent, Inc.
 *             http://www.tencent.com/
 */
#ifndef __EROFS_LIB_LIBEROFS_UBLK_H
#define __EROFS_LIB_LIBEROFS_UBLK_H

#include "erofs/defs.h"

#define EROFS_UBLK_DEF_NR_HW_QUEUES	1
#define EROFS_UBLK_DEF_QUEUE_DEPTH	128
#define EROFS_UBLK_DEF_MAX_IO_BUF_BYTES	(512 * 1024)
#define EROFS_UBLK_DEF_BLK_BITS		9

#define EROFS_UBLK_F_UNPRIVILEGED	(1U << 0)
#define EROFS_UBLK_F_USER_RECOVERY	(1U << 1)

#define EROFS_UBLK_OP_READ		0

struct erofs_ublk_dev_info {
	u16 nr_hw_queues;
	u16 queue_depth;
	u32 max_io_buf_bytes;
	u32 dev_id;
	u64 dev_size;
	u8 blkbits;
	u8 reserved[3];
	u32 flags;
};

struct erofs_ublk_request {
	u8 op;
	u64 start_sector;
	u32 nr_sectors;
	void *buf;
	int result;
};

typedef int (*erofsublk_io_handler_t)(void *ctx, struct erofs_ublk_request *rq);

#ifdef HAVE_LIBURING
int erofs_ublk_init(void);

int erofs_ublk_create_dev(const struct erofs_ublk_dev_info *info,
			  erofsublk_io_handler_t handler,
			  void *handler_ctx);
int erofs_ublk_start(int dev_id, int ready_fd);
void erofs_ublk_destroy(int dev_id);

int erofs_ublk_del_dev_by_id(int dev_id);

int erofs_ublk_recover_dev(int dev_id,
			   erofsublk_io_handler_t handler,
			   void *handler_ctx);
int erofs_ublk_is_recoverable(int dev_id);

#else

static inline int erofs_ublk_init(void)
{
	return -EOPNOTSUPP;
}

static inline int erofs_ublk_create_dev(const struct erofs_ublk_dev_info *info,
					erofsublk_io_handler_t handler,
					void *handler_ctx)
{
	return -EOPNOTSUPP;
}

static inline void erofs_ublk_destroy(int dev_id) {}

static inline int erofs_ublk_start(int dev_id, int ready_fd)
{
	return -EOPNOTSUPP;
}

static inline int erofs_ublk_recover_dev(int dev_id,
					 erofsublk_io_handler_t handler,
					 void *handler_ctx)
{
	return -EOPNOTSUPP;
}

static inline int erofs_ublk_is_recoverable(int dev_id) { return 0; }

static inline int erofs_ublk_del_dev_by_id(int dev_id) { return -EOPNOTSUPP; }
#endif

#endif
