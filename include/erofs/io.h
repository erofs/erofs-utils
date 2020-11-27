/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs-utils/include/erofs/io.h
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_IO_H
#define __EROFS_IO_H

#include <unistd.h>
#include "internal.h"

#ifndef O_BINARY
#define O_BINARY	0
#endif

int dev_open(const char *devname);
int dev_open_ro(const char *dev);
void dev_close(void);
int dev_write(const void *buf, u64 offset, size_t len);
int dev_read(void *buf, u64 offset, size_t len);
int dev_fillzero(u64 offset, size_t len, bool padding);
int dev_fsync(void);
int dev_resize(erofs_blk_t nblocks);
u64 dev_length(void);

static inline int blk_write(const void *buf, erofs_blk_t blkaddr,
			    u32 nblocks)
{
	return dev_write(buf, blknr_to_addr(blkaddr),
			 blknr_to_addr(nblocks));
}

static inline int blk_read(void *buf, erofs_blk_t start,
			    u32 nblocks)
{
	return dev_read(buf, blknr_to_addr(start),
			 blknr_to_addr(nblocks));
}

#endif

