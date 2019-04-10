/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_utils/include/erofs/io.h
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
void dev_close(void);
int dev_write(const void *buf, u64 offset, size_t len);
int dev_fsync(void);
u64 dev_length(void);

static inline int blk_write(const void *buf, erofs_blk_t blkaddr,
			    u32 nblocks)
{
	return dev_write(buf, blknr_to_addr(blkaddr),
			 blknr_to_addr(nblocks));
}

#endif

