/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_IO_H
#define __EROFS_IO_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include "internal.h"

#ifndef O_BINARY
#define O_BINARY	0
#endif

void blob_closeall(void);
int blob_open_ro(const char *dev);
int dev_open(const char *devname);
int dev_open_ro(const char *dev);
void dev_close(void);
int dev_write(const void *buf, u64 offset, size_t len);
int dev_read(int device_id, void *buf, u64 offset, size_t len);
int dev_fillzero(u64 offset, size_t len, bool padding);
int dev_fsync(void);
int dev_resize(erofs_blk_t nblocks);
u64 dev_length(void);

extern int erofs_devfd;

ssize_t erofs_copy_file_range(int fd_in, erofs_off_t *off_in,
			      int fd_out, erofs_off_t *off_out,
			      size_t length);

static inline int blk_write(const void *buf, erofs_blk_t blkaddr,
			    u32 nblocks)
{
	return dev_write(buf, blknr_to_addr(blkaddr),
			 blknr_to_addr(nblocks));
}

static inline int blk_read(int device_id, void *buf,
			   erofs_blk_t start, u32 nblocks)
{
	return dev_read(device_id, buf, blknr_to_addr(start),
			 blknr_to_addr(nblocks));
}

#ifdef __cplusplus
}
#endif

#endif // EROFS_IO_H_
