/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
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

void blob_closeall(struct erofs_sb_info *sbi);
int blob_open_ro(struct erofs_sb_info *sbi, const char *dev);
int dev_open(struct erofs_sb_info *sbi, const char *devname);
int dev_open_ro(struct erofs_sb_info *sbi, const char *dev);
void dev_close(struct erofs_sb_info *sbi);
int dev_write(struct erofs_sb_info *sbi, const void *buf,
	      u64 offset, size_t len);
int dev_read(struct erofs_sb_info *sbi, int device_id,
	     void *buf, u64 offset, size_t len);
int dev_fillzero(struct erofs_sb_info *sbi, u64 offset,
		 size_t len, bool padding);
int dev_fsync(struct erofs_sb_info *sbi);
int dev_resize(struct erofs_sb_info *sbi, erofs_blk_t nblocks);

ssize_t erofs_copy_file_range(int fd_in, erofs_off_t *off_in,
			      int fd_out, erofs_off_t *off_out,
			      size_t length);

static inline int blk_write(struct erofs_sb_info *sbi, const void *buf,
			    erofs_blk_t blkaddr, u32 nblocks)
{
	return dev_write(sbi, buf, erofs_pos(sbi, blkaddr),
			 erofs_pos(sbi, nblocks));
}

static inline int blk_read(struct erofs_sb_info *sbi, int device_id, void *buf,
			   erofs_blk_t start, u32 nblocks)
{
	return dev_read(sbi, device_id, buf, erofs_pos(sbi, start),
			erofs_pos(sbi, nblocks));
}

#ifdef __cplusplus
}
#endif

#endif // EROFS_IO_H_
