/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_io.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_IO_H
#define __EROFS_IO_H

#include <sys/cdefs.h>
#include "erofs_types.h"

int dev_open(const char *devname);
void dev_close(void);
int dev_write(void *buf, u64 offset, size_t len);
int dev_write_block(void *buf, u32 blkaddr);
int dev_fsync(void);
u64 dev_length(void);

#endif


