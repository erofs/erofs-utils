/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs-utils/include/erofs/compress.h
 *
 * Copyright (C) 2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <gaoxiang25@huawei.com>
 */
#ifndef __EROFS_COMPRESS_H
#define __EROFS_COMPRESS_H

#include "internal.h"

/* workaround for an upstream lz4 compression issue, which can crash us */
/* #define EROFS_CONFIG_COMPR_MAX_SZ        (1024 * 1024) */
#define EROFS_CONFIG_COMPR_MAX_SZ           (900  * 1024)
#define EROFS_CONFIG_COMPR_MIN_SZ           (32   * 1024)

int erofs_write_compressed_file(struct erofs_inode *inode);

int z_erofs_compress_init(void);
int z_erofs_compress_exit(void);

const char *z_erofs_list_available_compressors(unsigned int i);

#endif

