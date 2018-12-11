/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_lz4hc.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_LZ4HC_H__
#define __EROFS_LZ4HC_H__

#include <stdint.h>
#include <lz4hc.h>

#define EROFS_COMPR_LZ4HC_DEF_LVL (9)

void *erofs_lz4hc_init(void);
void erofs_lz4hc_deinit(void *ctx);
int64_t erofs_lz4hc_compress(char *in, size_t insz, char *out, size_t outsz,
			     size_t *inszptr, int level, void *);
#endif
