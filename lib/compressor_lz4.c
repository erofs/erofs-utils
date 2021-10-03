// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <gaoxiang25@huawei.com>
 */
#include <lz4.h>
#include "erofs/internal.h"
#include "compressor.h"

#ifndef LZ4_DISTANCE_MAX	/* history window size */
#define LZ4_DISTANCE_MAX 65535	/* set to maximum value by default */
#endif

static int lz4_compress_destsize(struct erofs_compress *c,
				 void *src, unsigned int *srcsize,
				 void *dst, unsigned int dstsize)
{
	int srcSize = (int)*srcsize;
	int rc = LZ4_compress_destSize(src, dst, &srcSize, (int)dstsize);

	if (!rc)
		return -EFAULT;
	*srcsize = srcSize;
	return rc;
}

static int compressor_lz4_exit(struct erofs_compress *c)
{
	return 0;
}

static int compressor_lz4_init(struct erofs_compress *c)
{
	c->alg = &erofs_compressor_lz4;
	sbi.lz4_max_distance = LZ4_DISTANCE_MAX;
	return 0;
}

struct erofs_compressor erofs_compressor_lz4 = {
	.name = "lz4",
	.default_level = 0,
	.best_level = 0,
	.init = compressor_lz4_init,
	.exit = compressor_lz4_exit,
	.compress_destsize = lz4_compress_destsize,
};
