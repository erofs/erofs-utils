// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <xiang@kernel.org>
 */
#include <lz4hc.h>
#include "erofs/internal.h"
#include "erofs/print.h"
#include "compressor.h"

#ifndef LZ4_DISTANCE_MAX	/* history window size */
#define LZ4_DISTANCE_MAX 65535	/* set to maximum value by default */
#endif

static int lz4hc_compress_destsize(const struct erofs_compress *c,
				   const void *src, unsigned int *srcsize,
				   void *dst, unsigned int dstsize)
{
	int srcSize = (int)*srcsize;
	int rc = LZ4_compress_HC_destSize(c->private_data, src, dst,
					  &srcSize, (int)dstsize,
					  c->compression_level);
	if (!rc)
		return -EFAULT;
	*srcsize = srcSize;
	return rc;
}

static int compressor_lz4hc_exit(struct erofs_compress *c)
{
	if (!c->private_data)
		return -EINVAL;

	LZ4_freeStreamHC(c->private_data);
	return 0;
}

static int compressor_lz4hc_init(struct erofs_compress *c)
{
	c->private_data = LZ4_createStreamHC();
	if (!c->private_data)
		return -ENOMEM;

	c->sbi->lz4.max_distance = max_t(u16, c->sbi->lz4.max_distance,
					 LZ4_DISTANCE_MAX);
	return 0;
}

static int compressor_lz4hc_setlevel(struct erofs_compress *c,
				     int compression_level)
{
	if (compression_level > erofs_compressor_lz4hc.best_level) {
		erofs_err("invalid compression level %d", compression_level);
		return -EINVAL;
	}

	c->compression_level = compression_level < 0 ?
		LZ4HC_CLEVEL_DEFAULT : compression_level;
	return 0;
}

const struct erofs_compressor erofs_compressor_lz4hc = {
	.default_level = LZ4HC_CLEVEL_DEFAULT,
	.best_level = LZ4HC_CLEVEL_MAX,
	.init = compressor_lz4hc_init,
	.exit = compressor_lz4hc_exit,
	.setlevel = compressor_lz4hc_setlevel,
	.compress_destsize = lz4hc_compress_destsize,
};
