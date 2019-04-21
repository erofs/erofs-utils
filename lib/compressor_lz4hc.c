// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/compressor-lz4hc.c
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <gaoxiang25@huawei.com>
 */
#define LZ4_HC_STATIC_LINKING_ONLY (1)
#include <lz4hc.h>
#include "erofs/internal.h"
#include "compressor.h"

static int lz4hc_compress_destsize(struct erofs_compress *c,
				   int compression_level,
				   void *src,
				   unsigned int *srcsize,
				   void *dst,
				   unsigned int dstsize)
{
	int srcSize = (int)*srcsize;
	int rc = LZ4_compress_HC_destSize(c->private_data, src, dst,
					  &srcSize, (int)dstsize,
					  compression_level);
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

static int compressor_lz4hc_init(struct erofs_compress *c,
				 char *alg_name)
{
	if (alg_name && strcmp(alg_name, "lz4hc"))
		return -EINVAL;

	c->alg = &erofs_compressor_lz4hc;

	c->private_data = LZ4_createStreamHC();
	if (!c->private_data)
		return -ENOMEM;
	return 0;
}

struct erofs_compressor erofs_compressor_lz4hc = {
	.default_level = LZ4HC_CLEVEL_DEFAULT,
	.best_level = LZ4HC_CLEVEL_MAX,
	.init = compressor_lz4hc_init,
	.exit = compressor_lz4hc_exit,
	.compress_destsize = lz4hc_compress_destsize,
};

