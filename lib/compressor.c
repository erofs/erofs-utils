// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <gaoxiang25@huawei.com>
 */
#include "erofs/internal.h"
#include "compressor.h"
#include "erofs/print.h"

#define EROFS_CONFIG_COMPR_DEF_BOUNDARY		(128)

static struct erofs_compressor *compressors[] = {
#if LZ4_ENABLED
#if LZ4HC_ENABLED
		&erofs_compressor_lz4hc,
#endif
		&erofs_compressor_lz4,
#endif
#if HAVE_LIBLZMA
		&erofs_compressor_lzma,
#endif
};

int erofs_compress_destsize(struct erofs_compress *c,
			    void *src, unsigned int *srcsize,
			    void *dst, unsigned int dstsize)
{
	unsigned int uncompressed_size;
	int ret;

	DBG_BUGON(!c->alg);
	if (!c->alg->compress_destsize)
		return -ENOTSUP;

	ret = c->alg->compress_destsize(c, src, srcsize, dst, dstsize);
	if (ret < 0)
		return ret;

	/* check if there is enough gains to compress */
	uncompressed_size = *srcsize;
	if (roundup(ret, EROFS_BLKSIZ) >= uncompressed_size *
	    c->compress_threshold / 100)
		return -EAGAIN;
	return ret;
}

const char *z_erofs_list_available_compressors(unsigned int i)
{
	return i >= ARRAY_SIZE(compressors) ? NULL : compressors[i]->name;
}

int erofs_compressor_setlevel(struct erofs_compress *c, int compression_level)
{
	DBG_BUGON(!c->alg);
	if (c->alg->setlevel)
		return c->alg->setlevel(c, compression_level);

	if (compression_level >= 0)
		return -EINVAL;
	c->compression_level = 0;
	return 0;
}

int erofs_compressor_init(struct erofs_compress *c, char *alg_name)
{
	int ret, i;

	/* should be written in "minimum compression ratio * 100" */
	c->compress_threshold = 100;

	/* optimize for 4k size page */
	c->destsize_alignsize = PAGE_SIZE;
	c->destsize_redzone_begin = PAGE_SIZE - 16;
	c->destsize_redzone_end = EROFS_CONFIG_COMPR_DEF_BOUNDARY;

	if (!alg_name) {
		c->alg = NULL;
		return 0;
	}

	ret = -EINVAL;
	for (i = 0; i < ARRAY_SIZE(compressors); ++i) {
		if (alg_name && strcmp(alg_name, compressors[i]->name))
			continue;

		ret = compressors[i]->init(c);
		if (!ret) {
			DBG_BUGON(!c->alg);
			return 0;
		}
	}
	erofs_err("Cannot find a valid compressor %s", alg_name);
	return ret;
}

int erofs_compressor_exit(struct erofs_compress *c)
{
	if (c->alg && c->alg->exit)
		return c->alg->exit(c);
	return 0;
}
