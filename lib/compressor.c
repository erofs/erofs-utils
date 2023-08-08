// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <gaoxiang25@huawei.com>
 */
#include "erofs/internal.h"
#include "compressor.h"
#include "erofs/print.h"

#define EROFS_CONFIG_COMPR_DEF_BOUNDARY		(128)

static const struct erofs_algorithm {
	char *name;
	const struct erofs_compressor *c;
	unsigned int id;

	/* its name won't be shown as a supported algorithm */
	bool optimisor;
} erofs_algs[] = {
	{ "lz4",
#if LZ4_ENABLED
		&erofs_compressor_lz4,
#else
		NULL,
#endif
	  Z_EROFS_COMPRESSION_LZ4, false },

#if LZ4HC_ENABLED
	{ "lz4hc", &erofs_compressor_lz4hc,
	  Z_EROFS_COMPRESSION_LZ4, true },
#endif

	{ "lzma",
#if HAVE_LIBLZMA
		&erofs_compressor_lzma,
#else
		NULL,
#endif
	  Z_EROFS_COMPRESSION_LZMA, false },

	{ "deflate", &erofs_compressor_deflate,
	  Z_EROFS_COMPRESSION_DEFLATE, false },

#if HAVE_LIBDEFLATE
	{ "libdeflate", &erofs_compressor_libdeflate,
	  Z_EROFS_COMPRESSION_DEFLATE, true },
#endif
};

int z_erofs_get_compress_algorithm_id(const struct erofs_compress *c)
{
	DBG_BUGON(!c->alg);
	return c->alg->id;
}

const char *z_erofs_list_supported_algorithms(int i, unsigned int *mask)
{
	if (i >= ARRAY_SIZE(erofs_algs))
		return NULL;
	if (!erofs_algs[i].optimisor && (*mask & (1 << erofs_algs[i].id))) {
		*mask ^= 1 << erofs_algs[i].id;
		return erofs_algs[i].name;
	}
	return "";
}

const char *z_erofs_list_available_compressors(int *i)
{
	for (;*i < ARRAY_SIZE(erofs_algs); ++*i) {
		if (!erofs_algs[*i].c)
			continue;
		return erofs_algs[(*i)++].name;
	}
	return NULL;
}

int erofs_compress_destsize(const struct erofs_compress *c,
			    const void *src, unsigned int *srcsize,
			    void *dst, unsigned int dstsize, bool inblocks)
{
	unsigned int uncompressed_capacity, compressed_size;
	int ret;

	DBG_BUGON(!c->alg);
	if (!c->alg->c->compress_destsize)
		return -ENOTSUP;

	uncompressed_capacity = *srcsize;
	ret = c->alg->c->compress_destsize(c, src, srcsize, dst, dstsize);
	if (ret < 0)
		return ret;

	/* XXX: ret >= destsize_alignsize is a temporary hack for ztailpacking */
	if (inblocks || ret >= c->destsize_alignsize ||
	    uncompressed_capacity != *srcsize)
		compressed_size = roundup(ret, c->destsize_alignsize);
	else
		compressed_size = ret;
	DBG_BUGON(c->compress_threshold < 100);
	/* check if there is enough gains to compress */
	if (*srcsize <= compressed_size * c->compress_threshold / 100)
		return -EAGAIN;
	return ret;
}

int erofs_compressor_setlevel(struct erofs_compress *c, int compression_level)
{
	DBG_BUGON(!c->alg);
	if (c->alg->c->setlevel)
		return c->alg->c->setlevel(c, compression_level);

	if (compression_level >= 0)
		return -EINVAL;
	c->compression_level = 0;
	return 0;
}

int erofs_compressor_init(struct erofs_sb_info *sbi,
			  struct erofs_compress *c, char *alg_name)
{
	int ret, i;

	c->sbi = sbi;

	/* should be written in "minimum compression ratio * 100" */
	c->compress_threshold = 100;

	/* optimize for 4k size page */
	c->destsize_alignsize = erofs_blksiz(sbi);
	c->destsize_redzone_begin = erofs_blksiz(sbi) - 16;
	c->destsize_redzone_end = EROFS_CONFIG_COMPR_DEF_BOUNDARY;

	if (!alg_name) {
		c->alg = NULL;
		return 0;
	}

	ret = -EINVAL;
	for (i = 0; i < ARRAY_SIZE(erofs_algs); ++i) {
		if (alg_name && strcmp(alg_name, erofs_algs[i].name))
			continue;

		if (!erofs_algs[i].c)
			continue;

		ret = erofs_algs[i].c->init(c);
		if (!ret) {
			c->alg = &erofs_algs[i];
			return 0;
		}
	}
	erofs_err("Cannot find a valid compressor %s", alg_name);
	return ret;
}

int erofs_compressor_exit(struct erofs_compress *c)
{
	if (c->alg && c->alg->c->exit)
		return c->alg->c->exit(c);
	return 0;
}
