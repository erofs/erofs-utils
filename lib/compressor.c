// SPDX-License-Identifier: GPL-2.0+ OR MIT
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <xiang@kernel.org>
 */
#include "erofs/internal.h"
#include "compressor.h"
#include "erofs/print.h"

static const struct erofs_algorithm erofs_algs[] = {
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

	{ "zstd",
#ifdef HAVE_LIBZSTD
		&erofs_compressor_libzstd,
#else
		NULL,
#endif
	  Z_EROFS_COMPRESSION_ZSTD, false },
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

const struct erofs_algorithm *z_erofs_list_available_compressors(int *i)
{
	for (;*i < ARRAY_SIZE(erofs_algs); ++*i) {
		if (!erofs_algs[*i].c)
			continue;
		return &erofs_algs[(*i)++];
	}
	return NULL;
}

int erofs_compress_destsize(const struct erofs_compress *c,
			    const void *src, unsigned int *srcsize,
			    void *dst, unsigned int dstsize)
{
	DBG_BUGON(!c->alg);
	if (!c->alg->c->compress_destsize)
		return -EOPNOTSUPP;

	return c->alg->c->compress_destsize(c, src, srcsize, dst, dstsize);
}

int erofs_compress(const struct erofs_compress *c,
		   const void *src, unsigned int srcsize,
		   void *dst, unsigned int dstcapacity)
{
	DBG_BUGON(!c->alg);
	if (!c->alg->c->compress)
		return -EOPNOTSUPP;

	return c->alg->c->compress(c, src, srcsize, dst, dstcapacity);
}

int erofs_compressor_exit(struct erofs_compress *c)
{
	if (c->alg && c->alg->c->exit)
		return c->alg->c->exit(c);
	return 0;
}

int erofs_compressor_init(struct erofs_sb_info *sbi, struct erofs_compress *c,
			  const struct z_erofs_paramset *zset,
			  u32 pclustersize_max)
{
	int ret, i;

	c->sbi = sbi;

	/* should be written in "minimum compression ratio * 100" */
	c->compress_threshold = 100;
	c->compression_level = -1;
	c->dict_size = 0;

	ret = -EINVAL;
	for (i = 0; i < ARRAY_SIZE(erofs_algs); ++i) {
		if (strcmp(zset->alg, erofs_algs[i].name))
			continue;

		if (!erofs_algs[i].c)
			continue;

		if (!erofs_algs[i].c->setlevel && zset->clevel >= 0) {
			erofs_err("compression level %d is not supported for %s",
				  zset->clevel, zset->alg);
			return -EINVAL;
		}

		if (!erofs_algs[i].c->setdictsize && zset->dict_size) {
			erofs_err("unsupported dict size for %s", zset->alg);
			return -EINVAL;
		}

		if (!erofs_algs[i].c->setextraopts && zset->extraopts) {
			erofs_err("invalid compression option %s for %s",
				  zset->extraopts, zset->alg);
			return -EINVAL;
		}

		if (erofs_algs[i].c->preinit) {
			ret = erofs_algs[i].c->preinit(c);
			if (ret)
				return ret;
		}

		if (erofs_algs[i].c->setlevel) {
			ret = erofs_algs[i].c->setlevel(c, zset->clevel);
			if (ret) {
				erofs_err("failed to set compression level %d for %s",
					  zset->clevel, zset->alg);
				goto fail;
			}
		}

		if (erofs_algs[i].c->setdictsize) {
			ret = erofs_algs[i].c->setdictsize(c, zset->dict_size,
							   pclustersize_max);
			if (ret) {
				erofs_err("failed to set dict size %u for %s",
					  zset->dict_size, zset->alg);
				goto fail;
			}
		}

		if (zset->extraopts && erofs_algs[i].c->setextraopts) {
			ret = erofs_algs[i].c->setextraopts(c, zset->extraopts);
			if (ret)
				goto fail;
		}

		if (erofs_algs[i].c->init) {
			ret = erofs_algs[i].c->init(c);
			if (ret)
				goto fail;
		}
		c->alg = &erofs_algs[i];
		return 0;
	}
	erofs_err("Cannot find a valid compressor %s", zset->alg);
	return ret;
fail:
	if (erofs_algs[i].c->preinit && erofs_algs[i].c->exit)
		erofs_algs[i].c->exit(c);
	return ret;
}

void erofs_compressor_reset(struct erofs_compress *c)
{
	if (c->alg && c->alg->c->reset)
		c->alg->c->reset(c);
}
