// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2021 Gao Xiang <xiang@kernel.org>
 */
#include <stdlib.h>
#include "config.h"
#ifdef HAVE_LIBLZMA
#include <lzma.h>
#include "erofs/config.h"
#include "erofs/print.h"
#include "erofs/internal.h"
#include "erofs/atomic.h"
#include "compressor.h"

struct erofs_liblzma_context {
	lzma_options_lzma opt;
	lzma_stream strm;
};

static int erofs_liblzma_compress_destsize(const struct erofs_compress *c,
					   const void *src, unsigned int *srcsize,
					   void *dst, unsigned int dstsize)
{
	struct erofs_liblzma_context *ctx = c->private_data;
	lzma_stream *strm = &ctx->strm;

	lzma_ret ret = lzma_microlzma_encoder(strm, &ctx->opt);
	if (ret != LZMA_OK)
		return -EFAULT;

	strm->next_in = src;
	strm->avail_in = *srcsize;
	strm->next_out = dst;
	strm->avail_out = dstsize;

	ret = lzma_code(strm, LZMA_FINISH);
	if (ret != LZMA_STREAM_END)
		return -EBADMSG;

	*srcsize = strm->total_in;
	return strm->total_out;
}

static int erofs_compressor_liblzma_exit(struct erofs_compress *c)
{
	struct erofs_liblzma_context *ctx = c->private_data;

	if (!ctx)
		return -EINVAL;

	lzma_end(&ctx->strm);
	free(ctx);
	c->private_data = NULL;
	return 0;
}

static int erofs_compressor_liblzma_preinit(struct erofs_compress *c)
{
	struct erofs_liblzma_context *ctx;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;
	ctx->strm = (lzma_stream)LZMA_STREAM_INIT;
	DBG_BUGON(c->private_data);
	c->private_data = ctx;
	return 0;
}

static int erofs_compressor_liblzma_setlevel(struct erofs_compress *c,
					     int compression_level)
{
	struct erofs_liblzma_context *ctx = c->private_data;
	u32 preset;

	if (compression_level > erofs_compressor_lzma.best_level) {
		erofs_err("invalid compression level %d", compression_level);
		return -EINVAL;
	}

	if (compression_level < 0)
		preset = LZMA_PRESET_DEFAULT;
	else if (compression_level >= 100)
		preset = (compression_level - 100) | LZMA_PRESET_EXTREME;
	else
		preset = compression_level;

	if (lzma_lzma_preset(&ctx->opt, preset))
		return -EINVAL;
	c->compression_level = compression_level;
	return 0;
}

static int erofs_compressor_liblzma_setdictsize(struct erofs_compress *c,
						u32 dict_size, u32 pclustersize_max)
{
	struct erofs_liblzma_context *ctx = c->private_data;

	if (!dict_size) {
		if (erofs_compressor_lzma.default_dictsize) {
			dict_size = erofs_compressor_lzma.default_dictsize;
		} else {
			dict_size = min_t(u32, Z_EROFS_LZMA_MAX_DICT_SIZE,
					  pclustersize_max << 2);
			if (dict_size < 32768)
				dict_size = 32768;
		}
	}

	if (dict_size > Z_EROFS_LZMA_MAX_DICT_SIZE || dict_size < 4096) {
		erofs_err("invalid dictionary size %u", dict_size);
		return -EINVAL;
	}
	ctx->opt.dict_size = c->dict_size = dict_size;
	return 0;
}

static int erofs_compressor_liblzma_setextraopts(struct erofs_compress *c,
						 const char *extraopts)
{
	struct erofs_liblzma_context *ctx = c->private_data;
	const char *token, *next;

	for (token = extraopts; *token != '\0'; token = next) {
		const char *p = strchr(token, ',');
		const char *rhs;
		char *endptr;
		unsigned long val;
		uint32_t *key;

		next = NULL;
		if (p) {
			next = p + 1;
		} else {
			p = token + strlen(token);
			next = p;
		}

		if (!strncmp(token, "lc=", sizeof("lc=") - 1)) {
			key = &ctx->opt.lc;
			rhs = token + sizeof("lc=") - 1;
		} else if (!strncmp(token, "lp=", sizeof("lp=") - 1)) {
			key = &ctx->opt.lp;
			rhs = token + sizeof("lp=") - 1;
		} else if (!strncmp(token, "pb=", sizeof("pb=") - 1)) {
			key = &ctx->opt.pb;
			rhs = token + sizeof("pb=") - 1;
		} else {
			erofs_err("unknown extra options %s", extraopts);
			return -EINVAL;
		}

		val = strtoul(rhs, &endptr, 0);
		if (val == ULONG_MAX || endptr != p) {
			erofs_err("invalid option %.*s", p - token, token);
			return -EINVAL;
		}
		*key = val;
	}
	return 0;
}

const struct erofs_compressor erofs_compressor_lzma = {
	.default_level = LZMA_PRESET_DEFAULT,
	.best_level = 109,
	.max_dictsize = Z_EROFS_LZMA_MAX_DICT_SIZE,
	.preinit = erofs_compressor_liblzma_preinit,
	.exit = erofs_compressor_liblzma_exit,
	.setlevel = erofs_compressor_liblzma_setlevel,
	.setdictsize = erofs_compressor_liblzma_setdictsize,
	.setextraopts = erofs_compressor_liblzma_setextraopts,
	.compress_destsize = erofs_liblzma_compress_destsize,
};
#endif
