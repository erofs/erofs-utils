// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include "erofs/internal.h"
#include "erofs/print.h"
#include "erofs/config.h"
#include <zstd.h>
#include <zstd_errors.h>
#include <alloca.h>
#include "compressor.h"
#include "erofs/atomic.h"

static int libzstd_compress_destsize(const struct erofs_compress *c,
				     const void *src, unsigned int *srcsize,
				     void *dst, unsigned int dstsize)
{
	ZSTD_CCtx *cctx = c->private_data;
	size_t l = 0;		/* largest input that fits so far */
	size_t l_csize = 0;
	size_t r = *srcsize + 1; /* smallest input that doesn't fit so far */
	size_t m;
	u8 *fitblk_buffer = alloca(dstsize + 32);

	m = dstsize * 4;
	for (;;) {
		size_t csize;

		m = max(m, l + 1);
		m = min(m, r - 1);

		csize = ZSTD_compress2(cctx, fitblk_buffer,
				       dstsize + 32, src, m);
		if (ZSTD_isError(csize)) {
			if (ZSTD_getErrorCode(csize) == ZSTD_error_dstSize_tooSmall)
				goto doesnt_fit;
			return -EFAULT;
		}

		if (csize > 0 && csize <= dstsize) {
			/* Fits */
			memcpy(dst, fitblk_buffer, csize);
			l = m;
			l_csize = csize;
			if (r <= l + 1 || csize + 1 >= dstsize)
				break;
			/*
			 * Estimate needed input prefix size based on current
			 * compression ratio.
			 */
			m = (dstsize * m) / csize;
		} else {
doesnt_fit:
			/* Doesn't fit */
			r = m;
			if (r <= l + 1)
				break;
			m = (l + r) / 2;
		}
	}
	*srcsize = l;
	return l_csize;
}

static int compressor_libzstd_exit(struct erofs_compress *c)
{
	if (!c->private_data)
		return -EINVAL;
	ZSTD_freeCCtx(c->private_data);
	return 0;
}

static int erofs_compressor_libzstd_setlevel(struct erofs_compress *c,
					     int compression_level)
{
	if (compression_level > erofs_compressor_libzstd.best_level) {
		erofs_err("invalid compression level %d", compression_level);
		return -EINVAL;
	}
	c->compression_level = compression_level;
	return 0;
}

static int erofs_compressor_libzstd_setdictsize(struct erofs_compress *c,
						u32 dict_size)
{
	if (!dict_size) {
		if (erofs_compressor_libzstd.default_dictsize) {
			dict_size = erofs_compressor_libzstd.default_dictsize;
		} else {
			dict_size = min_t(u32, Z_EROFS_ZSTD_MAX_DICT_SIZE,
					  cfg.c_mkfs_pclustersize_max << 3);
			dict_size = 1 << ilog2(dict_size);
		}
	}
	if (dict_size != 1 << ilog2(dict_size) ||
	    dict_size > Z_EROFS_ZSTD_MAX_DICT_SIZE) {
		erofs_err("invalid dictionary size %u", dict_size);
		return -EINVAL;
	}
	c->dict_size = dict_size;
	return 0;
}

static int compressor_libzstd_init(struct erofs_compress *c)
{
	static erofs_atomic_bool_t __warnonce;
	ZSTD_CCtx *cctx = c->private_data;
	size_t err;

	ZSTD_freeCCtx(cctx);
	cctx = ZSTD_createCCtx();
	if (!cctx)
		return -ENOMEM;

	err = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, c->compression_level);
	if (ZSTD_isError(err)) {
		erofs_err("failed to set compression level: %s",
			  ZSTD_getErrorName(err));
		return -EINVAL;
	}
	err = ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, ilog2(c->dict_size));
	if (ZSTD_isError(err)) {
		erofs_err("failed to set window log: %s", ZSTD_getErrorName(err));
		return -EINVAL;
	}
	c->private_data = cctx;

	if (!erofs_atomic_test_and_set(&__warnonce)) {
		erofs_warn("EXPERIMENTAL libzstd compressor in use. Note that `fitblk` isn't supported by upstream zstd for now.");
		erofs_warn("Therefore it will takes more time in order to get the optimal result.");
		erofs_info("You could clarify further needs in zstd repository <https://github.com/facebook/zstd/issues> for reference too.");
	}
	return 0;
}

const struct erofs_compressor erofs_compressor_libzstd = {
	.default_level = ZSTD_CLEVEL_DEFAULT,
	.best_level = 22,
	.max_dictsize = Z_EROFS_ZSTD_MAX_DICT_SIZE,
	.init = compressor_libzstd_init,
	.exit = compressor_libzstd_exit,
	.setlevel = erofs_compressor_libzstd_setlevel,
	.setdictsize = erofs_compressor_libzstd_setdictsize,
	.compress_destsize = libzstd_compress_destsize,
};
