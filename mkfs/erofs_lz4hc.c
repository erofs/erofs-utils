// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs_lz4hc.c
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#include <errno.h>
#define LZ4_HC_STATIC_LINKING_ONLY (1)
#include <lz4hc.h>

#include "erofs_error.h"
#include "erofs_lz4hc.h"
#include "erofs_compressor.h"
#include "erofs_debug.h"

void *erofs_lz4hc_init(void)
{
	LZ4_streamHC_t *ctx;

	ctx = LZ4_createStreamHC();
	if (!ctx) {
		erofs_err("Cannot allocate LZ4HC context");
		return ERR_PTR(-ENOMEM);
	}

	return (void *)ctx;
}

void erofs_lz4hc_deinit(void *ctx)
{
	if (!ctx)
		return;

	LZ4_freeStreamHC((LZ4_streamHC_t *)ctx);
}

int64_t erofs_lz4hc_compress(char *in, size_t insz, char *out, size_t outsz,
			     size_t *inszptr, int level, void *ctx)
{
	int count;

	*inszptr = insz;
	count = LZ4_compress_HC_destSize((LZ4_streamHC_t *)ctx, in, out,
					 (int *)inszptr, outsz, level);
	if (count <= 0) {
		erofs_err("Failed to compress data by LZ4HC");
		return EROFS_COMPRESS_ERROR;
	}
	return (int64_t)count;
}
