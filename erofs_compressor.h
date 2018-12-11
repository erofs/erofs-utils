/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_compressor.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_COMPRESSOR_H__
#define __EROFS_COMPRESSOR_H__

#include <stdint.h>

#define EROFS_COMPRESS_ERROR (-1LL)

enum erofs_compr_algs {
	EROFS_COMPR_NONE,
	EROFS_COMPR_LZ4HC,
	EROFS_COMPR_ALG_MAX,
};

typedef int64_t (*compress_func)(char *in, size_t insize, char *out,
				 size_t outsize, size_t *insizeptr, int level,
				 void *);
typedef void *(*init_func)();
typedef void (*deinit_func)(void *cctx);

struct erofs_compr_alg {
	char *ca_name;
	int ca_idx;
	int ca_max_lvl;
	int ca_min_lvl;
	int ca_def_lvl;
	compress_func ca_compress;
	init_func ca_init;
	deinit_func ca_deinit;
};

void erofs_compress_alg_init(const char *name);
struct erofs_compr_alg *erofs_get_compress_alg(const char *name);
int erofs_adjust_compress_level(struct erofs_compr_alg *alg, int lvl);
void *erofs_compress_init(struct erofs_compr_alg *alg);
void erofs_compress_deinit(struct erofs_compr_alg *alg, void *cctx);
int64_t erofs_compress_onctx(struct erofs_compr_alg *alg, void *ctx, char *in,
			     size_t insz, char *out, size_t outsz,
			     size_t *srcsz, int lvl);
int64_t erofs_compress(struct erofs_compr_alg *alg, char *in, size_t insz,
		       char *out, size_t outsz, size_t *srcsz, int lvl);
#endif
