// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs_compressor.c
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Miao Xie <miaoxie@huawei.com>
 */
#include <string.h>
#include <assert.h>

#include "erofs_error.h"
#include "erofs_compressor.h"
#include "erofs_lz4hc.h"
#include "erofs_debug.h"
#include "mkfs_erofs.h"

static struct erofs_compr_alg erofs_compr_desc[EROFS_COMPR_ALG_MAX] = {
	[EROFS_COMPR_NONE] = {
		.ca_name    = "none",
		.ca_idx     = EROFS_COMPR_NONE,
		.ca_max_lvl = 0,
		.ca_min_lvl = 0,
		.ca_def_lvl = 0,
		.ca_compress    = NULL,
		.ca_init    = NULL,
		.ca_deinit  = NULL,
	},
	[EROFS_COMPR_LZ4HC] = {
		.ca_name    = "lz4hc",
		.ca_idx     = EROFS_COMPR_LZ4HC,
		.ca_max_lvl = LZ4HC_CLEVEL_MAX,
		.ca_min_lvl = LZ4HC_CLEVEL_MIN,
		.ca_def_lvl = EROFS_COMPR_LZ4HC_DEF_LVL,
		.ca_compress    = erofs_lz4hc_compress,
		.ca_init    = erofs_lz4hc_init,
		.ca_deinit  = erofs_lz4hc_deinit,
	},
};

void erofs_compress_alg_init(const char *name)
{
	int level;
	struct erofs_compr_alg *alg;

	if (!name) {
		erofs_err("compress alg name is NULL !!!");
		exit(EXIT_FAILURE);
	}

	/* name:  lz4hc or none */
	alg = erofs_get_compress_alg(name);
	if (!alg) {
		erofs_err("can found alg[%s]", name);
		exit(EXIT_FAILURE);
	}
	erofs_cfg.c_compr_alg   = alg;
	erofs_cfg.c_compr_maxsz = BLK_ALIGN(EROFS_CONFIG_COMPR_MAX_SZ);

	level = erofs_adjust_compress_level(alg, EROFS_COMPR_LZ4HC_DEF_LVL);
	erofs_cfg.c_compr_lvl	 = level;
	erofs_cfg.c_compr_boundary    = EROFS_CONFIG_COMPR_DEF_BOUNDARY;
	erofs_cfg.c_compr_ratio_limit = EROFS_CONFIG_COMPR_RATIO_MAX_LIMIT;
}
struct erofs_compr_alg *erofs_get_compress_alg(const char *name)
{
	int i;

	for (i = EROFS_COMPR_NONE; i < EROFS_COMPR_ALG_MAX; i++) {
		if (strcmp(name, erofs_compr_desc[i].ca_name) == 0)
			return &erofs_compr_desc[i];
	}

	return NULL;
}

int erofs_adjust_compress_level(struct erofs_compr_alg *alg, int lvl)
{
	if (!alg || alg->ca_idx == EROFS_COMPR_NONE)
		return 0;

	if (lvl > alg->ca_max_lvl) {
		erofs_err("Compress level(%d) is greater than max level(%d), adjust it to default level(%d).\n",
			   lvl, alg->ca_max_lvl, EROFS_COMPR_LZ4HC_DEF_LVL);
		return alg->ca_def_lvl;
	}

	if (lvl < alg->ca_min_lvl) {
		erofs_err("Compress level(%d) is less than min level(%d), adjust it to default level(%d).\n",
			   lvl, alg->ca_min_lvl, EROFS_COMPR_LZ4HC_DEF_LVL);
		return alg->ca_def_lvl;
	}

	return lvl;
}

void *erofs_compress_init(struct erofs_compr_alg *alg)
{
	void *ctx;

	if (!alg->ca_init)
		return NULL;

	ctx = alg->ca_init();

	return ctx;
}

void erofs_compress_deinit(struct erofs_compr_alg *alg, void *cctx)
{
	if (!alg->ca_deinit)
		return;

	alg->ca_deinit(cctx);
}

int64_t erofs_compress_onctx(struct erofs_compr_alg *alg, void *ctx, char *in,
			     size_t insz, char *out, size_t outsz,
			     size_t *srcsz, int lvl)
{
	assert(alg->ca_compress);

	return alg->ca_compress(in, insz, out, outsz, srcsz, lvl, ctx);
}

int64_t erofs_compress(struct erofs_compr_alg *alg, char *in, size_t insz,
		       char *out, size_t outsz, size_t *srcsz, int lvl)
{
	void *ctx = NULL;
	int64_t ret;

	if (alg->ca_init) {
		ctx = alg->ca_init();
		if (IS_ERR(ctx))
			return EROFS_COMPRESS_ERROR;
	}

	ret = alg->ca_compress(in, insz, out, outsz, srcsz, lvl, ctx);
	if (alg->ca_deinit)
		alg->ca_deinit(ctx);

	return ret;
}
