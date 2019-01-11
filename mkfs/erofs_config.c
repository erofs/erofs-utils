// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs_config.c
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "erofs_config.h"
#include "erofs_debug.h"

struct erofs_configure erofs_cfg;

void mkfs_init_configure(void)
{
	memset(&erofs_cfg, 0, sizeof(erofs_cfg));
	erofs_cfg.c_alg_name = "none";
	erofs_cfg.c_dbg_lvl  = 0;
	erofs_cfg.c_version  = PACKAGE_VERSION "   " __DATE__ " " __TIME__;
}

void mkfs_dump_config(void)
{
	const struct erofs_configure *c = &erofs_cfg;

	erofs_dump("\tc_version:           [%8s]\n", c->c_version);
	erofs_dump("\tc_img_path:          [%8s]\n", c->c_img_path);
	erofs_dump("\tc_src_path:          [%8s]\n", c->c_src_path);
	erofs_dump("\tc_dbg_lvl:           [%8d]\n", c->c_dbg_lvl);
	erofs_dump("\tc_dry_run:           [%8d]\n", c->c_dry_run);
	erofs_dump("\tc_alg_name:          [%8s]\n", c->c_alg_name);
	erofs_dump("\tc_compr_maxsz:       [%8d]\n", c->c_compr_maxsz);
	erofs_dump("\tc_compr_lvl:         [%8d]\n", c->c_compr_lvl);
	erofs_dump("\tc_compr_boundary:    [%8d]\n", c->c_compr_boundary);
	erofs_dump("\tc_compr_ratio_limit: [%8d]\n", c->c_compr_ratio_limit);
}

void mkfs_free_config(void)
{
	if (erofs_cfg.c_img_path)
		free(erofs_cfg.c_img_path);

	if (erofs_cfg.c_src_path)
		free(erofs_cfg.c_src_path);
}
