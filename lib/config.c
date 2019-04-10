// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs_utils/lib/config.c
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#include <string.h>
#include "erofs/print.h"

struct erofs_configure cfg;

void erofs_init_configure(void)
{
	memset(&cfg, 0, sizeof(cfg));

	cfg.c_dbg_lvl  = 0;
	cfg.c_version  = PACKAGE_VERSION;
	cfg.c_dry_run  = false;
}

void erofs_show_config(void)
{
	const struct erofs_configure *c = &cfg;

	erofs_dump("\tc_version:           [%8s]\n", c->c_version);
	erofs_dump("\tc_dbg_lvl:           [%8d]\n", c->c_dbg_lvl);
	erofs_dump("\tc_dry_run:           [%8d]\n", c->c_dry_run);
}

void erofs_exit_configure(void)
{

}

