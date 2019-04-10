/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_utils/include/erofs/config.h
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_CONFIG_H
#define __EROFS_CONFIG_H

#include "defs.h"

struct erofs_configure {
	const char *c_version;
	int c_dbg_lvl;
	bool c_dry_run;

	/* related arguments for mkfs.erofs */
	char *c_img_path;
	char *c_src_path;
};

extern struct erofs_configure cfg;

void erofs_init_configure(void);
void erofs_show_config(void);
void erofs_exit_configure(void);

#endif

