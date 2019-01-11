/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * mkfs_config.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_MKFS_CONFIG_H
#define __EROFS_MKFS_CONFIG_H

/* workaround of a lz4 native compression issue, which can crash the program */
/* #define EROFS_CONFIG_COMPR_MAX_SZ        (1024 * 1024) */
#define EROFS_CONFIG_COMPR_MAX_SZ           (900  * 1024)
#define EROFS_CONFIG_COMPR_MIN_SZ           (32   * 1024)
#define EROFS_CONFIG_COMPR_DEF_BOUNDARY     (128)
#define EROFS_CONFIG_COMPR_RATIO_MAX_LIMIT  (100)

struct erofs_compr_alg;

struct erofs_configure {
	char        *c_version;
	int         c_dry_run;
	int         c_dbg_lvl;

	struct erofs_compr_alg *c_compr_alg;
	int         c_compr_maxsz;
	int         c_compr_lvl;
	int         c_compr_boundary;
	int         c_compr_ratio_limit;

	char        *c_src_path;
	char        *c_img_path;
	char        *c_label;
	const char  *c_alg_name;
};

extern struct erofs_configure erofs_cfg;

void mkfs_init_configure(void);
void mkfs_dump_config(void);
void mkfs_free_config(void);

#endif
