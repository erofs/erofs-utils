// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/config.c
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#include <string.h>
#include "erofs/print.h"
#include "erofs/internal.h"

struct erofs_configure cfg;
struct erofs_sb_info sbi;

void erofs_init_configure(void)
{
	memset(&cfg, 0, sizeof(cfg));

	cfg.c_dbg_lvl  = 0;
	cfg.c_version  = PACKAGE_VERSION;
	cfg.c_dry_run  = false;
	cfg.c_compr_level_master = -1;
	cfg.c_force_inodeversion = 0;
	cfg.c_inline_xattr_tolerance = 2;
	cfg.c_unix_timestamp = -1;
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
#ifdef HAVE_LIBSELINUX
	if (cfg.sehnd)
		selabel_close(cfg.sehnd);
#endif
}

static unsigned int fullpath_prefix;	/* root directory prefix length */

void erofs_set_fs_root(const char *rootdir)
{
	fullpath_prefix = strlen(rootdir);
}

const char *erofs_fspath(const char *fullpath)
{
	const char *s = fullpath + fullpath_prefix;

	while (*s == '/')
		s++;
	return s;
}

#ifdef HAVE_LIBSELINUX
int erofs_selabel_open(const char *file_contexts)
{
	struct selinux_opt seopts[] = {
		{ .type = SELABEL_OPT_PATH, .value = file_contexts }
	};

	if (cfg.sehnd) {
		erofs_info("ignore duplicated file contexts \"%s\"",
			   file_contexts);
		return -EBUSY;
	}

	cfg.sehnd = selabel_open(SELABEL_CTX_FILE, seopts, 1);
	if (!cfg.sehnd) {
		erofs_err("failed to open file contexts \"%s\"",
			  file_contexts);
		return -EINVAL;
	}
	return 0;
}
#endif

