/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Created by Li Guifu <bluce.lee@aliyun.com>
 */
#ifndef __EROFS_EXCLUDE_H
#define __EROFS_EXCLUDE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/types.h>
#include <regex.h>

struct erofs_exclude_rule {
	struct list_head list;

	char *pattern;
	regex_t reg;
};

void erofs_exclude_set_root(const char *rootdir);
void erofs_cleanup_exclude_rules(void);

int erofs_parse_exclude_path(const char *args, bool is_regex);
struct erofs_exclude_rule *erofs_is_exclude_path(const char *dir,
						 const char *name);

#ifdef __cplusplus
}
#endif

#endif
