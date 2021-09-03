// SPDX-License-Identifier: GPL-2.0+
/*
 * Created by Li Guifu <bluce.lee@aliyun.com>
 */
#include <string.h>
#include <stdlib.h>
#include "erofs/err.h"
#include "erofs/list.h"
#include "erofs/print.h"
#include "erofs/exclude.h"

#define EXCLUDE_RULE_EXACT_SIZE	offsetof(struct erofs_exclude_rule, reg)
#define EXCLUDE_RULE_REGEX_SIZE	sizeof(struct erofs_exclude_rule)

static LIST_HEAD(exclude_head);
static LIST_HEAD(regex_exclude_head);

static void dump_regerror(int errcode, const char *s, const regex_t *preg)
{
	char str[512];

	regerror(errcode, preg, str, sizeof(str));
	erofs_err("invalid regex %s (%s)\n", s, str);
}

static struct erofs_exclude_rule *erofs_insert_exclude(const char *s,
						       bool is_regex)
{
	struct erofs_exclude_rule *r;
	int ret;
	struct list_head *h;

	r = malloc(is_regex ? EXCLUDE_RULE_REGEX_SIZE :
			      EXCLUDE_RULE_EXACT_SIZE);
	if (!r)
		return ERR_PTR(-ENOMEM);

	r->pattern = strdup(s);
	if (!r->pattern) {
		ret = -ENOMEM;
		goto err_rule;
	}

	if (is_regex) {
		ret = regcomp(&r->reg, s, REG_EXTENDED|REG_NOSUB);
		if (ret) {
			dump_regerror(ret, s, &r->reg);
			goto err_rule;
		}
		h = &regex_exclude_head;
	} else {
		h = &exclude_head;
	}

	list_add_tail(&r->list, h);
	erofs_info("insert exclude %s: %s\n",
		   is_regex ? "regex" : "path", s);
	return r;

err_rule:
	if (r->pattern)
		free(r->pattern);
	free(r);
	return ERR_PTR(ret);
}

void erofs_cleanup_exclude_rules(void)
{
	struct erofs_exclude_rule *r, *n;
	struct list_head *h;

	h = &exclude_head;
	list_for_each_entry_safe(r, n, h, list) {
		list_del(&r->list);
		free(r->pattern);
		free(r);
	}

	h = &regex_exclude_head;
	list_for_each_entry_safe(r, n, h, list) {
		list_del(&r->list);
		free(r->pattern);
		regfree(&r->reg);
		free(r);
	}
}

int erofs_parse_exclude_path(const char *args, bool is_regex)
{
	struct erofs_exclude_rule *r = erofs_insert_exclude(args, is_regex);

	if (IS_ERR(r)) {
		erofs_cleanup_exclude_rules();
		return PTR_ERR(r);
	}
	return 0;
}

struct erofs_exclude_rule *erofs_is_exclude_path(const char *dir,
						 const char *name)
{
	char buf[PATH_MAX];
	const char *s;
	struct erofs_exclude_rule *r;

	if (!dir) {
		/* no prefix */
		s = name;
	} else {
		sprintf(buf, "%s/%s", dir, name);
		s = buf;
	}

	s = erofs_fspath(s);
	list_for_each_entry(r, &exclude_head, list) {
		if (!strcmp(r->pattern, s))
			return r;
	}

	list_for_each_entry(r, &regex_exclude_head, list) {
		int ret = regexec(&r->reg, s, (size_t)0, NULL, 0);

		if (!ret)
			return r;
		if (ret != REG_NOMATCH)
			dump_regerror(ret, s, &r->reg);
	}
	return NULL;
}
