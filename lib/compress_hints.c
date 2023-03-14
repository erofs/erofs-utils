// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C), 2008-2021, OPPO Mobile Comm Corp., Ltd.
 * Created by Huang Jianan <huangjianan@oppo.com>
 */
#include <string.h>
#include <stdlib.h>
#include "erofs/err.h"
#include "erofs/list.h"
#include "erofs/print.h"
#include "erofs/compress_hints.h"

static LIST_HEAD(compress_hints_head);

static void dump_regerror(int errcode, const char *s, const regex_t *preg)
{
	char str[512];

	regerror(errcode, preg, str, sizeof(str));
	erofs_err("invalid regex %s (%s)\n", s, str);
}

/* algorithmtype is actually ccfg # here */
static int erofs_insert_compress_hints(const char *s, unsigned int blks,
				       unsigned int algorithmtype)
{
	struct erofs_compress_hints *ch;
	int ret;

	ch = malloc(sizeof(struct erofs_compress_hints));
	if (!ch)
		return -ENOMEM;

	ret = regcomp(&ch->reg, s, REG_EXTENDED|REG_NOSUB);
	if (ret) {
		dump_regerror(ret, s, &ch->reg);
		free(ch);
		return ret;
	}
	ch->physical_clusterblks = blks;
	ch->algorithmtype = algorithmtype;

	list_add_tail(&ch->list, &compress_hints_head);
	erofs_info("compress hint %s (%u) is inserted", s, blks);
	return ret;
}

bool z_erofs_apply_compress_hints(struct erofs_inode *inode)
{
	const char *s;
	struct erofs_compress_hints *r;
	unsigned int pclusterblks, algorithmtype;

	if (inode->z_physical_clusterblks)
		return true;

	s = erofs_fspath(inode->i_srcpath);
	pclusterblks = cfg.c_pclusterblks_def;
	algorithmtype = 0;

	list_for_each_entry(r, &compress_hints_head, list) {
		int ret = regexec(&r->reg, s, (size_t)0, NULL, 0);

		if (!ret) {
			pclusterblks = r->physical_clusterblks;
			algorithmtype = r->algorithmtype;
			break;
		}
		if (ret != REG_NOMATCH)
			dump_regerror(ret, s, &r->reg);
	}
	inode->z_physical_clusterblks = pclusterblks;
	inode->z_algorithmtype[0] = algorithmtype;

	/* pclusterblks is 0 means this file shouldn't be compressed */
	return pclusterblks != 0;
}

void erofs_cleanup_compress_hints(void)
{
	struct erofs_compress_hints *r, *n;

	list_for_each_entry_safe(r, n, &compress_hints_head, list) {
		list_del(&r->list);
		free(r);
	}
}

int erofs_load_compress_hints(void)
{
	char buf[PATH_MAX + 100];
	FILE *f;
	unsigned int line, max_pclustersize = 0;
	int ret = 0;

	if (!cfg.c_compress_hints_file)
		return 0;

	f = fopen(cfg.c_compress_hints_file, "r");
	if (!f)
		return -errno;

	for (line = 1; fgets(buf, sizeof(buf), f); ++line) {
		unsigned int pclustersize, ccfg;
		char *alg, *pattern;

		if (*buf == '#' || *buf == '\n')
			continue;

		pclustersize = atoi(strtok(buf, "\t "));
		alg = strtok(NULL, "\n\t ");
		pattern = strtok(NULL, "\n");
		if (!pattern) {
			pattern = alg;
			alg = NULL;
		}
		if (!pattern || *pattern == '\0') {
			erofs_err("cannot find a match pattern at line %u",
				  line);
			ret = -EINVAL;
			goto out;
		}
		if (!alg || *alg == '\0') {
			ccfg = 0;
		} else {
			ccfg = atoi(alg);
			if (ccfg >= EROFS_MAX_COMPR_CFGS ||
			    !cfg.c_compr_alg[ccfg]) {
				erofs_err("invalid compressing configuration \"%s\" at line %u",
					  alg, line);
				ret = -EINVAL;
				goto out;
			}
		}

		if (pclustersize % erofs_blksiz()) {
			erofs_warn("invalid physical clustersize %u, "
				   "use default pclusterblks %u",
				   pclustersize, cfg.c_pclusterblks_def);
			continue;
		}
		erofs_insert_compress_hints(pattern,
					    pclustersize / erofs_blksiz(), ccfg);

		if (pclustersize > max_pclustersize)
			max_pclustersize = pclustersize;
	}

	if (cfg.c_pclusterblks_max * erofs_blksiz() < max_pclustersize) {
		cfg.c_pclusterblks_max = max_pclustersize / erofs_blksiz();
		erofs_warn("update max pclusterblks to %u", cfg.c_pclusterblks_max);
	}
out:
	fclose(f);
	return ret;
}
