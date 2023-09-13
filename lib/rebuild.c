// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "erofs/print.h"
#include "erofs/inode.h"
#include "erofs/rebuild.h"
#include "erofs/internal.h"

#ifdef HAVE_LINUX_AUFS_TYPE_H
#include <linux/aufs_type.h>
#else
#define AUFS_WH_PFX		".wh."
#define AUFS_DIROPQ_NAME	AUFS_WH_PFX ".opq"
#define AUFS_WH_DIROPQ		AUFS_WH_PFX AUFS_DIROPQ_NAME
#endif

static struct erofs_dentry *erofs_rebuild_mkdir(struct erofs_inode *dir,
						const char *s)
{
	struct erofs_inode *inode;
	struct erofs_dentry *d;

	inode = erofs_new_inode();
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	inode->i_mode = S_IFDIR | 0755;
	inode->i_parent = dir;
	inode->i_uid = getuid();
	inode->i_gid = getgid();
	inode->i_mtime = inode->sbi->build_time;
	inode->i_mtime_nsec = inode->sbi->build_time_nsec;
	erofs_init_empty_dir(inode);

	d = erofs_d_alloc(dir, s);
	if (!IS_ERR(d)) {
		d->type = EROFS_FT_DIR;
		d->inode = inode;
	}
	return d;
}

struct erofs_dentry *erofs_rebuild_get_dentry(struct erofs_inode *pwd,
		char *path, bool aufs, bool *whout, bool *opq)
{
	struct erofs_dentry *d = NULL;
	unsigned int len = strlen(path);
	char *s = path;

	*whout = false;
	*opq = false;

	while (s < path + len) {
		char *slash = memchr(s, '/', path + len - s);

		if (slash) {
			if (s == slash) {
				while (*++s == '/');	/* skip '//...' */
				continue;
			}
			*slash = '\0';
		}

		if (!memcmp(s, ".", 2)) {
			/* null */
		} else if (!memcmp(s, "..", 3)) {
			pwd = pwd->i_parent;
		} else {
			struct erofs_inode *inode = NULL;

			if (aufs && !slash) {
				if (!memcmp(s, AUFS_WH_DIROPQ, sizeof(AUFS_WH_DIROPQ))) {
					*opq = true;
					break;
				}
				if (!memcmp(s, AUFS_WH_PFX, sizeof(AUFS_WH_PFX) - 1)) {
					s += sizeof(AUFS_WH_PFX) - 1;
					*whout = true;
				}
			}

			list_for_each_entry(d, &pwd->i_subdirs, d_child) {
				if (!strcmp(d->name, s)) {
					if (d->type != EROFS_FT_DIR && slash)
						return ERR_PTR(-EIO);
					inode = d->inode;
					break;
				}
			}

			if (inode) {
				pwd = inode;
			} else if (!slash) {
				d = erofs_d_alloc(pwd, s);
				if (IS_ERR(d))
					return d;
				d->type = EROFS_FT_UNKNOWN;
				d->inode = pwd;
			} else {
				d = erofs_rebuild_mkdir(pwd, s);
				if (IS_ERR(d))
					return d;
				pwd = d->inode;
			}
		}
		if (slash) {
			*slash = '/';
			s = slash + 1;
		} else {
			break;
		}
	}
	return d;
}
