// SPDX-License-Identifier: GPL-2.0+
/*
 * mkfs_file.c
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _LARGEFILE64_SOURCE
#include <assert.h>
#include <libgen.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/kdev_t.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif
#include "erofs_types.h"
#include "list_head.h"
#include "erofs_cache.h"

#define pr_fmt(fmt) "MKFS-FILE: " FUNC_LINE_FMT fmt "\n"
#include "erofs_debug.h"

#include "mkfs_erofs.h"
#include "mkfs_file.h"
#include "mkfs_inode.h"
#include "erofs_io.h"

#define DIRENT_MAX_NAME_LEN 256

static u8 get_file_type(struct stat64 *st)
{
	u8 file_type = EROFS_FT_MAX;

	switch (st->st_mode & S_IFMT) {
	case S_IFREG:
		file_type = EROFS_FT_REG_FILE;
		break;

	case S_IFDIR:
		file_type = EROFS_FT_DIR;
		break;

	case S_IFLNK:
		file_type = EROFS_FT_SYMLINK;
		break;

	case S_IFCHR:
		file_type = EROFS_FT_CHRDEV;
		break;

	case S_IFBLK:
		file_type = EROFS_FT_BLKDEV;
		break;

	case S_IFIFO:
		file_type = EROFS_FT_FIFO;
		break;

	case S_IFSOCK:
		file_type = EROFS_FT_SOCK;
		break;

	default:
		erofs_err("file type[0x%X]", st->st_mode & S_IFMT);
		break;
	}

	return file_type;
}

static inline u32 new_encode_dev(dev_t dev)
{
	unsigned int major = MAJOR(dev);
	unsigned int minor = MINOR(dev);

	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

struct erofs_node_info *erofs_init_inode(char *full_path_name)
{
	int ret;
	struct stat64 st;
	struct erofs_node_info *inode = NULL;
	char *file_name		      = NULL;

	file_name = strrchr(full_path_name, '/');
	if (!file_name)
		file_name = full_path_name;
	else
		file_name = file_name + 1;

	inode = alloc_erofs_node();
	if (!inode) {
		erofs_err("inode is NULL, alloc failed");
		goto Err_alloc;
	}

	ret = snprintf(inode->i_name, MAX_NAME, "%s", file_name);
	if (ret < 0 || ret >= MAX_PATH) {
		erofs_err("snprintf errorly file_name[%s] ret[%d]",
			  file_name,
			  ret);
		goto Err_alloced;
	}
	ret = snprintf(inode->i_fullpath, MAX_PATH, "%s", full_path_name);
	if (ret < 0 || ret >= MAX_PATH) {
		erofs_err("snprintf errorly full_path_name[%s] ret[%d]",
			  full_path_name,
			  ret);
		goto Err_alloced;
	}

	ret = lstat64(inode->i_fullpath, &st);
	if (ret) {
		erofs_err("stat failed path[%s]", inode->i_fullpath);
		goto Err_alloced;
	}

	/* It is ugly code that is for old code everywhere */
	inode->i_mode  = st.st_mode;
	inode->i_uid   = st.st_uid;
	inode->i_gid   = st.st_gid;
	inode->i_nlink = st.st_nlink;
	inode->i_type  = get_file_type(&st);

	if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode) ||
	    S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
		inode->i_rdev = new_encode_dev(st.st_rdev);
		inode->i_size = 0;
	} else {
		inode->i_size = st.st_size;
	}

	return inode;

Err_alloced:
	free(inode);

Err_alloc:
	return NULL;
}

int erofs_create_files_list(struct erofs_node_info *inode)
{
	int ret    = 0;
	u64 d_size = 0;
	DIR *dirp  = NULL;
	char file_path[MAX_PATH + 1];
	struct stat64 s;
	struct dirent *dp;
	struct list_head *pos;
	struct erofs_node_info *dl;

	if (!strncmp(inode->i_name, "lost+found", strlen("lost+found")))
		return 0;

	if (lstat64(inode->i_fullpath, &s) == 0) {
		if (S_ISREG(s.st_mode)) {
			erofs_err("[%s] is a regular file",
				  inode->i_fullpath);
			ret = -ENOTDIR;
			goto error;
		}
	} else {
		erofs_err("stat failed [%s]", inode->i_fullpath);
		ret = -ENOENT;
		goto error;
	}

	dirp = opendir(inode->i_fullpath);
	if (!dirp) {
		erofs_info("dirp is NULL dir=%s errno=%s",
			   inode->i_fullpath,
			   strerror(errno));
		ret = -errno;
		goto error;
	}

	errno = 0;
	while ((dp = readdir(dirp)) != NULL) {
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;

		ret = snprintf(file_path, MAX_PATH, "%s/%s",
			       inode->i_fullpath, dp->d_name);
		if (ret < 0 || ret >= MAX_PATH) {
			erofs_err("snprintf errorly ret[%d]", ret);
			ret = -ENOMEM;
			goto error;
		}
		dl = erofs_init_inode(file_path);
		if (!dl) {
			erofs_err("init inode failed !!");
			ret = -ENOENT;
			goto error;
		}

		dl->i_iver = erofs_check_disk_inode_version(dl);
		list_add_sort(&inode->i_subdir_head, dl);
	}

	if (errno != 0) {
		erofs_err("inode[%s] error[%s]",
			  inode->i_name, strerror(EBADF));
		ret = -errno;
		goto error;
	}

	list_for_each(pos, &inode->i_subdir_head) {
		struct erofs_node_info *d =
			container_of(pos, struct erofs_node_info, i_list);
		if (((d_size & (EROFS_BLKSIZE - 1)) + EROFS_DIRENT_SIZE +
		     strlen(d->i_name)) > EROFS_BLKSIZE) {
			d_size = round_up(d_size, EROFS_BLKSIZE);
		}
		d_size += EROFS_DIRENT_SIZE + strlen(d->i_name);
	}
	inode->i_size = d_size;

	list_for_each(pos, &inode->i_subdir_head) {
		struct erofs_node_info *d =
			container_of(pos, struct erofs_node_info, i_list);
		if (d->i_type == EROFS_FT_DIR) {
			ret = erofs_create_files_list(d);
			if (ret < 0)
				goto error;
		}
	}

	closedir(dirp);
	return 0;
error:
	return ret;
}

int list_add_sort(struct list_head *head, struct erofs_node_info *inode)
{
	struct list_head *pos;

	if (list_empty(head)) {
		list_add(&inode->i_list, head);
		return 0;
	}

	list_for_each(pos, head) {
		struct erofs_node_info *d =
			container_of(pos, struct erofs_node_info, i_list);

		if (strcmp(d->i_name, inode->i_name) <= 0)
			continue;

		list_add_tail(&inode->i_list, &d->i_list);
		return 0;
	}

	list_add_tail(&inode->i_list, head);
	return 0;
}

struct erofs_node_info *alloc_erofs_node(void)
{
	struct erofs_node_info *f = calloc(sizeof(struct erofs_node_info), 1);

	if (!f) {
		erofs_err("calloc failed!!!");
		return NULL;
	}

	f->i_inline_align_size = EROFS_INLINE_GENERIC_ALIGN_SIZE;
	erofs_meta_node_init(&f->i_meta_node, EROFS_META_INODE);
	init_list_head(&f->i_subdir_head);
	init_list_head(&f->i_compr_idxs_list);
	init_list_head(&f->i_xattr_head);

	return f;
}
