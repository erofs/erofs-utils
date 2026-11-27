// SPDX-License-Identifier: GPL-2.0+ OR MIT
#define _GNU_SOURCE
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "erofs/importer.h"
#include "erofs/inode.h"
#include "erofs/xattr.h"
#include "erofs/print.h"
#include "erofs/manifest.h"
#include "liberofs_rebuild.h"
#include "liberofs_file_delta.h"
#include "liberofs_chunk.h"

#ifndef HAVE_STRSEP
static char *__erofs_strsep(char **stringp, const char *delim)
{
	char *token = *stringp, *end;

	if (!token)
		return NULL;
	end = token + strcspn(token, delim);
	if (*end)
		*end++ = '\0';
	else
		end = NULL;
	*stringp = end;
	return token;
}
#define strsep __erofs_strsep
#endif

#ifndef HAVE_GETLINE
static ssize_t __erofs_getline(char **line, size_t *capacity, FILE *fp)
{
	size_t len = 0;
	int c;

	while ((c = fgetc(fp)) != EOF) {
		size_t size;

		if (len + 1 >= *capacity) {
			char *buf;

			size = *capacity ? *capacity * 2 : 256;
			if (size <= *capacity || size > (size_t)PTRDIFF_MAX) {
				errno = EOVERFLOW;
				return -1;
			}
			buf = realloc(*line, size);
			if (!buf)
				return -1;
			*line = buf;
			*capacity = size;
		}
		(*line)[len++] = c;
		if (c == '\n')
			break;
	}
	if (ferror(fp) || !len)
		return -1;
	(*line)[len] = '\0';
	return len;
}
#define getline __erofs_getline
#endif

static int erofs_manifest_hex(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Decode hexadecimal byte escapes in place. */
static int erofs_manifest_decode(char *s)
{
	char *p = s, *q = s;
	int a, b;

	while (*p) {
		unsigned char c = *p++;

		if (c == '\\') {
			/*
			 * A space terminates the token before decoding, so
			 * \x or \xX immediately followed by a space is invalid.
			 */
			if (p[0] != 'x' || !p[1] || !p[2])
				return -EINVAL;
			a = erofs_manifest_hex(p[1]);
			b = erofs_manifest_hex(p[2]);
			if (a < 0 || b < 0)
				return -EINVAL;
			c = (a << 4) | b;
			p += 3;
		} else if (c <= ' ' || c == 127) {
			return -EINVAL;
		}
		/* NUL is invalid in paths. */
		if (!c)
			return -EINVAL;
		*q++ = c;
	}
	*q = '\0';
	return 0;
}

static int erofs_manifest_load_local(struct erofs_importer *im,
		struct erofs_inode *root,
		char *imagepath, const char *srcpath, bool delta_fmt)
{
	struct erofs_inode *inode, *parent;
	struct erofs_dentry *d;
	erofs_os_stat_t st;
	bool dumb, existing;
	int ret;

	if (delta_fmt && cfg.c_force_chunkformat == FORCE_INODE_BLOCK_MAP)
		return -EOPNOTSUPP;
	d = erofs_rebuild_get_dentry(root, imagepath, false,
				      &dumb, &dumb, false);
	if (IS_ERR(d))
		return PTR_ERR(d);
	existing = !d || d->type != EROFS_FT_UNKNOWN;

	if (delta_fmt) {
		struct erofs_file_delta *fdl;
		struct erofs_vfile input = {};

		if (!existing) {
			ret = -ENOENT;
			goto out_dentry;
		}
		inode = d ? d->inode : root;
		if (!S_ISREG(inode->i_mode) || !inode->i_size)
			return -EINVAL;
		/* TODO: prepare chunk indexes for locally imported targets. */
		if (inode->datalayout != EROFS_INODE_CHUNK_BASED || !inode->chunkindexes)
			return -EOPNOTSUPP;
		input.fd = erofs_os_open(srcpath, O_RDONLY | O_BINARY);
		if (input.fd < 0)
			return -errno;
		fdl = erofs_dm_persistent_open(&input);
		if (IS_ERR(fdl)) {
			ret = PTR_ERR(fdl);
		} else {
			ret = erofs_chunk_apply_deltas(inode, fdl);
			/* TODO: update inode digest xattrs after COW updates. */
			if (!ret)
				erofs_inode_clear_digest(inode);
			fdl->ops->close(fdl);
		}
		erofs_io_close(&input);
		return ret;
	}

	ret = erofs_os_lstat(srcpath, &st) ? -errno : 0;
	if (ret) {
		if (!existing)
			goto out_dentry;
		return ret;
	}

	if (existing) {
		inode = d ? d->inode : root;
		/* Allow updating directory meta while preserving existing children */
		if (!S_ISDIR(st.st_mode) || !S_ISDIR(inode->i_mode))
			return -ENOTDIR;
		parent = inode->i_parent;
		free(inode->i_srcpath);
		inode->i_srcpath = NULL;
		erofs_remove_ihash(inode);
		erofs_inode_clear_xattrs(inode);
	} else {
		parent = d->inode;
		if (!S_ISDIR(st.st_mode) && !im->params->hard_dereference) {
			inode = erofs_iget(st.st_dev, st.st_ino);
			if (inode) {
				if (check_add_overflow(inode->i_nlink, 1U,
						       &inode->i_nlink)) {
					erofs_iput(inode);
					ret = -EOVERFLOW;
					goto out_dentry;
				}
				d->inode = inode;
				d->type = erofs_mode_to_ftype(inode->i_mode);
				goto out;
			}
		}
		inode = erofs_new_inode(im->sbi);
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			goto out_dentry;
		}
		inode->i_parent = parent;
	}

	ret = erofs_fill_inode(im, inode, &st, srcpath);
	if (ret)
		goto out_inode;
	inode->datasource = EROFS_INODE_DATA_SOURCE_LOCALPATH;
	if (S_ISLNK(inode->i_mode)) {
		ssize_t len;

		inode->i_link = malloc(st.st_size + 1);
		if (!inode->i_link) {
			ret = -ENOMEM;
			goto out_inode;
		}
		len = erofs_os_readlink(srcpath, inode->i_link, st.st_size);
		if (len < 0) {
			ret = -errno;
			goto out_inode;
		}
		inode->i_link[len] = '\0';
		inode->i_size = len;
	}

	if (!im->params->no_xattrs) {
		ret = erofs_scan_file_xattrs(inode);
		if (ret)
			goto out_inode;
	}

	if (!existing) {
		d->inode = inode;
		d->type = erofs_mode_to_ftype(inode->i_mode);
	}
out:
	if (erofs_inode_is_whiteout(inode))
		parent->whiteouts = true;
	return 0;
out_inode:
	if (existing)
		return ret;
	erofs_iput(inode);
out_dentry:
	list_del(&d->d_child);
	free(d);
	return ret;
}

static int erofs_manifest_parse_record(struct erofs_importer *im,
		struct erofs_inode *root,
		char *line)
{
	char *fields[3], *token, *imagepath, *srcpath;
	unsigned int nr = 0;
	bool dm_snap = false;
	int ret;

	while ((token = strsep(&line, " "))) {
		if (!*token)
			continue;
		if (nr == ARRAY_SIZE(fields))
			return -EINVAL;
		fields[nr++] = token;
	}
	if (!nr)
		return -EINVAL;
	if (!strncmp(fields[0], "DIFF[", 5)) {
		size_t len = strlen(fields[0]);

		if (len <= 6 || fields[0][len - 1] != ']' || nr != 3)
			return -EINVAL;
		fields[0][len - 1] = '\0';
		if (strcmp(fields[0] + 5, "DM_SNAP"))
			return -EOPNOTSUPP;
		dm_snap = true;
	}
	if (nr != (dm_snap ? 3 : 2))
		return -EINVAL;
	imagepath = fields[dm_snap ? 1 : 0];
	token = fields[dm_snap ? 2 : 1];
	if (erofs_manifest_decode(imagepath) || *imagepath != '/' ||
	    erofs_manifest_decode(token))
		return -EINVAL;
	if (asprintf(&srcpath, "%s/%s", im->params->source, token) < 0)
		return -ENOMEM;
	ret = erofs_manifest_load_local(im, root,
				       imagepath, srcpath, dm_snap);
	free(srcpath);
	return ret;
}

/* The importer has not taken ownership of a new tree on a load error. */
static void erofs_manifest_drop_children(struct erofs_inode *dir)
{
	struct erofs_dentry *d, *next;

	list_for_each_entry_safe(d, next, &dir->i_subdirs, d_child) {
		if (d->type != EROFS_FT_UNKNOWN) {
			if (S_ISDIR(d->inode->i_mode))
				erofs_manifest_drop_children(d->inode);
			erofs_iput(d->inode);
		}
		list_del(&d->d_child);
		free(d);
	}
}

int erofs_manifest_load(struct erofs_importer *im, FILE *fp)
{
	struct erofs_inode *root = im->root;
	bool newroot = !root;
	char *line = NULL;
	size_t capacity = 0;
	unsigned long lineno = 0;
	ssize_t len;
	int ret = 0;

	if (newroot) {
		root = erofs_make_empty_root_inode(im, im->sbi);
		if (IS_ERR(root))
			return PTR_ERR(root);
	}
	/*
	 * Directories created for manifest paths inherit root->dev but have
	 * no base NID.
	 * Keep them out of base directory reads until incremental merging
	 * finds an existing directory and sets its device and NID.
	 */
	root->dev = UINT32_MAX;

	while ((len = getline(&line, &capacity, fp)) >= 0) {
		++lineno;
		if (line[0] == '#')
			continue;
		if (memchr(line, '\0', len)) {
			ret = -EINVAL;
			break;
		}
		if (len && line[len - 1] == '\n') {
			line[--len] = '\0';
			if (len && line[len - 1] == '\r')
				line[--len] = '\0';
		}
		ret = erofs_manifest_parse_record(im, root, line);
		if (ret)
			break;
	}
	if (!ret && ferror(fp))
		ret = -EIO;
	if (!ret && len < 0 && !feof(fp))
		ret = errno ? -errno : -EIO;
	if (!ret && !lineno)
		ret = -EINVAL;
	if (ret) {
		if (newroot) {
			erofs_manifest_drop_children(root);
			erofs_iput(root);
		}
		erofs_err("failed to parse manifest at line %lu: %s",
			  lineno, erofs_strerror(ret));
	}
	if (!ret)
		im->root = root;
	free(line);
	return ret;
}
