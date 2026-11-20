// SPDX-License-Identifier: GPL-2.0+ OR MIT
#define _GNU_SOURCE
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "erofs/importer.h"
#include "erofs/inode.h"
#include "erofs/print.h"
#include "erofs/manifest.h"
#include "liberofs_rebuild.h"

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
		struct erofs_inode *root, char *imagepath, const char *srcpath)
{
	struct erofs_inode *inode, *parent;
	struct erofs_dentry *d;
	erofs_os_stat_t st;
	bool dumb, existing;
	int ret;

	ret = erofs_os_lstat(srcpath, &st) ? -errno : 0;
	if (ret)
		return ret;

	d = erofs_rebuild_get_dentry(root, imagepath, false,
				      &dumb, &dumb, false);
	if (IS_ERR(d))
		return PTR_ERR(d);
	existing = !d || d->type != EROFS_FT_UNKNOWN;
	if (existing) {
		inode = d ? d->inode : root;
		/* Allow updating directory meta while preserving existing children */
		if (!S_ISDIR(st.st_mode) || !S_ISDIR(inode->i_mode))
			return -ENOTDIR;
		parent = inode->i_parent;
		free(inode->i_srcpath);
		inode->i_srcpath = NULL;
		erofs_remove_ihash(inode);
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
				 struct erofs_inode *root, char *line)
{
	char *fields[2], *token, *path;
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(fields); ++i) {
		do {
			token = strsep(&line, " ");
		} while (token && !*token);
		if (!token)
			return -EINVAL;
		fields[i] = token;
	}
	while ((token = strsep(&line, " ")))
		if (*token)
			return -EINVAL;

	if (erofs_manifest_decode(fields[0]) || *fields[0] != '/' ||
	    erofs_manifest_decode(fields[1]))
		return -EINVAL;
	if (asprintf(&path, "%s/%s", im->params->source, fields[1]) < 0)
		return -ENOMEM;
	ret = erofs_manifest_load_local(im, root, fields[0], path);
	free(path);
	return ret;
}

/* The importer has not taken ownership of the tree on a parse error. */
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
	struct erofs_inode *root;
	char *line = NULL;
	size_t capacity = 0;
	unsigned long lineno = 0;
	ssize_t len;
	int ret = 0;

	root = erofs_make_empty_root_inode(im, im->sbi);
	if (IS_ERR(root))
		return PTR_ERR(root);
	/* Synthesized directories do not belong to the base image. */
	root->dev = im->sbi->dev + 1;

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
		erofs_manifest_drop_children(root);
		erofs_iput(root);
		erofs_err("failed to parse manifest at line %lu: %s",
			  lineno, erofs_strerror(ret));
	} else {
		im->root = root;
	}
	free(line);
	return ret;
}
