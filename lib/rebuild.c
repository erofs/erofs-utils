// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <config.h>
#if defined(HAVE_SYS_SYSMACROS_H)
#include <sys/sysmacros.h>
#endif
#include "erofs/print.h"
#include "erofs/inode.h"
#include "erofs/rebuild.h"
#include "erofs/io.h"
#include "erofs/dir.h"
#include "erofs/xattr.h"
#include "erofs/blobchunk.h"
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
		char *path, bool aufs, bool *whout, bool *opq, bool to_head)
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
				if (to_head) {
					list_del(&d->d_child);
					list_add(&d->d_child, &pwd->i_subdirs);
				}
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

static int erofs_rebuild_fixup_inode_index(struct erofs_inode *inode)
{
	int ret;
	unsigned int count, unit, chunkbits, i;
	struct erofs_inode_chunk_index *idx;
	erofs_off_t chunksize;
	erofs_blk_t blkaddr;

	/* TODO: fill data map in other layouts */
	if (inode->datalayout != EROFS_INODE_CHUNK_BASED &&
	    inode->datalayout != EROFS_INODE_FLAT_PLAIN) {
		erofs_err("%s: unsupported datalayout %d", inode->i_srcpath, inode->datalayout);
		return -EOPNOTSUPP;
	}

	if (inode->sbi->extra_devices) {
		chunkbits = inode->u.chunkbits;
		if (chunkbits < sbi.blkszbits) {
			erofs_err("%s: chunk size %u is too small to fit the target block size %u",
				  inode->i_srcpath, 1U << chunkbits, 1U << sbi.blkszbits);
			return -EINVAL;
		}
	} else {
		chunkbits = ilog2(inode->i_size - 1) + 1;
		if (chunkbits < sbi.blkszbits)
			chunkbits = sbi.blkszbits;
		if (chunkbits - sbi.blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
			chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + sbi.blkszbits;
	}
	chunksize = 1ULL << chunkbits;
	count = DIV_ROUND_UP(inode->i_size, chunksize);

	unit = sizeof(struct erofs_inode_chunk_index);
	inode->extent_isize = count * unit;
	idx = malloc(max(sizeof(*idx), sizeof(void *)));
	if (!idx)
		return -ENOMEM;
	inode->chunkindexes = idx;

	for (i = 0; i < count; i++) {
		struct erofs_blobchunk *chunk;
		struct erofs_map_blocks map = {
			.index = UINT_MAX,
		};

		map.m_la = i << chunkbits;
		ret = erofs_map_blocks(inode, &map, 0);
		if (ret)
			goto err;

		blkaddr = erofs_blknr(&sbi, map.m_pa);
		chunk = erofs_get_unhashed_chunk(inode->dev, blkaddr, 0);
		if (IS_ERR(chunk)) {
			ret = PTR_ERR(chunk);
			goto err;
		}
		*(void **)idx++ = chunk;

	}
	inode->datalayout = EROFS_INODE_CHUNK_BASED;
	inode->u.chunkformat = EROFS_CHUNK_FORMAT_INDEXES;
	inode->u.chunkformat |= chunkbits - sbi.blkszbits;
	return 0;
err:
	free(inode->chunkindexes);
	inode->chunkindexes = NULL;
	return ret;
}

static int erofs_rebuild_fill_inode(struct erofs_inode *inode)
{
	switch (inode->i_mode & S_IFMT) {
	case S_IFCHR:
		if (erofs_inode_is_whiteout(inode))
			inode->i_parent->whiteouts = true;
		/* fallthrough */
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		inode->i_size = 0;
		erofs_dbg("\tdev: %d %d", major(inode->u.i_rdev),
			  minor(inode->u.i_rdev));
		inode->u.i_rdev = erofs_new_encode_dev(inode->u.i_rdev);
		return 0;
	case S_IFDIR:
		return erofs_init_empty_dir(inode);
	case S_IFLNK: {
		int ret;

		inode->i_link = malloc(inode->i_size + 1);
		if (!inode->i_link)
			return -ENOMEM;
		ret = erofs_pread(inode, inode->i_link, inode->i_size, 0);
		erofs_dbg("\tsymlink: %s -> %s", inode->i_srcpath, inode->i_link);
		return ret;
	}
	case S_IFREG:
		if (inode->i_size)
			return erofs_rebuild_fixup_inode_index(inode);
		return 0;
	default:
		break;
	}
	return -EINVAL;
}

/*
 * @parent:  parent directory in inode tree
 * @ctx.dir: parent directory when itering erofs_iterate_dir()
 */
struct erofs_rebuild_dir_context {
	struct erofs_dir_context ctx;
	struct erofs_inode *parent;
};

static int erofs_rebuild_dirent_iter(struct erofs_dir_context *ctx)
{
	struct erofs_rebuild_dir_context *rctx = (void *)ctx;
	struct erofs_inode *parent = rctx->parent;
	struct erofs_inode *dir = ctx->dir;
	struct erofs_inode *inode, *candidate;
	struct erofs_inode src;
	struct erofs_dentry *d;
	char *path, *dname;
	bool dumb;
	int ret;

	if (ctx->dot_dotdot)
		return 0;

	ret = asprintf(&path, "%s/%.*s", rctx->parent->i_srcpath,
		       ctx->de_namelen, ctx->dname);
	if (ret < 0)
		return ret;

	erofs_dbg("parsing %s", path);
	dname = path + strlen(parent->i_srcpath) + 1;

	d = erofs_rebuild_get_dentry(parent, dname, false,
				     &dumb, &dumb, false);
	if (IS_ERR(d)) {
		ret = PTR_ERR(d);
		goto out;
	}

	ret = 0;
	if (d->type != EROFS_FT_UNKNOWN) {
		/*
		 * bail out if the file exists in the upper layers.  (Note that
		 * extended attributes won't be merged too even for dirs.)
		 */
		if (!S_ISDIR(d->inode->i_mode) || d->inode->opaque)
			goto out;

		/* merge directory entries */
		src = (struct erofs_inode) {
			.sbi = dir->sbi,
			.nid = ctx->de_nid
		};
		ret = erofs_read_inode_from_disk(&src);
		if (ret || !S_ISDIR(src.i_mode))
			goto out;
		parent = d->inode;
		inode = dir = &src;
	} else {
		u64 nid;

		DBG_BUGON(parent != d->inode);
		inode = erofs_new_inode();
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			goto out;
		}

		/* reuse i_ino[0] to read nid in source fs */
		nid = inode->i_ino[0];
		inode->sbi = dir->sbi;
		inode->nid = ctx->de_nid;
		ret = erofs_read_inode_from_disk(inode);
		if (ret)
			goto out;

		/* restore nid in new generated fs */
		inode->i_ino[1] = inode->i_ino[0];
		inode->i_ino[0] = nid;
		inode->dev = inode->sbi->dev;

		if (S_ISREG(inode->i_mode) && inode->i_nlink > 1 &&
		    (candidate = erofs_iget(inode->dev, ctx->de_nid))) {
			/* hardlink file */
			erofs_iput(inode);
			inode = candidate;
			if (S_ISDIR(inode->i_mode)) {
				erofs_err("hardlink directory not supported");
				ret = -EISDIR;
				goto out;
			}
			inode->i_nlink++;
			erofs_dbg("\thardlink: %s -> %s", path, inode->i_srcpath);
		} else {
			ret = erofs_read_xattrs_from_disk(inode);
			if (ret) {
				erofs_iput(inode);
				goto out;
			}

			inode->i_parent = d->inode;
			inode->i_srcpath = path;
			path = NULL;
			inode->i_ino[1] = inode->nid;
			inode->i_nlink = 1;

			ret = erofs_rebuild_fill_inode(inode);
			if (ret) {
				erofs_iput(inode);
				goto out;
			}

			erofs_insert_ihash(inode, inode->dev, inode->i_ino[1]);
			parent = dir = inode;
		}

		d->inode = inode;
		d->type = erofs_mode_to_ftype(inode->i_mode);
	}

	if (S_ISDIR(inode->i_mode)) {
		struct erofs_rebuild_dir_context nctx = *rctx;

		nctx.parent = parent;
		nctx.ctx.dir = dir;
		ret = erofs_iterate_dir(&nctx.ctx, false);
		if (ret)
			goto out;
	}

	/* reset sbi, nid after subdirs are all loaded for the final dump */
	inode->sbi = &sbi;
	inode->nid = 0;
out:
	free(path);
	return ret;
}

int erofs_rebuild_load_tree(struct erofs_inode *root, struct erofs_sb_info *sbi)
{
	struct erofs_inode inode = {};
	struct erofs_rebuild_dir_context ctx;
	int ret;

	if (!sbi->devname) {
		erofs_err("failed to find a device for rebuilding");
		return -EINVAL;
	}

	ret = erofs_read_superblock(sbi);
	if (ret) {
		erofs_err("failed to read superblock of %s", sbi->devname);
		return ret;
	}

	inode.nid = sbi->root_nid;
	inode.sbi = sbi;
	ret = erofs_read_inode_from_disk(&inode);
	if (ret) {
		erofs_err("failed to read root inode of %s", sbi->devname);
		return ret;
	}
	inode.i_srcpath = strdup("/");

	ctx = (struct erofs_rebuild_dir_context) {
		.ctx.dir = &inode,
		.ctx.cb = erofs_rebuild_dirent_iter,
		.parent = root,
	};
	ret = erofs_iterate_dir(&ctx.ctx, false);
	free(inode.i_srcpath);
	return ret;
}
