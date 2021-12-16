// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include "erofs/print.h"
#include "erofs/dir.h"
#include <stdlib.h>

static int traverse_dirents(struct erofs_dir_context *ctx,
			    void *dentry_blk, unsigned int lblk,
			    unsigned int next_nameoff, unsigned int maxsize,
			    bool fsck)
{
	struct erofs_dirent *de = dentry_blk;
	const struct erofs_dirent *end = dentry_blk + next_nameoff;
	const char *prev_name = NULL;
	const char *errmsg;
	unsigned int prev_namelen = 0;
	int ret = 0;
	bool silent = false;

	while (de < end) {
		const char *de_name;
		unsigned int de_namelen;
		unsigned int nameoff;

		nameoff = le16_to_cpu(de->nameoff);
		de_name = (char *)dentry_blk + nameoff;

		/* the last dirent check */
		if (de + 1 >= end)
			de_namelen = strnlen(de_name, maxsize - nameoff);
		else
			de_namelen = le16_to_cpu(de[1].nameoff) - nameoff;

		ctx->de_nid = le64_to_cpu(de->nid);
		erofs_dbg("traversed nid (%llu)", ctx->de_nid | 0ULL);

		ret = -EFSCORRUPTED;
		/* corrupted entry check */
		if (nameoff != next_nameoff) {
			errmsg = "bogus dirent nameoff";
			break;
		}

		if (nameoff + de_namelen > maxsize ||
				de_namelen > EROFS_NAME_LEN) {
			errmsg = "bogus dirent namelen";
			break;
		}

		if (fsck && prev_name) {
			int cmp = strncmp(prev_name, de_name,
					  min(prev_namelen, de_namelen));

			if (cmp > 0 || (cmp == 0 &&
					prev_namelen >= de_namelen)) {
				errmsg = "wrong dirent name order";
				break;
			}
		}

		if (fsck && de->file_type >= EROFS_FT_MAX) {
			errmsg = "invalid file type %u";
			break;
		}

		ctx->dname = de_name;
		ctx->de_namelen = de_namelen;
		ctx->de_ftype = de->file_type;
		ctx->dot_dotdot = is_dot_dotdot_len(de_name, de_namelen);
		if (ctx->dot_dotdot) {
			switch (de_namelen) {
			case 2:
				if (fsck &&
				    (ctx->flags & EROFS_READDIR_DOTDOT_FOUND)) {
					errmsg = "duplicated `..' dirent";
					goto out;
				}
				ctx->flags |= EROFS_READDIR_DOTDOT_FOUND;
				if (sbi.root_nid == ctx->dir->nid) {
					ctx->pnid = sbi.root_nid;
					ctx->flags |= EROFS_READDIR_VALID_PNID;
				}
				if (fsck &&
				    (ctx->flags & EROFS_READDIR_VALID_PNID) &&
				    ctx->de_nid != ctx->pnid) {
					errmsg = "corrupted `..' dirent";
					goto out;
				}
				break;
			case 1:
				if (fsck &&
				    (ctx->flags & EROFS_READDIR_DOT_FOUND)) {
					errmsg = "duplicated `.' dirent";
					goto out;
				}

				ctx->flags |= EROFS_READDIR_DOT_FOUND;
				if (fsck && ctx->de_nid != ctx->dir->nid) {
					errmsg = "corrupted `.' dirent";
					goto out;
				}
				break;
			}
		}
		ret = ctx->cb(ctx);
		if (ret) {
			silent = true;
			break;
		}
		prev_name = de_name;
		prev_namelen = de_namelen;
		next_nameoff += de_namelen;
		++de;
	}
out:
	if (ret && !silent)
		erofs_err("%s @ nid %llu, lblk %u, index %lu",
			  errmsg, ctx->dir->nid | 0ULL, lblk,
			  (de - (struct erofs_dirent *)dentry_blk) | 0UL);
	return ret;
}

int erofs_iterate_dir(struct erofs_dir_context *ctx, bool fsck)
{
	struct erofs_inode *dir = ctx->dir;
	int err = 0;
	erofs_off_t pos;
	char buf[EROFS_BLKSIZ];

	if ((dir->i_mode & S_IFMT) != S_IFDIR)
		return -ENOTDIR;

	ctx->flags &= ~EROFS_READDIR_ALL_SPECIAL_FOUND;
	pos = 0;
	while (pos < dir->i_size) {
		erofs_blk_t lblk = erofs_blknr(pos);
		erofs_off_t maxsize = min_t(erofs_off_t,
					dir->i_size - pos, EROFS_BLKSIZ);
		const struct erofs_dirent *de = (const void *)buf;
		unsigned int nameoff;

		err = erofs_pread(dir, buf, maxsize, pos);
		if (err) {
			erofs_err("I/O error occurred when reading dirents @ nid %llu, lblk %u: %d",
				  dir->nid | 0ULL, lblk, err);
			return err;
		}

		nameoff = le16_to_cpu(de->nameoff);
		if (nameoff < sizeof(struct erofs_dirent) ||
		    nameoff >= PAGE_SIZE) {
			erofs_err("invalid de[0].nameoff %u @ nid %llu, lblk %u",
				  nameoff, dir->nid | 0ULL, lblk);
			return -EFSCORRUPTED;
		}
		err = traverse_dirents(ctx, buf, lblk, nameoff, maxsize, fsck);
		if (err)
			break;
		pos += maxsize;
	}

	if (fsck && (ctx->flags & EROFS_READDIR_ALL_SPECIAL_FOUND) !=
			EROFS_READDIR_ALL_SPECIAL_FOUND) {
		erofs_err("`.' or `..' dirent is missing @ nid %llu",
			  dir->nid | 0ULL);
		return -EFSCORRUPTED;
	}
	return err;
}
