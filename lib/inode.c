// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs_utils/lib/inode.c
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
 */
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include "erofs/print.h"
#include "erofs/inode.h"
#include "erofs/cache.h"
#include "erofs/io.h"
#include "erofs/compress.h"
#include "erofs/fuzzer.h"

struct erofs_sb_info sbi;

#define S_SHIFT                 12
static unsigned char erofs_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]  = EROFS_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]  = EROFS_FT_DIR,
	[S_IFCHR >> S_SHIFT]  = EROFS_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]  = EROFS_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]  = EROFS_FT_FIFO,
	[S_IFSOCK >> S_SHIFT] = EROFS_FT_SOCK,
	[S_IFLNK >> S_SHIFT]  = EROFS_FT_SYMLINK,
};

#define NR_INODE_HASHTABLE	64

struct list_head inode_hashtable[NR_INODE_HASHTABLE];

void erofs_inode_manager_init(void)
{
	unsigned int i;

	for (i = 0; i < NR_INODE_HASHTABLE; ++i)
		init_list_head(&inode_hashtable[i]);
}

static struct erofs_inode *erofs_igrab(struct erofs_inode *inode)
{
	++inode->i_count;
	return inode;
}

/* get the inode from the (source) inode # */
struct erofs_inode *erofs_iget(ino_t ino)
{
	struct list_head *head =
		&inode_hashtable[ino % NR_INODE_HASHTABLE];
	struct erofs_inode *inode;

	list_for_each_entry(inode, head, i_hash)
		if (inode->i_ino[1] == ino)
			return erofs_igrab(inode);
	return NULL;
}

struct erofs_inode *erofs_iget_by_nid(erofs_nid_t nid)
{
	struct list_head *head =
		&inode_hashtable[nid % NR_INODE_HASHTABLE];
	struct erofs_inode *inode;

	list_for_each_entry(inode, head, i_hash)
		if (inode->nid == nid)
			return erofs_igrab(inode);
	return NULL;
}

unsigned int erofs_iput(struct erofs_inode *inode)
{
	struct erofs_dentry *d, *t;

	if (inode->i_count > 1)
		return --inode->i_count;

	list_for_each_entry_safe(d, t, &inode->i_subdirs, d_child)
		free(d);

	list_del(&inode->i_hash);
	free(inode);
	return 0;
}

static int dentry_add_sorted(struct erofs_dentry *d, struct list_head *head)
{
	struct list_head *pos;

	list_for_each(pos, head) {
		struct erofs_dentry *d2 =
			container_of(pos, struct erofs_dentry, d_child);

		if (strcmp(d->name, d2->name) < 0)
			break;
	}
	list_add_tail(&d->d_child, pos);
	return 0;
}

struct erofs_dentry *erofs_d_alloc(struct erofs_inode *parent,
				   const char *name)
{
	struct erofs_dentry *d = malloc(sizeof(*d));

	if (!d)
		return ERR_PTR(-ENOMEM);

	strncpy(d->name, name, EROFS_NAME_LEN - 1);
	d->name[EROFS_NAME_LEN - 1] = '\0';

	dentry_add_sorted(d, &parent->i_subdirs);
	return d;
}

/* allocate main data for a inode */
static int __allocate_inode_bh_data(struct erofs_inode *inode,
				    unsigned long nblocks)
{
	struct erofs_buffer_head *bh;
	int ret;

	if (!nblocks) {
		inode->bh_data = NULL;
		/* it has only tail-end inlined data */
		inode->u.i_blkaddr = NULL_ADDR;
		return 0;
	}

	/* allocate main data buffer */
	bh = erofs_balloc(DATA, blknr_to_addr(nblocks), 0, 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);

	bh->op = &erofs_skip_write_bhops;
	inode->bh_data = bh;

	/* get blkaddr of the bh */
	ret = erofs_mapbh(bh->block, true);
	DBG_BUGON(ret < 0);

	/* write blocks except for the tail-end block */
	inode->u.i_blkaddr = bh->block->blkaddr;
	return 0;
}

int erofs_prepare_dir_file(struct erofs_inode *dir)
{
	struct erofs_dentry *d;
	unsigned int d_size;
	int ret;

	/* dot is pointed to the current dir inode */
	d = erofs_d_alloc(dir, ".");
	d->inode = erofs_igrab(dir);
	d->type = EROFS_FT_DIR;

	/* dotdot is pointed to the parent dir */
	d = erofs_d_alloc(dir, "..");
	d->inode = erofs_igrab(dir->i_parent);
	d->type = EROFS_FT_DIR;

	/* let's calculate dir size */
	d_size = 0;
	list_for_each_entry(d, &dir->i_subdirs, d_child) {
		int len = strlen(d->name) + sizeof(struct erofs_dirent);

		if (d_size % EROFS_BLKSIZ + len > EROFS_BLKSIZ)
			d_size = round_up(d_size, EROFS_BLKSIZ);
		d_size += len;
	}
	dir->i_size = d_size;

	/* no compression for all dirs */
	dir->data_mapping_mode = EROFS_INODE_FLAT_INLINE;

	/* allocate dir main data */
	ret = __allocate_inode_bh_data(dir, erofs_blknr(d_size));
	if (ret)
		return ret;

	/* it will be used in erofs_prepare_inode_buffer */
	dir->idata_size = d_size % EROFS_BLKSIZ;
	return 0;
}

static void fill_dirblock(char *buf, unsigned int size, unsigned int q,
			  struct erofs_dentry *head, struct erofs_dentry *end)
{
	unsigned int p = 0;

	/* write out all erofs_dirents + filenames */
	while (head != end) {
		const unsigned int namelen = strlen(head->name);
		struct erofs_dirent d = {
			.nid = cpu_to_le64(head->nid),
			.nameoff = cpu_to_le16(q),
			.file_type = head->type,
		};

		memcpy(buf + p, &d, sizeof(d));
		memcpy(buf + q, head->name, namelen);
		p += sizeof(d);
		q += namelen;

		head = list_next_entry(head, d_child);
	}
	memset(buf + q, 0, size - q);

	erofs_fuzz(buf, size);
}

static int write_dirblock(unsigned int q, struct erofs_dentry *head,
			  struct erofs_dentry *end, erofs_blk_t blkaddr)
{
	char buf[EROFS_BLKSIZ];

	fill_dirblock(buf, EROFS_BLKSIZ, q, head, end);
	return blk_write(buf, blkaddr, 1);
}

int erofs_write_dir_file(struct erofs_inode *dir)
{
	struct erofs_dentry *head = list_first_entry(&dir->i_subdirs,
						     struct erofs_dentry,
						     d_child);
	struct erofs_dentry *d;
	int ret;
	unsigned int q, used, blkno;

	q = used = blkno = 0;

	list_for_each_entry(d, &dir->i_subdirs, d_child) {
		const unsigned int len = strlen(d->name) +
			sizeof(struct erofs_dirent);

		if (used + len > EROFS_BLKSIZ) {
			ret = write_dirblock(q, head, d,
					     dir->u.i_blkaddr + blkno);
			if (ret)
				return ret;

			head = d;
			q = used = 0;
			++blkno;
		}
		used += len;
		q += sizeof(struct erofs_dirent);
	}

	DBG_BUGON(used > EROFS_BLKSIZ);
	if (used == EROFS_BLKSIZ) {
		DBG_BUGON(dir->i_size % EROFS_BLKSIZ);
		DBG_BUGON(dir->idata_size);
		return write_dirblock(q, head, d, dir->u.i_blkaddr + blkno);
	}
	DBG_BUGON(used != dir->i_size % EROFS_BLKSIZ);
	if (used) {
		/* fill tail-end dir block */
		dir->idata = malloc(used);
		DBG_BUGON(used != dir->idata_size);
		fill_dirblock(dir->idata, dir->idata_size, q, head, d);
	}
	return 0;
}

int erofs_write_file_from_buffer(struct erofs_inode *inode, char *buf)
{
	const unsigned int nblocks = erofs_blknr(inode->i_size);
	int ret;

	inode->data_mapping_mode = EROFS_INODE_FLAT_INLINE;

	ret = __allocate_inode_bh_data(inode, nblocks);
	if (ret)
		return ret;

	if (nblocks)
		blk_write(buf, inode->u.i_blkaddr, nblocks);
	inode->idata_size = inode->i_size % EROFS_BLKSIZ;
	if (inode->idata_size) {
		inode->idata = malloc(inode->idata_size);
		memcpy(inode->idata, buf + blknr_to_addr(nblocks),
		       inode->idata_size);
	}
	return 0;
}

/* rules to decide whether a file could be compressed or not */
static bool erofs_file_is_compressible(struct erofs_inode *inode)
{
	return true;
}

int erofs_write_file(struct erofs_inode *inode)
{
	unsigned int nblocks, i;
	int ret, fd;

	if (cfg.c_compr_alg_master && erofs_file_is_compressible(inode)) {
		ret = erofs_write_compressed_file(inode);

		if (!ret || ret != -ENOSPC)
			return ret;
	}

	/* fallback to all data uncompressed */
	inode->data_mapping_mode = EROFS_INODE_FLAT_INLINE;
	nblocks = inode->i_size / EROFS_BLKSIZ;

	ret = __allocate_inode_bh_data(inode, nblocks);
	if (ret)
		return ret;

	fd = open(inode->i_srcpath, O_RDONLY | O_BINARY);
	if (fd < 0)
		return -errno;

	for (i = 0; i < nblocks; ++i) {
		char buf[EROFS_BLKSIZ];

		ret = read(fd, buf, EROFS_BLKSIZ);
		if (ret != EROFS_BLKSIZ) {
			if (ret < 0)
				goto fail;
			close(fd);
			return -EAGAIN;
		}

		ret = blk_write(buf, inode->u.i_blkaddr + i, 1);
		if (ret)
			goto fail;
	}

	/* read the tail-end data */
	inode->idata_size = inode->i_size % EROFS_BLKSIZ;
	if (inode->idata_size) {
		inode->idata = malloc(inode->idata_size);

		ret = read(fd, inode->idata, inode->idata_size);
		if (ret < inode->idata_size) {
			close(fd);
			return -EIO;
		}
	}
	close(fd);
	return 0;
fail:
	ret = -errno;
	close(fd);
	return ret;
}

static bool erofs_bh_flush_write_inode(struct erofs_buffer_head *bh)
{
	struct erofs_inode *const inode = bh->fsprivate;
	erofs_off_t off = erofs_btell(bh, false);

	/* let's support v1 currently */
	struct erofs_inode_v1 v1 = {0};
	int ret;

	v1.i_advise = cpu_to_le16(0 | (inode->data_mapping_mode << 1));
	v1.i_mode = cpu_to_le16(inode->i_mode);
	v1.i_nlink = cpu_to_le16(inode->i_nlink);
	v1.i_size = cpu_to_le32((u32)inode->i_size);

	v1.i_ino = cpu_to_le32(inode->i_ino[0]);

	v1.i_uid = cpu_to_le16((u16)inode->i_uid);
	v1.i_gid = cpu_to_le16((u16)inode->i_gid);

	switch ((inode->i_mode) >> S_SHIFT) {
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		v1.i_u.rdev = cpu_to_le32(inode->u.i_rdev);
		break;

	default:
		if (is_inode_layout_compression(inode))
			v1.i_u.compressed_blocks =
				cpu_to_le32(inode->u.i_blocks);
		else
			v1.i_u.raw_blkaddr =
				cpu_to_le32(inode->u.i_blkaddr);
		break;
	}

	erofs_fuzz(&v1, sizeof(struct erofs_inode_v1));

	ret = dev_write(&v1, off, sizeof(struct erofs_inode_v1));
	if (ret)
		return false;
	off += inode->inode_isize;

	if (inode->extent_isize) {
		/* write compression metadata */
		off = Z_EROFS_VLE_EXTENT_ALIGN(off);
		ret = dev_write(inode->compressmeta, off, inode->extent_isize);
		if (ret)
			return false;
	}

	inode->bh = NULL;
	erofs_iput(inode);
	return erofs_bh_flush_generic_end(bh);
}

static struct erofs_bhops erofs_write_inode_bhops = {
	.flush = erofs_bh_flush_write_inode,
};

int erofs_prepare_tail_block(struct erofs_inode *inode)
{
	struct erofs_buffer_head *bh;
	int ret;

	if (!inode->idata_size)
		return 0;

	bh = inode->bh_data;
	if (!bh) {
		bh = erofs_balloc(DATA, EROFS_BLKSIZ, 0, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		bh->op = &erofs_skip_write_bhops;

		/* get blkaddr of bh */
		ret = erofs_mapbh(bh->block, true);
		DBG_BUGON(ret < 0);
		inode->u.i_blkaddr = bh->block->blkaddr;

		inode->bh_data = bh;
		return 0;
	}
	/* expend a block as the tail block (should be successful) */
	ret = erofs_bh_balloon(bh, EROFS_BLKSIZ);
	DBG_BUGON(ret);
	return 0;
}

int erofs_prepare_inode_buffer(struct erofs_inode *inode)
{
	unsigned int inodesize;
	struct erofs_buffer_head *bh, *ibh;

	DBG_BUGON(inode->bh || inode->bh_inline);

	inodesize = inode->inode_isize + inode->xattr_isize +
		    inode->extent_isize;

	if (is_inode_layout_compression(inode))
		goto noinline;

	/*
	 * if the file size is block-aligned for uncompressed files,
	 * should use EROFS_INODE_FLAT_PLAIN data mapping mode.
	 */
	if (!inode->idata_size)
		inode->data_mapping_mode = EROFS_INODE_FLAT_PLAIN;

	bh = erofs_balloc(INODE, inodesize, 0, inode->idata_size);
	if (bh == ERR_PTR(-ENOSPC)) {
		int ret;

		inode->data_mapping_mode = EROFS_INODE_FLAT_PLAIN;
noinline:
		/* expend an extra block for tail-end data */
		ret = erofs_prepare_tail_block(inode);
		if (ret)
			return ret;
		bh = erofs_balloc(INODE, inodesize, 0, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		DBG_BUGON(inode->bh_inline);
	} else if (IS_ERR(bh)) {
		return PTR_ERR(bh);
	} else if (inode->idata_size) {
		inode->data_mapping_mode = EROFS_INODE_FLAT_INLINE;

		/* allocate inline buffer */
		ibh = erofs_battach(bh, META, inode->idata_size);
		if (IS_ERR(ibh))
			return PTR_ERR(ibh);

		ibh->op = &erofs_skip_write_bhops;
		inode->bh_inline = ibh;
	}

	bh->fsprivate = erofs_igrab(inode);
	bh->op = &erofs_write_inode_bhops;
	inode->bh = bh;
	return 0;
}

static bool erofs_bh_flush_write_inline(struct erofs_buffer_head *bh)
{
	struct erofs_inode *const inode = bh->fsprivate;
	const erofs_off_t off = erofs_btell(bh, false);
	int ret;

	ret = dev_write(inode->idata, off, inode->idata_size);
	if (ret)
		return false;

	inode->idata_size = 0;
	free(inode->idata);
	inode->idata = NULL;

	erofs_iput(inode);
	return erofs_bh_flush_generic_end(bh);
}

static struct erofs_bhops erofs_write_inline_bhops = {
	.flush = erofs_bh_flush_write_inline,
};

int erofs_write_tail_end(struct erofs_inode *inode)
{
	struct erofs_buffer_head *bh, *ibh;

	bh = inode->bh_data;

	if (!inode->idata_size)
		goto out;

	/* have enough room to inline data */
	if (inode->bh_inline) {
		ibh = inode->bh_inline;

		ibh->fsprivate = erofs_igrab(inode);
		ibh->op = &erofs_write_inline_bhops;
	} else {
		int ret;
		erofs_off_t pos;

		erofs_mapbh(bh->block, true);
		pos = erofs_btell(bh, true) - EROFS_BLKSIZ;
		ret = dev_write(inode->idata, pos, inode->idata_size);
		if (ret)
			return ret;
		if (inode->idata_size < EROFS_BLKSIZ) {
			ret = dev_fillzero(pos + inode->idata_size,
					   EROFS_BLKSIZ - inode->idata_size,
					   false);
			if (ret)
				return ret;
		}
		inode->idata_size = 0;
		free(inode->idata);
		inode->idata = NULL;
	}
out:
	/* now bh_data can drop directly */
	if (bh) {
		/*
		 * Don't leave DATA buffers which were written in the global
		 * buffer list. It will make balloc() slowly.
		 */
#if 0
		bh->op = &erofs_drop_directly_bhops;
#else
		erofs_bdrop(bh, false);
#endif
		inode->bh_data = NULL;
	}
	return 0;
}

int erofs_fill_inode(struct erofs_inode *inode,
		     struct stat64 *st,
		     const char *path)
{
	inode->i_mode = st->st_mode;
	inode->i_uid = st->st_uid;
	inode->i_gid = st->st_gid;
	inode->i_nlink = 1;	/* fix up later if needed */

	if (!S_ISDIR(inode->i_mode))
		inode->i_size = st->st_size;
	else
		inode->i_size = 0;

	strncpy(inode->i_srcpath, path, sizeof(inode->i_srcpath) - 1);
	inode->i_srcpath[sizeof(inode->i_srcpath) - 1] = '\0';

	inode->i_ino[1] = st->st_ino;
	inode->inode_isize = sizeof(struct erofs_inode_v1);

	list_add(&inode->i_hash,
		 &inode_hashtable[st->st_ino % NR_INODE_HASHTABLE]);
	return 0;
}

struct erofs_inode *erofs_new_inode(void)
{
	static unsigned int counter;
	struct erofs_inode *inode;

	inode = malloc(sizeof(struct erofs_inode));
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_parent = NULL;	/* also used to indicate a new inode */

	inode->i_ino[0] = counter++;	/* inode serial number */
	inode->i_count = 1;

	init_list_head(&inode->i_subdirs);
	inode->xattr_isize = 0;
	inode->extent_isize = 0;

	inode->bh = inode->bh_inline = inode->bh_data = NULL;
	inode->idata = NULL;
	return inode;
}

/* get the inode from the (source) path */
struct erofs_inode *erofs_iget_from_path(const char *path, bool is_src)
{
	struct stat64 st;
	struct erofs_inode *inode;
	int ret;

	/* currently, only source path is supported */
	if (!is_src)
		return ERR_PTR(-EINVAL);

	ret = lstat64(path, &st);
	if (ret)
		return ERR_PTR(-errno);

	inode = erofs_iget(st.st_ino);
	if (inode)
		return inode;

	/* cannot find in the inode cache */
	inode = erofs_new_inode();
	if (IS_ERR(inode))
		return inode;

	ret = erofs_fill_inode(inode, &st, path);
	if (ret)
		return ERR_PTR(ret);

	return inode;
}

void erofs_fixup_meta_blkaddr(struct erofs_inode *rootdir)
{
	const erofs_off_t rootnid_maxoffset = 0xffff << EROFS_ISLOTBITS;
	struct erofs_buffer_head *const bh = rootdir->bh;
	erofs_off_t off, meta_offset;

	erofs_mapbh(bh->block, true);
	off = erofs_btell(bh, false);

	if (off > rootnid_maxoffset)
		meta_offset = round_up(off - rootnid_maxoffset, EROFS_BLKSIZ);
	else
		meta_offset = 0;
	sbi.meta_blkaddr = erofs_blknr(meta_offset);
	rootdir->nid = (off - meta_offset) >> EROFS_ISLOTBITS;
}

erofs_nid_t erofs_lookupnid(struct erofs_inode *inode)
{
	struct erofs_buffer_head *const bh = inode->bh;
	erofs_off_t off, meta_offset;

	if (!bh)
		return inode->nid;

	erofs_mapbh(bh->block, true);
	off = erofs_btell(bh, false);

	meta_offset = blknr_to_addr(sbi.meta_blkaddr);
	DBG_BUGON(off < meta_offset);
	return inode->nid = (off - meta_offset) >> EROFS_ISLOTBITS;
}

void erofs_d_invalidate(struct erofs_dentry *d)
{
	struct erofs_inode *const inode = d->inode;

	d->nid = erofs_lookupnid(inode);
	erofs_iput(inode);
}

struct erofs_inode *erofs_mkfs_build_tree(struct erofs_inode *dir)
{
	int ret;
	DIR *_dir;
	struct dirent *dp;
	struct erofs_dentry *d;

	if (!S_ISDIR(dir->i_mode)) {
		if (S_ISLNK(dir->i_mode)) {
			char *const symlink = malloc(dir->i_size);

			ret = readlink(dir->i_srcpath, symlink, dir->i_size);
			if (ret < 0)
				return ERR_PTR(-errno);

			erofs_write_file_from_buffer(dir, symlink);
			free(symlink);
		} else {
			erofs_write_file(dir);
		}

		erofs_prepare_inode_buffer(dir);
		erofs_write_tail_end(dir);
		return dir;
	}

	_dir = opendir(dir->i_srcpath);
	if (!_dir) {
		erofs_err("%s, failed to opendir at %s: %s",
			  __func__, dir->i_srcpath, erofs_strerror(errno));
		return ERR_PTR(-errno);
	}

	while (1) {
		/*
		 * set errno to 0 before calling readdir() in order to
		 * distinguish end of stream and from an error.
		 */
		errno = 0;
		dp = readdir(_dir);
		if (!dp)
			break;

		if (is_dot_dotdot(dp->d_name) ||
		    !strncmp(dp->d_name, "lost+found", strlen("lost+found")))
			continue;

		d = erofs_d_alloc(dir, dp->d_name);
		if (IS_ERR(d)) {
			ret = PTR_ERR(d);
			goto err_closedir;
		}
	}

	if (errno) {
		ret = -errno;
		goto err_closedir;
	}
	closedir(_dir);

	ret = erofs_prepare_dir_file(dir);
	if (ret)
		goto err_closedir;

	ret = erofs_prepare_inode_buffer(dir);
	if (ret)
		goto err_closedir;

	if (IS_ROOT(dir))
		erofs_fixup_meta_blkaddr(dir);

	list_for_each_entry(d, &dir->i_subdirs, d_child) {
		char buf[PATH_MAX];

		if (is_dot_dotdot(d->name)) {
			erofs_d_invalidate(d);
			continue;
		}

		ret = snprintf(buf, PATH_MAX, "%s/%s",
			       dir->i_srcpath, d->name);
		if (ret < 0 || ret >= PATH_MAX) {
			/* ignore the too long path */
			goto fail;
		}

		d->inode = erofs_mkfs_build_tree_from_path(dir, buf);
		if (IS_ERR(d->inode)) {
fail:
			d->inode = NULL;
			d->type = EROFS_FT_UNKNOWN;
			continue;
		}

		d->type = erofs_type_by_mode[d->inode->i_mode >> S_SHIFT];
		erofs_d_invalidate(d);
		erofs_info("add file %s/%s (nid %lu, type %d)",
			   dir->i_srcpath, d->name, d->nid, d->type);
	}
	erofs_write_dir_file(dir);
	erofs_write_tail_end(dir);
	return dir;

err_closedir:
	closedir(_dir);
	return ERR_PTR(ret);
}

struct erofs_inode *erofs_mkfs_build_tree_from_path(struct erofs_inode *parent,
						    const char *path)
{
	struct erofs_inode *const inode = erofs_iget_from_path(path, true);

	if (IS_ERR(inode))
		return inode;

	/* a hardlink to the existed inode */
	if (inode->i_parent) {
		++inode->i_nlink;
		return inode;
	}

	/* a completely new inode is found */
	if (parent)
		inode->i_parent = parent;
	else
		inode->i_parent = inode;	/* rootdir mark */

	return erofs_mkfs_build_tree(inode);
}

