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
#include <erofs/list.h>
#include "erofs_cache.h"
#include "erofs_compressor.h"

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

static void
erofs_compr_idx_host_to_disk(struct erofs_compr_idx *hidx,
			     struct z_erofs_vle_decompressed_index *didx)
{
	switch (hidx->di_advise) {
	case Z_EROFS_VLE_CLUSTER_TYPE_PLAIN:
	case Z_EROFS_VLE_CLUSTER_TYPE_HEAD:
		didx->di_advise     = cpu_to_le16(hidx->di_advise);
		didx->di_clusterofs = cpu_to_le16(hidx->di_clusterofs);
		didx->di_u.blkaddr  = cpu_to_le32(hidx->blkaddr);
		break;

	case Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD:
		didx->di_advise     = cpu_to_le16(hidx->di_advise);
		didx->di_clusterofs = cpu_to_le16(hidx->di_clusterofs);
		didx->di_u.delta[0] = cpu_to_le16(hidx->delta[0]);
		didx->di_u.delta[1] = cpu_to_le16(hidx->delta[1]);
		break;

	default:
		assert(0);
		break;
	}
}

static int erofs_compress_inline_file_data(struct erofs_compr_info *cinfo,
					   struct erofs_compr_ctx *ctx)
{
	int64_t compr_count;
	size_t comprsz = 0;

	assert(ctx->cc_srclen <= EROFS_BLKSIZE);
	assert(ctx->cc_buflen >= 2 * EROFS_BLKSIZE);

	compr_count = erofs_compress(cinfo->ci_alg,
				     ctx->cc_srcbuf,
				     ctx->cc_srclen,
				     ctx->cc_dstbuf,
				     EROFS_BLKSIZE,
				     &comprsz,
				     cinfo->ci_lvl);

	if (compr_count == 0 || compr_count == EROFS_COMPRESS_ERROR) {
		erofs_err("Failed to compress data by %s",
			  cinfo->ci_alg->ca_name);
		return -EIO;
	}

	assert(comprsz == (size_t)ctx->cc_srclen);

	ctx->cc_dstlen = (int)compr_count;
	ctx->cc_nidxs  = EROFS_COMPR_CTX_INLINED_DATA;
	return 0;
}

/* Note: it is not for inline data compress */
static int erofs_compress_noinline_file_data(struct erofs_compr_info *cinfo,
					     struct erofs_compr_ctx *ctx)
{
	char *in;
	char *out;
	size_t insz;
	size_t outsz;
	u32 blkaddr;
	size_t comprsz;
	int64_t compr_count;
	long long pos;
	int start;
	int end;
	int i;
	int advise;
	int clusterofs;
	int delta;
	int cross;
	int nidxs;
	struct erofs_compr_idx *idx;

	in      = ctx->cc_srcbuf;
	insz    = ctx->cc_srclen;
	out     = ctx->cc_dstbuf;
	outsz   = EROFS_BLKSIZE;
	blkaddr = 0;
	pos     = ctx->cc_pos;
	nidxs   = 0;

	assert(pos % EROFS_BLKSIZE == 0);
	assert(insz % EROFS_BLKSIZE == 0);

	while (insz > 0) {
		advise = Z_EROFS_VLE_CLUSTER_TYPE_MAX;
		/* Data is less than a block, don't compress */
		if (insz <= EROFS_BLKSIZE) {
			advise      = Z_EROFS_VLE_CLUSTER_TYPE_PLAIN;
			comprsz     = insz;
			compr_count = insz;
			memcpy(out, in, insz);
			goto update_index;
		}

		comprsz     = 0;
		compr_count = erofs_compress(cinfo->ci_alg,
					     in,
					     insz,
					     out,
					     outsz,
					     &comprsz,
					     cinfo->ci_lvl);

		if (compr_count == 0 || compr_count == EROFS_COMPRESS_ERROR) {
			erofs_err("Failed to compress data by %s",
				  cinfo->ci_alg->ca_name);
			return -EIO;
		}

		/* compress ratio is very bad, don't compress */
		if ((int)comprsz - (int)compr_count <
		    erofs_cfg.c_compr_boundary) {
			advise = Z_EROFS_VLE_CLUSTER_TYPE_PLAIN;

			if (pos % EROFS_BLKSIZE == 0)
				comprsz = EROFS_BLKSIZE;
			else
				comprsz = (int)(round_up(pos, EROFS_BLKSIZE) -
						pos);

			compr_count = comprsz;
			memcpy(out, in, comprsz);
			goto update_index;
		}

		if ((pos + comprsz) % EROFS_BLKSIZE <=
		    (unsigned int)erofs_cfg.c_compr_boundary)
			comprsz -= (int)((pos + comprsz) % EROFS_BLKSIZE);

		assert(comprsz);

	update_index:
		start = (int)((pos - ctx->cc_pos) / EROFS_BLKSIZE);
		end   = (int)((pos + comprsz - ctx->cc_pos) / EROFS_BLKSIZE);

		assert(end > start);

		if ((pos + comprsz) % EROFS_BLKSIZE != 0)
			cross = end - start + 1;
		else
			cross = end - start;

		clusterofs = pos % EROFS_BLKSIZE;
		delta = 0;

		/*
		 * Here we against the rule that the length of code should
		 * less than 80 bytes, it is because we want to make
		 * the readability of mathematical expression be better.
		 */
		erofs_dbg("Compress range(Original[%lld - %lld], Index[%d - %d], Aligned[%lld - %lld], Index[%lld - %lld]) Start index %s, end index %s, end pos %s\n",
			  pos, pos + comprsz - 1,
			  start, end,
			  round_down(pos, EROFS_BLKSIZE),
			  round_up(pos + comprsz - 1, EROFS_BLKSIZE) - 1,
			  (round_down(pos, EROFS_BLKSIZE) - ctx->cc_pos) / EROFS_BLKSIZE,
			  (round_up(pos + comprsz - 1, EROFS_BLKSIZE) - ctx->cc_pos) / EROFS_BLKSIZE - 1,
			  start == (int)(round_down(pos, EROFS_BLKSIZE) - ctx->cc_pos) / EROFS_BLKSIZE ?  "SAME" : "DIFF",
			  end == (int)(round_up(pos + comprsz - 1, EROFS_BLKSIZE) - ctx->cc_pos) / EROFS_BLKSIZE - 1 ?  "SAME" : "DIFF",
			  pos + comprsz - 1 == round_up(pos + comprsz - 1, EROFS_BLKSIZE) - 1 ?  "SAME" : "DIFF");

		for (i = start; i < end; i++) {
			idx = &ctx->cc_idxs[i];
			if (advise == Z_EROFS_VLE_CLUSTER_TYPE_MAX) {
				if (delta == 0) {
					idx->di_advise =
						Z_EROFS_VLE_CLUSTER_TYPE_HEAD;
				} else {
					idx->di_advise =
						Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD;
				}
			} else {
				idx->di_advise = advise;
			}
			idx->di_clusterofs = clusterofs;
			idx->delta[0] = delta;
			idx->delta[1] = cross - delta - 1;
			/* Allocate the blocks later */
			idx->blkaddr = blkaddr;

			erofs_dbg("Compress Index: advise - %u, clusterofs - %u, delta0 - %u, delta1 - %u, blkaddr - %u",
				  idx->di_advise, clusterofs,
				  delta, cross - delta,
				  blkaddr);
			delta++;
			nidxs++;
		}

		insz -= comprsz;
		in += comprsz;
		out += EROFS_BLKSIZE;
		pos += comprsz;
		blkaddr++;
	}

	ctx->cc_dstlen = (int)(out - ctx->cc_dstbuf);
	ctx->cc_nidxs  = nidxs;
	return 0;
}

int erofs_write_compress_data(struct erofs_compr_ctx *cctx)
{
	u32 nblocks;
	u32 blkaddr;
	int ret;
	int i;

	nblocks = cctx->cc_dstlen / EROFS_BLKSIZE;
	blkaddr = erofs_alloc_blocks(nblocks);

	if (!blkaddr)
		return -ENOSPC;

	ret = dev_write(cctx->cc_dstbuf, blknr_to_addr(blkaddr),
			cctx->cc_dstlen);

	if (ret)
		return -EIO;

	for (i = 0; i < cctx->cc_nidxs; i++)
		cctx->cc_idxs[i].blkaddr += blkaddr;

	return 0;
}

int erofs_update_indexes(struct erofs_node_info *inode,
			 struct erofs_compr_ctx *cctx)
{
	u64 index = cctx->cc_pos / EROFS_BLKSIZE;
	struct erofs_index_info *iinfo;
	struct z_erofs_vle_decompressed_index *didx;
	int i;
	int j = 0;
	int end;

	iinfo = inode->i_compr_cur_index_info;

	/* Find index struct which we want */
	if (iinfo && index >= iinfo->i_1st_idx)
		goto search_next_index_info;

	if (index >= inode->i_compr_inlined_nidxs)
		goto search_from_1st_index_info;

	didx = (void *)(inode->i_inline_data +
			sizeof(struct erofs_extent_header));
	end  = inode->i_compr_inlined_nidxs;

	for (i = (int)index; i < end && j < cctx->cc_nidxs; i++, j++)
		erofs_compr_idx_host_to_disk(&cctx->cc_idxs[j], &didx[i]);

	if (j == cctx->cc_nidxs)
		return 0;

	index = i;
search_from_1st_index_info:
	iinfo = list_first_entry(&inode->i_compr_idxs_list,
				 struct erofs_index_info, i_node);
search_next_index_info:
	list_for_each_entry_from(iinfo, &inode->i_compr_idxs_list, i_node) {
		if (index < iinfo->i_1st_idx + iinfo->i_nidxs)
			break;
	}

	assert(index >= iinfo->i_1st_idx);

	do {
		didx = iinfo->i_idxs;
		i    = index - iinfo->i_1st_idx;
		end  = iinfo->i_nidxs;

		for (; i < end && j < cctx->cc_nidxs; i++, j++)
			erofs_compr_idx_host_to_disk(&cctx->cc_idxs[j],
						     &didx[i]);

		if (j == cctx->cc_nidxs)
			break;

		index = i + iinfo->i_1st_idx;
		iinfo = list_next_entry(iinfo, i_node);
	} while (1);

	inode->i_compr_cur_index_info = iinfo;
	return 0;
}

int erofs_compress_file(struct erofs_node_info *inode)
{
	int fd = -1;
	size_t read_count;
	off64_t pos			    = 0;
	u64 isize			    = inode->i_size;
	u64 itotal			    = 0;
	u64 ototal			    = 0;
	u64 nidxs			    = 0;
	int ret				    = 0;
	struct erofs_compr_ctx *cctx	= &inode->i_compr_ctx;
	struct erofs_compr_info *compressor = &inode->i_compressor;
	struct erofs_extent_header *header;

	assert(!inode->i_inline_data);
	assert(inode->i_size > 0);

	inode->i_inline_data = malloc(EROFS_BLKSIZE);

	if (!inode->i_inline_data) {
		erofs_err("Fail to alloc inline data buffer(%s)",
			  inode->i_name);
		return -ENOMEM;
	}

	memset(inode->i_inline_data, 0, EROFS_BLKSIZE);

	/* Init header */
	header = (struct erofs_extent_header *)inode->i_inline_data;
	header->eh_checksum = 0;

	/*
	 * We have compressed some data at the head of the file when we check
	 * the compressible, so we should go to the branch, put a assert here
	 * to check LOGICAL BUG in the code.
	 */
	if (cctx->cc_pos != 0 || cctx->cc_nidxs == 0) {
		assert(0);
		return -EIO;
	}

	/*
	 * Check cctx, write out the compress data and update the metadatae if
	 * we have compressed some data before.
	 */
	if (cctx->cc_nidxs == EROFS_COMPR_CTX_INLINED_DATA) {
		/*
		 * TODO: Now we don't support inlined compress data,
		 * we will implement it in the future, add a assert
		 * here to avoid someone making a mistake.
		 *
		 * ? where can we keep the compress data len? i_blocks?
		 */
		assert(0);
		erofs_dbg("Size: %d(%"PRIu64") ==> %d, Inline Compress, Compress Ratio %.2lf%%.\n",
			  cctx->cc_srclen, isize, cctx->cc_dstlen,
			  (double)cctx->cc_dstlen * 100 / (double)cctx->cc_srclen);
		return 0;
	} else if (cctx->cc_nidxs < 0) {
		/* There is something wrong with nidxs */
		assert(0);
		return -EIO;
	}

	ret = erofs_write_compress_data(cctx);

	if (ret)
		return ret;

	ret = erofs_update_indexes(inode, cctx);

	if (ret)
		return ret;

	itotal = cctx->cc_srclen;
	ototal = cctx->cc_dstlen;
	nidxs  = cctx->cc_nidxs;

	pos = cctx->cc_pos + cctx->cc_srclen;

	if ((u64)pos >= inode->i_size)
		goto compress_complete;

	fd = open(inode->i_fullpath, O_RDONLY | O_BINARY);

	if (fd < 0) {
		erofs_err("Fail to open a file(%s)", inode->i_name);
		return -ENOENT;
	}

	pos = lseek64(fd, pos, SEEK_SET);

	if (pos == (off64_t)-1ULL) {
		ret = -EINVAL;
		goto close_file;
	}

	assert(pos != 0);

	while (1) {
		erofs_reset_compress_context(cctx);

		read_count = read(fd, cctx->cc_srcbuf, cctx->cc_buflen);

		if (read_count == 0) {
			if (itotal == isize) {
				/* EOF, go out and complete compression */
				ret = 0;
			} else {
				/*
				 * Read error happened and the operation was
				 * interrupted.
				 */
				erofs_err("Read file(%s) interrupted at offset - %lld",
					  inode->i_name, (long long)pos);
				ret = -EIO;
			}

			break;
		}

		itotal += read_count;

		if (itotal > isize) {
			erofs_err("Read overflow (File: %s, Real Size:%llu, Read Size: %llu)",
				  inode->i_name, (unsigned long long)isize,
				  (unsigned long long)itotal);
			ret = -EIO;
			break;
		} else if (itotal == isize) {
			read_count = round_up(read_count, EROFS_BLKSIZE);
		} else {
			if (read_count % EROFS_BLKSIZE != 0) {
				erofs_err("Read size is not aligned(File: %s, Pos: %"PRIu64", Size: %zd)",
					  inode->i_name, (u64)pos, read_count);
				ret = -EIO;
				break;
			}
		}

		cctx->cc_pos    = pos;
		cctx->cc_srclen = read_count;

		ret = erofs_compress_noinline_file_data(compressor, cctx);

		if (ret) {
			erofs_err("Compress file Fail(File: %s, Pos: %"PRIu64", Size: %zd)",
				  inode->i_name, (u64)pos, read_count);
			ret = -EIO;
			break;
		}

		ret = erofs_write_compress_data(cctx);

		if (ret)
			break;

		ret = erofs_update_indexes(inode, cctx);

		if (ret)
			break;

		ototal += cctx->cc_dstlen;
		nidxs += cctx->cc_nidxs;
		pos += read_count;
	}

compress_complete:

	if (!ret) {
		inode->i_blocks = (u32)(ototal / EROFS_BLKSIZE);
		erofs_dbg("Size: %"PRIu64"(%"PRIu64") ==> %"PRIu64", Indexs %"PRIu64", Compress Ratio %.2lf%%.\n",
			  itotal, isize, ototal, nidxs,
			  (double)ototal * 100 / (double)itotal);
	}

close_file:

	if (fd >= 0)
		close(fd);

	return ret;
}

int erofs_try_compress_file_once(struct erofs_node_info *inode,
				 struct erofs_compr_info *cinfo,
				 struct erofs_compr_ctx *cctx)
{
	int fd;
	size_t read_count;
	loff_t pos  = 0;
	u64 isize   = inode->i_size;
	int inlined = 0;
	int ret     = 0;

	assert(cinfo->ci_alg);
	assert(cinfo->ci_alg->ca_idx != EROFS_COMPR_NONE);
	assert(cctx->cc_buflen > EROFS_BLKSIZE &&
	       cctx->cc_buflen % EROFS_BLKSIZE == 0);
	assert(cctx->cc_pos == 0);
	assert(inode->i_size > 0);
	assert(inode->i_compressor.ci_alg == NULL);
	assert(inode->i_compr_ctx.cc_srcbuf == NULL);

	fd = open(inode->i_fullpath, O_RDONLY | O_BINARY);

	if (fd < 0) {
		erofs_err("Fail to open a file(%s)", inode->i_fullpath);
		return -ENOENT;
	}

	read_count = read(fd, cctx->cc_srcbuf, cctx->cc_buflen);

	if (read_count == 0) {
		erofs_err("Read file(%s) interrupted at offset - %"PRIu64"",
			  inode->i_name, (u64)pos);
		ret = -EIO;
		goto close_file;
	}

	if (read_count > isize) {
		erofs_err("Read overflow(File: %s, Real Size:%"PRIu64", Read Size: %zd)",
			  inode->i_name, (u64)isize, read_count);
		ret = -EIO;
		goto close_file;
	} else if (read_count == isize) {
		if (isize > EROFS_BLKSIZE)
			read_count = round_up(read_count, EROFS_BLKSIZE);
		else
			inlined = 1;
	} else {
		if (read_count % EROFS_BLKSIZE != 0) {
			erofs_err("Read size is not aligned(File: %s, Pos: %"PRIu64", Size: %zd)",
				  inode->i_name, (u64)pos, read_count);
			ret = -EIO;
			goto close_file;
		}
	}

	cctx->cc_pos    = 0;
	cctx->cc_srclen = read_count;

	if (inlined)
		ret = erofs_compress_inline_file_data(cinfo, cctx);
	else
		ret = erofs_compress_noinline_file_data(cinfo, cctx);

	if (ret) {
		erofs_err("Compress file Fail(File: %s, Pos: %"PRIu64", Size: %zd)",
			  inode->i_name, (u64)pos, read_count);
		ret = -EIO;
	}

close_file:
	close(fd);
	return ret;
}

static int erofs_get_node_compress_info(struct erofs_node_info *inode,
					struct erofs_compr_info *cinfo)
{
	/* Get specified compress algorithm which is set in the config file */
	/*
	 * Now we have not implement it, just use the algorithm
	 * set in command line.
	 */
	(void)inode;
	cinfo->ci_alg = erofs_cfg.c_compr_alg;
	cinfo->ci_lvl = erofs_cfg.c_compr_lvl;

	return 0;
}

void erofs_deinit_compress_context(struct erofs_compr_ctx *ctx)
{
	if (ctx->cc_srcbuf)
		free(ctx->cc_srcbuf);

	if (ctx->cc_dstbuf)
		free(ctx->cc_dstbuf);

	if (ctx->cc_idxs)
		free(ctx->cc_idxs);

	memset(ctx, 0, sizeof(struct erofs_compr_ctx));
}

int erofs_init_compress_context(struct erofs_compr_ctx *ctx)
{
	memset(ctx, 0, sizeof(struct erofs_compr_ctx));

	ctx->cc_srcbuf = malloc(erofs_cfg.c_compr_maxsz);
	ctx->cc_dstbuf = malloc(erofs_cfg.c_compr_maxsz * 2);
	ctx->cc_idxs   = calloc(erofs_cfg.c_compr_maxsz / EROFS_BLKSIZE,
				sizeof(struct erofs_compr_idx));

	if (!ctx->cc_srcbuf || !ctx->cc_dstbuf || !ctx->cc_idxs) {
		erofs_deinit_compress_context(ctx);
		return -ENOMEM;
	}

	ctx->cc_buflen = erofs_cfg.c_compr_maxsz;

	memset(ctx->cc_srcbuf, 0, ctx->cc_buflen);
	memset(ctx->cc_dstbuf, 0, ctx->cc_buflen);
	memset(ctx->cc_idxs, 0,
	       ctx->cc_buflen / EROFS_BLKSIZE * sizeof(struct erofs_compr_idx));

	return 0;
}

void erofs_reset_compress_context(struct erofs_compr_ctx *ctx)
{
	ctx->cc_pos    = 0;
	ctx->cc_srclen = 0;
	ctx->cc_dstlen = 0;
	ctx->cc_nidxs  = 0;
	memset(ctx->cc_srcbuf, 0, ctx->cc_buflen);
	memset(ctx->cc_dstbuf, 0, ctx->cc_buflen);
	memset(ctx->cc_idxs, 0,
	       ctx->cc_buflen / EROFS_BLKSIZE * sizeof(struct erofs_compr_idx));
}

int erofs_check_compressible(struct erofs_node_info *inode)
{
	struct erofs_compr_info cinfo;
	struct erofs_compr_ctx ctx;
	int ratio;
	int ret;

	if (erofs_cfg.c_compr_alg->ca_idx == EROFS_COMPR_NONE) {
		/* Compress is disable by the user */
		return 0;
	}

	if (inode->i_type != EROFS_FT_REG_FILE)
		return 0;

	/* check if we can inline data directly */
	if (inode->i_size <= erofs_calc_inline_data_size(inode))
		return 0;

	/* check if the user don't want to compress this file */
	cinfo.ci_alg = NULL;
	cinfo.ci_lvl = 0;

	ret = erofs_get_node_compress_info(inode, &cinfo);

	if (ret) {
		erofs_err("Failed to get compress algorithm for %s",
			  inode->i_name);
		assert(ret < 0);
		return ret;
	}

	if (!cinfo.ci_alg || cinfo.ci_alg->ca_idx == EROFS_COMPR_NONE)
		return 0;

	assert(erofs_cfg.c_compr_maxsz % EROFS_BLKSIZE == 0);
	ret = erofs_init_compress_context(&ctx);

	if (ret)
		return ret;

	ret = erofs_try_compress_file_once(inode, &cinfo, &ctx);

	if (ret) {
		erofs_deinit_compress_context(&ctx);
		return ret;
	}

	/* FIXME: Now we don't implement inline compress, so... */
	if (inode->i_size <= EROFS_BLKSIZE) {
		/*
		 * TODO: Now we haven't support inline compress data, so
		 * disable compress if
		 *  inline_data_size < i_size <= block_size
		 */
#ifdef CONFIG_EROFS_INLINE_COMPRESS_DATA
		if (ctx.dstlen > erofs_calc_inline_data_size(inode)) {
			erofs_deinit_compress_context(&ctx);
			return 0;
		}

#else
		erofs_deinit_compress_context(&ctx);
		return 0;
#endif
	} else {
		ratio = ctx.cc_dstlen * 100 / ctx.cc_srclen;

		if (ratio > erofs_cfg.c_compr_ratio_limit ||
		    ctx.cc_srclen - ctx.cc_dstlen < EROFS_BLKSIZE) {
			erofs_deinit_compress_context(&ctx);
			return 0;
		}
	}

	/*
	 * Check the file compress ratio by trying to compress the 1st segment,
	 * If the ratio is greater than the limit or we can not save a block,
	 * don't compress.
	 */
	inode->i_compressor.ci_alg = cinfo.ci_alg;
	inode->i_compressor.ci_lvl = cinfo.ci_lvl;
	memcpy(&inode->i_compr_ctx, &ctx, sizeof(struct erofs_compr_ctx));
	return 1;
}
