// SPDX-License-Identifier: GPL-2.0+
/*
 * mkfs_inode.c
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>
#include <libgen.h>

#include "erofs_cache.h"
#include "erofs_error.h"
#include "mkfs_erofs.h"
#include "mkfs_file.h"
#include "mkfs_inode.h"
#include "erofs_io.h"

#define pr_fmt(fmt) "MKFS_INODE: " FUNC_LINE_FMT fmt "\n"
#include "erofs_debug.h"

extern struct erofs_super_block *sb;

u32 erofs_calc_inode_base_size(struct erofs_node_info *inode)
{
	u32 size;

	if (inode->i_iver == EROFS_INODE_LAYOUT_V1)
		size = sizeof(struct erofs_inode_v1);
	else
		size = sizeof(struct erofs_inode_v2);

	return size;
}

u32 erofs_calc_inline_data_size(struct erofs_node_info *inode)
{
	u32 size = erofs_calc_inode_base_size(inode);

	if (size >= EROFS_BLKSIZE)
		return 0;
	else
		return (EROFS_BLKSIZE - size);
}

static inline u64 erofs_calc_compr_index_count(struct erofs_node_info *inode)
{
	return round_up(inode->i_size, EROFS_BLKSIZE) / EROFS_BLKSIZE;
}

static int erofs_calc_inline_compr_index_count(struct erofs_node_info *inode)
{
	int size;

	size = erofs_calc_inode_base_size(inode);
	size = round_up(size, EROFS_INLINE_INDEX_ALIGN_SIZE);
	size += sizeof(struct erofs_extent_header);

	assert(size < EROFS_BLKSIZE);

	size = EROFS_BLKSIZE - size;

	assert(size % EROFS_DECOMPR_IDX_SZ == 0);

	return size / EROFS_DECOMPR_IDX_SZ;
}

u8 erofs_check_disk_inode_version(struct erofs_node_info *inode)
{
#if 1
	(void)inode;
	return EROFS_INODE_LAYOUT_V1;
#else
	/*
	 * Check if the members of v0 inode structure can hold the data,
	 * Check Item:
	 * - i_size: 32bits vs 64 bits
	 * - i_uid:  16bits vs 32bits
	 * - i_gid:  16bits vs 32bits
	 * - i_nlink:16bits vs 32bits
	 * - i_ctime:If it is set or not
	 */
#endif
}

static void erofs_init_compress_inode(struct erofs_node_info *inode)
{
	int inlined_nidxs;

	inode->i_dmode = EROFS_INODE_LAYOUT_COMPRESSION;

	if (inode->i_compr_ctx.cc_nidxs == EROFS_COMPR_CTX_INLINED_DATA) {
		inode->i_inline_datalen = inode->i_compr_ctx.cc_dstlen;
		return;
	}

	inode->i_compr_nidxs = erofs_calc_compr_index_count(inode);

	inlined_nidxs = erofs_calc_inline_compr_index_count(inode);

	if (inode->i_compr_nidxs > (u64)inlined_nidxs)
		inode->i_compr_inlined_nidxs = inlined_nidxs;
	else
		inode->i_compr_inlined_nidxs = inode->i_compr_nidxs;

	inlined_nidxs = inode->i_compr_inlined_nidxs * EROFS_DECOMPR_IDX_SZ;
	inode->i_inline_datalen = sizeof(struct erofs_extent_header);
	inode->i_inline_datalen += inlined_nidxs;

	inode->i_inline_align_size = EROFS_INLINE_INDEX_ALIGN_SIZE;
}

void mkfs_rank_inode(struct erofs_node_info *inode)
{
	block_buffer_t *blk;
	block_buffer_t *next;
	struct erofs_meta_node *node;
	struct erofs_index_info *indexes;
	u64 request_size;
	u64 noninline_nidxs;
	u64 first_idx;
	u64 idx_nblks;
	int nidxs;
	int inline_size = 0;

	node	 = &inode->i_meta_node;
	request_size = erofs_calc_inode_base_size(inode);

	request_size = round_up(request_size, inode->i_inline_align_size);

	if (inode->i_dmode == EROFS_INODE_LAYOUT_INLINE) {
		inline_size = inode->i_size % EROFS_BLKSIZE;
		/* we put inode into inline mode asasp */
		if (inline_size + request_size > EROFS_BLKSIZE) {
			erofs_err("inode[%s] inline data overflow  i_size=%u slots size=%d",
				  inode->i_name, inode->i_dmode, inline_size);
			assert(0);
		}

	} else if (inode->i_dmode == EROFS_INODE_LAYOUT_COMPRESSION) {
		inline_size += inode->i_inline_datalen;

		/* we put inode into inline mode asasp */
		if (inline_size + request_size > EROFS_BLKSIZE) {
			erofs_err("inode[%s] inline data overflow  i_size=%" PRIu64 " slots size=%d",
				  inode->i_name, inode->i_size, inline_size);
			assert(0);
		}
	}
	request_size += inline_size;

	/*
	 * If no compress indexes or all indexes are inlined, noninline_nidxs
	 * should be zero.
	 */
	noninline_nidxs = inode->i_compr_nidxs - inode->i_compr_inlined_nidxs;
	idx_nblks       = noninline_nidxs * EROFS_DECOMPR_IDX_SZ;
	idx_nblks       = round_up(idx_nblks, EROFS_BLKSIZE) / EROFS_BLKSIZE;

	if (idx_nblks) {
		assert(request_size == EROFS_BLKSIZE);

		blk = erofs_alloc_multi_block_buffer(idx_nblks + 1);
	} else {
		blk = erofs_look_up_free_pos(request_size);
	}

	if (IS_ERR(blk))
		assert(0);

	node->m_blk  = blk;
	node->m_slot = blk->bb_free_slot;
	node->m_len  = round_up(request_size, EROFS_SLOTSIZE);
	list_add_tail(&node->m_node, &blk->bb_metadata_list);
	inode->i_base_addr = blknr_to_addr(blk->bb_blkaddr) +
			     blk->bb_free_slot * EROFS_SLOTSIZE;
	blk->bb_free_slot += node->m_len / EROFS_SLOTSIZE;
	next = list_next_entry(blk, bb_global_node);
	erofs_put_block_buffer(blk);
	blk       = next;
	first_idx = inode->i_compr_inlined_nidxs;

	while (noninline_nidxs) {
		if (noninline_nidxs >= EROFS_DECOMPR_IDXS_PER_BLK) {
			nidxs	= EROFS_DECOMPR_IDXS_PER_BLK;
			request_size = EROFS_BLKSIZE;
		} else {
			nidxs	= noninline_nidxs;
			request_size = nidxs * EROFS_DECOMPR_IDX_SZ;
			request_size = round_up(request_size, EROFS_SLOTSIZE);
		}

		indexes = malloc(sizeof(*indexes) + request_size);
		if (!indexes) {
			erofs_err("Failed to alloc memory for index info structure");
			exit(EXIT_FAILURE);
		}

		erofs_meta_node_init(&indexes->i_meta_node, EROFS_META_INDEX);
		indexes->i_1st_idx = first_idx;
		indexes->i_nidxs   = nidxs;
		memset(indexes->i_idxs, 0, request_size);
		list_add_tail(&indexes->i_node, &inode->i_compr_idxs_list);

		node	 = &indexes->i_meta_node;
		node->m_blk  = blk;
		node->m_type = EROFS_META_INDEX;

		node->m_slot = blk->bb_free_slot;
		blk->bb_free_slot += request_size / EROFS_SLOTSIZE;

		node->m_len = request_size;
		list_add_tail(&node->m_node, &blk->bb_metadata_list);

		noninline_nidxs -= nidxs;
		first_idx += nidxs;

		next = list_next_entry(blk, bb_global_node);
		erofs_put_block_buffer(blk);
		blk = next;
	}
}

struct erofs_node_info *mkfs_prepare_root_inode(char *root)
{
	if (!root)
		return NULL;
	return erofs_init_inode(root);
}

int mkfs_relocate_sub_inodes(struct erofs_node_info *inode)
{
	int ret;
	int compressible;
	u32 blkaddr;
	u32 nblocks;
	u32 unaligned;
	struct erofs_node_info *d = inode;

	switch (d->i_type) {
	case EROFS_FT_REG_FILE:
		compressible = erofs_check_compressible(d);
		if (compressible < 0) {
			assert(0);
		} else if (compressible > 0) {
			erofs_init_compress_inode(d);
			mkfs_rank_inode(d);
			break;
		}
	case EROFS_FT_DIR:
	case EROFS_FT_SYMLINK:
		unaligned = d->i_size % EROFS_BLKSIZE;
		nblocks   = d->i_size / EROFS_BLKSIZE;

		if (unaligned > erofs_calc_inline_data_size(d) ||
		    (unaligned == 0 && nblocks != 0)) {
			d->i_dmode = EROFS_INODE_LAYOUT_PLAIN;
			mkfs_rank_inode(d);

			if (unaligned != 0)
				nblocks++;
			blkaddr = erofs_alloc_blocks(nblocks);
			if (!blkaddr)
				return -ENOSPC;

			d->i_blkaddr = blkaddr;
		} else {
			d->i_dmode	  = EROFS_INODE_LAYOUT_INLINE;
			d->i_inline_datalen = unaligned;
			mkfs_rank_inode(d);

			if (nblocks > 0) {
				blkaddr = erofs_alloc_blocks(nblocks);
				if (!blkaddr)
					return -ENOSPC;

				d->i_blkaddr = blkaddr;
			} else {
				d->i_blkaddr = 0;
			}
		}
		break;
	case EROFS_FT_BLKDEV:
	case EROFS_FT_CHRDEV:
	case EROFS_FT_FIFO:
	case EROFS_FT_SOCK:
		mkfs_rank_inode(d);
		break;

	default:
		erofs_err("inode[%s] file_type error =%d",
			  d->i_fullpath,
			  d->i_type);
		return -EINVAL;
	}

	list_for_each_entry(d, &inode->i_subdir_head, i_list) {
		ret = mkfs_relocate_sub_inodes(d);
		if (ret)
			return ret;
	}

	return 0;
}

static u32 write_dirents(char *buf, u32 sum, struct list_head *start,
			 struct list_head *end)
{
	char *pbuf       = buf;
	u32 size	 = 0;
	u32 base_nameoff = 0;
	struct erofs_dirent dirent;
	struct list_head *start_tmp = NULL;

	base_nameoff = sum * EROFS_DIRENT_SIZE;
	start_tmp    = start;
	while (start_tmp != end) {
		struct erofs_node_info *d =
			container_of(start_tmp, struct erofs_node_info, i_list);
		u32 name_len = strlen(d->i_name);

		d->i_nameoff = base_nameoff;
		memcpy(pbuf + base_nameoff, d->i_name, name_len);
		base_nameoff += name_len;
		start_tmp = start_tmp->next;
	}

	start_tmp = start;
	while (start_tmp != end) {
		struct erofs_node_info *d =
			container_of(start_tmp, struct erofs_node_info, i_list);
		memset(&dirent, 0, EROFS_DIRENT_SIZE);

		dirent.nid = cpu_to_le64(mkfs_addr_to_nid(d->i_base_addr));
		dirent.file_type = d->i_type;
		dirent.nameoff   = cpu_to_le16(d->i_nameoff);
		memcpy(pbuf + size, &dirent, EROFS_DIRENT_SIZE);
		size += EROFS_DIRENT_SIZE;
		start_tmp = start_tmp->next;
	}
	assert(base_nameoff <= EROFS_BLKSIZE);

	return base_nameoff;
}
static int mkfs_write_inode_dir(struct erofs_node_info *inode)
{
	struct list_head *pos;
	struct list_head *start;
	u32 sum		 = 0;
	u32 blk_cnt      = 0;
	u32 dentrys_size = 0;
	char *pbuf       = NULL;
	int ret		 = 0;

	/* dentrys were at inline area */
	if (inode->i_dmode == EROFS_INODE_LAYOUT_INLINE) {
		start = (&inode->i_subdir_head)->next;
		/* dentry begin from the next block offset to inode,
		 * so page_num should be 1
		 */
		pbuf = calloc(EROFS_BLKSIZE, 1);

		if (!pbuf) {
			erofs_err("calloc inode[%s] error[%s]",
				  inode->i_fullpath,
				  strerror(errno));
			return -ENOMEM;
		}

		list_for_each(pos, &inode->i_subdir_head) {
			struct erofs_node_info *d;
			u32 len;

			d   = container_of(pos, struct erofs_node_info, i_list);
			len = strlen(d->i_name);

			if (dentrys_size + EROFS_DIRENT_SIZE + len >
			    EROFS_BLKSIZE) {
				const u32 blkaddr = inode->i_blkaddr + blk_cnt;

				memset(pbuf, 0, EROFS_BLKSIZE);
				write_dirents(pbuf, sum, start, pos);
				ret = blk_write(pbuf, blkaddr);
				if (ret < 0) {
					erofs_err("blk_write(file %s, err %s)",
						  inode->i_fullpath,
						  strerror(errno));
					return ret;
				}

				blk_cnt += 1;
				sum	  = 0;
				dentrys_size = 0;
				start	= pos;
			}

			dentrys_size += EROFS_DIRENT_SIZE + len;
			sum += 1;
		}

		/* write last page names */
		if (start != pos) {
			s32 len;

			memset(pbuf, 0, EROFS_BLKSIZE);
			len = write_dirents(pbuf, sum, start, pos);
			inode->i_inline_data    = pbuf;
			inode->i_inline_datalen = len;
		}

	} else if (inode->i_dmode == EROFS_INODE_LAYOUT_PLAIN) {
		start = (&inode->i_subdir_head)->next;
		/* dentry begin from the next block offset to inode,
		 * so page_num should be 1
		 */
		pbuf = calloc(EROFS_BLKSIZE, 1);
		if (!pbuf) {
			perror("calloc");
			return -ENOMEM;
		}

		list_for_each(pos, &inode->i_subdir_head) {
			struct erofs_node_info *d;
			u32 len;

			d   = container_of(pos, struct erofs_node_info, i_list);
			len = strlen(d->i_name);
			if (dentrys_size + EROFS_DIRENT_SIZE + len >
			    EROFS_BLKSIZE) {
				const u32 blkaddr = inode->i_blkaddr + blk_cnt;

				memset(pbuf, 0, EROFS_BLKSIZE);
				write_dirents(pbuf, sum, start, pos);
				blk_write(pbuf, blkaddr);
				if (ret < 0) {
					erofs_err("blk_write(file %s, err %s)",
						  inode->i_fullpath,
						  strerror(errno));
					return ret;
				}

				blk_cnt += 1;
				sum	  = 0;
				dentrys_size = 0;
				start	= pos;
			}

			dentrys_size += EROFS_DIRENT_SIZE + len;
			sum += 1;
		}

		/* write last page names */
		if (start != pos) {
			const u32 blkaddr = inode->i_blkaddr + blk_cnt;

			memset(pbuf, 0, EROFS_BLKSIZE);
			write_dirents(pbuf, sum, start, pos);
			ret = blk_write(pbuf, blkaddr);
			if (ret < 0) {
				erofs_err("blk_write(file %s, err %s)",
					  inode->i_fullpath,
					  strerror(errno));
				return ret;
			}
		}

		free(pbuf);

	} else {
		erofs_err("inode->i_dmode[%u]mode 1 is not support right now",
			  inode->i_dmode);
		return -EINVAL;
	}

	return 0;
}

static int mkfs_write_inode_regfile(struct erofs_node_info *inode)
{
	char *pbuf     = NULL;
	int ret	= 0;
	u32 i	  = 0;
	int fd	 = 0;
	u32 nblocks    = 0;
	int unaligned  = 0;
	u32 page_cnt   = inode->i_size / EROFS_BLKSIZE;
	char *filepath = inode->i_fullpath;

	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		erofs_err("current path=%s filepath=%s",
			  getcwd(NULL, 0),
			  filepath);
		return -errno;
	}

	switch (inode->i_dmode) {
	case EROFS_INODE_LAYOUT_PLAIN:
		if ((inode->i_size % EROFS_BLKSIZE) != 0)
			page_cnt += 1;

		pbuf = calloc(EROFS_BLKSIZE, 1);
		if (!pbuf) {
			erofs_err("calloc inode[%s] error[%s]",
				  inode->i_fullpath,
				  strerror(errno));
			return -errno;
		}

		for (i = 0; i < page_cnt; i++) {
			ret = read(fd, pbuf, EROFS_BLKSIZE);
			if (ret < 0) {
				erofs_err("read inode[%s] error[%s]",
					  filepath,
					  strerror(errno));
				return -errno;
			}

			ret = blk_write(pbuf, inode->i_blkaddr + i);
			if (ret < 0) {
				erofs_err("blk_write inode[%s] ret[%d]",
					  filepath,
					  ret);
				return ret;
			}
		}

		free(pbuf);
		break;

	case EROFS_INODE_LAYOUT_COMPRESSION:
		ret = erofs_compress_file(inode);
		if (ret) {
			erofs_err("Compress file failed ret=%d", ret);
			return ret;
		}
		break;

	case EROFS_INODE_LAYOUT_INLINE:
		if (inode->i_size == 0)
			break;

		nblocks   = inode->i_size / EROFS_BLKSIZE;
		unaligned = inode->i_size % EROFS_BLKSIZE;
		if (nblocks > 0) {
			assert(inode->i_blkaddr != 0);

			pbuf = calloc(EROFS_BLKSIZE, 1);
			if (!pbuf) {
				erofs_err("calloc inode[%s] error[%s]",
					  inode->i_fullpath,
					  strerror(errno));
				return -errno;
			}

			for (i = 0; i < nblocks; i++) {
				ret = read(fd, pbuf, EROFS_BLKSIZE);
				if (ret < 0) {
					erofs_err("read inode[%s] error[%s]",
						  filepath,
						  strerror(errno));
					exit(EXIT_FAILURE);
				}

				ret = blk_write(pbuf, inode->i_blkaddr + i);
				if (ret < 0) {
					erofs_err("blk_write inode[%s] ret[%d]",
						  filepath,
						  ret);
					return ret;
				}
			}

			free(pbuf);
		}

		if (unaligned > 0) {
			s32 len;

			inode->i_inline_data = calloc(EROFS_BLKSIZE, 1);
			if (!inode->i_inline_data) {
				erofs_err("calloc inode[%s] error[%s]",
					  filepath,
					  strerror(errno));
				return -errno;
			}

			(void)lseek(fd, nblocks * EROFS_BLKSIZE, SEEK_SET);

			len = read(fd, inode->i_inline_data, unaligned);
			if (len < 0) {
				erofs_err("read inode[%s] error[%s]",
					  filepath,
					  strerror(errno));
				return -errno;
			}
			inode->i_inline_datalen = len;
		}
		break;

	default:
		erofs_err(
			"Inode[%s] mode error [%d]", filepath, inode->i_dmode);
		return -EINVAL;
	}

	close(fd);
	return 0;
}

static int mkfs_write_inode_symfile(struct erofs_node_info *inode)
{
	char *pbuf = NULL;
	int ret    = 0;

	switch (inode->i_dmode) {
	case EROFS_INODE_LAYOUT_PLAIN:
		pbuf = calloc(EROFS_BLKSIZE, 1);
		if (!pbuf) {
			erofs_err("calloc inode[%s] error[%s]",
				  inode->i_fullpath,
				  strerror(errno));
			return -errno;
		}

		ret = readlink(inode->i_fullpath, pbuf, inode->i_size);
		if (ret < 0) {
			erofs_err("readlink inode[%s] error[%s]",
				  inode->i_fullpath,
				  strerror(errno));
			return -errno;
		}

		ret = blk_write(pbuf, inode->i_blkaddr);
		if (ret < 0) {
			erofs_err("blk_write inode[%s] error[%s]",
				  inode->i_fullpath,
				  strerror(errno));
			return ret;
		}
		free(pbuf);
		break;

	case EROFS_INODE_LAYOUT_COMPRESSION:
		break;

	case EROFS_INODE_LAYOUT_INLINE:
		if (inode->i_size == 0)
			break;

		inode->i_inline_data = calloc(EROFS_BLKSIZE, 1);
		if (!inode->i_inline_data) {
			perror("calloc");
			return -errno;
		}

		inode->i_inline_datalen = readlink(
			inode->i_fullpath, inode->i_inline_data, inode->i_size);
		if (inode->i_inline_datalen < 0) {
			perror("readlink");
			return -errno;
		}

		break;

	default:
		erofs_err("Inode mode error [%d]", inode->i_dmode);
		return -EINVAL;
	}

	return 0;
}

int mkfs_do_write_inodes_data(struct erofs_node_info *inode)
{
	int ret;
	struct list_head *pos;

	switch (inode->i_type) {
	case EROFS_FT_DIR:
		ret = mkfs_write_inode_dir(inode);
		if (ret)
			return ret;
		break;

	case EROFS_FT_REG_FILE:
		ret = mkfs_write_inode_regfile(inode);
		if (ret)
			return ret;
		break;

	case EROFS_FT_SYMLINK:
		ret = mkfs_write_inode_symfile(inode);
		if (ret)
			return ret;
		break;

	default:
		/* special devices file eg. chr block pipe sock */
		break;
	}

	if (!list_empty(&inode->i_subdir_head)) {
		list_for_each(pos, &inode->i_subdir_head) {
			struct erofs_node_info *d;

			d   = container_of(pos, struct erofs_node_info, i_list);
			ret = mkfs_do_write_inodes_data(d);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int erofs_do_write_inode_buffer(struct erofs_node_info *inode, char *buf)
{
	struct erofs_inode_v1 *v1;
	struct erofs_inode_v2 *v2;

	if (inode->i_iver == EROFS_INODE_LAYOUT_V1) {
		v1 = (struct erofs_inode_v1 *)buf;
		v1->i_advise = cpu_to_le16(inode->i_iver|(inode->i_dmode<<1));
		v1->i_xattr_icount = cpu_to_le16(inode->i_xattr_scnt);
		v1->i_mode = cpu_to_le16(inode->i_mode);
		v1->i_nlink = cpu_to_le16((u16)inode->i_nlink);
		v1->i_size = cpu_to_le32((u32)inode->i_size);
		v1->i_ino = cpu_to_le32(inode->i_ino);
		v1->i_uid = cpu_to_le16((u16)inode->i_uid);
		v1->i_gid = cpu_to_le16((u16)inode->i_gid);

		switch (inode->i_type) {
		case EROFS_FT_CHRDEV:
		case EROFS_FT_BLKDEV:
		case EROFS_FT_FIFO:
		case EROFS_FT_SOCK:
			v1->i_u.rdev = cpu_to_le32(inode->i_rdev);
			break;

		default:
			if (inode->i_dmode == EROFS_INODE_LAYOUT_COMPRESSION)
				v1->i_u.compressed_blocks =
					cpu_to_le32(inode->i_blocks);
			else
				v1->i_u.raw_blkaddr =
					cpu_to_le32(inode->i_blkaddr);

			break;
		}

		v1->i_checksum = 0;
		return sizeof(*v1);
	}

	v2 = (struct erofs_inode_v2 *)buf;
	v2->i_advise = cpu_to_le16(inode->i_iver|(inode->i_dmode<<1));
	v2->i_xattr_icount = cpu_to_le16(inode->i_xattr_scnt);
	v2->i_mode = cpu_to_le16(inode->i_mode);
	v2->i_size = cpu_to_le64(inode->i_size);
	v2->i_u.raw_blkaddr = cpu_to_le32(inode->i_blkaddr);
	v2->i_ino = cpu_to_le32(inode->i_ino);
	v2->i_uid = cpu_to_le32(inode->i_uid);
	v2->i_gid = cpu_to_le32(inode->i_gid);
	v2->i_ctime = cpu_to_le64(inode->i_ctime);
	v2->i_ctime_nsec = cpu_to_le32(inode->i_ctime_nsec);
	v2->i_nlink = cpu_to_le32(inode->i_nlink);

	switch (inode->i_type) {
	case EROFS_FT_CHRDEV:
	case EROFS_FT_BLKDEV:
	case EROFS_FT_FIFO:
	case EROFS_FT_SOCK:
		v2->i_u.rdev = cpu_to_le32(inode->i_rdev);
		break;

	default:
		if (inode->i_dmode == EROFS_INODE_LAYOUT_COMPRESSION)
			v2->i_u.compressed_blocks =
				cpu_to_le32(inode->i_blocks);
		else
			v2->i_u.raw_blkaddr =
				cpu_to_le32(inode->i_blkaddr);

		break;
	}

	v2->i_checksum = 0;
	return sizeof(*v2);
}

int erofs_write_inode_buffer(struct erofs_node_info *inode, char *buf)
{
	char *pbuf = buf;
	int count  = 0;

	count += erofs_do_write_inode_buffer(inode, pbuf + count);

	switch (inode->i_dmode) {
	/* Compress File */
	case EROFS_INODE_LAYOUT_COMPRESSION:
	/* Inline softlink or dir or file */
	case EROFS_INODE_LAYOUT_INLINE:
		count = round_up(count, inode->i_inline_align_size);
		if (inode->i_size > 0) {
			memcpy(pbuf + count,
			       inode->i_inline_data,
			       inode->i_inline_datalen);
			count += inode->i_inline_datalen;
		}
		break;

	default:
		break;
	}

	count = SLOT_ALIGN(count);
	return count;
}

int erofs_write_index_buffer(struct erofs_index_info *index, char *buf)
{
	int count;

	assert(index->i_nidxs);

	count = index->i_nidxs * EROFS_DECOMPR_IDX_SZ;
	memcpy(buf, index->i_idxs, count);

	return count;
}

u64 mkfs_addr_to_nid(u64 addr)
{
	if (!IS_SLOT_ALIGN(addr)) {
		erofs_err("SLOT NOT ALIGN: addr=0x%08" PRIX64 "", addr);
		exit(EXIT_FAILURE);
	}
	return (u64)((addr - (u64)sb->meta_blkaddr * EROFS_BLKSIZE) / 32);
}
