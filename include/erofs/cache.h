/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Miao Xie <miaoxie@huawei.com>
 * with heavy changes by Gao Xiang <xiang@kernel.org>
 */
#ifndef __EROFS_CACHE_H
#define __EROFS_CACHE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "internal.h"

struct erofs_buffer_head;
struct erofs_buffer_block;

#define DATA		0
#define META		1
/* including inline xattrs, extent */
#define INODE		2
/* directory data */
#define DIRA		3
/* shared xattrs */
#define XATTR		4
/* device table */
#define DEVT		5

struct erofs_bhops {
	int (*flush)(struct erofs_buffer_head *bh);
};

struct erofs_buffer_head {
	struct list_head list;
	union {
		struct {
			struct erofs_buffer_block *block;
			const struct erofs_bhops *op;
		};
		erofs_blk_t nblocks;
	};
	erofs_off_t off;
	void *fsprivate;
};

struct erofs_buffer_block {
	struct list_head list;
	struct list_head sibling;	/* blocks of the same waterline */

	erofs_blk_t blkaddr;
	int type;

	struct erofs_buffer_head buffers;
};

struct erofs_bufmgr {
	struct erofs_sb_info *sbi;

	/* buckets for all buffer blocks to boost up allocation */
	struct list_head watermeter[META + 1][2][EROFS_MAX_BLOCK_SIZE];
	unsigned long bktmap[META + 1][2][EROFS_MAX_BLOCK_SIZE / BITS_PER_LONG];

	struct erofs_buffer_block blkh;
	erofs_blk_t tail_blkaddr, metablkcnt;

	/* last mapped buffer block to accelerate erofs_mapbh() */
	struct erofs_buffer_block *last_mapped_block;

	/* align data block addresses to multiples of `dsunit` */
	unsigned int dsunit;
};

static inline const int get_alignsize(struct erofs_sb_info *sbi, int type,
				      int *type_ret)
{
	if (type == DATA)
		return erofs_blksiz(sbi);

	if (type == INODE) {
		*type_ret = META;
		return sizeof(struct erofs_inode_compact);
	} else if (type == DIRA) {
		*type_ret = META;
		return erofs_blksiz(sbi);
	} else if (type == XATTR) {
		*type_ret = META;
		return sizeof(struct erofs_xattr_entry);
	} else if (type == DEVT) {
		*type_ret = META;
		return EROFS_DEVT_SLOT_SIZE;
	}

	if (type == META)
		return 1;
	return -EINVAL;
}

extern const struct erofs_bhops erofs_drop_directly_bhops;
extern const struct erofs_bhops erofs_skip_write_bhops;

static inline erofs_off_t erofs_btell(struct erofs_buffer_head *bh, bool end)
{
	const struct erofs_buffer_block *bb = bh->block;
	struct erofs_bufmgr *bmgr =
			(struct erofs_bufmgr *)bb->buffers.fsprivate;

	if (bb->blkaddr == NULL_ADDR)
		return NULL_ADDR_UL;

	return erofs_pos(bmgr->sbi, bb->blkaddr) +
		(end ? list_next_entry(bh, list)->off : bh->off);
}

static inline int erofs_bh_flush_generic_end(struct erofs_buffer_head *bh)
{
	list_del(&bh->list);
	free(bh);
	return 0;
}

struct erofs_bufmgr *erofs_buffer_init(struct erofs_sb_info *sbi,
				       erofs_blk_t startblk);
int erofs_bh_balloon(struct erofs_buffer_head *bh, erofs_off_t incr);

struct erofs_buffer_head *erofs_balloc(struct erofs_bufmgr *bmgr,
				       int type, erofs_off_t size,
				       unsigned int inline_ext);
struct erofs_buffer_head *erofs_battach(struct erofs_buffer_head *bh,
					int type, unsigned int size);

erofs_blk_t erofs_mapbh(struct erofs_bufmgr *bmgr,
			struct erofs_buffer_block *bb);
int erofs_bflush(struct erofs_bufmgr *bmgr,
		 struct erofs_buffer_block *bb);

void erofs_bdrop(struct erofs_buffer_head *bh, bool tryrevoke);
erofs_blk_t erofs_total_metablocks(struct erofs_bufmgr *bmgr);
void erofs_buffer_exit(struct erofs_bufmgr *bmgr);

#ifdef __cplusplus
}
#endif

#endif
