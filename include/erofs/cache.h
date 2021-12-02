/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Miao Xie <miaoxie@huawei.com>
 * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
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
/* shared xattrs */
#define XATTR		3
/* device table */
#define DEVT		4

struct erofs_bhops {
	bool (*preflush)(struct erofs_buffer_head *bh);
	bool (*flush)(struct erofs_buffer_head *bh);
};

struct erofs_buffer_head {
	struct list_head list;
	struct erofs_buffer_block *block;

	erofs_off_t off;
	const struct erofs_bhops *op;

	void *fsprivate;
};

struct erofs_buffer_block {
	struct list_head list;
	struct list_head mapped_list;

	erofs_blk_t blkaddr;
	int type;

	struct erofs_buffer_head buffers;
};

static inline const int get_alignsize(int type, int *type_ret)
{
	if (type == DATA)
		return EROFS_BLKSIZ;

	if (type == INODE) {
		*type_ret = META;
		return sizeof(struct erofs_inode_compact);
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
extern const struct erofs_bhops erofs_buf_write_bhops;

static inline erofs_off_t erofs_btell(struct erofs_buffer_head *bh, bool end)
{
	const struct erofs_buffer_block *bb = bh->block;

	if (bb->blkaddr == NULL_ADDR)
		return NULL_ADDR_UL;

	return blknr_to_addr(bb->blkaddr) +
		(end ? list_next_entry(bh, list)->off : bh->off);
}

static inline bool erofs_bh_flush_generic_end(struct erofs_buffer_head *bh)
{
	list_del(&bh->list);
	free(bh);
	return true;
}

struct erofs_buffer_head *erofs_buffer_init(void);
int erofs_bh_balloon(struct erofs_buffer_head *bh, erofs_off_t incr);

struct erofs_buffer_head *erofs_balloc(int type, erofs_off_t size,
				       unsigned int required_ext,
				       unsigned int inline_ext);
struct erofs_buffer_head *erofs_battach(struct erofs_buffer_head *bh,
					int type, unsigned int size);

erofs_blk_t erofs_mapbh(struct erofs_buffer_block *bb);
bool erofs_bflush(struct erofs_buffer_block *bb);

void erofs_bdrop(struct erofs_buffer_head *bh, bool tryrevoke);

#ifdef __cplusplus
}
#endif

#endif
