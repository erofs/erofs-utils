/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_cache.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_CACHE_H__
#define __EROFS_CACHE_H__
#include "mkfs_erofs.h"
#include "list_head.h"

enum erofs_meta_type {
	EROFS_META_INODE,
	EROFS_META_INDEX,
	EROFS_META_MAX_TYPES,
};

struct erofs_meta_node {
	struct list_head m_node;
	struct block_buffer *m_blk;
	int m_type;
	int m_slot;
	int m_len;
};

static inline void erofs_meta_node_init(struct erofs_meta_node *node, int type)
{
	init_list_head(&node->m_node);
	node->m_type = type;
	node->m_blk  = NULL;
	node->m_slot = 0;
	node->m_len  = 0;
}

typedef struct block_buffer {
	/* These two members are used to block management. */
	struct list_head bb_global_node;
	struct list_head bb_alloc_node;

	/* This is the head of all metadata which is hold in this block. */
	struct list_head bb_metadata_list;

	u32 bb_blkaddr;
	int bb_free_slot;
} block_buffer_t;

block_buffer_t *erofs_alloc_single_block_buffer(void);
block_buffer_t *erofs_alloc_multi_block_buffer(u32 nblocks);
block_buffer_t *erofs_look_up_free_pos(int request_size);
int erofs_flush_all_blocks(void);
int erofs_cache_init(u64 start_blk);
void erofs_cache_deinit(void);
u32 erofs_alloc_blocks(u32 nblocks);
void erofs_put_block_buffer(struct block_buffer *blk);
u64 erofs_get_total_blocks(void);
#endif
