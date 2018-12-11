// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs_cache.c
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Miao Xie <miaoxie@huawei.com>
 */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "erofs_types.h"
#include "erofs_cache.h"
#include "erofs_error.h"
#include "erofs_debug.h"
#include "erofs_io.h"
#include "mkfs_erofs.h"
#include "mkfs_inode.h"

/* The 1st block is used for SUPER BLOCK, so skip it. */
static u64 erofs_current_block = 1;
static LIST_HEAD(erofs_global_blocks);
static LIST_HEAD(erofs_free_blocks);
static LIST_HEAD(erofs_full_blocks);

/*
 * Note: Since we reserved the 1st block for super block, so we can reuse
 * this block number as a special number, we use it to tell the caller that
 * there is NO ENOUGH FREE SPACE!!!!
 *
 * So the result value:
 * !0 : Allocate the blocks successfully, this is block number of
 *      the 1st block.
 * 0  : ENOSPC, There is no enough space.
 */
u32 erofs_alloc_blocks(u32 nblocks)
{
	u32 blkaddr;
	u64 devlen;

	assert(nblocks);

	devlen = dev_length();
	if (erofs_current_block > (u64)UINT32_MAX ||
	    erofs_current_block + nblocks > ((u64)UINT32_MAX) + 1 ||
	    (erofs_current_block + nblocks) << EROFS_BLOCKSIZE_BITS > devlen) {
		erofs_err("There is no enough free space(curr: %llu, need: %u, device blocks: %llu).",
			  (unsigned long long)erofs_current_block, nblocks,
			  (unsigned long long)devlen >> EROFS_BLOCKSIZE_BITS);
		return 0;
	}

	blkaddr = (u32)erofs_current_block;
	erofs_current_block += nblocks;

	return blkaddr;
}

u64 erofs_get_total_blocks(void)
{
	return erofs_current_block;
}

block_buffer_t *erofs_alloc_multi_block_buffer(u32 nblocks)
{
	block_buffer_t *blk;
	block_buffer_t *next;
	block_buffer_t *first;
	struct list_head blocks;
	u32 blkaddr;
	u32 i;
	int ret;

	init_list_head(&blocks);

	for (i = 0; i < nblocks; i++) {
		blk = (block_buffer_t *)malloc(sizeof(block_buffer_t));
		if (!blk) {
			erofs_err("Fail to alloc memory for block buffer");
			ret = -ENOMEM;
			goto free_block_buffer;
		}
		memset(blk, 0, sizeof(block_buffer_t));
		init_list_head(&blk->bb_metadata_list);

		list_add_tail(&blk->bb_global_node, &blocks);
	}

	blkaddr = erofs_alloc_blocks(nblocks);
	if (!blkaddr) {
		ret = -ENOSPC;
		goto free_block_buffer;
	}

	first = list_first_entry(&blocks, block_buffer_t, bb_global_node);
	list_for_each_entry_safe(blk, next, &blocks, bb_global_node) {
		blk->bb_blkaddr = blkaddr;
		blkaddr++;

		list_del(&blk->bb_global_node);
		list_add_tail(&blk->bb_global_node, &erofs_global_blocks);
		list_add_tail(&blk->bb_alloc_node, &erofs_free_blocks);
	}

	return first;

free_block_buffer:
	list_for_each_entry_safe(blk, next, &blocks, bb_global_node) {
		list_del(&blk->bb_global_node);
		free(blk);
	}
	return ERR_PTR(ret);
}

block_buffer_t *erofs_alloc_single_block_buffer(void)
{
	return erofs_alloc_multi_block_buffer(1);
}

block_buffer_t *erofs_look_up_free_pos(int request_size)
{
	block_buffer_t *blk = NULL;

	list_for_each_entry(blk, &erofs_free_blocks, bb_alloc_node) {
		if ((request_size + blk->bb_free_slot * EROFS_SLOTSIZE) <
		    EROFS_BLKSIZE)
			return blk;
	}

	blk = erofs_alloc_single_block_buffer();
	return blk;
}

int erofs_flush_all_blocks(void)
{
	struct block_buffer *blk;
	struct erofs_meta_node *node;
	struct erofs_node_info *inode;
	struct erofs_index_info *index;
	char *erofs_blk_buf;
	char *pbuf;
	int count;
	int ret;
	u32 addr;

	erofs_blk_buf = malloc(EROFS_BLKSIZE);
	if (!erofs_blk_buf)
		return -ENOMEM;

	list_for_each_entry(blk, &erofs_global_blocks, bb_global_node) {
		pbuf = erofs_blk_buf;
		memset(pbuf, 0, EROFS_BLKSIZE);

		list_for_each_entry(node, &blk->bb_metadata_list, m_node) {
			switch (node->m_type) {
			case EROFS_META_INODE:
				inode = (struct erofs_node_info *)node;

				count = erofs_write_inode_buffer(inode, pbuf);
				break;
			case EROFS_META_INDEX:
				index = (struct erofs_index_info *)node;

				count = erofs_write_index_buffer(index, pbuf);
				break;
			default:
				erofs_err("Wrong metadata type");
				assert(0);
			}

			count = round_up(count, EROFS_SLOTSIZE);
			assert(count == node->m_len);
			pbuf += count;
		}

		addr = blk->bb_blkaddr;

		ret = dev_write(
			erofs_blk_buf, BLKNO_TO_ADDR(addr), EROFS_BLKSIZE);
		if (ret)
			break;
	}

	free(erofs_blk_buf);

	return ret;
}

void erofs_put_block_buffer(struct block_buffer *blk)
{
	if (blk->bb_free_slot == MAX_NID_INDEX_PER_BLK) {
		list_del(&blk->bb_alloc_node);
		list_add_tail(&blk->bb_alloc_node, &erofs_full_blocks);
	} else if (blk->bb_free_slot > MAX_NID_INDEX_PER_BLK) {
		erofs_err("block buffer overflow: free_slot = %d, MAX_NID_INDEX_PER_BLK = %d",
			  blk->bb_free_slot, MAX_NID_INDEX_PER_BLK);
		assert(0);
	}
}

int erofs_cache_init(u64 start_blk)
{
	erofs_current_block = start_blk;
	return 0;
}
