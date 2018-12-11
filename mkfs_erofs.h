/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * mkfs_erofs.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 *
 */
#ifndef __EROFS_MKFS_H
#define __EROFS_MKFS_H
#include <linux/limits.h>
#include "list_head.h"
#include "erofs_types.h"

typedef unsigned int __u32;

#define __packed __attribute__((__packed__))

#include "erofs_fs.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE               (4096)
#endif

#ifndef EROFS_BLKSIZE
#define EROFS_BLKSIZE           (4096)
#define EROFS_BLOCKSIZE_BITS    (12)
#endif

#define EROFS_BLOCK_SIZE_SHIFT_BITS     (12)
#define EROFS_SLOTSIZE_BITS             (5)
#define EROFS_SLOTSIZE                  (32)
#define MKFS_DIFF_SHIFT_8_BITS          (8)

#define __round_mask(x, y)      ((__typeof__(x))((y)-1))
#define round_up(x, y)          ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y)        ((x) & ~__round_mask(x, y))

#define SIZE_ALIGN(val, size)   (((val) + (size) - 1) & (~(size-1)))
#define SLOT_ALIGN(slots)       SIZE_ALIGN(slots, EROFS_SLOTSIZE)
#define PAGE_ALIGN(pages)       SIZE_ALIGN(pages, PAGE_SIZE)
#define BLK_ALIGN(blks)         SIZE_ALIGN(blks, EROFS_BLKSIZE)
#define IS_SLOT_ALIGN(__ADDR)   (((__ADDR)%(EROFS_SLOTSIZE))?0:1)
#define IS_BLK_ALIGN(__ADDR)    (((__ADDR)%(EROFS_BLKSIZE))?0:1)
#define ADDR_TO_BLKNO(__ADDR)   ((__ADDR) >> EROFS_BLOCKSIZE_BITS)
#define BLKNO_TO_ADDR(__ADDR)   ((u64)(__ADDR) << EROFS_BLOCKSIZE_BITS)
#define MAX_NID_INDEX_PER_BLK   (EROFS_BLKSIZE / EROFS_SLOTSIZE)

#define EROFS_INODE_V1_SIZE     sizeof(struct erofs_inode_v1)
#define EROFS_INODE_V2_SIZE     sizeof(struct erofs_inode_v2)

#define EROFS_DIRENT_SIZE       sizeof(struct erofs_dirent)

#define EROFS_DECOMPR_IDX_SZ    sizeof(struct z_erofs_vle_decompressed_index)
#define EROFS_DECOMPR_IDXS_PER_BLK  (EROFS_BLKSIZE / EROFS_DECOMPR_IDX_SZ)

#define ondisk_extent_size(data_mapping_mode, count) \
	((data_mapping_mode) == EROFS_INODE_LAYOUT_COMPRESSION ? \
	(sizeof(struct erofs_extent_header) + \
	sizeof(__u32) * le32_to_cpu(count)) : 0)

#define EROFS_INLINE_GENERIC_ALIGN_SIZE     (4)
#define EROFS_INLINE_INDEX_ALIGN_SIZE       (8)

#endif
