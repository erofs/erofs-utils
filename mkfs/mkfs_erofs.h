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
#include <erofs/list.h>
#include "erofs_types.h"

typedef unsigned int __u32;

#define __packed __attribute__((__packed__))

#include "erofs_fs.h"

#define LOG_BLOCK_SIZE          (12)
#define EROFS_BLKSIZE           (4096)

#define EROFS_SLOTSIZE_BITS             (5)
#define EROFS_SLOTSIZE                  (32)

#define __round_mask(x, y)      ((__typeof__(x))((y)-1))
#define round_up(x, y)          ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y)        ((x) & ~__round_mask(x, y))

#define SIZE_ALIGN(val, size)   (((val) + (size) - 1) & (~(size-1)))
#define SLOT_ALIGN(slots)       SIZE_ALIGN(slots, EROFS_SLOTSIZE)
#define BLK_ALIGN(blks)         SIZE_ALIGN(blks, EROFS_BLKSIZE)
#define IS_SLOT_ALIGN(__ADDR)   (((__ADDR)%(EROFS_SLOTSIZE))?0:1)
#define IS_BLK_ALIGN(__ADDR)    (((__ADDR)%(EROFS_BLKSIZE))?0:1)
#define MAX_NID_INDEX_PER_BLK   (EROFS_BLKSIZE / EROFS_SLOTSIZE)

typedef u64 erofs_off_t;

/* data type for filesystem-wide blocks number */
typedef u32 erofs_blk_t;

#define erofs_blknr(addr)       ((addr) / EROFS_BLKSIZE)
#define erofs_blkoff(addr)      ((addr) % EROFS_BLKSIZE)
#define blknr_to_addr(nr)       ((erofs_off_t)(nr) * EROFS_BLKSIZE)

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
