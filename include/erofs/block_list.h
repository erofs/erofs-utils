/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C), 2021, Coolpad Group Limited.
 * Created by Yue Hu <huyue2@yulong.com>
 */
#ifndef __EROFS_BLOCK_LIST_H
#define __EROFS_BLOCK_LIST_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "internal.h"

int erofs_blocklist_open(char *filename, bool srcmap);
void erofs_blocklist_close(void);

void tarerofs_blocklist_write(erofs_blk_t blkaddr, erofs_blk_t nblocks,
			      erofs_off_t srcoff);
#ifdef WITH_ANDROID
void erofs_droid_blocklist_write(struct erofs_inode *inode,
				 erofs_blk_t blk_start, erofs_blk_t nblocks);
void erofs_droid_blocklist_write_tail_end(struct erofs_inode *inode,
					  erofs_blk_t blkaddr);
void erofs_droid_blocklist_write_extent(struct erofs_inode *inode,
					erofs_blk_t blk_start, erofs_blk_t nblocks,
					bool first_extent, bool last_extent);
#else
static inline void erofs_droid_blocklist_write(struct erofs_inode *inode,
				 erofs_blk_t blk_start, erofs_blk_t nblocks) {}
static inline void
erofs_droid_blocklist_write_tail_end(struct erofs_inode *inode,
					  erofs_blk_t blkaddr) {}
static inline void
erofs_droid_blocklist_write_extent(struct erofs_inode *inode,
				   erofs_blk_t blk_start, erofs_blk_t nblocks,
				   bool first_extent, bool last_extent) {}
#endif

#ifdef __cplusplus
}
#endif

#endif
