/* SPDX-License-Identifier: GPL-2.0+ OR MIT */
/*
 * erofs-utils/lib/liberofs_chunk.h
 *
 * Copyright (C) 2021, Alibaba Cloud
 */
#ifndef __EROFS_BLOBCHUNK_H
#define __EROFS_BLOBCHUNK_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "erofs/internal.h"

struct erofs_chunkitem *erofs_get_unhashed_chunk(struct erofs_sb_info *sbi,
		unsigned int device_id, erofs_blk_t blkaddr,
		erofs_off_t sourceoffset);
void erofs_inode_fixup_chunkformat(struct erofs_inode *inode);
int erofs_write_chunk_indexes(struct erofs_inode *inode, struct erofs_vfile *vf,
			      erofs_off_t off);
int erofs_blob_write_chunked_file(struct erofs_inode *inode, int fd,
				  erofs_off_t startoff, int device_id);
int erofs_write_zero_inode(struct erofs_inode *inode);
int tarerofs_write_chunkes(struct erofs_inode *inode, erofs_off_t data_offset);
int erofs_blob_init(struct erofs_sb_info *sbi, unsigned int chunkbits_zero);
int erofs_blob_init_device(struct erofs_sb_info *sbi, int device_id);
int erofs_chunkmgr_exit(struct erofs_sb_info *sbi);

#ifdef __cplusplus
}
#endif

#endif
