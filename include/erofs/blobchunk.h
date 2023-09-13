/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * erofs-utils/lib/blobchunk.h
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

struct erofs_blobchunk *erofs_get_unhashed_chunk(unsigned int device_id,
		erofs_blk_t blkaddr, erofs_off_t sourceoffset);
int erofs_blob_write_chunk_indexes(struct erofs_inode *inode, erofs_off_t off);
int erofs_blob_write_chunked_file(struct erofs_inode *inode, int fd);
int tarerofs_write_chunkes(struct erofs_inode *inode, erofs_off_t data_offset);
int erofs_mkfs_dump_blobs(struct erofs_sb_info *sbi);
void erofs_blob_exit(void);
int erofs_blob_init(const char *blobfile_path);
int erofs_mkfs_init_devices(struct erofs_sb_info *sbi, unsigned int devices);

#ifdef __cplusplus
}
#endif

#endif
