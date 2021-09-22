// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/blobchunk.h
 *
 * Copyright (C) 2021, Alibaba Cloud
 */
#ifndef __EROFS_BLOBCHUNK_H
#define __EROFS_BLOBCHUNK_H

#include "erofs/internal.h"

int erofs_blob_write_chunk_indexes(struct erofs_inode *inode, erofs_off_t off);
int erofs_blob_write_chunked_file(struct erofs_inode *inode);
int erofs_blob_remap(void);
void erofs_blob_exit(void);
int erofs_blob_init(void);

#endif
