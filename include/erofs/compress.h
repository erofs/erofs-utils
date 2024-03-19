/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <xiang@kernel.org>
 */
#ifndef __EROFS_COMPRESS_H
#define __EROFS_COMPRESS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "internal.h"

#define EROFS_CONFIG_COMPR_MAX_SZ	(4000 * 1024)
#define Z_EROFS_COMPR_QUEUE_SZ		(EROFS_CONFIG_COMPR_MAX_SZ * 2)

void z_erofs_drop_inline_pcluster(struct erofs_inode *inode);
int erofs_write_compressed_file(struct erofs_inode *inode, int fd, u64 fpos);

int z_erofs_compress_init(struct erofs_sb_info *sbi,
			  struct erofs_buffer_head *bh);
int z_erofs_compress_exit(void);

const char *z_erofs_list_supported_algorithms(int i, unsigned int *mask);
const struct erofs_algorithm *z_erofs_list_available_compressors(int *i);

static inline bool erofs_is_packed_inode(struct erofs_inode *inode)
{
	erofs_nid_t packed_nid = inode->sbi->packed_nid;

	if (inode->nid == EROFS_PACKED_NID_UNALLOCATED) {
		DBG_BUGON(packed_nid != EROFS_PACKED_NID_UNALLOCATED);
		return true;
	}
	return (packed_nid > 0 && inode->nid == packed_nid);
}

#ifdef __cplusplus
}
#endif

#endif
