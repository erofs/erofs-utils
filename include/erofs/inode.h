/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
 */
#ifndef __EROFS_INODE_H
#define __EROFS_INODE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "erofs/internal.h"

unsigned char erofs_mode_to_ftype(umode_t mode);
void erofs_inode_manager_init(void);
unsigned int erofs_iput(struct erofs_inode *inode);
erofs_nid_t erofs_lookupnid(struct erofs_inode *inode);
struct erofs_inode *erofs_mkfs_build_tree_from_path(struct erofs_inode *parent,
						    const char *path);

#ifdef __cplusplus
}
#endif

#endif
