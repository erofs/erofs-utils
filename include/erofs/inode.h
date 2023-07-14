/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
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

static inline struct erofs_inode *erofs_igrab(struct erofs_inode *inode)
{
	++inode->i_count;
	return inode;
}

u32 erofs_new_encode_dev(dev_t dev);
unsigned char erofs_mode_to_ftype(umode_t mode);
unsigned char erofs_ftype_to_dtype(unsigned int filetype);
void erofs_inode_manager_init(void);
unsigned int erofs_iput(struct erofs_inode *inode);
erofs_nid_t erofs_lookupnid(struct erofs_inode *inode);
struct erofs_dentry *erofs_d_alloc(struct erofs_inode *parent,
				   const char *name);
int tarerofs_dump_tree(struct erofs_inode *dir);
int erofs_init_empty_dir(struct erofs_inode *dir);
struct erofs_inode *erofs_new_inode(void);
struct erofs_inode *erofs_mkfs_build_tree_from_path(const char *path);
struct erofs_inode *erofs_mkfs_build_special_from_fd(int fd, const char *name);

#ifdef __cplusplus
}
#endif

#endif
