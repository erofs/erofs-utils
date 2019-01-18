/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_inode.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef CONFIG_EROFS_MKFS_INODE_H
#define CONFIG_EROFS_MKFS_INODE_H

#include <erofs/list.h>
#include "erofs_cache.h"
#include "mkfs_file.h"

#define MAX_PATH 4096
#define MAX_NAME 256

struct erofs_index_info {
	/* Link to its block buffer */
	struct erofs_meta_node i_meta_node;

	/* Link to its inode */
	struct list_head i_node;

	u64 i_1st_idx;
	s32 i_nidxs;
	struct z_erofs_vle_decompressed_index i_idxs[0];
};

struct erofs_vnode {
	struct erofs_meta_node i_meta_node;

	/* Original member */
	struct list_head i_list;
	struct list_head i_subdir_head; /* sub dirs or files */
	struct list_head i_xattr_head;

	u64 i_base_addr;       /* base address of a inode */
	char i_name[MAX_NAME]; /* the name of current inode */
	char i_fullpath[MAX_PATH + 1];
	u16 i_nameoff;
	u16 i_iver;       /* Inode Version */
	u16 i_dmode;      /* Data mode */
	u16 i_xattr_scnt; /* Inline xattr space count */
	u16 i_shared_count;
	u16 i_mode;
	u8 i_type; /* Inode type: File, Dir...*/
	u64 i_size;
	union {
		u32 i_blkaddr;
		u32 i_blocks;
		u32 i_rdev;
	};
	u32 i_ino;
	u32 i_uid;
	u32 i_gid;
	u64 i_ctime;
	u32 i_ctime_nsec;
	u32 i_nlink;

	/* If compress file, we use it store index info */
	char *i_inline_data;
	s32 i_inline_datalen;
	s32 i_inline_align_size;

	struct erofs_compr_info i_compressor;
	struct erofs_compr_ctx i_compr_ctx;
	u64 i_compr_nidxs;
	u32 i_compr_inlined_nidxs;
	struct list_head i_compr_idxs_list;
	struct erofs_index_info *i_compr_cur_index_info;
};

struct erofs_vnode *mkfs_prepare_root_inode(char *root);
int mkfs_relocate_sub_inodes(struct erofs_vnode *droot);
int mkfs_do_write_inodes_data(struct erofs_vnode *droot);
u64 mkfs_addr_to_nid(u64 addr);
int erofs_write_inode_buffer(struct erofs_vnode *inode, char *buf);
int erofs_write_index_buffer(struct erofs_index_info *index, char *buf);
u8 erofs_check_disk_inode_version(struct erofs_vnode *inode);

#endif
