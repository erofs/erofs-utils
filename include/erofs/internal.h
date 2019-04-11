/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_utils/include/erofs/internal.h
 *
 * Copyright (C) 2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <gaoxiang25@huawei.com>
 */
#ifndef __EROFS_INTERNAL_H
#define __EROFS_INTERNAL_H

#include "list.h"
#include "err.h"

typedef unsigned short umode_t;

#define __packed __attribute__((__packed__))

#include "erofs_fs.h"
#include <fcntl.h>

#ifndef PATH_MAX
#define PATH_MAX        4096    /* # chars in a path name including nul */
#endif

#define PAGE_SHIFT		(12)
#define PAGE_SIZE		(1U << PAGE_SHIFT)

#define LOG_BLOCK_SIZE          (12)
#define EROFS_BLKSIZ            (1U << LOG_BLOCK_SIZE)

#define EROFS_ISLOTBITS		5
#define EROFS_SLOTSIZE		(1U << EROFS_ISLOTBITS)

typedef u64 erofs_off_t;
typedef u64 erofs_nid_t;
/* data type for filesystem-wide blocks number */
typedef u32 erofs_blk_t;

#define NULL_ADDR	((unsigned int)-1)
#define NULL_ADDR_UL	((unsigned long)-1)

#define erofs_blknr(addr)       ((addr) / EROFS_BLKSIZ)
#define erofs_blkoff(addr)      ((addr) % EROFS_BLKSIZ)
#define blknr_to_addr(nr)       ((erofs_off_t)(nr) * EROFS_BLKSIZ)

#define BLK_ROUND_UP(addr)	DIV_ROUND_UP(addr, EROFS_BLKSIZ)

struct erofs_buffer_head;

struct erofs_sb_info {
	erofs_blk_t meta_blkaddr;
	erofs_blk_t xattr_blkaddr;
};

/* global sbi */
extern struct erofs_sb_info sbi;

struct erofs_inode {
	struct list_head i_hash, i_subdirs;

	unsigned int i_count;
	struct erofs_inode *i_parent;

	umode_t i_mode;
	erofs_off_t i_size;

	u64 i_ino[2];
	u32 i_uid;
	u32 i_gid;
	u64 i_ctime;
	u32 i_ctime_nsec;
	u32 i_nlink;

	union {
		u32 i_blkaddr;
		u32 i_blocks;
		u32 i_rdev;
	} u;

	char i_srcpath[PATH_MAX + 1];

	unsigned char data_mapping_mode;
	unsigned char inode_isize;
	/* inline tail-end packing size */
	unsigned short idata_size;

	unsigned int xattr_isize;
	unsigned int extent_isize;

	erofs_nid_t nid;
	struct erofs_buffer_head *bh;
	struct erofs_buffer_head *bh_inline, *bh_data;

	void *idata;
};

#define IS_ROOT(x)	((x) == (x)->i_parent)

struct erofs_dentry {
	struct list_head d_child;	/* child of parent list */

	unsigned int type;
	char name[EROFS_NAME_LEN];
	union {
		struct erofs_inode *inode;
		erofs_nid_t nid;
	};
};

static inline bool is_dot_dotdot(const char *name)
{
	if (name[0] != '.')
		return false;

	return name[1] == '\0' || (name[1] == '.' && name[2] == '\0');
}

#include <stdio.h>
#include <string.h>

static inline const char *erofs_strerror(int err)
{
	static char msg[256];

	sprintf(msg, "[Error %d] %s", -err, strerror(-err));
	return msg;
}

#endif

