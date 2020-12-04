/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs-utils/include/erofs/internal.h
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

#ifndef PAGE_SHIFT
#define PAGE_SHIFT		(12)
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE		(1U << PAGE_SHIFT)
#endif

/* no obvious reason to support explicit PAGE_SIZE != 4096 for now */
#if PAGE_SIZE != 4096
#error incompatible PAGE_SIZE is already defined
#endif

#define PAGE_MASK		(~(PAGE_SIZE-1))

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
	u64 blocks;

	erofs_blk_t meta_blkaddr;
	erofs_blk_t xattr_blkaddr;

	u32 feature_compat;
	u32 feature_incompat;
	u64 build_time;
	u32 build_time_nsec;

	unsigned char islotbits;

	/* what we really care is nid, rather than ino.. */
	erofs_nid_t root_nid;
	/* used for statfs, f_files - f_favail */
	u64 inos;

	u8 uuid[16];
};

/* global sbi */
extern struct erofs_sb_info sbi;

static inline erofs_off_t iloc(erofs_nid_t nid)
{
	return blknr_to_addr(sbi.meta_blkaddr) + (nid << sbi.islotbits);
}

#define EROFS_FEATURE_FUNCS(name, compat, feature) \
static inline bool erofs_sb_has_##name(void) \
{ \
	return sbi.feature_##compat & EROFS_FEATURE_##feature; \
} \
static inline void erofs_sb_set_##name(void) \
{ \
	sbi.feature_##compat |= EROFS_FEATURE_##feature; \
} \
static inline void erofs_sb_clear_##name(void) \
{ \
	sbi.feature_##compat &= ~EROFS_FEATURE_##feature; \
}

EROFS_FEATURE_FUNCS(lz4_0padding, incompat, INCOMPAT_LZ4_0PADDING)
EROFS_FEATURE_FUNCS(sb_chksum, compat, COMPAT_SB_CHKSUM)

#define EROFS_I_EA_INITED	(1 << 0)
#define EROFS_I_Z_INITED	(1 << 1)

struct erofs_inode {
	struct list_head i_hash, i_subdirs, i_xattrs;

	union {
		/* (erofsfuse) runtime flags */
		unsigned int flags;
		/* (mkfs.erofs) device ID containing source file */
		u32 dev;
	};
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

	unsigned char datalayout;
	unsigned char inode_isize;
	/* inline tail-end packing size */
	unsigned short idata_size;

	unsigned int xattr_isize;
	unsigned int extent_isize;

	erofs_nid_t nid;
	struct erofs_buffer_head *bh;
	struct erofs_buffer_head *bh_inline, *bh_data;

	void *idata;

	union {
		void *compressmeta;
		struct {
			uint16_t z_advise;
			uint8_t  z_algorithmtype[2];
			uint8_t  z_logical_clusterbits;
			uint8_t  z_physical_clusterbits[2];
		};
	};
#ifdef WITH_ANDROID
	uint64_t capabilities;
#endif
};

static inline bool is_inode_layout_compression(struct erofs_inode *inode)
{
	return erofs_inode_is_data_compressed(inode->datalayout);
}

static inline unsigned int erofs_bitrange(unsigned int value, unsigned int bit,
					  unsigned int bits)
{
	return (value >> bit) & ((1 << bits) - 1);
}

static inline unsigned int erofs_inode_version(unsigned int value)
{
	return erofs_bitrange(value, EROFS_I_VERSION_BIT,
			      EROFS_I_VERSION_BITS);
}

static inline unsigned int erofs_inode_datalayout(unsigned int value)
{
	return erofs_bitrange(value, EROFS_I_DATALAYOUT_BIT,
			      EROFS_I_DATALAYOUT_BITS);
}

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

enum {
	BH_Meta,
	BH_Mapped,
	BH_Zipped,
	BH_FullMapped,
};

/* Has a disk mapping */
#define EROFS_MAP_MAPPED	(1 << BH_Mapped)
/* Located in metadata (could be copied from bd_inode) */
#define EROFS_MAP_META		(1 << BH_Meta)
/* The extent has been compressed */
#define EROFS_MAP_ZIPPED	(1 << BH_Zipped)
/* The length of extent is full */
#define EROFS_MAP_FULL_MAPPED	(1 << BH_FullMapped)

struct erofs_map_blocks {
	char mpage[EROFS_BLKSIZ];

	erofs_off_t m_pa, m_la;
	u64 m_plen, m_llen;

	unsigned int m_flags;
	erofs_blk_t index;
};

/* super.c */
int erofs_read_superblock(void);

/* namei.c */
int erofs_ilookup(const char *path, struct erofs_inode *vi);

/* data.c */
int erofs_pread(struct erofs_inode *inode, char *buf,
		erofs_off_t count, erofs_off_t offset);
/* zmap.c */
int z_erofs_fill_inode(struct erofs_inode *vi);
int z_erofs_map_blocks_iter(struct erofs_inode *vi,
			    struct erofs_map_blocks *map);

#define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */

#endif

