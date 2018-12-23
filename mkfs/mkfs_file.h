/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * mkfs_file.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __MKFS_FILE_H
#define __MKFS_FILE_H

#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include "list_head.h"
#include "mkfs_erofs.h"

#define FILE_TYPE_NONE (0)
#define FILE_TYPE_COMPR (1)
#define FILE_TYPE_MAX (2)

/*
 * Some micros for generic compress index conversion:
 * CIG: Compress Index Generic
 * D0: Delta0
 * D1: Delta1
 * LO: low 4 bits
 * HI: high 4 bits
 */
#define EROFS_CIG_D0_LO_MASK (0xF)
#define EROFS_CIG_D0_LO_SHL (12)
#define EROFS_CIG_D0_HI_MASK (0xF0)
#define EROFS_CIG_D0_HI_SHR (0)
#define EROFS_CIG_D1_SHIFT (8)

struct erofs_compr_idx {
	u16 di_advise;
	u16 di_clusterofs;
	u16 delta[2]; /* [0] - relative index to the 1st block */
	/* [1] - relative index to the last block */
	u32 blkaddr;
};

/* cc_nidxs == -1 means it is a inlined compress data */
#define EROFS_COMPR_CTX_INLINED_DATA (-1)

struct erofs_compr_ctx {
	char *cc_srcbuf;
	char *cc_dstbuf;
	u64 cc_pos;
	int cc_buflen;
	int cc_srclen;
	int cc_dstlen;
	struct erofs_compr_idx *cc_idxs;
	int cc_nidxs;
};

struct erofs_compr_info {
	struct erofs_compr_alg *ci_alg;
	int ci_lvl;
};

struct erofs_node_info;

struct erofs_node_info *alloc_erofs_node(void);
struct erofs_node_info *erofs_init_inode(char *full_path_name);
int list_add_sort(struct list_head *head, struct erofs_node_info *entry);
void dump_inode(struct erofs_inode_v1 *inode);
int erofs_create_files_list(struct erofs_node_info *entry);
u32 erofs_calc_inline_data_size(struct erofs_node_info *inode);
int erofs_check_compressible(struct erofs_node_info *inode);
int erofs_compress_file(struct erofs_node_info *inode);
void erofs_dump_compr_radio(void);
int erofs_init_compress_context(struct erofs_compr_ctx *ctx);
void erofs_deinit_compress_context(struct erofs_compr_ctx *ctx);
void erofs_reset_compress_context(struct erofs_compr_ctx *ctx);
#endif
