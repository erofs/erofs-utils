/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C), 2022, Coolpad Group Limited.
 */
#ifndef __EROFS_FRAGMENTS_H
#define __EROFS_FRAGMENTS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "erofs/internal.h"

extern const char *frags_packedname;
#define EROFS_PACKED_INODE	frags_packedname

int z_erofs_pack_fragments(struct erofs_inode *inode, void *data,
			   unsigned int len);
struct erofs_inode *erofs_mkfs_build_fragments(void);
int erofs_fragments_init(void);
void erofs_fragments_exit(void);

#ifdef __cplusplus
}
#endif

#endif
