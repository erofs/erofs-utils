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

extern const char *erofs_frags_packedname;
#define EROFS_PACKED_INODE	erofs_frags_packedname

FILE *erofs_packedfile_init(void);
void erofs_packedfile_exit(void);
struct erofs_inode *erofs_mkfs_build_packedfile(void);

int z_erofs_fragments_dedupe(struct erofs_inode *inode, int fd, u32 *tofcrc);
int z_erofs_pack_file_from_fd(struct erofs_inode *inode, int fd, u32 tofcrc);
int z_erofs_pack_fragments(struct erofs_inode *inode, void *data,
			   unsigned int len, u32 tofcrc);
void z_erofs_fragments_commit(struct erofs_inode *inode);
int z_erofs_fragments_init(void);
void z_erofs_fragments_exit(void);

#ifdef __cplusplus
}
#endif

#endif
