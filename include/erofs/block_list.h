/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C), 2021, Coolpad Group Limited.
 * Created by Yue Hu <huyue2@yulong.com>
 */
#ifndef __EROFS_BLOCK_LIST_H
#define __EROFS_BLOCK_LIST_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "internal.h"

int erofs_blocklist_open(FILE *fp, bool srcmap);
FILE *erofs_blocklist_close(void);

void tarerofs_blocklist_write(erofs_blk_t blkaddr, erofs_blk_t nblocks,
			      erofs_off_t srcoff, unsigned int zeroedlen);
#ifdef __cplusplus
}
#endif

#endif
