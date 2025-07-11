/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2022 Alibaba Cloud
 */
#ifndef __EROFS_DEDUPE_H
#define __EROFS_DEDUPE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "internal.h"

struct z_erofs_inmem_extent {
	erofs_off_t pstart;
	unsigned int plen;
	unsigned int length;
	bool raw, partial, inlined;
};

struct z_erofs_dedupe_ctx {
	u8		*start, *end;
	u8		*cur;
	struct z_erofs_inmem_extent	e;
};

int z_erofs_dedupe_match(struct z_erofs_dedupe_ctx *ctx);
int z_erofs_dedupe_insert(struct z_erofs_inmem_extent *e,
			  void *original_data);
void z_erofs_dedupe_commit(bool drop);
int z_erofs_dedupe_init(unsigned int wsiz);
void z_erofs_dedupe_exit(void);

int z_erofs_dedupe_ext_insert(struct z_erofs_inmem_extent *e,
			      u64 hash);
erofs_off_t z_erofs_dedupe_ext_match(struct erofs_sb_info *sbi,
			u8 *encoded, unsigned int size, bool raw, u64 *hash);
void z_erofs_dedupe_ext_commit(bool drop);
int z_erofs_dedupe_ext_init(void);
void z_erofs_dedupe_ext_exit(void);

#ifdef __cplusplus
}
#endif

#endif
