/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_LIB_SHA256_H
#define __EROFS_LIB_SHA256_H

#include "erofs/defs.h"

struct sha256_state {
	u64 length;
	u32 state[8], curlen;
	u8 buf[64];
};

void erofs_sha256_init(struct sha256_state *md);
int erofs_sha256_process(struct sha256_state *md,
		const unsigned char *in, unsigned long inlen);
int erofs_sha256_done(struct sha256_state *md, unsigned char *out);

void erofs_sha256(const unsigned char *in, unsigned long in_size,
		  unsigned char out[32]);

#endif
