/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2022 Alibaba Cloud
 */
#ifndef __ROLLING_HASH_H__
#define __ROLLING_HASH_H__

#include <erofs/defs.h>

#define PRIME_NUMBER	4294967295LL
#define RADIX		256

static inline long long erofs_rolling_hash_init(u8 *input,
						int len, bool backwards)
{
	long long hash = 0;

	if (!backwards) {
		int i;

		for (i = 0; i < len; ++i)
			hash = (RADIX * hash + input[i]) % PRIME_NUMBER;
	} else {
		while (len)
			hash = (RADIX * hash + input[--len]) % PRIME_NUMBER;
	}
	return hash;
}

/* RM = R ^ (M-1) % Q */
/*
 * NOTE: value of "hash" could be negative so we cannot use unsiged types for "hash"
 * "long long" is used here and PRIME_NUMBER can be ULONG_MAX
 */
static inline long long erofs_rolling_hash_advance(long long old_hash,
						   unsigned long long RM,
						   u8 to_remove, u8 to_add)
{
	long long hash = old_hash;
	long long to_remove_val = (to_remove * RM) % PRIME_NUMBER;

	hash = RADIX * (old_hash - to_remove_val) % PRIME_NUMBER;
	hash = (hash + to_add) % PRIME_NUMBER;

	/* We might get negative value of hash, converting it to positive */
	if (hash < 0)
		hash += PRIME_NUMBER;
	return hash;
}

static inline long long erofs_rollinghash_calc_rm(int window_size)
{
	int i;
	long long RM = 1;

	for (i = 0; i < window_size - 1; ++i)
		RM = (RM * RADIX) % PRIME_NUMBER;
	return RM;
}
#endif
