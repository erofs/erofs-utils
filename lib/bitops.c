// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * erofs-utils/lib/bitops.c
 *
 * Copyright (C) 2025, Alibaba Cloud
 */
#include <erofs/bitops.h>

unsigned long erofs_find_next_bit(const unsigned long *addr,
				  unsigned long nbits, unsigned long start)
{
	unsigned long tmp;

	if (__erofs_unlikely(start >= nbits))
		return nbits;

	tmp = addr[start / BITS_PER_LONG];

	tmp &= ~0UL << ((start) & (BITS_PER_LONG - 1));
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr[start / BITS_PER_LONG];
	}
	return min(start + ffs_long(tmp), nbits);
}
