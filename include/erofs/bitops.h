/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_BITOPS_H
#define __EROFS_BITOPS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "defs.h"

static inline void __erofs_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p  |= mask;
}

static inline void __erofs_clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p &= ~mask;
}

static inline int __erofs_test_bit(int nr, const volatile unsigned long *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

unsigned long erofs_find_next_bit(const unsigned long *addr,
				  unsigned long nbits, unsigned long start);

#ifdef __cplusplus
}
#endif

#endif
