/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */
#ifndef __EROFS_XXHASH_H
#define __EROFS_XXHASH_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

/**
 * xxh32() - calculate the 32-bit hash of the input with a given seed.
 *
 * @input:  The data to hash.
 * @length: The length of the data to hash.
 * @seed:   The seed can be used to alter the result predictably.
 *
 * Return:  The 32-bit hash of the data.
 */
uint32_t xxh32(const void *input, size_t length, uint32_t seed);

#ifdef __cplusplus
}
#endif

#endif
