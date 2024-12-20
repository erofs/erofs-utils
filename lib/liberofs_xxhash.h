/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */
#ifndef __EROFS_LIB_XXHASH_H
#define __EROFS_LIB_XXHASH_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#ifdef HAVE_XXHASH_H
#include <xxhash.h>
#endif

#ifdef HAVE_XXHASH
static inline uint32_t xxh32(const void *input, size_t length, uint32_t seed)
{
	return XXH32(input, length, seed);
}

static inline uint64_t xxh64(const void *input, const size_t len, const uint64_t seed)
{
	return XXH64(input, len, seed);
}
#else
/*
 * xxh32() - calculate the 32-bit hash of the input with a given seed.
 *
 * @input:  The data to hash.
 * @length: The length of the data to hash.
 * @seed:   The seed can be used to alter the result predictably.
 *
 * Return:  The 32-bit hash of the data.
 */
uint32_t xxh32(const void *input, size_t length, uint32_t seed);

/*
 * xxh64() - calculate the 64-bit hash of the input with a given seed.
 *
 * @input:  The data to hash.
 * @length: The length of the data to hash.
 * @seed:   The seed can be used to alter the result predictably.
 *
 * This function runs 2x faster on 64-bit systems, but slower on 32-bit systems.
 *
 * Return:  The 64-bit hash of the data.
 */
uint64_t xxh64(const void *input, const size_t len, const uint64_t seed);
#endif

#ifdef __cplusplus
}
#endif

#endif
