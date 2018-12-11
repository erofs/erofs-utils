/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_types.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_TYPES_H
#define __EROFS_TYPES_H
#include <inttypes.h>
#include <endian.h>
#include <linux/types.h>
#include <sys/types.h>
#include <asm/types.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <assert.h>
#include <bits/byteswap.h>

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define s8  int8_t
#define s16 int16_t
#define s32 int32_t
#define s64 int64_t

#if __BYTE_ORDER == __LITTLE_ENDIAN
/*
 * The host byte order is the same as network byte order,
 * so these functions are all just identity.
 */
#define cpu_to_le16(x) ((__u16)(x))
#define cpu_to_le32(x) ((__u32)(x))
#define cpu_to_le64(x) ((__u64)(x))
#define le16_to_cpu(x) ((__u16)(x))
#define le32_to_cpu(x) ((__u32)(x))
#define le64_to_cpu(x) ((__u64)(x))

#else
#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le16(x) (__builtin_bswap16(x))
#define cpu_to_le32(x) (__builtin_bswap32(x))
#define cpu_to_le64(x) (__builtin_bswap64(x))
#define le16_to_cpu(x) (__builtin_bswap16(x))
#define le32_to_cpu(x) (__builtin_bswap32(x))
#define le64_to_cpu(x) (__builtin_bswap64(x))
#else
#pragma error
#endif
#endif

#ifndef __OPTIMIZE__
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2 * !!(condition)]))
#else
#define BUILD_BUG_ON(condition) assert(condition)
#endif

#define BIT(nr)             (1UL << (nr))
#define BIT_ULL(nr)         (1ULL << (nr))
#define BIT_MASK(nr)        (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)        ((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)    (1ULL << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)    ((nr) / BITS_PER_LONG_LONG)
#define BITS_PER_BYTE       8
#define BITS_TO_LONGS(nr)   DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#endif
