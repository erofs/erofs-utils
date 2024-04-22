/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2024 Alibaba Cloud
 */
#ifndef __EROFS_ATOMIC_H
#define __EROFS_ATOMIC_H

/*
 * Just use GCC/clang built-in functions for now
 * See: https://gcc.gnu.org/onlinedocs/gcc/_005f_005fatomic-Builtins.html
 */
typedef unsigned long erofs_atomic_t;
typedef char erofs_atomic_bool_t;

#define erofs_atomic_read(ptr) ({ \
	typeof(*ptr) __n;    \
	__atomic_load(ptr, &__n, __ATOMIC_RELAXED); \
__n;})

#define erofs_atomic_set(ptr, n) do { \
	typeof(*ptr) __n = (n);    \
	__atomic_store(ptr, &__n, __ATOMIC_RELAXED); \
} while(0)

#define erofs_atomic_test_and_set(ptr) \
	__atomic_test_and_set(ptr, __ATOMIC_RELAXED)

#define erofs_atomic_add_return(ptr, i) \
	__atomic_add_fetch(ptr, i, __ATOMIC_RELAXED)

#define erofs_atomic_sub_return(ptr, i) \
	__atomic_sub_fetch(ptr, i, __ATOMIC_RELAXED)

#define erofs_atomic_inc_return(ptr) erofs_atomic_add_return(ptr, 1)

#define erofs_atomic_dec_return(ptr) erofs_atomic_sub_return(ptr, 1)

#endif
