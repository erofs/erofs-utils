/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_utils/include/erofs/err.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_ERR_H
#define __EROFS_ERR_H

#include <errno.h>

#define MAX_ERRNO (4095)
#define IS_ERR_VALUE(x)                                                        \
	((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void *ERR_PTR(long error)
{
	return (void *)error;
}

static inline int IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

#endif

