/* SPDX-License-Identifier: GPL-2.0+ OR MIT */
/*
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_ERR_H
#define __EROFS_ERR_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#ifndef ENODATA
#define ENODATA ENOATTR
#endif

static inline const char *erofs_strerror(int err)
{
	static char msg[256];

	sprintf(msg, "[Error %d] %s", -err, strerror(-err));
	return msg;
}

#define MAX_ERRNO (4095)
#define IS_ERR_VALUE(x)                                                        \
	((uintptr_t)(void *)(x) >= (uintptr_t)-MAX_ERRNO)

static inline void *ERR_PTR(long error)
{
	return (void *)error;
}

static inline int IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((uintptr_t)ptr);
}

static inline long PTR_ERR(const void *ptr)
{
	return (intptr_t)ptr;
}

static inline void * ERR_CAST(const void *ptr)
{
	/* cast away the const */
	return (void *)ptr;
}

/* EROFS-specific error codes */
#define EROFS_RETVAL_FALLBACK		MAX_ERRNO

#ifdef __cplusplus
}
#endif

#endif
