/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_PRINT_H
#define __EROFS_PRINT_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "config.h"
#include <stdio.h>

enum {
	EROFS_MSG_MIN = 0,
	EROFS_ERR     = 0,
	EROFS_WARN    = 2,
	EROFS_INFO    = 3,
	EROFS_DBG     = 7,
	EROFS_MSG_MAX = 9
};

#ifndef EROFS_MODNAME
#define EROFS_MODNAME	"erofs"
#endif
#define FUNC_LINE_FMT "%s() Line[%d] "

#ifdef NDEBUG
#ifndef pr_fmt
#define pr_fmt(fmt)	EROFS_MODNAME ": " fmt "\n"
#endif
#define PR_FMT_FUNC_LINE(fmt)	pr_fmt(fmt)
#else
#ifndef pr_fmt
#define pr_fmt(fmt)	EROFS_MODNAME ": " FUNC_LINE_FMT fmt "\n"
#endif
#define PR_FMT_FUNC_LINE(fmt)	pr_fmt(fmt), __func__, __LINE__
#endif

#define erofs_dbg(fmt, ...) do {			\
	if (cfg.c_dbg_lvl >= EROFS_DBG) {		\
		fprintf(stdout,				\
			"<D> " PR_FMT_FUNC_LINE(fmt),	\
			##__VA_ARGS__);			\
	}						\
} while (0)

#define erofs_info(fmt, ...) do {			\
	if (cfg.c_dbg_lvl >= EROFS_INFO) {		\
		fprintf(stdout,				\
			"<I> " PR_FMT_FUNC_LINE(fmt),	\
			##__VA_ARGS__);			\
		fflush(stdout);				\
	}						\
} while (0)

#define erofs_warn(fmt, ...) do {			\
	if (cfg.c_dbg_lvl >= EROFS_WARN) {		\
		fprintf(stdout,				\
			"<W> " PR_FMT_FUNC_LINE(fmt),	\
			##__VA_ARGS__);			\
		fflush(stdout);				\
	}						\
} while (0)

#define erofs_err(fmt, ...) do {			\
	if (cfg.c_dbg_lvl >= EROFS_ERR) {		\
		fprintf(stderr,				\
			"<E> " PR_FMT_FUNC_LINE(fmt),	\
			##__VA_ARGS__);			\
	}						\
} while (0)

#define erofs_dump(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
