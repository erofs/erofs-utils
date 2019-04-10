/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_utils/include/erofs/print.h
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_PRINT_H
#define __EROFS_PRINT_H

#include "config.h"
#include <stdio.h>

#define FUNC_LINE_FMT "%s() Line[%d] "

#ifndef pr_fmt
#define pr_fmt(fmt) "EROFS: " FUNC_LINE_FMT fmt "\n"
#endif

#define erofs_dbg(fmt, ...) do {				\
	if (cfg.c_dbg_lvl >= 7) {				\
		fprintf(stdout,					\
			pr_fmt(fmt),				\
			__func__,				\
			__LINE__,				\
			##__VA_ARGS__);				\
	}							\
} while (0)

#define erofs_info(fmt, ...) do {				\
	if (cfg.c_dbg_lvl >= 3) {				\
		fprintf(stdout,					\
			pr_fmt(fmt),				\
			__func__,				\
			__LINE__,				\
			##__VA_ARGS__);				\
		fflush(stdout);					\
	}							\
} while (0)

#define erofs_warn(fmt, ...) do {				\
	if (cfg.c_dbg_lvl >= 2) {				\
		fprintf(stdout,					\
			pr_fmt(fmt),				\
			__func__,				\
			__LINE__,				\
			##__VA_ARGS__);				\
		fflush(stdout);					\
	}							\
} while (0)

#define erofs_err(fmt, ...) do {				\
	if (cfg.c_dbg_lvl >= 0) {				\
		fprintf(stderr,					\
			"Err: " pr_fmt(fmt),			\
			__func__,				\
			__LINE__,				\
			##__VA_ARGS__);				\
	}							\
} while (0)

#define erofs_dump(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)


#endif

