/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs_utils/include/erofs/fuzzer.h
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 */
#ifndef __EROFS_FUZZER_H
#define __EROFS_FUZZER_H

#include "internal.h"

void erofs_fuzz(void *buf, unsigned int length);

#endif

