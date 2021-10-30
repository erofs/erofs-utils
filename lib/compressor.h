/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <gaoxiang25@huawei.com>
 */
#ifndef __EROFS_LIB_COMPRESSOR_H
#define __EROFS_LIB_COMPRESSOR_H

#include "erofs/defs.h"

struct erofs_compress;

struct erofs_compressor {
	const char *name;

	int default_level;
	int best_level;

	int (*init)(struct erofs_compress *c);
	int (*exit)(struct erofs_compress *c);
	int (*setlevel)(struct erofs_compress *c, int compression_level);

	int (*compress_destsize)(struct erofs_compress *c,
				 void *src, unsigned int *srcsize,
				 void *dst, unsigned int dstsize);
};

struct erofs_compress {
	struct erofs_compressor *alg;

	unsigned int compress_threshold;
	unsigned int compression_level;

	/* *_destsize specific */
	unsigned int destsize_alignsize;
	unsigned int destsize_redzone_begin;
	unsigned int destsize_redzone_end;

	void *private_data;
};

/* list of compression algorithms */
extern struct erofs_compressor erofs_compressor_lz4;
extern struct erofs_compressor erofs_compressor_lz4hc;
extern struct erofs_compressor erofs_compressor_lzma;

int erofs_compress_destsize(struct erofs_compress *c,
			    void *src, unsigned int *srcsize,
			    void *dst, unsigned int dstsize);

int erofs_compressor_setlevel(struct erofs_compress *c, int compression_level);
int erofs_compressor_init(struct erofs_compress *c, char *alg_name);
int erofs_compressor_exit(struct erofs_compress *c);

#endif
