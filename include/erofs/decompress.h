/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs-utils/include/erofs/decompress.h
 *
 * Copyright (C), 2008-2020, OPPO Mobile Comm Corp., Ltd.
 * Created by Huang Jianan <huangjianan@oppo.com>
 */
#ifndef __EROFS_DECOMPRESS_H
#define __EROFS_DECOMPRESS_H

#include "internal.h"

enum {
	Z_EROFS_COMPRESSION_SHIFTED = Z_EROFS_COMPRESSION_MAX,
	Z_EROFS_COMPRESSION_RUNTIME_MAX
};

struct z_erofs_decompress_req {
	char *in, *out;

	/*
	 * initial decompressed bytes that need to be skipped
	 * when finally copying to output buffer
	 */
	unsigned int decodedskip;
	unsigned int inputsize, decodedlength;

	/* indicate the algorithm will be used for decompression */
	unsigned int alg;
	bool partial_decoding;
};

int z_erofs_decompress(struct z_erofs_decompress_req *rq);

#endif
