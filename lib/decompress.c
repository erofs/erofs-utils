// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/decompress.c
 *
 * Copyright (C), 2008-2020, OPPO Mobile Comm Corp., Ltd.
 * Created by Huang Jianan <huangjianan@oppo.com>
 */
#include <stdlib.h>

#include "erofs/decompress.h"
#include "erofs/err.h"

#ifdef LZ4_ENABLED
#include <lz4.h>

static int z_erofs_decompress_lz4(struct z_erofs_decompress_req *rq)
{
	int ret = 0;
	char *dest = rq->out;
	char *src = rq->in;
	char *buff = NULL;
	bool support_0padding = false;
	unsigned int inputmargin = 0;

	if (erofs_sb_has_lz4_0padding()) {
		support_0padding = true;

		while (!src[inputmargin & ~PAGE_MASK])
			if (!(++inputmargin & ~PAGE_MASK))
				break;

		if (inputmargin >= rq->inputsize)
			return -EIO;
	}

	if (rq->decodedskip) {
		buff = malloc(rq->decodedlength);
		if (!buff)
			return -ENOMEM;
		dest = buff;
	}

	if (rq->partial_decoding || !support_0padding)
		ret = LZ4_decompress_safe_partial(src + inputmargin, dest,
				rq->inputsize - inputmargin,
				rq->decodedlength, rq->decodedlength);
	else
		ret = LZ4_decompress_safe(src + inputmargin, dest,
					  rq->inputsize - inputmargin,
					  rq->decodedlength);

	if (ret != (int)rq->decodedlength) {
		ret = -EIO;
		goto out;
	}

	if (rq->decodedskip)
		memcpy(rq->out, dest + rq->decodedskip,
		       rq->decodedlength - rq->decodedskip);

out:
	if (buff)
		free(buff);

	return ret;
}
#endif

int z_erofs_decompress(struct z_erofs_decompress_req *rq)
{
	if (rq->alg == Z_EROFS_COMPRESSION_SHIFTED) {
		if (rq->inputsize != EROFS_BLKSIZ)
			return -EFSCORRUPTED;

		DBG_BUGON(rq->decodedlength > EROFS_BLKSIZ);
		DBG_BUGON(rq->decodedlength < rq->decodedskip);

		memcpy(rq->out, rq->in + rq->decodedskip,
		       rq->decodedlength - rq->decodedskip);
		return 0;
	}

#ifdef LZ4_ENABLED
	if (rq->alg == Z_EROFS_COMPRESSION_LZ4)
		return z_erofs_decompress_lz4(rq);
#endif
	return -EOPNOTSUPP;
}
