// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C), 2008-2020, OPPO Mobile Comm Corp., Ltd.
 * Created by Huang Jianan <huangjianan@oppo.com>
 */
#include <stdlib.h>

#include "erofs/decompress.h"
#include "erofs/err.h"
#include "erofs/print.h"

#ifdef HAVE_LIBLZMA
#include <lzma.h>

static int z_erofs_decompress_lzma(struct z_erofs_decompress_req *rq)
{
	int ret = 0;
	u8 *dest = (u8 *)rq->out;
	u8 *src = (u8 *)rq->in;
	u8 *buff = NULL;
	unsigned int inputmargin = 0;
	lzma_stream strm;
	lzma_ret ret2;

	while (!src[inputmargin & ~PAGE_MASK])
		if (!(++inputmargin & ~PAGE_MASK))
			break;

	if (inputmargin >= rq->inputsize)
		return -EFSCORRUPTED;

	if (rq->decodedskip) {
		buff = malloc(rq->decodedlength);
		if (!buff)
			return -ENOMEM;
		dest = buff;
	}

	strm = (lzma_stream)LZMA_STREAM_INIT;
	strm.next_in = src + inputmargin;
	strm.avail_in = rq->inputsize - inputmargin;
	strm.next_out = dest;
	strm.avail_out = rq->decodedlength;

	ret2 = lzma_microlzma_decoder(&strm, strm.avail_in, rq->decodedlength,
				      !rq->partial_decoding,
				      Z_EROFS_LZMA_MAX_DICT_SIZE);
	if (ret2 != LZMA_OK) {
		erofs_err("fail to initialize lzma decoder %u", ret2 | 0U);
		ret = -EFAULT;
		goto out;
	}

	ret2 = lzma_code(&strm, LZMA_FINISH);
	if (ret2 != LZMA_STREAM_END) {
		ret = -EFSCORRUPTED;
		goto out_lzma_end;
	}

	if (rq->decodedskip)
		memcpy(rq->out, dest + rq->decodedskip,
		       rq->decodedlength - rq->decodedskip);

out_lzma_end:
	lzma_end(&strm);
out:
	if (buff)
		free(buff);
	return ret;
}
#endif

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
#ifdef HAVE_LIBLZMA
	if (rq->alg == Z_EROFS_COMPRESSION_LZMA)
		return z_erofs_decompress_lzma(rq);
#endif
	return -EOPNOTSUPP;
}
