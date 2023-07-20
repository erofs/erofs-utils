// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C), 2008-2020, OPPO Mobile Comm Corp., Ltd.
 * Created by Huang Jianan <huangjianan@oppo.com>
 */
#include <stdlib.h>

#include "erofs/decompress.h"
#include "erofs/err.h"
#include "erofs/print.h"

#ifdef HAVE_LIBDEFLATE
/* if libdeflate is available, use libdeflate instead. */
#include <libdeflate.h>

static int z_erofs_decompress_deflate(struct z_erofs_decompress_req *rq)
{
	struct erofs_sb_info *sbi = rq->sbi;
	u8 *dest = (u8 *)rq->out;
	u8 *src = (u8 *)rq->in;
	u8 *buff = NULL;
	size_t actual_out;
	unsigned int inputmargin = 0;
	struct libdeflate_decompressor *inf;
	enum libdeflate_result ret;

	while (!src[inputmargin & (erofs_blksiz(sbi) - 1)])
		if (!(++inputmargin & (erofs_blksiz(sbi) - 1)))
			break;

	if (inputmargin >= rq->inputsize)
		return -EFSCORRUPTED;

	if (rq->decodedskip) {
		buff = malloc(rq->decodedlength);
		if (!buff)
			return -ENOMEM;
		dest = buff;
	}

	inf = libdeflate_alloc_decompressor();
	if (!inf)
		return -ENOMEM;

	if (rq->partial_decoding) {
		ret = libdeflate_deflate_decompress(inf, src + inputmargin,
				rq->inputsize - inputmargin, dest,
				rq->decodedlength, &actual_out);
		if (ret && ret != LIBDEFLATE_INSUFFICIENT_SPACE) {
			ret = -EIO;
			goto out_inflate_end;
		}

		if (actual_out != rq->decodedlength) {
			ret = -EIO;
			goto out_inflate_end;
		}
	} else {
		ret = libdeflate_deflate_decompress(inf, src + inputmargin,
				rq->inputsize - inputmargin, dest,
				rq->decodedlength, NULL);
		if (ret) {
			ret = -EIO;
			goto out_inflate_end;
		}
	}

	if (rq->decodedskip)
		memcpy(rq->out, dest + rq->decodedskip,
		       rq->decodedlength - rq->decodedskip);

out_inflate_end:
	libdeflate_free_decompressor(inf);
	if (buff)
		free(buff);
	return ret;
}
#elif defined(HAVE_ZLIB)
#include <zlib.h>

/* report a zlib or i/o error */
static int zerr(int ret)
{
	switch (ret) {
	case Z_STREAM_ERROR:
		return -EINVAL;
	case Z_DATA_ERROR:
		return -EIO;
	case Z_MEM_ERROR:
		return -ENOMEM;
	case Z_ERRNO:
	case Z_VERSION_ERROR:
	default:
		return -EFAULT;
	}
}

static int z_erofs_decompress_deflate(struct z_erofs_decompress_req *rq)
{
	struct erofs_sb_info *sbi = rq->sbi;
	u8 *dest = (u8 *)rq->out;
	u8 *src = (u8 *)rq->in;
	u8 *buff = NULL;
	unsigned int inputmargin = 0;
	z_stream strm;
	int ret;

	while (!src[inputmargin & (erofs_blksiz(sbi) - 1)])
		if (!(++inputmargin & (erofs_blksiz(sbi) - 1)))
			break;

	if (inputmargin >= rq->inputsize)
		return -EFSCORRUPTED;

	if (rq->decodedskip) {
		buff = malloc(rq->decodedlength);
		if (!buff)
			return -ENOMEM;
		dest = buff;
	}

	/* allocate inflate state */
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;
	ret = inflateInit2(&strm, -15);
	if (ret != Z_OK)
		return zerr(ret);

	strm.next_in = src + inputmargin;
	strm.avail_in = rq->inputsize - inputmargin;
	strm.next_out = dest;
	strm.avail_out = rq->decodedlength;

	ret = inflate(&strm, rq->partial_decoding ? Z_SYNC_FLUSH : Z_FINISH);
	if (ret != Z_STREAM_END || strm.total_out != rq->decodedlength) {
		if (ret != Z_OK || !rq->partial_decoding) {
			ret = zerr(ret);
			goto out_inflate_end;
		}
	}

	if (rq->decodedskip)
		memcpy(rq->out, dest + rq->decodedskip,
		       rq->decodedlength - rq->decodedskip);

out_inflate_end:
	inflateEnd(&strm);
	if (buff)
		free(buff);
	return ret;
}
#endif

#ifdef HAVE_LIBLZMA
#include <lzma.h>

static int z_erofs_decompress_lzma(struct z_erofs_decompress_req *rq)
{
	int ret = 0;
	struct erofs_sb_info *sbi = rq->sbi;
	u8 *dest = (u8 *)rq->out;
	u8 *src = (u8 *)rq->in;
	u8 *buff = NULL;
	unsigned int inputmargin = 0;
	lzma_stream strm;
	lzma_ret ret2;

	while (!src[inputmargin & (erofs_blksiz(sbi) - 1)])
		if (!(++inputmargin & (erofs_blksiz(sbi) - 1)))
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
	struct erofs_sb_info *sbi = rq->sbi;

	if (erofs_sb_has_lz4_0padding(sbi)) {
		support_0padding = true;

		while (!src[inputmargin & (erofs_blksiz(sbi) - 1)])
			if (!(++inputmargin & (erofs_blksiz(sbi) - 1)))
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
		erofs_err("failed to %s decompress %d in[%u, %u] out[%u]",
			  rq->partial_decoding ? "partial" : "full",
			  ret, rq->inputsize, inputmargin, rq->decodedlength);
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
	struct erofs_sb_info *sbi = rq->sbi;

	if (rq->alg == Z_EROFS_COMPRESSION_INTERLACED) {
		unsigned int count, rightpart, skip;

		/* XXX: should support inputsize >= erofs_blksiz(sbi) later */
		if (rq->inputsize > erofs_blksiz(sbi))
			return -EFSCORRUPTED;

		if (rq->decodedlength > erofs_blksiz(sbi))
			return -EFSCORRUPTED;

		if (rq->decodedlength < rq->decodedskip)
			return -EFSCORRUPTED;

		count = rq->decodedlength - rq->decodedskip;
		skip = erofs_blkoff(sbi, rq->interlaced_offset + rq->decodedskip);
		rightpart = min(erofs_blksiz(sbi) - skip, count);
		memcpy(rq->out, rq->in + skip, rightpart);
		memcpy(rq->out + rightpart, rq->in, count - rightpart);
		return 0;
	} else if (rq->alg == Z_EROFS_COMPRESSION_SHIFTED) {
		if (rq->decodedlength > rq->inputsize)
			return -EFSCORRUPTED;

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
#if defined(HAVE_ZLIB) || defined(HAVE_LIBDEFLATE)
	if (rq->alg == Z_EROFS_COMPRESSION_DEFLATE)
		return z_erofs_decompress_deflate(rq);
#endif
	return -EOPNOTSUPP;
}
