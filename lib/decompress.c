// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C), 2008-2020, OPPO Mobile Comm Corp., Ltd.
 * Created by Huang Jianan <huangjianan@oppo.com>
 */
#include <stdlib.h>

#include "erofs/decompress.h"
#include "erofs/err.h"
#include "erofs/print.h"

static unsigned int z_erofs_fixup_insize(const u8 *padbuf, unsigned int padbufsize)
{
	unsigned int inputmargin;

	for (inputmargin = 0; inputmargin < padbufsize &&
	     !padbuf[inputmargin]; ++inputmargin);
	return inputmargin;
}

#ifdef HAVE_LIBZSTD
#include <zstd.h>
#include <zstd_errors.h>

/* also a very preliminary userspace version */
static int z_erofs_decompress_zstd(struct z_erofs_decompress_req *rq)
{
	int ret = 0;
	char *dest = rq->out;
	char *src = rq->in;
	char *buff = NULL;
	unsigned int inputmargin = 0;
	unsigned long long total;

	inputmargin = z_erofs_fixup_insize((u8 *)src, rq->inputsize);
	if (inputmargin >= rq->inputsize)
		return -EFSCORRUPTED;

#ifdef HAVE_ZSTD_GETFRAMECONTENTSIZE
	total = ZSTD_getFrameContentSize(src + inputmargin,
					 rq->inputsize - inputmargin);
	if (total == ZSTD_CONTENTSIZE_UNKNOWN ||
	    total == ZSTD_CONTENTSIZE_ERROR)
		return -EFSCORRUPTED;
#else
	total = ZSTD_getDecompressedSize(src + inputmargin,
					 rq->inputsize - inputmargin);
#endif
	if (rq->decodedskip || total != rq->decodedlength) {
		buff = malloc(total);
		if (!buff)
			return -ENOMEM;
		dest = buff;
	}

	ret = ZSTD_decompress(dest, total,
			      src + inputmargin, rq->inputsize - inputmargin);
	if (ZSTD_isError(ret)) {
		erofs_err("ZSTD decompress failed %d: %s", ZSTD_getErrorCode(ret),
			  ZSTD_getErrorName(ret));
		ret = -EIO;
		goto out;
	}

	if (ret != (int)total) {
		erofs_err("ZSTD decompress length mismatch %d, expected %d",
			  ret, total);
		goto out;
	}
	if (rq->decodedskip || total != rq->decodedlength)
		memcpy(rq->out, dest + rq->decodedskip,
		       rq->decodedlength - rq->decodedskip);
out:
	if (buff)
		free(buff);
	return ret;
}
#endif

#ifdef HAVE_QPL
#include <qpl/qpl.h>

struct z_erofs_qpl_job {
	struct z_erofs_qpl_job *next;
	u8 job[];
};
static struct z_erofs_qpl_job *z_erofs_qpl_jobs;
static unsigned int z_erofs_qpl_reclaim_quot;
#ifdef HAVE_PTHREAD_H
static pthread_mutex_t z_erofs_qpl_mutex;
#endif

int z_erofs_load_deflate_config(struct erofs_sb_info *sbi,
				struct erofs_super_block *dsb, void *data, int size)
{
	struct z_erofs_deflate_cfgs *dfl = data;
	static erofs_atomic_bool_t inited;

	if (!dfl || size < sizeof(struct z_erofs_deflate_cfgs)) {
		erofs_err("invalid deflate cfgs, size=%u", size);
		return -EINVAL;
	}

	/*
	 * In Intel QPL, decompression is supported for DEFLATE streams where
	 * the size of the history buffer is no more than 4 KiB, otherwise
	 * QPL_STS_BAD_DIST_ERR code is returned.
	 */
	sbi->useqpl = (dfl->windowbits <= 12);
	if (sbi->useqpl) {
		if (!erofs_atomic_test_and_set(&inited))
			z_erofs_qpl_reclaim_quot = erofs_get_available_processors();
		erofs_info("Intel QPL will be used for DEFLATE decompression");
	}
	return 0;
}

static qpl_job *z_erofs_qpl_get_job(void)
{
	qpl_path_t execution_path = qpl_path_auto;
	struct z_erofs_qpl_job *job;
	int32_t jobsize = 0;
	qpl_status status;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_lock(&z_erofs_qpl_mutex);
#endif
	job = z_erofs_qpl_jobs;
	if (job)
		z_erofs_qpl_jobs = job->next;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_unlock(&z_erofs_qpl_mutex);
#endif

	if (!job) {
		status = qpl_get_job_size(execution_path, &jobsize);
		if (status != QPL_STS_OK) {
			erofs_err("failed to get job size: %d", status);
			return ERR_PTR(-EOPNOTSUPP);
		}

		job = malloc(jobsize + sizeof(struct z_erofs_qpl_job));
		if (!job)
			return ERR_PTR(-ENOMEM);

		status = qpl_init_job(execution_path, (qpl_job *)job->job);
		if (status != QPL_STS_OK) {
			erofs_err("failed to initialize job: %d", status);
			return ERR_PTR(-EOPNOTSUPP);
		}
		erofs_atomic_dec_return(&z_erofs_qpl_reclaim_quot);
	}
	return (qpl_job *)job->job;
}

static bool z_erofs_qpl_put_job(qpl_job *qjob)
{
	struct z_erofs_qpl_job *job =
		container_of((void *)qjob, struct z_erofs_qpl_job, job);

	if (erofs_atomic_inc_return(&z_erofs_qpl_reclaim_quot) <= 0) {
		qpl_status status = qpl_fini_job(qjob);

		free(job);
		if (status != QPL_STS_OK)
			erofs_err("failed to finalize job: %d", status);
		return status == QPL_STS_OK;
	}
#ifdef HAVE_PTHREAD_H
	pthread_mutex_lock(&z_erofs_qpl_mutex);
#endif
	job->next = z_erofs_qpl_jobs;
	z_erofs_qpl_jobs = job;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_unlock(&z_erofs_qpl_mutex);
#endif
	return true;
}

static int z_erofs_decompress_qpl(struct z_erofs_decompress_req *rq)
{
	u8 *dest = (u8 *)rq->out;
	u8 *src = (u8 *)rq->in;
	u8 *buff = NULL;
	unsigned int inputmargin;
	qpl_status status;
	qpl_job *job;
	int ret;

	job = z_erofs_qpl_get_job();
	if (IS_ERR(job))
		return PTR_ERR(job);

	inputmargin = z_erofs_fixup_insize(src, rq->inputsize);
	if (inputmargin >= rq->inputsize)
		return -EFSCORRUPTED;

	if (rq->decodedskip) {
		buff = malloc(rq->decodedlength);
		if (!buff)
			return -ENOMEM;
		dest = buff;
	}

	job->op            = qpl_op_decompress;
	job->next_in_ptr   = src + inputmargin;
	job->next_out_ptr  = dest;
	job->available_in  = rq->inputsize - inputmargin;
	job->available_out = rq->decodedlength;
	job->flags         = QPL_FLAG_FIRST | QPL_FLAG_LAST;
	status = qpl_execute_job(job);
	if (status != QPL_STS_OK) {
		erofs_err("failed to decompress: %d", status);
		ret = -EIO;
		goto out_inflate_end;
	}

	if (rq->decodedskip)
		memcpy(rq->out, dest + rq->decodedskip,
		       rq->decodedlength - rq->decodedskip);
	ret = 0;
out_inflate_end:
	if (!z_erofs_qpl_put_job(job))
		ret = -EFAULT;
	if (buff)
		free(buff);
	return ret;
}
#else
int z_erofs_load_deflate_config(struct erofs_sb_info *sbi,
				struct erofs_super_block *dsb, void *data, int size)
{
	return 0;
}
#endif

#ifdef HAVE_LIBDEFLATE
/* if libdeflate is available, use libdeflate instead. */
#include <libdeflate.h>

static int z_erofs_decompress_deflate(struct z_erofs_decompress_req *rq)
{
	u8 *dest = (u8 *)rq->out;
	u8 *src = (u8 *)rq->in;
	u8 *buff = NULL;
	size_t actual_out;
	unsigned int inputmargin;
	struct libdeflate_decompressor *inf;
	enum libdeflate_result ret;
	unsigned int decodedcapacity;

	inputmargin = z_erofs_fixup_insize(src, rq->inputsize);
	if (inputmargin >= rq->inputsize)
		return -EFSCORRUPTED;

	decodedcapacity = rq->decodedlength << (4 * rq->partial_decoding);
	if (rq->decodedskip || rq->partial_decoding) {
		buff = malloc(decodedcapacity);
		if (!buff)
			return -ENOMEM;
		dest = buff;
	}

	inf = libdeflate_alloc_decompressor();
	if (!inf) {
		ret = -ENOMEM;
		goto out_free_mem;
	}

	if (rq->partial_decoding) {
		while (1) {
			ret = libdeflate_deflate_decompress(inf, src + inputmargin,
					rq->inputsize - inputmargin, dest,
					decodedcapacity, &actual_out);
			if (ret == LIBDEFLATE_SUCCESS)
				break;
			if (ret != LIBDEFLATE_INSUFFICIENT_SPACE) {
				ret = -EIO;
				goto out_inflate_end;
			}
			decodedcapacity = decodedcapacity << 1;
			dest = realloc(buff, decodedcapacity);
			if (!dest) {
				ret = -ENOMEM;
				goto out_inflate_end;
			}
			buff = dest;
		}

		if (actual_out < rq->decodedlength) {
			ret = -EIO;
			goto out_inflate_end;
		}
	} else {
		ret = libdeflate_deflate_decompress(inf, src + inputmargin,
				rq->inputsize - inputmargin, dest,
				rq->decodedlength, NULL);
		if (ret != LIBDEFLATE_SUCCESS) {
			ret = -EIO;
			goto out_inflate_end;
		}
	}

	if (rq->decodedskip || rq->partial_decoding)
		memcpy(rq->out, dest + rq->decodedskip,
		       rq->decodedlength - rq->decodedskip);

out_inflate_end:
	libdeflate_free_decompressor(inf);
out_free_mem:
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
	u8 *dest = (u8 *)rq->out;
	u8 *src = (u8 *)rq->in;
	u8 *buff = NULL;
	unsigned int inputmargin;
	z_stream strm;
	int ret;

	inputmargin = z_erofs_fixup_insize(src, rq->inputsize);
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
	if (ret != Z_OK) {
		free(buff);
		return zerr(ret);
	}

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
	u8 *dest = (u8 *)rq->out;
	u8 *src = (u8 *)rq->in;
	u8 *buff = NULL;
	unsigned int inputmargin;
	lzma_stream strm;
	lzma_ret ret2;

	inputmargin = z_erofs_fixup_insize(src, rq->inputsize);
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

		inputmargin = z_erofs_fixup_insize((u8 *)src, rq->inputsize);
		if (inputmargin >= rq->inputsize)
			return -EFSCORRUPTED;
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
#ifdef HAVE_QPL
	if (rq->alg == Z_EROFS_COMPRESSION_DEFLATE && rq->sbi->useqpl)
		if (!z_erofs_decompress_qpl(rq))
			return 0;
#endif
#if defined(HAVE_ZLIB) || defined(HAVE_LIBDEFLATE)
	if (rq->alg == Z_EROFS_COMPRESSION_DEFLATE)
		return z_erofs_decompress_deflate(rq);
#endif
#ifdef HAVE_LIBZSTD
	if (rq->alg == Z_EROFS_COMPRESSION_ZSTD)
		return z_erofs_decompress_zstd(rq);
#endif
	return -EOPNOTSUPP;
}

static int z_erofs_load_lz4_config(struct erofs_sb_info *sbi,
			    struct erofs_super_block *dsb, void *data, int size)
{
	struct z_erofs_lz4_cfgs *lz4 = data;
	u16 distance;

	if (lz4) {
		if (size < sizeof(struct z_erofs_lz4_cfgs)) {
			erofs_err("invalid lz4 cfgs, size=%u", size);
			return -EINVAL;
		}
		distance = le16_to_cpu(lz4->max_distance);

		sbi->lz4.max_pclusterblks = le16_to_cpu(lz4->max_pclusterblks);
		if (!sbi->lz4.max_pclusterblks)
			sbi->lz4.max_pclusterblks = 1;	/* reserved case */
	} else {
		distance = le16_to_cpu(dsb->u1.lz4_max_distance);
		sbi->lz4.max_pclusterblks = 1;
	}
	sbi->lz4.max_distance = distance;
	return 0;
}

int z_erofs_parse_cfgs(struct erofs_sb_info *sbi, struct erofs_super_block *dsb)
{
	unsigned int algs, alg;
	erofs_off_t offset;
	int size, ret = 0;

	if (!erofs_sb_has_compr_cfgs(sbi)) {
		sbi->available_compr_algs = 1 << Z_EROFS_COMPRESSION_LZ4;
		return z_erofs_load_lz4_config(sbi, dsb, NULL, 0);
	}

	sbi->available_compr_algs = le16_to_cpu(dsb->u1.available_compr_algs);
	if (sbi->available_compr_algs & ~Z_EROFS_ALL_COMPR_ALGS) {
		erofs_err("unidentified algorithms %x, please upgrade erofs-utils",
			  sbi->available_compr_algs & ~Z_EROFS_ALL_COMPR_ALGS);
		return -EOPNOTSUPP;
	}

	offset = EROFS_SUPER_OFFSET + sbi->sb_size;
	alg = 0;
	for (algs = sbi->available_compr_algs; algs; algs >>= 1, ++alg) {
		void *data;

		if (!(algs & 1))
			continue;

		data = erofs_read_metadata(sbi, 0, &offset, &size);
		if (IS_ERR(data)) {
			ret = PTR_ERR(data);
			break;
		}

		ret = 0;
		if (alg == Z_EROFS_COMPRESSION_LZ4)
			ret = z_erofs_load_lz4_config(sbi, dsb, data, size);
		else if (alg == Z_EROFS_COMPRESSION_DEFLATE)
			ret = z_erofs_load_deflate_config(sbi, dsb, data, size);
		free(data);
		if (ret)
			break;
	}
	return ret;
}
