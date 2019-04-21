// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs_utils/lib/compress.c
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Miao Xie <miaoxie@huawei.com>
 * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
 */
#define _LARGEFILE64_SOURCE
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "erofs/print.h"
#include "erofs/io.h"
#include "erofs/cache.h"
#include "erofs/compress.h"
#include "compressor.h"

static struct erofs_compress compresshandle;
static int compressionlevel;

struct z_erofs_vle_compress_ctx {
	u8 *metacur;

	u8 queue[EROFS_CONFIG_COMPR_MAX_SZ * 2];
	unsigned int head, tail;

	erofs_blk_t blkaddr;	/* pointing to the next blkaddr */
	u16 clusterofs;
};

#define Z_EROFS_LEGACY_MAP_HEADER_SIZE	\
	(sizeof(struct z_erofs_map_header) + Z_EROFS_VLE_LEGACY_HEADER_PADDING)

static unsigned int get_vle_compress_metasize(erofs_off_t filesize)
{
	const unsigned int indexsize = BLK_ROUND_UP(filesize) *
		sizeof(struct z_erofs_vle_decompressed_index);

	return Z_EROFS_LEGACY_MAP_HEADER_SIZE + indexsize;
}

static void vle_write_indexes_final(struct z_erofs_vle_compress_ctx *ctx)
{
	const unsigned int type = Z_EROFS_VLE_CLUSTER_TYPE_PLAIN;
	struct z_erofs_vle_decompressed_index di;

	if (!ctx->clusterofs)
		return;

	di.di_clusterofs = cpu_to_le16(ctx->clusterofs);
	di.di_u.blkaddr = 0;
	di.di_advise = cpu_to_le16(type << Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT);

	memcpy(ctx->metacur, &di, sizeof(di));
	ctx->metacur += sizeof(di);
}

static void vle_write_indexes(struct z_erofs_vle_compress_ctx *ctx,
			      unsigned int count, bool raw)
{
	unsigned int clusterofs = ctx->clusterofs;
	unsigned int d0 = 0, d1 = (clusterofs + count) / EROFS_BLKSIZ;
	struct z_erofs_vle_decompressed_index di;
	unsigned int type;
	__le16 advise;

	di.di_clusterofs = cpu_to_le16(ctx->clusterofs);

	/* whether the tail-end (un)compressed block or not */
	if (!d1) {
		type = raw ? Z_EROFS_VLE_CLUSTER_TYPE_PLAIN :
			Z_EROFS_VLE_CLUSTER_TYPE_HEAD;
		advise = cpu_to_le16(type << Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT);

		di.di_advise = advise;
		di.di_u.blkaddr = cpu_to_le32(ctx->blkaddr);
		memcpy(ctx->metacur, &di, sizeof(di));
		ctx->metacur += sizeof(di);

		/* don't add the final index if the tail-end block exists */
		ctx->clusterofs = 0;
		return;
	}

	do {
		if (d0) {
			type = Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD;

			di.di_u.delta[0] = cpu_to_le16(d0);
			di.di_u.delta[1] = cpu_to_le16(d1);
		} else {
			type = raw ? Z_EROFS_VLE_CLUSTER_TYPE_PLAIN :
				Z_EROFS_VLE_CLUSTER_TYPE_HEAD;
			di.di_u.blkaddr = cpu_to_le32(ctx->blkaddr);
		}
		advise = cpu_to_le16(type << Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT);
		di.di_advise = advise;

		memcpy(ctx->metacur, &di, sizeof(di));
		ctx->metacur += sizeof(di);

		count -= EROFS_BLKSIZ - clusterofs;
		clusterofs = 0;

		++d0;
		--d1;
	} while (clusterofs + count >= EROFS_BLKSIZ);

	ctx->clusterofs = clusterofs + count;
}

static int vle_compress_one(struct erofs_inode *inode,
			    struct z_erofs_vle_compress_ctx *ctx,
			    bool final)
{
	struct erofs_compress *const h = &compresshandle;
	unsigned int len = ctx->tail - ctx->head;
	unsigned int count;
	int ret;
	char dst[EROFS_BLKSIZ];

	while (len) {
		bool raw;

		if (len <= EROFS_BLKSIZ) {
			if (final)
				goto nocompression;
			break;
		}

		count = len;
		ret = erofs_compress_destsize(h, compressionlevel,
					      ctx->queue + ctx->head,
					      &count, dst, EROFS_BLKSIZ);
		if (ret <= 0) {
			if (ret != -EAGAIN) {
				erofs_err("failed to compress %s: %s",
					  inode->i_srcpath,
					  erofs_strerror(ret));
			}
nocompression:
			/* fix up clusterofs to 0 if possable */
			if (ctx->head >= ctx->clusterofs) {
				ctx->head -= ctx->clusterofs;
				len += ctx->clusterofs;
				ctx->clusterofs = 0;
			}

			/* write uncompressed data */
			count = min(EROFS_BLKSIZ, len);

			memcpy(dst, ctx->queue + ctx->head, count);
			memset(dst + count, 0, EROFS_BLKSIZ - count);

			erofs_dbg("Writing %u uncompressed data to block %u",
				  count, ctx->blkaddr);

			ret = blk_write(dst, ctx->blkaddr, 1);
			if (ret)
				return ret;
			raw = true;
		} else {
			/* write compressed data */
			erofs_dbg("Writing %u compressed data to block %u",
				  count, ctx->blkaddr);

			ret = blk_write(dst, ctx->blkaddr, 1);
			if (ret)
				return ret;
			raw = false;
		}

		ctx->head += count;
		/* write compression indexes for this blkaddr */
		vle_write_indexes(ctx, count, raw);

		++ctx->blkaddr;
		len -= count;

		if (!final && ctx->head >= EROFS_CONFIG_COMPR_MAX_SZ) {
			const uint qh_aligned = round_down(ctx->head, EROFS_BLKSIZ);
			const uint qh_after = ctx->head - qh_aligned;

			memmove(ctx->queue, ctx->queue + qh_aligned,
				len + qh_after);
			ctx->head = qh_after;
			ctx->tail = qh_after + len;
			break;
		}
	}
	return 0;
}

int erofs_write_compressed_file(struct erofs_inode *inode)
{
	const unsigned int metasize = get_vle_compress_metasize(inode->i_size);
	struct erofs_buffer_head *bh;
	struct z_erofs_vle_compress_ctx ctx;
	erofs_off_t remaining;
	erofs_blk_t blkaddr, compressed_blocks;

	int ret, fd;
	u8 *compressmeta = malloc(metasize);

	if (!compressmeta)
		return -ENOMEM;

	fd = open(inode->i_srcpath, O_RDONLY | O_BINARY);
	if (fd < 0) {
		ret = -errno;
		goto err_free;
	}

	/* allocate main data buffer */
	bh = erofs_balloc(DATA, 0, 0, 0);
	if (IS_ERR(bh)) {
		ret = PTR_ERR(bh);
		goto err_close;
	}

	memset(compressmeta, 0, Z_EROFS_LEGACY_MAP_HEADER_SIZE);

	blkaddr = erofs_mapbh(bh->block, true);	/* start_blkaddr */
	ctx.blkaddr = blkaddr;
	ctx.metacur = compressmeta + Z_EROFS_LEGACY_MAP_HEADER_SIZE;
	ctx.head = ctx.tail = 0;
	ctx.clusterofs = 0;
	remaining = inode->i_size;

	while (remaining) {
		const uint readcount = min_t(uint, remaining,
					     sizeof(ctx.queue) - ctx.tail);

		ret = read(fd, ctx.queue + ctx.tail, readcount);
		if (ret != readcount) {
			ret = -errno;
			goto err_bdrop;
		}
		remaining -= readcount;
		ctx.tail += readcount;

		/* do one compress round */
		ret = vle_compress_one(inode, &ctx, false);
		if (ret)
			goto err_bdrop;
	}

	/* do the final round */
	ret = vle_compress_one(inode, &ctx, true);
	if (ret)
		goto err_bdrop;

	/* fall back to no compression mode */
	compressed_blocks = ctx.blkaddr - blkaddr;
	if (compressed_blocks >= BLK_ROUND_UP(inode->i_size)) {
		ret = -ENOSPC;
		goto err_bdrop;
	}

	vle_write_indexes_final(&ctx);

	close(fd);
	ret = erofs_bh_balloon(bh, blknr_to_addr(compressed_blocks));
	DBG_BUGON(ret);

	erofs_info("compressed %s (%lu bytes) into %u blocks",
		   inode->i_srcpath, inode->i_size, compressed_blocks);

	/*
	 * TODO: need to move erofs_bdrop to erofs_write_tail_end
	 *       when both mkfs & kernel support compression inline.
	 */
	erofs_bdrop(bh, false);
	inode->compressmeta = compressmeta;
	inode->idata_size = 0;
	inode->u.i_blocks = compressed_blocks;
	inode->extent_isize = metasize;
	inode->data_mapping_mode = EROFS_INODE_LAYOUT_COMPRESSION;
	return 0;

err_bdrop:
	erofs_bdrop(bh, true);	/* revoke buffer */
err_close:
	close(fd);
err_free:
	free(compressmeta);
	return ret;
}

int z_erofs_compress_init(void)
{
	/* initialize for primary compression algorithm */
	int ret = erofs_compressor_init(&compresshandle,
					cfg.c_compr_alg_master);
	if (ret || !cfg.c_compr_alg_master)
		return ret;

	compressionlevel = cfg.c_compr_level_master < 0 ?
		compresshandle.alg->default_level :
		cfg.c_compr_level_master;
	return 0;
}

int z_erofs_compress_exit(void)
{
	return erofs_compressor_exit(&compresshandle);
}

