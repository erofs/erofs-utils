// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Miao Xie <miaoxie@huawei.com>
 * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
 */
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "erofs/print.h"
#include "erofs/io.h"
#include "erofs/cache.h"
#include "erofs/compress.h"
#include "compressor.h"
#include "erofs/block_list.h"
#include "erofs/compress_hints.h"

static struct erofs_compress compresshandle;
static unsigned int algorithmtype[2];

struct z_erofs_vle_compress_ctx {
	u8 *metacur;

	u8 queue[EROFS_CONFIG_COMPR_MAX_SZ * 2];
	unsigned int head, tail;
	unsigned int compressedblks;
	erofs_blk_t blkaddr;		/* pointing to the next blkaddr */
	u16 clusterofs;
};

#define Z_EROFS_LEGACY_MAP_HEADER_SIZE	\
	(sizeof(struct z_erofs_map_header) + Z_EROFS_VLE_LEGACY_HEADER_PADDING)

static unsigned int vle_compressmeta_capacity(erofs_off_t filesize)
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

	/* whether the tail-end uncompressed block or not */
	if (!d1) {
		/* TODO: tail-packing inline compressed data */
		DBG_BUGON(!raw);
		type = Z_EROFS_VLE_CLUSTER_TYPE_PLAIN;
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
		/* XXX: big pcluster feature should be per-inode */
		if (d0 == 1 && erofs_sb_has_big_pcluster()) {
			type = Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD;
			di.di_u.delta[0] = cpu_to_le16(ctx->compressedblks |
					Z_EROFS_VLE_DI_D0_CBLKCNT);
			di.di_u.delta[1] = cpu_to_le16(d1);
		} else if (d0) {
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

static int write_uncompressed_extent(struct z_erofs_vle_compress_ctx *ctx,
				     unsigned int *len, char *dst)
{
	int ret;
	unsigned int count;

	/* reset clusterofs to 0 if permitted */
	if (!erofs_sb_has_lz4_0padding() && ctx->clusterofs &&
	    ctx->head >= ctx->clusterofs) {
		ctx->head -= ctx->clusterofs;
		*len += ctx->clusterofs;
		ctx->clusterofs = 0;
	}

	/* write uncompressed data */
	count = min(EROFS_BLKSIZ, *len);

	memcpy(dst, ctx->queue + ctx->head, count);
	memset(dst + count, 0, EROFS_BLKSIZ - count);

	erofs_dbg("Writing %u uncompressed data to block %u",
		  count, ctx->blkaddr);
	ret = blk_write(dst, ctx->blkaddr, 1);
	if (ret)
		return ret;
	return count;
}

static unsigned int z_erofs_get_max_pclusterblks(struct erofs_inode *inode)
{
#ifndef NDEBUG
	if (cfg.c_random_pclusterblks)
		return 1 + rand() % cfg.c_pclusterblks_max;
#endif
	if (cfg.c_compress_hints_file) {
		z_erofs_apply_compress_hints(inode);
		DBG_BUGON(!inode->z_physical_clusterblks);
		return inode->z_physical_clusterblks;
	}
	return cfg.c_pclusterblks_def;
}

static int vle_compress_one(struct erofs_inode *inode,
			    struct z_erofs_vle_compress_ctx *ctx,
			    bool final)
{
	struct erofs_compress *const h = &compresshandle;
	unsigned int len = ctx->tail - ctx->head;
	unsigned int count;
	int ret;
	static char dstbuf[EROFS_CONFIG_COMPR_MAX_SZ + EROFS_BLKSIZ];
	char *const dst = dstbuf + EROFS_BLKSIZ;

	while (len) {
		const unsigned int pclustersize =
			z_erofs_get_max_pclusterblks(inode) * EROFS_BLKSIZ;
		bool raw;

		if (len <= pclustersize) {
			if (final) {
				if (len <= EROFS_BLKSIZ)
					goto nocompression;
			} else {
				break;
			}
		}

		count = min(len, cfg.c_max_decompressed_extent_bytes);
		ret = erofs_compress_destsize(h, ctx->queue + ctx->head,
					      &count, dst, pclustersize);
		if (ret <= 0) {
			if (ret != -EAGAIN) {
				erofs_err("failed to compress %s: %s",
					  inode->i_srcpath,
					  erofs_strerror(ret));
			}
nocompression:
			ret = write_uncompressed_extent(ctx, &len, dst);
			if (ret < 0)
				return ret;
			count = ret;
			ctx->compressedblks = 1;
			raw = true;
		} else {
			const unsigned int tailused = ret & (EROFS_BLKSIZ - 1);
			const unsigned int padding =
				erofs_sb_has_lz4_0padding() && tailused ?
					EROFS_BLKSIZ - tailused : 0;

			ctx->compressedblks = DIV_ROUND_UP(ret, EROFS_BLKSIZ);
			DBG_BUGON(ctx->compressedblks * EROFS_BLKSIZ >= count);

			/* zero out garbage trailing data for non-0padding */
			if (!erofs_sb_has_lz4_0padding())
				memset(dst + ret, 0,
				       roundup(ret, EROFS_BLKSIZ) - ret);

			/* write compressed data */
			erofs_dbg("Writing %u compressed data to %u of %u blocks",
				  count, ctx->blkaddr, ctx->compressedblks);

			ret = blk_write(dst - padding, ctx->blkaddr,
					ctx->compressedblks);
			if (ret)
				return ret;
			raw = false;
		}

		ctx->head += count;
		/* write compression indexes for this pcluster */
		vle_write_indexes(ctx, count, raw);

		ctx->blkaddr += ctx->compressedblks;
		len -= count;

		if (!final && ctx->head >= EROFS_CONFIG_COMPR_MAX_SZ) {
			const unsigned int qh_aligned =
				round_down(ctx->head, EROFS_BLKSIZ);
			const unsigned int qh_after = ctx->head - qh_aligned;

			memmove(ctx->queue, ctx->queue + qh_aligned,
				len + qh_after);
			ctx->head = qh_after;
			ctx->tail = qh_after + len;
			break;
		}
	}
	return 0;
}

struct z_erofs_compressindex_vec {
	union {
		erofs_blk_t blkaddr;
		u16 delta[2];
	} u;
	u16 clusterofs;
	u8  clustertype;
};

static void *parse_legacy_indexes(struct z_erofs_compressindex_vec *cv,
				  unsigned int nr, void *metacur)
{
	struct z_erofs_vle_decompressed_index *const db = metacur;
	unsigned int i;

	for (i = 0; i < nr; ++i, ++cv) {
		struct z_erofs_vle_decompressed_index *const di = db + i;
		const unsigned int advise = le16_to_cpu(di->di_advise);

		cv->clustertype = (advise >> Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT) &
			((1 << Z_EROFS_VLE_DI_CLUSTER_TYPE_BITS) - 1);
		cv->clusterofs = le16_to_cpu(di->di_clusterofs);

		if (cv->clustertype == Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD) {
			cv->u.delta[0] = le16_to_cpu(di->di_u.delta[0]);
			cv->u.delta[1] = le16_to_cpu(di->di_u.delta[1]);
		} else {
			cv->u.blkaddr = le32_to_cpu(di->di_u.blkaddr);
		}
	}
	return db + nr;
}

static void *write_compacted_indexes(u8 *out,
				     struct z_erofs_compressindex_vec *cv,
				     erofs_blk_t *blkaddr_ret,
				     unsigned int destsize,
				     unsigned int logical_clusterbits,
				     bool final, bool *dummy_head)
{
	unsigned int vcnt, encodebits, pos, i, cblks;
	bool update_blkaddr;
	erofs_blk_t blkaddr;

	if (destsize == 4)
		vcnt = 2;
	else if (destsize == 2 && logical_clusterbits == 12)
		vcnt = 16;
	else
		return ERR_PTR(-EINVAL);
	encodebits = (vcnt * destsize * 8 - 32) / vcnt;
	blkaddr = *blkaddr_ret;
	update_blkaddr = erofs_sb_has_big_pcluster();

	pos = 0;
	for (i = 0; i < vcnt; ++i) {
		unsigned int offset, v;
		u8 ch, rem;

		if (cv[i].clustertype == Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD) {
			if (cv[i].u.delta[0] & Z_EROFS_VLE_DI_D0_CBLKCNT) {
				cblks = cv[i].u.delta[0] & ~Z_EROFS_VLE_DI_D0_CBLKCNT;
				offset = cv[i].u.delta[0];
				blkaddr += cblks;
				*dummy_head = false;
			} else if (i + 1 == vcnt) {
				offset = cv[i].u.delta[1];
			} else {
				offset = cv[i].u.delta[0];
			}
		} else {
			offset = cv[i].clusterofs;
			if (*dummy_head) {
				++blkaddr;
				if (update_blkaddr)
					*blkaddr_ret = blkaddr;
			}
			*dummy_head = true;
			update_blkaddr = false;

			if (cv[i].u.blkaddr != blkaddr) {
				if (i + 1 != vcnt)
					DBG_BUGON(!final);
				DBG_BUGON(cv[i].u.blkaddr);
			}
		}
		v = (cv[i].clustertype << logical_clusterbits) | offset;
		rem = pos & 7;
		ch = out[pos / 8] & ((1 << rem) - 1);
		out[pos / 8] = (v << rem) | ch;
		out[pos / 8 + 1] = v >> (8 - rem);
		out[pos / 8 + 2] = v >> (16 - rem);
		pos += encodebits;
	}
	DBG_BUGON(destsize * vcnt * 8 != pos + 32);
	*(__le32 *)(out + destsize * vcnt - 4) = cpu_to_le32(*blkaddr_ret);
	*blkaddr_ret = blkaddr;
	return out + destsize * vcnt;
}

int z_erofs_convert_to_compacted_format(struct erofs_inode *inode,
					erofs_blk_t blkaddr,
					unsigned int legacymetasize,
					void *compressmeta)
{
	const unsigned int mpos = Z_EROFS_VLE_EXTENT_ALIGN(inode->inode_isize +
							   inode->xattr_isize) +
				  sizeof(struct z_erofs_map_header);
	const unsigned int totalidx = (legacymetasize -
				       Z_EROFS_LEGACY_MAP_HEADER_SIZE) / 8;
	const unsigned int logical_clusterbits = inode->z_logical_clusterbits;
	u8 *out, *in;
	struct z_erofs_compressindex_vec cv[16];
	/* # of 8-byte units so that it can be aligned with 32 bytes */
	unsigned int compacted_4b_initial, compacted_4b_end;
	unsigned int compacted_2b;
	bool dummy_head;

	if (logical_clusterbits < LOG_BLOCK_SIZE || LOG_BLOCK_SIZE < 12)
		return -EINVAL;
	if (logical_clusterbits > 14)	/* currently not supported */
		return -ENOTSUP;
	if (logical_clusterbits == 12) {
		compacted_4b_initial = (32 - mpos % 32) / 4;
		if (compacted_4b_initial == 32 / 4)
			compacted_4b_initial = 0;

		if (compacted_4b_initial > totalidx) {
			compacted_4b_initial = compacted_2b = 0;
			compacted_4b_end = totalidx;
		} else {
			compacted_2b = rounddown(totalidx -
						 compacted_4b_initial, 16);
			compacted_4b_end = totalidx - compacted_4b_initial -
					   compacted_2b;
		}
	} else {
		compacted_2b = compacted_4b_initial = 0;
		compacted_4b_end = totalidx;
	}

	out = in = compressmeta;

	out += sizeof(struct z_erofs_map_header);
	in += Z_EROFS_LEGACY_MAP_HEADER_SIZE;

	dummy_head = false;
	/* prior to bigpcluster, blkaddr was bumped up once coming into HEAD */
	if (!erofs_sb_has_big_pcluster()) {
		--blkaddr;
		dummy_head = true;
	}

	/* generate compacted_4b_initial */
	while (compacted_4b_initial) {
		in = parse_legacy_indexes(cv, 2, in);
		out = write_compacted_indexes(out, cv, &blkaddr,
					      4, logical_clusterbits, false,
					      &dummy_head);
		compacted_4b_initial -= 2;
	}
	DBG_BUGON(compacted_4b_initial);

	/* generate compacted_2b */
	while (compacted_2b) {
		in = parse_legacy_indexes(cv, 16, in);
		out = write_compacted_indexes(out, cv, &blkaddr,
					      2, logical_clusterbits, false,
					      &dummy_head);
		compacted_2b -= 16;
	}
	DBG_BUGON(compacted_2b);

	/* generate compacted_4b_end */
	while (compacted_4b_end > 1) {
		in = parse_legacy_indexes(cv, 2, in);
		out = write_compacted_indexes(out, cv, &blkaddr,
					      4, logical_clusterbits, false,
					      &dummy_head);
		compacted_4b_end -= 2;
	}

	/* generate final compacted_4b_end if needed */
	if (compacted_4b_end) {
		memset(cv, 0, sizeof(cv));
		in = parse_legacy_indexes(cv, 1, in);
		out = write_compacted_indexes(out, cv, &blkaddr,
					      4, logical_clusterbits, true,
					      &dummy_head);
	}
	inode->extent_isize = out - (u8 *)compressmeta;
	return 0;
}

static void z_erofs_write_mapheader(struct erofs_inode *inode,
				    void *compressmeta)
{
	struct z_erofs_map_header h = {
		.h_advise = cpu_to_le16(inode->z_advise),
		.h_algorithmtype = inode->z_algorithmtype[1] << 4 |
				   inode->z_algorithmtype[0],
		/* lclustersize */
		.h_clusterbits = inode->z_logical_clusterbits - 12,
	};

	memset(compressmeta, 0, Z_EROFS_LEGACY_MAP_HEADER_SIZE);
	/* write out map header */
	memcpy(compressmeta, &h, sizeof(struct z_erofs_map_header));
}

int erofs_write_compressed_file(struct erofs_inode *inode)
{
	struct erofs_buffer_head *bh;
	struct z_erofs_vle_compress_ctx ctx;
	erofs_off_t remaining;
	erofs_blk_t blkaddr, compressed_blocks;
	unsigned int legacymetasize;
	int ret, fd;
	u8 *compressmeta = malloc(vle_compressmeta_capacity(inode->i_size));

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

	/* initialize per-file compression setting */
	inode->z_advise = 0;
	if (!cfg.c_legacy_compress) {
		inode->z_advise |= Z_EROFS_ADVISE_COMPACTED_2B;
		inode->datalayout = EROFS_INODE_FLAT_COMPRESSION;
	} else {
		inode->datalayout = EROFS_INODE_FLAT_COMPRESSION_LEGACY;
	}

	if (erofs_sb_has_big_pcluster()) {
		inode->z_advise |= Z_EROFS_ADVISE_BIG_PCLUSTER_1;
		if (inode->datalayout == EROFS_INODE_FLAT_COMPRESSION)
			inode->z_advise |= Z_EROFS_ADVISE_BIG_PCLUSTER_2;
	}
	inode->z_algorithmtype[0] = algorithmtype[0];
	inode->z_algorithmtype[1] = algorithmtype[1];
	inode->z_logical_clusterbits = LOG_BLOCK_SIZE;

	z_erofs_write_mapheader(inode, compressmeta);

	blkaddr = erofs_mapbh(bh->block);	/* start_blkaddr */
	ctx.blkaddr = blkaddr;
	ctx.metacur = compressmeta + Z_EROFS_LEGACY_MAP_HEADER_SIZE;
	ctx.head = ctx.tail = 0;
	ctx.clusterofs = 0;
	remaining = inode->i_size;

	while (remaining) {
		const u64 readcount = min_t(u64, remaining,
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
	DBG_BUGON(!compressed_blocks);
	ret = erofs_bh_balloon(bh, blknr_to_addr(compressed_blocks));
	DBG_BUGON(ret != EROFS_BLKSIZ);

	erofs_info("compressed %s (%llu bytes) into %u blocks",
		   inode->i_srcpath, (unsigned long long)inode->i_size,
		   compressed_blocks);

	/*
	 * TODO: need to move erofs_bdrop to erofs_write_tail_end
	 *       when both mkfs & kernel support compression inline.
	 */
	erofs_bdrop(bh, false);
	inode->idata_size = 0;
	inode->u.i_blocks = compressed_blocks;

	legacymetasize = ctx.metacur - compressmeta;
	if (inode->datalayout == EROFS_INODE_FLAT_COMPRESSION_LEGACY) {
		inode->extent_isize = legacymetasize;
	} else {
		ret = z_erofs_convert_to_compacted_format(inode, blkaddr,
							  legacymetasize,
							  compressmeta);
		DBG_BUGON(ret);
	}
	inode->compressmeta = compressmeta;
	erofs_droid_blocklist_write(inode, blkaddr, compressed_blocks);
	return 0;

err_bdrop:
	erofs_bdrop(bh, true);	/* revoke buffer */
err_close:
	close(fd);
err_free:
	free(compressmeta);
	return ret;
}

static int erofs_get_compress_algorithm_id(const char *name)
{
	if (!strcmp(name, "lz4") || !strcmp(name, "lz4hc"))
		return Z_EROFS_COMPRESSION_LZ4;
	if (!strcmp(name, "lzma"))
		return Z_EROFS_COMPRESSION_LZMA;
	return -ENOTSUP;
}

int z_erofs_build_compr_cfgs(struct erofs_buffer_head *sb_bh)
{
	struct erofs_buffer_head *bh = sb_bh;
	int ret = 0;

	if (sbi.available_compr_algs & (1 << Z_EROFS_COMPRESSION_LZ4)) {
		struct {
			__le16 size;
			struct z_erofs_lz4_cfgs lz4;
		} __packed lz4alg = {
			.size = cpu_to_le16(sizeof(struct z_erofs_lz4_cfgs)),
			.lz4 = {
				.max_distance =
					cpu_to_le16(sbi.lz4_max_distance),
				.max_pclusterblks = cfg.c_pclusterblks_max,
			}
		};

		bh = erofs_battach(bh, META, sizeof(lz4alg));
		if (IS_ERR(bh)) {
			DBG_BUGON(1);
			return PTR_ERR(bh);
		}
		erofs_mapbh(bh->block);
		ret = dev_write(&lz4alg, erofs_btell(bh, false),
				sizeof(lz4alg));
		bh->op = &erofs_drop_directly_bhops;
	}
#ifdef HAVE_LIBLZMA
	if (sbi.available_compr_algs & (1 << Z_EROFS_COMPRESSION_LZMA)) {
		struct {
			__le16 size;
			struct z_erofs_lzma_cfgs lzma;
		} __packed lzmaalg = {
			.size = cpu_to_le16(sizeof(struct z_erofs_lzma_cfgs)),
			.lzma = {
				.dict_size = cpu_to_le32(cfg.c_dict_size),
			}
		};

		bh = erofs_battach(bh, META, sizeof(lzmaalg));
		if (IS_ERR(bh)) {
			DBG_BUGON(1);
			return PTR_ERR(bh);
		}
		erofs_mapbh(bh->block);
		ret = dev_write(&lzmaalg, erofs_btell(bh, false),
				sizeof(lzmaalg));
		bh->op = &erofs_drop_directly_bhops;
	}
#endif
	return ret;
}

int z_erofs_compress_init(struct erofs_buffer_head *sb_bh)
{
	/* initialize for primary compression algorithm */
	int ret = erofs_compressor_init(&compresshandle,
					cfg.c_compr_alg_master);

	if (ret)
		return ret;

	/*
	 * if primary algorithm is empty (e.g. compression off),
	 * clear 0PADDING feature for old kernel compatibility.
	 */
	if (!cfg.c_compr_alg_master ||
	    (cfg.c_legacy_compress && !strcmp(cfg.c_compr_alg_master, "lz4")))
		erofs_sb_clear_lz4_0padding();

	if (!cfg.c_compr_alg_master)
		return 0;

	ret = erofs_compressor_setlevel(&compresshandle,
					cfg.c_compr_level_master);
	if (ret)
		return ret;

	/* figure out primary algorithm */
	ret = erofs_get_compress_algorithm_id(cfg.c_compr_alg_master);
	if (ret < 0)
		return ret;

	algorithmtype[0] = ret;	/* primary algorithm (head 0) */
	algorithmtype[1] = 0;	/* secondary algorithm (head 1) */
	/*
	 * if big pcluster is enabled, an extra CBLKCNT lcluster index needs
	 * to be loaded in order to get those compressed block counts.
	 */
	if (cfg.c_pclusterblks_max > 1) {
		if (cfg.c_pclusterblks_max >
		    Z_EROFS_PCLUSTER_MAX_SIZE / EROFS_BLKSIZ) {
			erofs_err("unsupported clusterblks %u (too large)",
				  cfg.c_pclusterblks_max);
			return -EINVAL;
		}
		erofs_sb_set_big_pcluster();
		erofs_warn("EXPERIMENTAL big pcluster feature in use. Use at your own risk!");
	}

	if (ret != Z_EROFS_COMPRESSION_LZ4)
		erofs_sb_set_compr_cfgs();

	if (erofs_sb_has_compr_cfgs()) {
		sbi.available_compr_algs |= 1 << ret;
		return z_erofs_build_compr_cfgs(sb_bh);
	}
	return 0;
}

int z_erofs_compress_exit(void)
{
	return erofs_compressor_exit(&compresshandle);
}
