// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/data.c
 *
 * Copyright (C) 2020 Gao Xiang <hsiangkao@aol.com>
 * Compression support by Huang Jianan <huangjianan@oppo.com>
 */
#include "erofs/print.h"
#include "erofs/internal.h"
#include "erofs/io.h"
#include "erofs/trace.h"
#include "erofs/decompress.h"

static int erofs_map_blocks_flatmode(struct erofs_inode *inode,
				     struct erofs_map_blocks *map,
				     int flags)
{
	int err = 0;
	erofs_blk_t nblocks, lastblk;
	u64 offset = map->m_la;
	struct erofs_inode *vi = inode;
	bool tailendpacking = (vi->datalayout == EROFS_INODE_FLAT_INLINE);

	trace_erofs_map_blocks_flatmode_enter(inode, map, flags);

	nblocks = DIV_ROUND_UP(inode->i_size, PAGE_SIZE);
	lastblk = nblocks - tailendpacking;

	if (offset >= inode->i_size) {
		/* leave out-of-bound access unmapped */
		map->m_flags = 0;
		goto out;
	}

	/* there is no hole in flatmode */
	map->m_flags = EROFS_MAP_MAPPED;

	if (offset < blknr_to_addr(lastblk)) {
		map->m_pa = blknr_to_addr(vi->u.i_blkaddr) + map->m_la;
		map->m_plen = blknr_to_addr(lastblk) - offset;
	} else if (tailendpacking) {
		/* 2 - inode inline B: inode, [xattrs], inline last blk... */
		map->m_pa = iloc(vi->nid) + vi->inode_isize +
			vi->xattr_isize + erofs_blkoff(map->m_la);
		map->m_plen = inode->i_size - offset;

		/* inline data should be located in one meta block */
		if (erofs_blkoff(map->m_pa) + map->m_plen > PAGE_SIZE) {
			erofs_err("inline data cross block boundary @ nid %" PRIu64,
				  vi->nid);
			DBG_BUGON(1);
			err = -EFSCORRUPTED;
			goto err_out;
		}

		map->m_flags |= EROFS_MAP_META;
	} else {
		erofs_err("internal error @ nid: %" PRIu64 " (size %llu), m_la 0x%" PRIx64,
			  vi->nid, (unsigned long long)inode->i_size, map->m_la);
		DBG_BUGON(1);
		err = -EIO;
		goto err_out;
	}

out:
	map->m_llen = map->m_plen;

err_out:
	trace_erofs_map_blocks_flatmode_exit(inode, map, flags, 0);
	return err;
}

static int erofs_read_raw_data(struct erofs_inode *inode, char *buffer,
			       erofs_off_t size, erofs_off_t offset)
{
	struct erofs_map_blocks map = {
		.index = UINT_MAX,
	};
	int ret;
	erofs_off_t ptr = offset;

	while (ptr < offset + size) {
		erofs_off_t eend;

		map.m_la = ptr;
		ret = erofs_map_blocks_flatmode(inode, &map, 0);
		if (ret)
			return ret;

		DBG_BUGON(map.m_plen != map.m_llen);

		if (!(map.m_flags & EROFS_MAP_MAPPED)) {
			if (!map.m_llen) {
				ptr = offset + size;
				continue;
			}
			ptr = map.m_la + map.m_llen;
			continue;
		}

		/* trim extent */
		eend = min(offset + size, map.m_la + map.m_llen);
		DBG_BUGON(ptr < map.m_la);

		if (ptr > map.m_la) {
			map.m_pa += ptr - map.m_la;
			map.m_la = ptr;
		}

		ret = dev_read(buffer + ptr - offset,
			       map.m_pa, eend - map.m_la);
		if (ret < 0)
			return -EIO;

		ptr = eend;
	}
	return 0;
}

static int z_erofs_read_data(struct erofs_inode *inode, char *buffer,
			     erofs_off_t size, erofs_off_t offset)
{
	int ret;
	erofs_off_t end, length, skip;
	struct erofs_map_blocks map = {
		.index = UINT_MAX,
	};
	bool partial;
	unsigned int algorithmformat;
	char raw[EROFS_BLKSIZ];

	end = offset + size;
	while (end > offset) {
		map.m_la = end - 1;

		ret = z_erofs_map_blocks_iter(inode, &map);
		if (ret)
			return ret;

		if (!(map.m_flags & EROFS_MAP_MAPPED)) {
			end = map.m_la;
			continue;
		}

		ret = dev_read(raw, map.m_pa, EROFS_BLKSIZ);
		if (ret < 0)
			return -EIO;

		algorithmformat = map.m_flags & EROFS_MAP_ZIPPED ?
						Z_EROFS_COMPRESSION_LZ4 :
						Z_EROFS_COMPRESSION_SHIFTED;

		/*
		 * trim to the needed size if the returned extent is quite
		 * larger than requested, and set up partial flag as well.
		 */
		if (end < map.m_la + map.m_llen) {
			length = end - map.m_la;
			partial = true;
		} else {
			DBG_BUGON(end != map.m_la + map.m_llen);
			length = map.m_llen;
			partial = !(map.m_flags & EROFS_MAP_FULL_MAPPED);
		}

		if (map.m_la < offset) {
			skip = offset - map.m_la;
			end = offset;
		} else {
			skip = 0;
			end = map.m_la;
		}

		ret = z_erofs_decompress(&(struct z_erofs_decompress_req) {
					.in = raw,
					.out = buffer + end - offset,
					.decodedskip = skip,
					.inputsize = map.m_plen,
					.decodedlength = length,
					.alg = algorithmformat,
					.partial_decoding = partial
					 });
		if (ret < 0)
			return ret;
	}
	return 0;
}

int erofs_pread(struct erofs_inode *inode, char *buf,
		erofs_off_t count, erofs_off_t offset)
{
	switch (inode->datalayout) {
	case EROFS_INODE_FLAT_PLAIN:
	case EROFS_INODE_FLAT_INLINE:
		return erofs_read_raw_data(inode, buf, count, offset);
	case EROFS_INODE_FLAT_COMPRESSION_LEGACY:
	case EROFS_INODE_FLAT_COMPRESSION:
		return z_erofs_read_data(inode, buf, count, offset);
	default:
		break;
	}
	return -EINVAL;
}

