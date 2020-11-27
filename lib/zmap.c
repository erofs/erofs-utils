// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/zmap.c
 *
 * (a large amount of code was adapted from Linux kernel. )
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Created by Gao Xiang <gaoxiang25@huawei.com>
 * Modified by Huang Jianan <huangjianan@oppo.com>
 */
#include "erofs/io.h"
#include "erofs/print.h"

int z_erofs_fill_inode(struct erofs_inode *vi)
{
	if (vi->datalayout == EROFS_INODE_FLAT_COMPRESSION_LEGACY) {
		vi->z_advise = 0;
		vi->z_algorithmtype[0] = 0;
		vi->z_algorithmtype[1] = 0;
		vi->z_logical_clusterbits = LOG_BLOCK_SIZE;
		vi->z_physical_clusterbits[0] = vi->z_logical_clusterbits;
		vi->z_physical_clusterbits[1] = vi->z_logical_clusterbits;

		vi->flags |= EROFS_I_Z_INITED;
	}
	return 0;
}

static int z_erofs_fill_inode_lazy(struct erofs_inode *vi)
{
	int ret;
	erofs_off_t pos;
	struct z_erofs_map_header *h;
	char buf[sizeof(struct z_erofs_map_header)];

	if (vi->flags & EROFS_I_Z_INITED)
		return 0;

	DBG_BUGON(vi->datalayout == EROFS_INODE_FLAT_COMPRESSION_LEGACY);
	pos = round_up(iloc(vi->nid) + vi->inode_isize + vi->xattr_isize, 8);

	ret = dev_read(buf, pos, sizeof(buf));
	if (ret < 0)
		return -EIO;

	h = (struct z_erofs_map_header *)buf;
	vi->z_advise = le16_to_cpu(h->h_advise);
	vi->z_algorithmtype[0] = h->h_algorithmtype & 15;
	vi->z_algorithmtype[1] = h->h_algorithmtype >> 4;

	if (vi->z_algorithmtype[0] >= Z_EROFS_COMPRESSION_MAX) {
		erofs_err("unknown compression format %u for nid %llu",
			  vi->z_algorithmtype[0], (unsigned long long)vi->nid);
		return -EOPNOTSUPP;
	}

	vi->z_logical_clusterbits = LOG_BLOCK_SIZE + (h->h_clusterbits & 7);
	vi->z_physical_clusterbits[0] = vi->z_logical_clusterbits +
					((h->h_clusterbits >> 3) & 3);

	if (vi->z_physical_clusterbits[0] != LOG_BLOCK_SIZE) {
		erofs_err("unsupported physical clusterbits %u for nid %llu",
			  vi->z_physical_clusterbits[0], (unsigned long long)vi->nid);
		return -EOPNOTSUPP;
	}

	vi->z_physical_clusterbits[1] = vi->z_logical_clusterbits +
					((h->h_clusterbits >> 5) & 7);
	vi->flags |= EROFS_I_Z_INITED;
	return 0;
}

struct z_erofs_maprecorder {
	struct erofs_inode *inode;
	struct erofs_map_blocks *map;
	void *kaddr;

	unsigned long lcn;
	/* compression extent information gathered */
	u8  type;
	u16 clusterofs;
	u16 delta[2];
	erofs_blk_t pblk;
};

static int z_erofs_reload_indexes(struct z_erofs_maprecorder *m,
				  erofs_blk_t eblk)
{
	int ret;
	struct erofs_map_blocks *const map = m->map;
	char *mpage = map->mpage;

	if (map->index == eblk)
		return 0;

	ret = blk_read(mpage, eblk, 1);
	if (ret < 0)
		return -EIO;

	map->index = eblk;

	return 0;
}

static int legacy_load_cluster_from_disk(struct z_erofs_maprecorder *m,
					 unsigned long lcn)
{
	struct erofs_inode *const vi = m->inode;
	const erofs_off_t ibase = iloc(vi->nid);
	const erofs_off_t pos =
		Z_EROFS_VLE_LEGACY_INDEX_ALIGN(ibase + vi->inode_isize +
					       vi->xattr_isize) +
		lcn * sizeof(struct z_erofs_vle_decompressed_index);
	struct z_erofs_vle_decompressed_index *di;
	unsigned int advise, type;
	int err;

	err = z_erofs_reload_indexes(m, erofs_blknr(pos));
	if (err)
		return err;

	m->lcn = lcn;
	di = m->kaddr + erofs_blkoff(pos);

	advise = le16_to_cpu(di->di_advise);
	type = (advise >> Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT) &
		((1 << Z_EROFS_VLE_DI_CLUSTER_TYPE_BITS) - 1);
	switch (type) {
	case Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD:
		m->clusterofs = 1 << vi->z_logical_clusterbits;
		m->delta[0] = le16_to_cpu(di->di_u.delta[0]);
		m->delta[1] = le16_to_cpu(di->di_u.delta[1]);
		break;
	case Z_EROFS_VLE_CLUSTER_TYPE_PLAIN:
	case Z_EROFS_VLE_CLUSTER_TYPE_HEAD:
		m->clusterofs = le16_to_cpu(di->di_clusterofs);
		m->pblk = le32_to_cpu(di->di_u.blkaddr);
		break;
	default:
		DBG_BUGON(1);
		return -EOPNOTSUPP;
	}
	m->type = type;
	return 0;
}

static unsigned int decode_compactedbits(unsigned int lobits,
					 unsigned int lomask,
					 u8 *in, unsigned int pos, u8 *type)
{
	const unsigned int v = get_unaligned_le32(in + pos / 8) >> (pos & 7);
	const unsigned int lo = v & lomask;

	*type = (v >> lobits) & 3;
	return lo;
}

static int unpack_compacted_index(struct z_erofs_maprecorder *m,
				  unsigned int amortizedshift,
				  unsigned int eofs)
{
	struct erofs_inode *const vi = m->inode;
	const unsigned int lclusterbits = vi->z_logical_clusterbits;
	const unsigned int lomask = (1 << lclusterbits) - 1;
	unsigned int vcnt, base, lo, encodebits, nblk;
	int i;
	u8 *in, type;

	if (1 << amortizedshift == 4)
		vcnt = 2;
	else if (1 << amortizedshift == 2 && lclusterbits == 12)
		vcnt = 16;
	else
		return -EOPNOTSUPP;

	encodebits = ((vcnt << amortizedshift) - sizeof(__le32)) * 8 / vcnt;
	base = round_down(eofs, vcnt << amortizedshift);
	in = m->kaddr + base;

	i = (eofs - base) >> amortizedshift;

	lo = decode_compactedbits(lclusterbits, lomask,
				  in, encodebits * i, &type);
	m->type = type;
	if (type == Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD) {
		m->clusterofs = 1 << lclusterbits;
		if (i + 1 != (int)vcnt) {
			m->delta[0] = lo;
			return 0;
		}
		/*
		 * since the last lcluster in the pack is special,
		 * of which lo saves delta[1] rather than delta[0].
		 * Hence, get delta[0] by the previous lcluster indirectly.
		 */
		lo = decode_compactedbits(lclusterbits, lomask,
					  in, encodebits * (i - 1), &type);
		if (type != Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD)
			lo = 0;
		m->delta[0] = lo + 1;
		return 0;
	}
	m->clusterofs = lo;
	m->delta[0] = 0;
	/* figout out blkaddr (pblk) for HEAD lclusters */
	nblk = 1;
	while (i > 0) {
		--i;
		lo = decode_compactedbits(lclusterbits, lomask,
					  in, encodebits * i, &type);
		if (type == Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD)
			i -= lo;

		if (i >= 0)
			++nblk;
	}
	in += (vcnt << amortizedshift) - sizeof(__le32);
	m->pblk = le32_to_cpu(*(__le32 *)in) + nblk;
	return 0;
}

static int compacted_load_cluster_from_disk(struct z_erofs_maprecorder *m,
					    unsigned long lcn)
{
	struct erofs_inode *const vi = m->inode;
	const unsigned int lclusterbits = vi->z_logical_clusterbits;
	const erofs_off_t ebase = round_up(iloc(vi->nid) + vi->inode_isize +
					   vi->xattr_isize, 8) +
		sizeof(struct z_erofs_map_header);
	const unsigned int totalidx = DIV_ROUND_UP(vi->i_size, EROFS_BLKSIZ);
	unsigned int compacted_4b_initial, compacted_2b;
	unsigned int amortizedshift;
	erofs_off_t pos;
	int err;

	if (lclusterbits != 12)
		return -EOPNOTSUPP;

	if (lcn >= totalidx)
		return -EINVAL;

	m->lcn = lcn;
	/* used to align to 32-byte (compacted_2b) alignment */
	compacted_4b_initial = (32 - ebase % 32) / 4;
	if (compacted_4b_initial == 32 / 4)
		compacted_4b_initial = 0;

	if (vi->z_advise & Z_EROFS_ADVISE_COMPACTED_2B)
		compacted_2b = rounddown(totalidx - compacted_4b_initial, 16);
	else
		compacted_2b = 0;

	pos = ebase;
	if (lcn < compacted_4b_initial) {
		amortizedshift = 2;
		goto out;
	}
	pos += compacted_4b_initial * 4;
	lcn -= compacted_4b_initial;

	if (lcn < compacted_2b) {
		amortizedshift = 1;
		goto out;
	}
	pos += compacted_2b * 2;
	lcn -= compacted_2b;
	amortizedshift = 2;
out:
	pos += lcn * (1 << amortizedshift);
	err = z_erofs_reload_indexes(m, erofs_blknr(pos));
	if (err)
		return err;
	return unpack_compacted_index(m, amortizedshift, erofs_blkoff(pos));
}

static int z_erofs_load_cluster_from_disk(struct z_erofs_maprecorder *m,
					  unsigned int lcn)
{
	const unsigned int datamode = m->inode->datalayout;

	if (datamode == EROFS_INODE_FLAT_COMPRESSION_LEGACY)
		return legacy_load_cluster_from_disk(m, lcn);

	if (datamode == EROFS_INODE_FLAT_COMPRESSION)
		return compacted_load_cluster_from_disk(m, lcn);

	return -EINVAL;
}

static int z_erofs_extent_lookback(struct z_erofs_maprecorder *m,
				   unsigned int lookback_distance)
{
	struct erofs_inode *const vi = m->inode;
	struct erofs_map_blocks *const map = m->map;
	const unsigned int lclusterbits = vi->z_logical_clusterbits;
	unsigned long lcn = m->lcn;
	int err;

	if (lcn < lookback_distance) {
		erofs_err("bogus lookback distance @ nid %llu",
			  (unsigned long long)vi->nid);
		DBG_BUGON(1);
		return -EFSCORRUPTED;
	}

	/* load extent head logical cluster if needed */
	lcn -= lookback_distance;
	err = z_erofs_load_cluster_from_disk(m, lcn);
	if (err)
		return err;

	switch (m->type) {
	case Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD:
		if (!m->delta[0]) {
			erofs_err("invalid lookback distance 0 @ nid %llu",
				  (unsigned long long)vi->nid);
			DBG_BUGON(1);
			return -EFSCORRUPTED;
		}
		return z_erofs_extent_lookback(m, m->delta[0]);
	case Z_EROFS_VLE_CLUSTER_TYPE_PLAIN:
		map->m_flags &= ~EROFS_MAP_ZIPPED;
	case Z_EROFS_VLE_CLUSTER_TYPE_HEAD:
		map->m_la = (lcn << lclusterbits) | m->clusterofs;
		break;
	default:
		erofs_err("unknown type %u @ lcn %lu of nid %llu",
			  m->type, lcn, (unsigned long long)vi->nid);
		DBG_BUGON(1);
		return -EOPNOTSUPP;
	}
	return 0;
}

int z_erofs_map_blocks_iter(struct erofs_inode *vi,
			    struct erofs_map_blocks *map)
{
	struct z_erofs_maprecorder m = {
		.inode = vi,
		.map = map,
		.kaddr = map->mpage,
	};
	int err = 0;
	unsigned int lclusterbits, endoff;
	unsigned long long ofs, end;

	/* when trying to read beyond EOF, leave it unmapped */
	if (map->m_la >= vi->i_size) {
		map->m_llen = map->m_la + 1 - vi->i_size;
		map->m_la = vi->i_size;
		map->m_flags = 0;
		goto out;
	}

	err = z_erofs_fill_inode_lazy(vi);
	if (err)
		goto out;

	lclusterbits = vi->z_logical_clusterbits;
	ofs = map->m_la;
	m.lcn = ofs >> lclusterbits;
	endoff = ofs & ((1 << lclusterbits) - 1);

	err = z_erofs_load_cluster_from_disk(&m, m.lcn);
	if (err)
		goto out;

	map->m_flags = EROFS_MAP_ZIPPED;	/* by default, compressed */
	end = (m.lcn + 1ULL) << lclusterbits;
	switch (m.type) {
	case Z_EROFS_VLE_CLUSTER_TYPE_PLAIN:
		if (endoff >= m.clusterofs)
			map->m_flags &= ~EROFS_MAP_ZIPPED;
	case Z_EROFS_VLE_CLUSTER_TYPE_HEAD:
		if (endoff >= m.clusterofs) {
			map->m_la = (m.lcn << lclusterbits) | m.clusterofs;
			break;
		}
		/* m.lcn should be >= 1 if endoff < m.clusterofs */
		if (!m.lcn) {
			erofs_err("invalid logical cluster 0 at nid %llu",
				  (unsigned long long)vi->nid);
			err = -EFSCORRUPTED;
			goto out;
		}
		end = (m.lcn << lclusterbits) | m.clusterofs;
		map->m_flags |= EROFS_MAP_FULL_MAPPED;
		m.delta[0] = 1;
	case Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD:
		/* get the correspoinding first chunk */
		err = z_erofs_extent_lookback(&m, m.delta[0]);
		if (err)
			goto out;
		break;
	default:
		erofs_err("unknown type %u @ offset %llu of nid %llu",
			  m.type, ofs, (unsigned long long)vi->nid);
		err = -EOPNOTSUPP;
		goto out;
	}

	map->m_llen = end - map->m_la;
	map->m_plen = 1 << lclusterbits;
	map->m_pa = blknr_to_addr(m.pblk);
	map->m_flags |= EROFS_MAP_MAPPED;

out:
	erofs_dbg("m_la %" PRIu64 " m_pa %" PRIu64 " m_llen %" PRIu64 " m_plen %" PRIu64 " m_flags 0%o",
		  map->m_la, map->m_pa,
		  map->m_llen, map->m_plen, map->m_flags);

	DBG_BUGON(err < 0 && err != -ENOMEM);
	return err;
}
