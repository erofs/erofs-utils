// SPDX-License-Identifier: GPL-2.0+ OR MIT
/*
 * erofs-utils/lib/blobchunk.c
 *
 * Copyright (C) 2021, Alibaba Cloud
 */
#define _GNU_SOURCE
#include "erofs/print.h"
#include "erofs/block_list.h"
#include "erofs/importer.h"
#include "liberofs_cache.h"
#include "liberofs_chunk.h"
#include "liberofs_private.h"
#include "liberofs_sha256.h"
#include <unistd.h>

struct erofs_chunkitem {
	u8 sha256[32];
	struct list_head list;
	struct {
		unsigned int device_id;
		union {
			u64 chunksize;
			erofs_off_t sourceoffset;
		};
		erofs_blk_t	blkaddr;
	};
};

struct erofs_chunkitem erofs_holechunk = {
	.blkaddr = EROFS_NULL_ADDR,
};

struct erofs_chunkmgr {
	struct list_head chunks[65536];
	struct list_head unhashed_chunks;
	int device_id;
};

#define EROFS_CHUNK_NR_BUCKETS	\
	ARRAY_SIZE(((struct erofs_chunkmgr *)0)->chunks)

struct erofs_chunkitem *erofs_get_unhashed_chunk(struct erofs_sb_info *sbi,
		unsigned int device_id, erofs_blk_t blkaddr,
		erofs_off_t sourceoffset)
{
	struct erofs_chunkmgr *chunkmgr = sbi->chunkmgr;
	struct erofs_chunkitem *chunk;
	int ret;

	if (__erofs_unlikely(!chunkmgr)) {
		ret = erofs_blob_init(sbi, 0, 0);
		if (ret)
			return ERR_PTR(ret);
		chunkmgr = sbi->chunkmgr;
	}
	chunk = calloc(1, sizeof(*chunk));
	if (!chunk)
		return ERR_PTR(-ENOMEM);

	chunk->device_id = device_id;
	chunk->blkaddr = blkaddr;
	chunk->sourceoffset = sourceoffset;
	list_add_tail(&chunk->list, &chunkmgr->unhashed_chunks);
	return chunk;
}

#define FNV32_BASE ((unsigned int)0x811c9dc5)
#define FNV32_PRIME ((unsigned int)0x01000193)

static unsigned int memhash(const void *buf, size_t len)
{
	unsigned int hash = FNV32_BASE;
	unsigned char *ucbuf = (unsigned char *)buf;

	while (len--) {
		unsigned int c = *ucbuf++;

		hash = (hash * FNV32_PRIME) ^ c;
	}
	return hash;
}

static struct erofs_chunkitem *erofs_get_chunk(struct erofs_sb_info *sbi,
					       int device_id,
					       u8 *buf, u64 size)
{
	struct erofs_bufmgr *bmgr = device_id ? sbi->devs[device_id - 1].bmgr : sbi->bmgr;
	struct erofs_chunkmgr *chunkmgr = sbi->chunkmgr;
	static u8 zeroed[EROFS_MAX_BLOCK_SIZE];
	struct erofs_chunkitem *chunk;
	struct erofs_buffer_head *bh;
	unsigned int hash, padding;
	struct list_head *head;
	erofs_blk_t pos;
	u8 sha256[32];
	int ret;

	erofs_sha256(buf, size, sha256);
	hash = memhash(sha256, sizeof(sha256));
	head = &chunkmgr->chunks[hash & (EROFS_CHUNK_NR_BUCKETS - 1)];
	if (cfg.c_dedupe != EROFS_DEDUPE_FORCE_OFF) {
		list_for_each_entry(chunk, head, list) {
			if (chunk->chunksize != size)
				continue;
			if (memcmp(chunk->sha256, sha256, sizeof(sha256)))
				continue;
			sbi->saved_by_deduplication += size;
			if (chunk->blkaddr == erofs_holechunk.blkaddr) {
				chunk = &erofs_holechunk;
				erofs_dbg("Found duplicated hole chunk");
			} else {
				erofs_dbg("Found duplicated chunk at %llu",
					  chunk->blkaddr | 0ULL);
			}
			return chunk;
		}
	}

	chunk = malloc(sizeof(*chunk));
	if (!chunk)
		return ERR_PTR(-ENOMEM);

	chunk->chunksize = size;
	memcpy(chunk->sha256, sha256, sizeof(sha256));

	chunk->device_id = device_id;
	bh = erofs_balloc(bmgr, DATA, size, 0);
	if (IS_ERR(bh)) {
		free(chunk);
		return ERR_CAST(bh);
	}
	bh->op = &erofs_drop_directly_bhops;
	erofs_mapbh(NULL, bh->block);
	pos = erofs_btell(bh, false);
	chunk->blkaddr = pos >> sbi->blkszbits;

	erofs_dbg("Writing chunk (%llu bytes) to %llu (device %d)",
		  size | 0ULL, chunk->blkaddr | 0ULL, chunk->device_id);

	ret = erofs_io_pwrite(bmgr->vf, buf, pos, size);
	if (ret == size) {
		padding = erofs_blkoff(sbi, size);
		if (padding) {
			padding = erofs_blksiz(sbi) - padding;
			ret = erofs_io_pwrite(bmgr->vf, zeroed,
					      pos + size, padding);
			if (ret > 0 && ret != padding)
				ret = -EIO;
		}
	} else if (ret >= 0) {
		ret = -EIO;
	}

	if (ret < 0) {
		erofs_bdrop(bh, true);
		free(chunk);
		return ERR_PTR(ret);
	}
	list_add(&chunk->list, head);
	erofs_bdrop(bh, false);
	return chunk;
}

void erofs_inode_fixup_chunkformat(struct erofs_inode *inode)
{
	unsigned int unit, src;
	u64 extent_count;
	bool _48bit;

	if (inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(struct erofs_inode_chunk_index);
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;

	_48bit = inode->u.chunkformat & EROFS_CHUNK_FORMAT_48BIT;
	if (_48bit)
		return;

	extent_count = inode->extent_isize / unit;
	for (src = 0; src < extent_count; ++src) {
		struct erofs_chunkitem *chunk =
			*(void **)(inode->chunkindexes + src * sizeof(void *));

		if (chunk->blkaddr == EROFS_NULL_ADDR)
			continue;
		if (chunk->blkaddr > UINT32_MAX) {
			_48bit = true;
			break;
		}
	}
	if (_48bit)
		inode->u.chunkformat |= EROFS_CHUNK_FORMAT_48BIT;
}

int erofs_write_chunk_indexes(struct erofs_inode *inode, struct erofs_vfile *vf,
			      erofs_off_t off)
{
	struct erofs_sb_info *sbi = inode->sbi;
	erofs_blk_t remaining_blks = BLK_ROUND_UP(sbi, inode->i_size);
	struct erofs_inode_chunk_index idx = {0};
	erofs_blk_t extent_end = EROFS_NULL_ADDR, chunkblks, addrmask;
	erofs_blk_t extent_start = EROFS_NULL_ADDR;
	erofs_off_t source_offset;
	unsigned int dst, src, unit, zeroedlen;
	bool _48bit;

	if (inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(struct erofs_inode_chunk_index);
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;

	chunkblks = 1ULL << (inode->u.chunkformat & EROFS_CHUNK_FORMAT_BLKBITS_MASK);
	_48bit = inode->u.chunkformat & EROFS_CHUNK_FORMAT_48BIT;
	for (dst = src = 0; dst < inode->extent_isize;
	     src += sizeof(void *), dst += unit) {
		struct erofs_chunkitem *chunk;
		erofs_blk_t startblk;

		chunk = *(void **)(inode->chunkindexes + src);

		if (chunk->blkaddr == EROFS_NULL_ADDR) {
			startblk = EROFS_NULL_ADDR;
		} else if (chunk->device_id) {
			DBG_BUGON(!(inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES));
			startblk = chunk->blkaddr;
			extent_start = EROFS_NULL_ADDR;
		} else {
			startblk = chunk->blkaddr;
		}

		if (extent_start == EROFS_NULL_ADDR || startblk != extent_end) {
			if (extent_start != EROFS_NULL_ADDR) {
				remaining_blks -= extent_end - extent_start;
				tarerofs_blocklist_write(extent_start,
						extent_end - extent_start,
						source_offset, 0);
			}
			extent_start = startblk;
			source_offset = chunk->sourceoffset;
		}
		extent_end = startblk + chunkblks;

		addrmask = _48bit ? BIT_ULL(48) - 1 : BIT_ULL(32) - 1;
		startblk &= addrmask;
		idx.device_id = cpu_to_le16(chunk->device_id);
		idx.startblk_lo = cpu_to_le32(startblk);
		idx.startblk_hi = cpu_to_le16(startblk >> 32);
		DBG_BUGON(!_48bit && idx.startblk_hi);

		if (unit == EROFS_BLOCK_MAP_ENTRY_SIZE)
			memcpy(inode->chunkindexes + dst, &idx.startblk_lo, unit);
		else
			memcpy(inode->chunkindexes + dst, &idx, sizeof(idx));
	}
	if (extent_start != EROFS_NULL_ADDR) {
		extent_end = min(extent_end, extent_start + remaining_blks);
		zeroedlen = inode->i_size & (erofs_blksiz(sbi) - 1);
		if (zeroedlen)
			zeroedlen = erofs_blksiz(sbi) - zeroedlen;
		tarerofs_blocklist_write(extent_start, extent_end - extent_start,
					 source_offset, zeroedlen);
	}
	off = roundup(off, unit);
	return erofs_io_pwrite(vf, inode->chunkindexes,
			       off, inode->extent_isize);
}

int erofs_blob_mergechunks(struct erofs_inode *inode, unsigned int chunkbits,
			   unsigned int new_chunkbits)
{
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int dst, src, unit, count;

	if (new_chunkbits - sbi->blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
		new_chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + sbi->blkszbits;
	if (chunkbits >= new_chunkbits)		/* no need to merge */
		goto out;

	if (inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(struct erofs_inode_chunk_index);
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;

	count = round_up(inode->i_size, 1ULL << new_chunkbits) >> new_chunkbits;
	for (dst = src = 0; dst < count; ++dst) {
		*((void **)inode->chunkindexes + dst) =
			*((void **)inode->chunkindexes + src);
		src += 1U << (new_chunkbits - chunkbits);
	}

	DBG_BUGON(count * unit >= inode->extent_isize);
	inode->extent_isize = count * unit;
	chunkbits = new_chunkbits;
out:
	inode->u.chunkformat = (chunkbits - sbi->blkszbits) |
		(inode->u.chunkformat & ~EROFS_CHUNK_FORMAT_BLKBITS_MASK);
	return 0;
}

static void erofs_update_minextblks(struct erofs_sb_info *sbi,
		    erofs_off_t start, erofs_off_t end, erofs_blk_t *minextblks)
{
	erofs_blk_t lb;
	lb = lowbit((end - start) >> sbi->blkszbits);
	if (lb && lb < *minextblks)
		*minextblks = lb;
}
static bool erofs_blob_can_merge(struct erofs_sb_info *sbi,
				 struct erofs_chunkitem *lastch,
				 struct erofs_chunkitem *chunk)
{
	if (!lastch)
		return true;
	if (lastch == &erofs_holechunk && chunk == &erofs_holechunk)
		return true;
	if (lastch->device_id == chunk->device_id &&
		erofs_pos(sbi, lastch->blkaddr) + lastch->chunksize ==
		erofs_pos(sbi, chunk->blkaddr))
		return true;

	return false;
}

int erofs_blob_write_chunked_file(struct erofs_inode *inode, int fd,
				  erofs_off_t startoff)
{
	struct erofs_sb_info *sbi = inode->sbi;
	struct erofs_chunkmgr *cmgr = sbi->chunkmgr;
	int device_id = cmgr->device_id;
	unsigned int chunkbits = inode->u.chunkbits;
	unsigned int count, unit;
	struct erofs_chunkitem *chunk, *lastch;
	struct erofs_inode_chunk_index *idx;
	erofs_off_t pos, len, chunksize, interval_start;
	erofs_blk_t minextblks;
	u8 *chunkdata;
	int ret;

	/* if the file is fully sparsed, use one big chunk instead */
	if (lseek(fd, startoff, SEEK_DATA) < 0 && errno == ENXIO) {
		chunkbits = ilog2(inode->i_size - 1) + 1;
		if (chunkbits < sbi->blkszbits)
			chunkbits = sbi->blkszbits;
	}
	if (chunkbits - sbi->blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
		chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + sbi->blkszbits;
	chunksize = 1ULL << chunkbits;
	count = DIV_ROUND_UP(inode->i_size, chunksize);

	if (device_id)
		inode->u.chunkformat |= EROFS_CHUNK_FORMAT_INDEXES;
	if (inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(struct erofs_inode_chunk_index);
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;

	chunkdata = malloc(chunksize);
	if (!chunkdata)
		return -ENOMEM;

	inode->extent_isize = count * unit;
	inode->chunkindexes = malloc(count * max(sizeof(*idx), sizeof(void *)));
	if (!inode->chunkindexes) {
		ret = -ENOMEM;
		goto err;
	}
	idx = inode->chunkindexes;
	lastch = NULL;
	minextblks = BLK_ROUND_UP(sbi, inode->i_size);
	interval_start = 0;

	for (pos = 0; pos < inode->i_size; pos += len) {
		off_t offset = lseek(fd, pos + startoff, SEEK_DATA);

		if (offset >= 0 && offset < startoff + inode->i_size) {
			offset -= startoff;

			if (offset != (offset & ~(chunksize - 1))) {
				offset &= ~(chunksize - 1);
				if (lseek(fd, offset + startoff, SEEK_SET) !=
					  startoff + offset) {
					ret = -EIO;
					goto err;
				}
			}
		} else if (offset < 0 && errno != ENXIO) {
			/* SEEK_DATA doesn't work as expected (unimplemented) */
			offset = pos;
		} else {
			/* lseek returns ENXIO or OOB (considering diskbuf) */
			offset = ((pos >> chunkbits) + 1) << chunkbits;
		}

		if (offset > pos) {
			if (!erofs_blob_can_merge(sbi, lastch,
							&erofs_holechunk)) {
				erofs_update_minextblks(sbi, interval_start,
							pos, &minextblks);
				interval_start = pos;
			}
			do {
				*(void **)idx++ = &erofs_holechunk;
				pos += chunksize;
			} while (pos < offset);
			DBG_BUGON(pos != offset);
			lastch = &erofs_holechunk;
			len = 0;
			continue;
		}

		len = min_t(u64, inode->i_size - pos, chunksize);
		ret = read(fd, chunkdata, len);
		if (ret < len) {
			ret = -EIO;
			goto err;
		}

		chunk = erofs_get_chunk(sbi, device_id, chunkdata, len);
		if (IS_ERR(chunk)) {
			ret = PTR_ERR(chunk);
			goto err;
		}

		if (!erofs_blob_can_merge(sbi, lastch, chunk)) {
			erofs_update_minextblks(sbi, interval_start, pos,
						&minextblks);
			interval_start = pos;
		}
		*(void **)idx++ = chunk;
		lastch = chunk;
	}
	erofs_update_minextblks(sbi, interval_start, pos, &minextblks);
	inode->datalayout = EROFS_INODE_CHUNK_BASED;
	free(chunkdata);
	return erofs_blob_mergechunks(inode, chunkbits,
				      ilog2(minextblks) + sbi->blkszbits);
err:
	free(inode->chunkindexes);
	inode->chunkindexes = NULL;
	free(chunkdata);
	return ret;
}

int erofs_write_zero_inode(struct erofs_inode *inode)
{
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int chunkbits = ilog2(inode->i_size - 1) + 1;
	unsigned int count;
	erofs_off_t chunksize, len, pos;
	struct erofs_inode_chunk_index *idx;

	if (chunkbits < sbi->blkszbits)
		chunkbits = sbi->blkszbits;
	if (chunkbits - sbi->blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
		chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + sbi->blkszbits;

	inode->u.chunkformat |= chunkbits - sbi->blkszbits;

	chunksize = 1ULL << chunkbits;
	count = DIV_ROUND_UP(inode->i_size, chunksize);

	inode->extent_isize = count * EROFS_BLOCK_MAP_ENTRY_SIZE;
	idx = calloc(count, max(sizeof(*idx), sizeof(void *)));
	if (!idx)
		return -ENOMEM;
	inode->chunkindexes = idx;

	for (pos = 0; pos < inode->i_size; pos += len) {
		struct erofs_chunkitem *chunk;

		len = min_t(erofs_off_t, inode->i_size - pos, chunksize);
		chunk = erofs_get_unhashed_chunk(sbi, 0, EROFS_NULL_ADDR, -1);
		if (IS_ERR(chunk)) {
			free(inode->chunkindexes);
			inode->chunkindexes = NULL;
			return PTR_ERR(chunk);
		}

		*(void **)idx++ = chunk;
	}
	inode->datalayout = EROFS_INODE_CHUNK_BASED;
	return 0;
}

int tarerofs_write_chunkes(struct erofs_inode *inode, erofs_off_t data_offset)
{
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int chunkbits = ilog2(inode->i_size - 1) + 1;
	unsigned int count, unit, device_id;
	struct erofs_inode_chunk_index *idx;
	struct erofs_buffer_head *bh;
	erofs_off_t chunksize, len, pos;
	erofs_blk_t blkaddr;

	if (chunkbits < sbi->blkszbits)
		chunkbits = sbi->blkszbits;
	if (chunkbits - sbi->blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
		chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + sbi->blkszbits;

	inode->u.chunkformat |= chunkbits - sbi->blkszbits;
	if (sbi->extra_devices) {
		device_id = 1;
		inode->u.chunkformat |= EROFS_CHUNK_FORMAT_INDEXES;
		unit = sizeof(struct erofs_inode_chunk_index);
		DBG_BUGON(erofs_blkoff(sbi, data_offset));
		blkaddr = erofs_blknr(sbi, data_offset);
	} else {
		device_id = 0;
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;
		bh = erofs_balloc(sbi->bmgr, DATA,
				  round_up(inode->i_size, erofs_blksiz(sbi)), 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		bh->op = &erofs_drop_directly_bhops;
		erofs_mapbh(NULL, bh->block);
		blkaddr = erofs_btell(bh, false) >> sbi->blkszbits;
		erofs_bdrop(bh, false);
	}
	chunksize = 1ULL << chunkbits;
	count = DIV_ROUND_UP(inode->i_size, chunksize);

	inode->extent_isize = count * unit;
	idx = calloc(count, max(sizeof(*idx), sizeof(void *)));
	if (!idx)
		return -ENOMEM;
	inode->chunkindexes = idx;

	for (pos = 0; pos < inode->i_size; pos += len) {
		struct erofs_chunkitem *chunk;

		len = min_t(erofs_off_t, inode->i_size - pos, chunksize);

		chunk = erofs_get_unhashed_chunk(sbi, device_id, blkaddr,
						 data_offset);
		if (IS_ERR(chunk)) {
			free(inode->chunkindexes);
			inode->chunkindexes = NULL;
			return PTR_ERR(chunk);
		}

		*(void **)idx++ = chunk;
		blkaddr += erofs_blknr(sbi, len);
		data_offset += len;
	}

	/*
	 * XXX: it's safe for now, but we really need to refactor blobchunk
	 * after 1.9 is out.
	 */
	if (blkaddr > UINT32_MAX) {
		inode->u.chunkformat |= EROFS_CHUNK_FORMAT_48BIT;
		erofs_info("48-bit block addressin enabled for indexing larger tar");
		erofs_sb_set_48bit(sbi);
	}
	inode->datalayout = EROFS_INODE_CHUNK_BASED;
	return 0;
}

int erofs_mkfs_dump_blobs(struct erofs_sb_info *sbi)
{
	struct erofs_device_info *di;

	for (di = sbi->devs; di < sbi->devs + sbi->extra_devices; ++di) {
		if (!di->bmgr)
			continue;
		di->blocks = erofs_mapbh(di->bmgr, NULL);
	}
	return 0;
}

static int erofs_insert_zerochunk(struct erofs_chunkmgr *cmgr,
				  unsigned int cbitsdef)
{
	erofs_off_t chunksize = 1ULL << cbitsdef;
	struct erofs_chunkitem *chunk;
	struct list_head *head;
	unsigned int hash;
	u8 sha256[32], *zeros;
	int ret = 0;

	zeros = calloc(1, chunksize);
	if (!zeros)
		return -ENOMEM;

	erofs_sha256(zeros, chunksize, sha256);
	free(zeros);
	hash = memhash(sha256, sizeof(sha256));
	chunk = malloc(sizeof(*chunk));
	if (!chunk)
		return -ENOMEM;

	chunk->chunksize = chunksize;
	/* treat chunk filled with zeros as hole */
	chunk->blkaddr = erofs_holechunk.blkaddr;
	memcpy(chunk->sha256, sha256, sizeof(sha256));

	head = &cmgr->chunks[hash & (EROFS_CHUNK_NR_BUCKETS - 1)];
	list_add(&chunk->list, head);
	return ret;
}

int erofs_blob_init_device(struct erofs_sb_info *sbi, int device_id)
{
	struct erofs_bufmgr *bmgr;
	struct erofs_vfile *vf;
	int fd, ret;

	if (!device_id || sbi->devs[device_id - 1].bmgr)
		return 0;

	/* TODO: move it into (struct erofs_device_info) */
	vf = malloc(sizeof(struct erofs_vfile));
	if (!vf)
		return -ENOMEM;

	fd = open(sbi->devs[device_id - 1].src_path,
		  O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0666);
	if (fd < 0) {
		ret = -errno;
		goto err_vf;
	}
	*vf = (struct erofs_vfile){ .fd = fd };
	bmgr = erofs_buffer_init(sbi, 0, vf);
	if (!bmgr) {
		ret = -ENOMEM;
		goto err_fd;
	}
	sbi->devs[device_id - 1].bmgr = bmgr;
	return 0;

err_fd:
	close(fd);
err_vf:
	free(vf);
	return ret;
}

int erofs_blob_init(struct erofs_sb_info *sbi, int blobdev_id,
		    unsigned int chunkbits_zero)
{
	struct erofs_chunkmgr *cmgr;
	int i, ret;

	if (!sbi->chunkmgr) {
		cmgr = malloc(sizeof(*cmgr));
		if (!cmgr)
			return -ENOMEM;

		for (i = 0; i < EROFS_CHUNK_NR_BUCKETS; ++i)
			init_list_head(&cmgr->chunks[i]);
		init_list_head(&cmgr->unhashed_chunks);

		if (chunkbits_zero) {
			ret = erofs_insert_zerochunk(cmgr, chunkbits_zero);
			if (ret)
				goto err_out;
		}
		cmgr->device_id = blobdev_id;
		sbi->chunkmgr = cmgr;
	}
	return 0;
err_out:
	free(cmgr);
	return ret;
}

int erofs_chunkmgr_exit(struct erofs_sb_info *sbi)
{
	struct erofs_chunkmgr *cmgr = sbi->chunkmgr;
	struct erofs_chunkitem *bc, *n;
	int i;

	if (!cmgr)
		return 0;
	for (i = 0; i < EROFS_CHUNK_NR_BUCKETS; ++i) {
		list_for_each_entry_safe(bc, n, &cmgr->chunks[i], list) {
			list_del(&bc->list);
			free(bc);
		}
	}

	list_for_each_entry_safe(bc, n, &cmgr->unhashed_chunks, list) {
		list_del(&bc->list);
		free(bc);
	}
	free(cmgr);
	sbi->chunkmgr = NULL;
	return 0;
}
