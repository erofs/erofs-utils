// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/blobchunk.c
 *
 * Copyright (C) 2021, Alibaba Cloud
 */
#define _GNU_SOURCE
#include "erofs/hashmap.h"
#include "erofs/blobchunk.h"
#include "erofs/block_list.h"
#include "erofs/cache.h"
#include "erofs/io.h"
#include <unistd.h>

void erofs_sha256(const unsigned char *in, unsigned long in_size,
		  unsigned char out[32]);

struct erofs_blobchunk {
	struct hashmap_entry ent;
	char		sha256[32];
	unsigned int	chunksize;
	erofs_blk_t	blkaddr;
};

static struct hashmap blob_hashmap;
static FILE *blobfile;
static erofs_blk_t remapped_base;
static bool multidev;
static struct erofs_buffer_head *bh_devt;

static struct erofs_blobchunk *erofs_blob_getchunk(int fd,
		unsigned int chunksize)
{
	static u8 zeroed[EROFS_BLKSIZ];
	u8 *chunkdata, sha256[32];
	int ret;
	unsigned int hash;
	erofs_off_t blkpos;
	struct erofs_blobchunk *chunk;

	chunkdata = malloc(chunksize);
	if (!chunkdata)
		return ERR_PTR(-ENOMEM);

	ret = read(fd, chunkdata, chunksize);
	if (ret < chunksize) {
		chunk = ERR_PTR(-EIO);
		goto out;
	}
	erofs_sha256(chunkdata, chunksize, sha256);
	hash = memhash(sha256, sizeof(sha256));
	chunk = hashmap_get_from_hash(&blob_hashmap, hash, sha256);
	if (chunk) {
		DBG_BUGON(chunksize != chunk->chunksize);
		goto out;
	}
	chunk = malloc(sizeof(struct erofs_blobchunk));
	if (!chunk) {
		chunk = ERR_PTR(-ENOMEM);
		goto out;
	}

	chunk->chunksize = chunksize;
	blkpos = ftell(blobfile);
	DBG_BUGON(erofs_blkoff(blkpos));
	chunk->blkaddr = erofs_blknr(blkpos);
	memcpy(chunk->sha256, sha256, sizeof(sha256));
	hashmap_entry_init(&chunk->ent, hash);
	hashmap_add(&blob_hashmap, chunk);

	erofs_dbg("Writing chunk (%u bytes) to %u", chunksize, chunk->blkaddr);
	ret = fwrite(chunkdata, chunksize, 1, blobfile);
	if (ret == 1 && erofs_blkoff(chunksize))
		ret = fwrite(zeroed, EROFS_BLKSIZ - erofs_blkoff(chunksize),
			     1, blobfile);
	if (ret < 1) {
		struct hashmap_entry key;

		hashmap_entry_init(&key, hash);
		hashmap_remove(&blob_hashmap, &key, sha256);
		free(chunk);
		chunk = ERR_PTR(-ENOSPC);
		goto out;
	}
out:
	free(chunkdata);
	return chunk;
}

static int erofs_blob_hashmap_cmp(const void *a, const void *b,
				  const void *key)
{
	const struct erofs_blobchunk *ec1 =
			container_of((struct hashmap_entry *)a,
				     struct erofs_blobchunk, ent);
	const struct erofs_blobchunk *ec2 =
			container_of((struct hashmap_entry *)b,
				     struct erofs_blobchunk, ent);

	return memcmp(ec1->sha256, key ? key : ec2->sha256,
		      sizeof(ec1->sha256));
}

int erofs_blob_write_chunk_indexes(struct erofs_inode *inode,
				   erofs_off_t off)
{
	struct erofs_inode_chunk_index idx = {0};
	erofs_blk_t extent_start = EROFS_NULL_ADDR;
	erofs_blk_t extent_end, extents_blks;
	unsigned int dst, src, unit;
	bool first_extent = true;
	erofs_blk_t base_blkaddr = 0;

	if (multidev) {
		idx.device_id = 1;
		inode->u.chunkformat |= EROFS_CHUNK_FORMAT_INDEXES;
	} else {
		base_blkaddr = remapped_base;
	}

	if (inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(struct erofs_inode_chunk_index);
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;

	for (dst = src = 0; dst < inode->extent_isize;
	     src += sizeof(void *), dst += unit) {
		struct erofs_blobchunk *chunk;

		chunk = *(void **)(inode->chunkindexes + src);

		idx.blkaddr = base_blkaddr + chunk->blkaddr;
		if (extent_start != EROFS_NULL_ADDR &&
		    idx.blkaddr == extent_end + 1) {
			extent_end = idx.blkaddr;
		} else {
			if (extent_start != EROFS_NULL_ADDR) {
				erofs_droid_blocklist_write_extent(inode,
					extent_start,
					(extent_end - extent_start) + 1,
					first_extent, false);
				first_extent = false;
			}
			extent_start = idx.blkaddr;
			extent_end = idx.blkaddr;
		}
		if (unit == EROFS_BLOCK_MAP_ENTRY_SIZE)
			memcpy(inode->chunkindexes + dst, &idx.blkaddr, unit);
		else
			memcpy(inode->chunkindexes + dst, &idx, sizeof(idx));
	}
	off = roundup(off, unit);

	if (extent_start == EROFS_NULL_ADDR)
		extents_blks = 0;
	else
		extents_blks = (extent_end - extent_start) + 1;
	erofs_droid_blocklist_write_extent(inode, extent_start, extents_blks,
					   first_extent, true);

	return dev_write(inode->chunkindexes, off, inode->extent_isize);
}

int erofs_blob_write_chunked_file(struct erofs_inode *inode)
{
	unsigned int chunksize = 1 << cfg.c_chunkbits;
	unsigned int count = DIV_ROUND_UP(inode->i_size, chunksize);
	struct erofs_inode_chunk_index *idx;
	erofs_off_t pos, len;
	unsigned int unit;
	int fd, ret;

	inode->u.chunkformat |= inode->u.chunkbits - LOG_BLOCK_SIZE;

	if (inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(struct erofs_inode_chunk_index);
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;

	inode->extent_isize = count * unit;
	idx = malloc(count * max(sizeof(*idx), sizeof(void *)));
	if (!idx)
		return -ENOMEM;
	inode->chunkindexes = idx;

	fd = open(inode->i_srcpath, O_RDONLY | O_BINARY);
	if (fd < 0) {
		ret = -errno;
		goto err;
	}

	for (pos = 0; pos < inode->i_size; pos += len) {
		struct erofs_blobchunk *chunk;

		len = min_t(u64, inode->i_size - pos, chunksize);
		chunk = erofs_blob_getchunk(fd, len);
		if (IS_ERR(chunk)) {
			ret = PTR_ERR(chunk);
			close(fd);
			goto err;
		}
		*(void **)idx++ = chunk;
	}
	inode->datalayout = EROFS_INODE_CHUNK_BASED;
	close(fd);
	return 0;
err:
	free(inode->chunkindexes);
	inode->chunkindexes = NULL;
	return ret;
}

int erofs_blob_remap(void)
{
	struct erofs_buffer_head *bh;
	ssize_t length;
	erofs_off_t pos_in, pos_out;
	ssize_t ret;

	fflush(blobfile);
	length = ftell(blobfile);
	if (multidev) {
		struct erofs_deviceslot dis = {
			.blocks = erofs_blknr(length),
		};

		pos_out = erofs_btell(bh_devt, false);
		ret = dev_write(&dis, pos_out, sizeof(dis));
		if (ret)
			return ret;

		bh_devt->op = &erofs_drop_directly_bhops;
		erofs_bdrop(bh_devt, false);
		return 0;
	}
	bh = erofs_balloc(DATA, length, 0, 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);

	erofs_mapbh(bh->block);
	pos_out = erofs_btell(bh, false);
	pos_in = 0;
	remapped_base = erofs_blknr(pos_out);
	ret = erofs_copy_file_range(fileno(blobfile), &pos_in,
				    erofs_devfd, &pos_out, length);
	bh->op = &erofs_drop_directly_bhops;
	erofs_bdrop(bh, false);
	return ret < length ? -EIO : 0;
}

void erofs_blob_exit(void)
{
	if (blobfile)
		fclose(blobfile);

	hashmap_free(&blob_hashmap, 1);
}

int erofs_blob_init(const char *blobfile_path)
{
	if (!blobfile_path) {
#ifdef HAVE_TMPFILE64
		blobfile = tmpfile64();
#else
		blobfile = tmpfile();
#endif
		multidev = false;
	} else {
		blobfile = fopen(blobfile_path, "wb");
		multidev = true;
	}
	if (!blobfile)
		return -EACCES;

	hashmap_init(&blob_hashmap, erofs_blob_hashmap_cmp, 0);
	return 0;
}

int erofs_generate_devtable(void)
{
	struct erofs_deviceslot dis;

	if (!multidev)
		return 0;

	bh_devt = erofs_balloc(DEVT, sizeof(dis), 0, 0);
	if (IS_ERR(bh_devt))
		return PTR_ERR(bh_devt);

	dis = (struct erofs_deviceslot) {};
	erofs_mapbh(bh_devt->block);
	bh_devt->op = &erofs_skip_write_bhops;
	sbi.devt_slotoff = erofs_btell(bh_devt, false) / EROFS_DEVT_SLOT_SIZE;
	sbi.extra_devices = 1;
	erofs_sb_set_device_table();
	return 0;
}
