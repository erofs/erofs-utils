// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C), 2022, Coolpad Group Limited.
 * Created by Yue Hu <huyue2@coolpad.com>
 */
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include "erofs/err.h"
#include "erofs/inode.h"
#include "erofs/compress.h"
#include "erofs/print.h"
#include "erofs/internal.h"
#include "erofs/fragments.h"
#include "erofs/bitops.h"
#include "liberofs_private.h"

struct erofs_fragment_dedupe_item {
	struct list_head	list;
	unsigned int		length;
	erofs_off_t		pos;
	u8			data[];
};

#define EROFS_FRAGMENT_INMEM_SZ_MAX	(256 * 1024)
#define EROFS_TOF_HASHLEN		16

#define FRAGMENT_HASHSIZE		65536
#define FRAGMENT_HASH(c)		((c) & (FRAGMENT_HASHSIZE - 1))

struct erofs_packed_inode {
	struct list_head *hash;
	int fd;
	unsigned long *uptodate;
#if EROFS_MT_ENABLED
	pthread_mutex_t mutex;
#endif
	u64 uptodate_bits;
};

const char *erofs_frags_packedname = "packed_file";

#ifndef HAVE_LSEEK64
#define erofs_lseek64 lseek
#else
#define erofs_lseek64 lseek64
#endif

static int z_erofs_fragments_dedupe_find(struct erofs_inode *inode, int fd,
					 u32 crc)
{
	struct erofs_packed_inode *epi = inode->sbi->packedinode;
	struct erofs_fragment_dedupe_item *cur, *di = NULL;
	struct list_head *head = &epi->hash[FRAGMENT_HASH(crc)];
	unsigned int s1, e1;
	erofs_off_t deduped;
	u8 *data;
	int ret;

	if (list_empty(head))
		return 0;

	s1 = min_t(u64, EROFS_FRAGMENT_INMEM_SZ_MAX, inode->i_size);
	data = malloc(s1);
	if (!data)
		return -ENOMEM;

	ret = pread(fd, data, s1, inode->i_size - s1);
	if (ret != s1) {
		free(data);
		return -errno;
	}
	e1 = s1 - EROFS_TOF_HASHLEN;
	deduped = 0;
	list_for_each_entry(cur, head, list) {
		unsigned int e2, mn;
		erofs_off_t i, pos;

		DBG_BUGON(cur->length <= EROFS_TOF_HASHLEN);
		e2 = cur->length - EROFS_TOF_HASHLEN;

		if (memcmp(data + e1, cur->data + e2, EROFS_TOF_HASHLEN))
			continue;

		i = 0;
		mn = min(e1, e2);
		while (i < mn && cur->data[e2 - i - 1] == data[e1 - i - 1])
			++i;

		i += EROFS_TOF_HASHLEN;
		if (i >= s1) {		/* full short match */
			DBG_BUGON(i > s1);
			pos = cur->pos + cur->length - s1;
			while (i < inode->i_size && pos) {
				char buf[2][16384];
				unsigned int sz;

				sz = min_t(u64, pos, sizeof(buf[0]));
				sz = min_t(u64, sz, inode->i_size - i);
				if (pread(epi->fd, buf[0], sz, pos - sz) != sz)
					break;
				if (pread(fd, buf[1], sz,
					  inode->i_size - i - sz) != sz)
					break;

				if (memcmp(buf[0], buf[1], sz))
					break;
				pos -= sz;
				i += sz;
			}
		}

		if (i <= deduped)
			continue;
		di = cur;
		deduped = i;
		if (deduped == inode->i_size)
			break;
	}

	free(data);
	if (deduped) {
		DBG_BUGON(!di);
		inode->fragment_size = deduped;
		inode->fragmentoff = di->pos + di->length - deduped;
		erofs_dbg("Dedupe %llu tail data at %llu",
			  inode->fragment_size | 0ULL, inode->fragmentoff | 0ULL);
	}
	return 0;
}

int z_erofs_fragments_dedupe(struct erofs_inode *inode, int fd, u32 *tofcrc)
{
	u8 data_to_hash[EROFS_TOF_HASHLEN];
	int ret;

	if (inode->i_size <= EROFS_TOF_HASHLEN)
		return 0;

	ret = pread(fd, data_to_hash, EROFS_TOF_HASHLEN,
		    inode->i_size - EROFS_TOF_HASHLEN);
	if (ret != EROFS_TOF_HASHLEN)
		return -errno;

	*tofcrc = erofs_crc32c(~0, data_to_hash, EROFS_TOF_HASHLEN);
	return z_erofs_fragments_dedupe_find(inode, fd, *tofcrc);
}

static int z_erofs_fragments_dedupe_insert(struct list_head *hash, void *data,
					   unsigned int len, erofs_off_t pos)
{
	struct erofs_fragment_dedupe_item *di;

	if (len <= EROFS_TOF_HASHLEN)
		return 0;
	if (len > EROFS_FRAGMENT_INMEM_SZ_MAX) {
		data += len - EROFS_FRAGMENT_INMEM_SZ_MAX;
		pos += len - EROFS_FRAGMENT_INMEM_SZ_MAX;
		len = EROFS_FRAGMENT_INMEM_SZ_MAX;
	}
	di = malloc(sizeof(*di) + len);
	if (!di)
		return -ENOMEM;

	memcpy(di->data, data, len);
	di->length = len;
	di->pos = pos;

	list_add_tail(&di->list, hash);
	return 0;
}

void z_erofs_fragments_commit(struct erofs_inode *inode)
{
	if (!inode->fragment_size)
		return;
	/*
	 * If the packed inode is larger than 4GiB, the full fragmentoff
	 * will be recorded by switching to the noncompact layout anyway.
	 */
	if (inode->fragmentoff >> 32)
		inode->datalayout = EROFS_INODE_COMPRESSED_FULL;

	inode->z_advise |= Z_EROFS_ADVISE_FRAGMENT_PCLUSTER;
	erofs_sb_set_fragments(inode->sbi);
}

int z_erofs_pack_file_from_fd(struct erofs_inode *inode, int fd, u32 tofcrc)
{
	struct erofs_packed_inode *epi = inode->sbi->packedinode;
	s64 offset, rc;
	char *memblock;

	offset = lseek(epi->fd, 0, SEEK_CUR);
	if (offset < 0)
		return -errno;

	inode->fragmentoff = (erofs_off_t)offset;
	inode->fragment_size = inode->i_size;

	memblock = mmap(NULL, inode->i_size, PROT_READ, MAP_SHARED, fd, 0);
	if (memblock == MAP_FAILED || !memblock) {
		unsigned long long remaining = inode->fragment_size;

		memblock = NULL;
		while (remaining) {
			char buf[32768];
			unsigned int sz = min_t(unsigned int, remaining,
						sizeof(buf));

			rc = read(fd, buf, sz);
			if (rc != sz) {
				if (rc <= 0) {
					if (!rc)
						rc = -EIO;
					else
						rc = -errno;
					goto out;
				}
				sz = rc;
			}
			rc = __erofs_io_write(epi->fd, buf, sz);
			if (rc != sz) {
				if (rc >= 0)
					rc = -EIO;
				goto out;
			}
			remaining -= sz;
		}
		rc = lseek(fd, 0, SEEK_SET);
		if (rc < 0) {
			rc = -errno;
			goto out;
		}
	} else {
		rc = __erofs_io_write(epi->fd, memblock, inode->fragment_size);
		if (rc != inode->fragment_size) {
			if (rc >= 0)
				rc = -EIO;
			goto out;
		}
	}

	erofs_dbg("Recording %llu fragment data at %llu",
		  inode->fragment_size | 0ULL, inode->fragmentoff | 0ULL);

	if (memblock)
		rc = z_erofs_fragments_dedupe_insert(
			&epi->hash[FRAGMENT_HASH(tofcrc)], memblock,
			inode->fragment_size, inode->fragmentoff);
	else
		rc = 0;
out:
	if (rc)
		erofs_err("Failed to record %llu-byte fragment data @ %llu for nid %llu: %d",
			  inode->fragment_size | 0ULL,
			  inode->fragmentoff | 0ULL, inode->nid | 0ULL, (int)rc);
	if (memblock)
		munmap(memblock, inode->i_size);
	return rc;
}

int z_erofs_pack_fragments(struct erofs_inode *inode, void *data,
			   unsigned int len, u32 tofcrc)
{
	struct erofs_packed_inode *epi = inode->sbi->packedinode;
	s64 offset = lseek(epi->fd, 0, SEEK_CUR);
	int ret;

	if (offset < 0)
		return -errno;

	inode->fragmentoff = (erofs_off_t)offset;
	inode->fragment_size = len;

	ret = write(epi->fd, data, len);
	if (ret != len) {
		if (ret < 0)
			return -errno;
		return -EIO;
	}

	erofs_dbg("Recording %llu fragment data at %llu",
		  inode->fragment_size | 0ULL, inode->fragmentoff | 0ULL);

	ret = z_erofs_fragments_dedupe_insert(&epi->hash[FRAGMENT_HASH(tofcrc)],
					      data, len, inode->fragmentoff);
	if (ret)
		return ret;
	return len;
}

int erofs_flush_packed_inode(struct erofs_sb_info *sbi)
{
	struct erofs_packed_inode *epi = sbi->packedinode;
	struct erofs_inode *inode;

	if (!epi || !erofs_sb_has_fragments(sbi))
		return -EINVAL;

	if (lseek(epi->fd, 0, SEEK_CUR) <= 0)
		return 0;
	inode = erofs_mkfs_build_special_from_fd(sbi, epi->fd,
						 EROFS_PACKED_INODE);
	sbi->packed_nid = erofs_lookupnid(inode);
	erofs_iput(inode);
	return 0;
}

int erofs_packedfile(struct erofs_sb_info *sbi)
{
	return sbi->packedinode->fd;
}

void erofs_packedfile_exit(struct erofs_sb_info *sbi)
{
	struct erofs_packed_inode *epi = sbi->packedinode;
	struct erofs_fragment_dedupe_item *di, *n;
	int i;

	if (!epi)
		return;

	if (epi->uptodate)
		free(epi->uptodate);

	if (epi->hash) {
		for (i = 0; i < FRAGMENT_HASHSIZE; ++i)
			list_for_each_entry_safe(di, n, &epi->hash[i], list)
				free(di);
		free(epi->hash);
	}

	if (epi->fd >= 0)
		close(epi->fd);
	free(epi);
	sbi->packedinode = NULL;
}

int erofs_packedfile_init(struct erofs_sb_info *sbi, bool fragments_mkfs)
{
	struct erofs_packed_inode *epi;
	int err, i;

	if (sbi->packedinode)
		return -EINVAL;

	epi = calloc(1, sizeof(*epi));
	if (!epi)
		return -ENOMEM;

	sbi->packedinode = epi;
	if (fragments_mkfs) {
		epi->hash = malloc(sizeof(*epi->hash) * FRAGMENT_HASHSIZE);
		if (!epi->hash) {
			err = -ENOMEM;
			goto err_out;
		}
		for (i = 0; i < FRAGMENT_HASHSIZE; ++i)
			init_list_head(&epi->hash[i]);
	}

	epi->fd = erofs_tmpfile();
	if (epi->fd < 0) {
		err = epi->fd;
		goto err_out;
	}

	if (erofs_sb_has_fragments(sbi) && sbi->packed_nid > 0) {
		struct erofs_inode ei = {
			.sbi = sbi,
			.nid = sbi->packed_nid,
		};
		s64 offset;

		err = erofs_read_inode_from_disk(&ei);
		if (err) {
			erofs_err("failed to read packed inode from disk: %s",
				  erofs_strerror(-errno));
			goto err_out;
		}

		offset = lseek(epi->fd, ei.i_size, SEEK_SET);
		if (offset < 0) {
			err = -errno;
			goto err_out;
		}
		epi->uptodate_bits = round_up(BLK_ROUND_UP(sbi, ei.i_size),
					      sizeof(epi->uptodate) * 8);
		epi->uptodate = calloc(1, epi->uptodate_bits >> 3);
		if (!epi->uptodate) {
			err = -ENOMEM;
			goto err_out;
		}
	}
	return 0;

err_out:
	erofs_packedfile_exit(sbi);
	return err;
}

static int erofs_load_packedinode_from_disk(struct erofs_inode *pi)
{
	struct erofs_sb_info *sbi = pi->sbi;
	int err;

	if (pi->nid)
		return 0;

	pi->nid = sbi->packed_nid;
	err = erofs_read_inode_from_disk(pi);
	if (err) {
		erofs_err("failed to read packed inode from disk: %s",
			  erofs_strerror(err));
		return err;
	}
	return 0;
}

static void *erofs_packedfile_preload(struct erofs_inode *pi,
				      struct erofs_map_blocks *map)
{
	struct erofs_sb_info *sbi = pi->sbi;
	struct erofs_packed_inode *epi = sbi->packedinode;
	unsigned int bsz = erofs_blksiz(sbi);
	char *buffer;
	erofs_off_t pos, end;
	ssize_t err;

	err = erofs_load_packedinode_from_disk(pi);
	if (err)
		return ERR_PTR(err);

	pos = map->m_la;
	err = erofs_map_blocks(pi, map, EROFS_GET_BLOCKS_FIEMAP);
	if (err)
		return ERR_PTR(err);

	end = round_up(map->m_la + map->m_llen, bsz);
	if (map->m_la < pos)
		map->m_la = round_up(map->m_la, bsz);
	else
		DBG_BUGON(map->m_la > pos);

	map->m_llen = end - map->m_la;
	DBG_BUGON(!map->m_llen);
	buffer = malloc(map->m_llen);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	err = erofs_pread(pi, buffer, map->m_llen, map->m_la);
	if (err)
		goto err_out;

	err = pwrite(epi->fd, buffer, map->m_llen, map->m_la);
	if (err < 0) {
		err = -errno;
		if (err == -ENOSPC) {
			memset(epi->uptodate, 0, epi->uptodate_bits >> 3);
			(void)!ftruncate(epi->fd, 0);
		}
		goto err_out;
	}
	if (err != map->m_llen) {
		err = -EIO;
		goto err_out;
	}
	for (pos = map->m_la; pos < end; pos += bsz)
		__erofs_set_bit(erofs_blknr(sbi, pos), epi->uptodate);
	return buffer;

err_out:
	free(buffer);
	map->m_llen = 0;
	return ERR_PTR(err);
}

int erofs_packedfile_read(struct erofs_sb_info *sbi,
			  void *buf, erofs_off_t len, erofs_off_t pos)
{
	struct erofs_packed_inode *epi = sbi->packedinode;
	struct erofs_inode pi = {
		.sbi = sbi,
	};
	struct erofs_map_blocks map = {
		.index = UINT_MAX,
	};
	unsigned int bsz = erofs_blksiz(sbi);
	erofs_off_t end = pos + len;
	char *buffer = NULL;
	int err;

	if (!epi) {
		err = erofs_load_packedinode_from_disk(&pi);
		if (!err)
			err = erofs_pread(&pi, buf, len, pos);
		return err;
	}

	err = 0;
	while (pos < end) {
		if (pos >= map.m_la && pos < map.m_la + map.m_llen) {
			len = min_t(erofs_off_t, end - pos,
				    map.m_la + map.m_llen - pos);
			memcpy(buf, buffer + pos - map.m_la, len);
		} else {
			erofs_blk_t bnr = erofs_blknr(sbi, pos);
			bool uptodate;

			if (__erofs_unlikely(bnr >= epi->uptodate_bits)) {
				erofs_err("packed inode EOF exceeded @ %llu",
					  pos | 0ULL);
				return -EFSCORRUPTED;
			}
			map.m_la = round_down(pos, bsz);
			len = min_t(erofs_off_t, bsz - (pos & (bsz - 1)),
				    end - pos);
			uptodate = __erofs_test_bit(bnr, epi->uptodate);
			if (!uptodate) {
#if EROFS_MT_ENABLED
				pthread_mutex_lock(&epi->mutex);
				uptodate = __erofs_test_bit(bnr, epi->uptodate);
				if (!uptodate) {
#endif
					free(buffer);
					buffer = erofs_packedfile_preload(&pi, &map);
					if (IS_ERR(buffer)) {
#if EROFS_MT_ENABLED
						pthread_mutex_unlock(&epi->mutex);
#endif
						buffer = NULL;
						goto fallback;
					}

#if EROFS_MT_ENABLED
				}
				pthread_mutex_unlock(&epi->mutex);
#endif
			}

			if (!uptodate)
				continue;

			err = pread(epi->fd, buf, len, pos);
			if (err < 0)
				break;
			if (err == len) {
				err = 0;
			} else {
fallback:
				err = erofs_load_packedinode_from_disk(&pi);
				if (!err)
					err = erofs_pread(&pi, buf, len, pos);
				if (err)
					break;
			}
			map.m_llen = 0;
		}
		buf += len;
		pos += len;
	}
	free(buffer);
	return err;
}
