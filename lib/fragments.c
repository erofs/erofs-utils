// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C), 2022, Coolpad Group Limited.
 * Created by Yue Hu <huyue2@coolpad.com>
 */
#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE
#endif
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

struct erofs_fragment_dedupe_item {
	struct list_head	list;
	unsigned int		length;
	erofs_off_t		pos;
	u8			data[];
};

#define EROFS_FRAGMENT_INMEM_SZ_MAX	EROFS_CONFIG_COMPR_MAX_SZ
#define EROFS_TOF_HASHLEN		16

#define FRAGMENT_HASHSIZE		65536
#define FRAGMENT_HASH(c)		((c) & (FRAGMENT_HASHSIZE - 1))

struct erofs_packed_inode {
	struct list_head *hash;
	FILE *file;
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
				if (pread(fileno(epi->file), buf[0], sz,
					  pos - sz) != sz)
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

	if (erofs_lseek64(fd, inode->i_size - EROFS_TOF_HASHLEN, SEEK_SET) < 0)
		return -errno;

	ret = read(fd, data_to_hash, EROFS_TOF_HASHLEN);
	if (ret != EROFS_TOF_HASHLEN)
		return -errno;

	*tofcrc = erofs_crc32c(~0, data_to_hash, EROFS_TOF_HASHLEN);
	ret = z_erofs_fragments_dedupe_find(inode, fd, *tofcrc);
	if (ret < 0)
		return ret;
	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0)
		return -errno;
	return 0;
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
#ifdef HAVE_FTELLO64
	off64_t offset = ftello64(epi->file);
#else
	off_t offset = ftello(epi->file);
#endif
	char *memblock;
	int rc;

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
				if (rc < 0)
					rc = -errno;
				else
					rc = -EAGAIN;
				goto out;
			}
			if (fwrite(buf, sz, 1, epi->file) != 1) {
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
	} else if (fwrite(memblock, inode->fragment_size, 1, epi->file) != 1) {
		rc = -EIO;
		goto out;
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
	if (memblock)
		munmap(memblock, inode->i_size);
	return rc;
}

int z_erofs_pack_fragments(struct erofs_inode *inode, void *data,
			   unsigned int len, u32 tofcrc)
{
	struct erofs_packed_inode *epi = inode->sbi->packedinode;
#ifdef HAVE_FTELLO64
	off64_t offset = ftello64(epi->file);
#else
	off_t offset = ftello(epi->file);
#endif
	int ret;

	if (offset < 0)
		return -errno;

	inode->fragmentoff = (erofs_off_t)offset;
	inode->fragment_size = len;

	if (fwrite(data, len, 1, epi->file) != 1)
		return -EIO;

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

	fflush(epi->file);
	if (!ftello(epi->file))
		return 0;
	inode = erofs_mkfs_build_special_from_fd(sbi, fileno(epi->file),
						 EROFS_PACKED_INODE);
	sbi->packed_nid = erofs_lookupnid(inode);
	erofs_iput(inode);
	return 0;
}

FILE *erofs_packedfile(struct erofs_sb_info *sbi)
{
	return sbi->packedinode->file;
}

void erofs_packedfile_exit(struct erofs_sb_info *sbi)
{
	struct erofs_packed_inode *epi = sbi->packedinode;
	struct erofs_fragment_dedupe_item *di, *n;
	int i;

	if (!epi)
		return;

	if (epi->hash) {
		for (i = 0; i < FRAGMENT_HASHSIZE; ++i)
			list_for_each_entry_safe(di, n, &epi->hash[i], list)
				free(di);
		free(epi->hash);
	}

	if (epi->file)
		fclose(epi->file);
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

	epi->file =
#ifdef HAVE_TMPFILE64
		tmpfile64();
#else
		tmpfile();
#endif
	if (!epi->file) {
		err = -errno;
		goto err_out;
	}
	return 0;

err_out:
	erofs_packedfile_exit(sbi);
	return err;
}
