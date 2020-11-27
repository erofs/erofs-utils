// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/fuse/dir.c
 *
 * Created by Li Guifu <blucerlee@gmail.com>
 */
#include <fuse.h>
#include <fuse_opt.h>

#include "erofs/internal.h"
#include "erofs/print.h"

static int erofs_fill_dentries(struct erofs_inode *dir,
			       fuse_fill_dir_t filler, void *buf,
			       void *dblk, unsigned int nameoff,
			       unsigned int maxsize)
{
	struct erofs_dirent *de = dblk;
	const struct erofs_dirent *end = dblk + nameoff;
	char namebuf[EROFS_NAME_LEN + 1];

	while (de < end) {
		const char *de_name;
		unsigned int de_namelen;

		nameoff = le16_to_cpu(de->nameoff);
		de_name = (char *)dblk + nameoff;

		/* the last dirent in the block? */
		if (de + 1 >= end)
			de_namelen = strnlen(de_name, maxsize - nameoff);
		else
			de_namelen = le16_to_cpu(de[1].nameoff) - nameoff;

		/* a corrupted entry is found */
		if (nameoff + de_namelen > maxsize ||
		    de_namelen > EROFS_NAME_LEN) {
			erofs_err("bogus dirent @ nid %llu", dir->nid | 0ULL);
			DBG_BUGON(1);
			return -EFSCORRUPTED;
		}

		memcpy(namebuf, de_name, de_namelen);
		namebuf[de_namelen] = '\0';

		filler(buf, namebuf, NULL, 0);
		++de;
	}
	return 0;
}

int erofsfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		      off_t offset, struct fuse_file_info *fi)
{
	int ret;
	struct erofs_inode dir;
	char dblk[EROFS_BLKSIZ];
	erofs_off_t pos;

	erofs_dbg("readdir:%s offset=%llu", path, (long long)offset);

	ret = erofs_ilookup(path, &dir);
	if (ret)
		return ret;

	erofs_dbg("path=%s nid = %llu", path, dir.nid | 0ULL);

	if (!S_ISDIR(dir.i_mode))
		return -ENOTDIR;

	if (!dir.i_size)
		return 0;

	pos = 0;
	while (pos < dir.i_size) {
		unsigned int nameoff, maxsize;
		struct erofs_dirent *de;

		maxsize = min_t(unsigned int, EROFS_BLKSIZ,
				dir.i_size - pos);
		ret = erofs_pread(&dir, dblk, maxsize, pos);
		if (ret)
			return ret;

		de = (struct erofs_dirent *)dblk;
		nameoff = le16_to_cpu(de->nameoff);
		if (nameoff < sizeof(struct erofs_dirent) ||
		    nameoff >= PAGE_SIZE) {
			erofs_err("invalid de[0].nameoff %u @ nid %llu",
				  nameoff, dir.nid | 0ULL);
			ret = -EFSCORRUPTED;
			break;
		}

		ret = erofs_fill_dentries(&dir, filler, buf,
					  dblk, nameoff, maxsize);
		if (ret)
			break;
		pos += maxsize;
	}
	return 0;
}

