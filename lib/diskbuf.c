// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include "erofs/diskbuf.h"
#include "erofs/internal.h"
#include "erofs/print.h"
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

/* A simple approach to avoid creating too many temporary files */
static struct erofs_diskbufstrm {
	u64 count;
	u64 tailoffset, devpos;
	int fd;
	unsigned int alignsize;
	bool locked;
} *dbufstrm;

int erofs_diskbuf_getfd(struct erofs_diskbuf *db, u64 *fpos)
{
	const struct erofs_diskbufstrm *strm = db->sp;
	u64 offset;

	if (!strm)
		return -1;
	offset = db->offset + strm->devpos;
	if (lseek(strm->fd, offset, SEEK_SET) != offset)
		return -E2BIG;
	if (fpos)
		*fpos = offset;
	return strm->fd;
}

int erofs_diskbuf_reserve(struct erofs_diskbuf *db, int sid, u64 *off)
{
	struct erofs_diskbufstrm *strm = dbufstrm + sid;

	if (strm->tailoffset & (strm->alignsize - 1)) {
		strm->tailoffset = round_up(strm->tailoffset, strm->alignsize);
		if (lseek(strm->fd, strm->tailoffset + strm->devpos,
			  SEEK_SET) != strm->tailoffset + strm->devpos)
			return -EIO;
	}
	db->offset = strm->tailoffset;
	if (off)
		*off = db->offset + strm->devpos;
	db->sp = strm;
	++strm->count;
	strm->locked = true;	/* TODO: need a real lock for MT */
	return strm->fd;
}

void erofs_diskbuf_commit(struct erofs_diskbuf *db, u64 len)
{
	struct erofs_diskbufstrm *strm = db->sp;

	DBG_BUGON(!strm);
	DBG_BUGON(!strm->locked);
	DBG_BUGON(strm->tailoffset != db->offset);
	strm->tailoffset += len;
}

void erofs_diskbuf_close(struct erofs_diskbuf *db)
{
	struct erofs_diskbufstrm *strm = db->sp;

	DBG_BUGON(!strm);
	DBG_BUGON(strm->count <= 1);
	--strm->count;
	db->sp = NULL;
}

int erofs_tmpfile(void)
{
#define	TRAILER		"tmp.XXXXXXXXXX"
	char buf[PATH_MAX];
	int fd;
	umode_t u;

	(void)snprintf(buf, sizeof(buf), "%s/" TRAILER,
		       getenv("TMPDIR") ?: "/tmp");

	fd = mkstemp(buf);
	if (fd < 0)
		return -errno;

	unlink(buf);
	u = umask(0);
	(void)umask(u);
	(void)fchmod(fd, 0666 & ~u);
	return fd;
}

int erofs_diskbuf_init(unsigned int nstrms)
{
	struct erofs_diskbufstrm *strm;

	strm = calloc(nstrms + 1, sizeof(*strm));
	if (!strm)
		return -ENOMEM;
	strm[nstrms].fd = -1;
	dbufstrm = strm;

	for (; strm < dbufstrm + nstrms; ++strm) {
		struct stat st;

		/* try to use the devfd for regfiles on stream 0 */
		if (strm == dbufstrm && sbi.devsz == INT64_MAX) {
			strm->devpos = 1ULL << 40;
			if (!ftruncate(sbi.devfd, strm->devpos << 1)) {
				strm->fd = dup(sbi.devfd);
				if (lseek(strm->fd, strm->devpos,
					  SEEK_SET) != strm->devpos)
					return -EIO;
				goto setupone;
			}
		}
		strm->devpos = 0;
		strm->fd = erofs_tmpfile();
		if (strm->fd < 0)
			return -ENOSPC;
setupone:
		strm->tailoffset = 0;
		strm->count = 1;
		if (fstat(strm->fd, &st))
			return -errno;
		strm->alignsize = max_t(u32, st.st_blksize, getpagesize());
	}
	return 0;
}

void erofs_diskbuf_exit(void)
{
	struct erofs_diskbufstrm *strm;

	if (!dbufstrm)
		return;

	for (strm = dbufstrm; strm->fd >= 0; ++strm) {
		DBG_BUGON(strm->count != 1);

		close(strm->fd);
		strm->fd = -1;
	}
}
