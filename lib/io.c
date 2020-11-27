// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/io.c
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "erofs/io.h"
#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>
#endif
#ifdef HAVE_LINUX_FALLOC_H
#include <linux/falloc.h>
#endif

#define pr_fmt(fmt) "EROFS IO: " FUNC_LINE_FMT fmt "\n"
#include "erofs/print.h"

static const char *erofs_devname;
static int erofs_devfd = -1;
static u64 erofs_devsz;

int dev_get_blkdev_size(int fd, u64 *bytes)
{
	errno = ENOTSUP;
#ifdef BLKGETSIZE64
	if (ioctl(fd, BLKGETSIZE64, bytes) >= 0)
		return 0;
#endif

#ifdef BLKGETSIZE
	{
		unsigned long size;
		if (ioctl(fd, BLKGETSIZE, &size) >= 0) {
			*bytes = ((u64)size << 9);
			return 0;
		}
	}
#endif
	return -errno;
}

void dev_close(void)
{
	close(erofs_devfd);
	erofs_devname = NULL;
	erofs_devfd   = -1;
	erofs_devsz   = 0;
}

int dev_open(const char *dev)
{
	struct stat st;
	int fd, ret;

	fd = open(dev, O_RDWR | O_CREAT | O_BINARY, 0644);
	if (fd < 0) {
		erofs_err("failed to open(%s).", dev);
		return -errno;
	}

	ret = fstat(fd, &st);
	if (ret) {
		erofs_err("failed to fstat(%s).", dev);
		close(fd);
		return -errno;
	}

	switch (st.st_mode & S_IFMT) {
	case S_IFBLK:
		ret = dev_get_blkdev_size(fd, &erofs_devsz);
		if (ret) {
			erofs_err("failed to get block device size(%s).", dev);
			close(fd);
			return ret;
		}
		erofs_devsz = round_down(erofs_devsz, EROFS_BLKSIZ);
		break;
	case S_IFREG:
		ret = ftruncate(fd, 0);
		if (ret) {
			erofs_err("failed to ftruncate(%s).", dev);
			close(fd);
			return -errno;
		}
		/* INT64_MAX is the limit of kernel vfs */
		erofs_devsz = INT64_MAX;
		break;
	default:
		erofs_err("bad file type (%s, %o).", dev, st.st_mode);
		close(fd);
		return -EINVAL;
	}

	erofs_devname = dev;
	erofs_devfd = fd;

	erofs_info("successfully to open %s", dev);
	return 0;
}

/* XXX: temporary soluation. Disk I/O implementation needs to be refactored. */
int dev_open_ro(const char *dev)
{
	int fd = open(dev, O_RDONLY | O_BINARY);

	if (fd < 0) {
		erofs_err("failed to open(%s).", dev);
		return -errno;
	}

	erofs_devfd = fd;
	erofs_devname = dev;
	erofs_devsz = INT64_MAX;
	return 0;
}

u64 dev_length(void)
{
	return erofs_devsz;
}

int dev_write(const void *buf, u64 offset, size_t len)
{
	int ret;

	if (cfg.c_dry_run)
		return 0;

	if (!buf) {
		erofs_err("buf is NULL");
		return -EINVAL;
	}

	if (offset >= erofs_devsz || len > erofs_devsz ||
	    offset > erofs_devsz - len) {
		erofs_err("Write posion[%" PRIu64 ", %zd] is too large beyond the end of device(%" PRIu64 ").",
			  offset, len, erofs_devsz);
		return -EINVAL;
	}

	ret = pwrite64(erofs_devfd, buf, len, (off64_t)offset);
	if (ret != (int)len) {
		if (ret < 0) {
			erofs_err("Failed to write data into device - %s:[%" PRIu64 ", %zd].",
				  erofs_devname, offset, len);
			return -errno;
		}

		erofs_err("Writing data into device - %s:[%" PRIu64 ", %zd] - was truncated.",
			  erofs_devname, offset, len);
		return -ERANGE;
	}
	return 0;
}

int dev_fillzero(u64 offset, size_t len, bool padding)
{
	static const char zero[EROFS_BLKSIZ] = {0};
	int ret;

	if (cfg.c_dry_run)
		return 0;

#if defined(HAVE_FALLOCATE) && defined(FALLOC_FL_PUNCH_HOLE)
	if (!padding && fallocate(erofs_devfd, FALLOC_FL_PUNCH_HOLE |
				  FALLOC_FL_KEEP_SIZE, offset, len) >= 0)
		return 0;
#endif
	while (len > EROFS_BLKSIZ) {
		ret = dev_write(zero, offset, EROFS_BLKSIZ);
		if (ret)
			return ret;
		len -= EROFS_BLKSIZ;
		offset += EROFS_BLKSIZ;
	}
	return dev_write(zero, offset, len);
}

int dev_fsync(void)
{
	int ret;

	ret = fsync(erofs_devfd);
	if (ret) {
		erofs_err("Could not fsync device!!!");
		return -EIO;
	}
	return 0;
}

int dev_resize(unsigned int blocks)
{
	int ret;
	struct stat st;
	u64 length;

	if (cfg.c_dry_run || erofs_devsz != INT64_MAX)
		return 0;

	ret = fstat(erofs_devfd, &st);
	if (ret) {
		erofs_err("failed to fstat.");
		return -errno;
	}

	length = (u64)blocks * EROFS_BLKSIZ;
	if (st.st_size == length)
		return 0;
	if (st.st_size > length)
		return ftruncate(erofs_devfd, length);

	length = length - st.st_size;
#if defined(HAVE_FALLOCATE)
	if (fallocate(erofs_devfd, 0, st.st_size, length) >= 0)
		return 0;
#endif
	return dev_fillzero(st.st_size, length, true);
}

int dev_read(void *buf, u64 offset, size_t len)
{
	int ret;

	if (cfg.c_dry_run)
		return 0;

	if (!buf) {
		erofs_err("buf is NULL");
		return -EINVAL;
	}
	if (offset >= erofs_devsz || len > erofs_devsz ||
	    offset > erofs_devsz - len) {
		erofs_err("read posion[%" PRIu64 ", %zd] is too large beyond"
			  "the end of device(%" PRIu64 ").",
			  offset, len, erofs_devsz);
		return -EINVAL;
	}

	ret = pread64(erofs_devfd, buf, len, (off64_t)offset);
	if (ret != (int)len) {
		erofs_err("Failed to read data from device - %s:[%" PRIu64 ", %zd].",
			  erofs_devname, offset, len);
		return -errno;
	}
	return 0;
}
