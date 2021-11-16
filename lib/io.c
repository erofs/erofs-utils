// SPDX-License-Identifier: GPL-2.0+
/*
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

#define EROFS_MODNAME	"erofs_io"
#include "erofs/print.h"

static const char *erofs_devname;
int erofs_devfd = -1;
static u64 erofs_devsz;
static unsigned int erofs_nblobs, erofs_blobfd[256];

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

void blob_closeall(void)
{
	unsigned int i;

	for (i = 0; i < erofs_nblobs; ++i)
		close(erofs_blobfd[i]);
	erofs_nblobs = 0;
}

int blob_open_ro(const char *dev)
{
	int fd = open(dev, O_RDONLY | O_BINARY);

	if (fd < 0) {
		erofs_err("failed to open(%s).", dev);
		return -errno;
	}

	erofs_blobfd[erofs_nblobs] = fd;
	erofs_info("successfully to open blob%u %s", erofs_nblobs, dev);
	++erofs_nblobs;
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

#ifdef HAVE_PWRITE64
	ret = pwrite64(erofs_devfd, buf, len, (off64_t)offset);
#else
	ret = pwrite(erofs_devfd, buf, len, (off_t)offset);
#endif
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

int dev_read(int device_id, void *buf, u64 offset, size_t len)
{
	int ret, fd;

	if (cfg.c_dry_run)
		return 0;

	if (!buf) {
		erofs_err("buf is NULL");
		return -EINVAL;
	}

	if (!device_id) {
		fd = erofs_devfd;
	} else {
		if (device_id > erofs_nblobs) {
			erofs_err("invalid device id %d", device_id);
			return -ENODEV;
		}
		fd = erofs_blobfd[device_id - 1];
	}

#ifdef HAVE_PREAD64
	ret = pread64(fd, buf, len, (off64_t)offset);
#else
	ret = pread(fd, buf, len, (off_t)offset);
#endif
	if (ret != (int)len) {
		erofs_err("Failed to read data from device - %s:[%" PRIu64 ", %zd].",
			  erofs_devname, offset, len);
		return -errno;
	}
	return 0;
}

static ssize_t __erofs_copy_file_range(int fd_in, erofs_off_t *off_in,
				       int fd_out, erofs_off_t *off_out,
				       size_t length)
{
	size_t copied = 0;
	char buf[8192];

	/*
	 * Main copying loop.  The buffer size is arbitrary and is a
	 * trade-off between stack size consumption, cache usage, and
	 * amortization of system call overhead.
	 */
	while (length > 0) {
		size_t to_read;
		ssize_t read_count;
		char *end, *p;

		to_read = min_t(size_t, length, sizeof(buf));
#ifdef HAVE_PREAD64
		read_count = pread64(fd_in, buf, to_read, *off_in);
#else
		read_count = pread(fd_in, buf, to_read, *off_in);
#endif
		if (read_count == 0)
			/* End of file reached prematurely. */
			return copied;
		if (read_count < 0) {
			/* Report the number of bytes copied so far. */
			if (copied > 0)
				return copied;
			return -1;
		}
		*off_in += read_count;

		/* Write the buffer part which was read to the destination. */
		end = buf + read_count;
		for (p = buf; p < end; ) {
			ssize_t write_count;

#ifdef HAVE_PWRITE64
			write_count = pwrite64(fd_out, p, end - p, *off_out);
#else
			write_count = pwrite(fd_out, p, end - p, *off_out);
#endif
			if (write_count < 0) {
				/*
				 * Adjust the input read position to match what
				 * we have written, so that the caller can pick
				 * up after the error.
				 */
				size_t written = p - buf;
				/*
				 * NB: This needs to be signed so that we can
				 * form the negative value below.
				 */
				ssize_t overread = read_count - written;

				*off_in -= overread;
				/* Report the number of bytes copied so far. */
				if (copied + written > 0)
					return copied + written;
				return -1;
			}
			p += write_count;
			*off_out += write_count;
		} /* Write loop.  */
		copied += read_count;
		length -= read_count;
	}
	return copied;
}

ssize_t erofs_copy_file_range(int fd_in, erofs_off_t *off_in,
			      int fd_out, erofs_off_t *off_out,
			      size_t length)
{
#ifdef HAVE_COPY_FILE_RANGE
	off64_t off64_in = *off_in, off64_out = *off_out;
	ssize_t ret;

	ret = copy_file_range(fd_in, &off64_in, fd_out, &off64_out,
                              length, 0);
	if (ret >= 0)
		goto out;
	if (errno != ENOSYS) {
		ret = -errno;
out:
		*off_in = off64_in;
		*off_out = off64_out;
		return ret;
	}
#endif
	return __erofs_copy_file_range(fd_in, off_in, fd_out, off_out, length);
}
