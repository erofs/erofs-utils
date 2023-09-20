// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
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
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "erofs/io.h"
#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>
#endif
#ifdef HAVE_LINUX_FALLOC_H
#include <linux/falloc.h>
#endif
#ifdef HAVE_SYS_STATFS_H
#include <sys/statfs.h>
#endif
#define EROFS_MODNAME	"erofs_io"
#include "erofs/print.h"

static int dev_get_blkdev_size(int fd, u64 *bytes)
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

void dev_close(struct erofs_sb_info *sbi)
{
	close(sbi->devfd);
	free(sbi->devname);
	sbi->devname = NULL;
	sbi->devfd   = -1;
	sbi->devsz   = 0;
}

int dev_open(struct erofs_sb_info *sbi, const char *dev)
{
	struct stat st;
	int fd, ret;

#if defined(HAVE_SYS_STATFS_H) && defined(HAVE_FSTATFS)
	bool again = false;

repeat:
#endif
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
		ret = dev_get_blkdev_size(fd, &sbi->devsz);
		if (ret) {
			erofs_err("failed to get block device size(%s).", dev);
			close(fd);
			return ret;
		}
		sbi->devsz = round_down(sbi->devsz, erofs_blksiz(sbi));
		break;
	case S_IFREG:
		if (st.st_size) {
#if defined(HAVE_SYS_STATFS_H) && defined(HAVE_FSTATFS)
			struct statfs stfs;

			if (again)
				return -ENOTEMPTY;

			/*
			 * fses like EXT4 and BTRFS will flush dirty blocks
			 * after truncate(0) even after the writeback happens
			 * (see kernel commit 7d8f9f7d150d and ccd2506bd431),
			 * which is NOT our intention.  Let's work around this.
			 */
			if (!fstatfs(fd, &stfs) && (stfs.f_type == 0xEF53 ||
					stfs.f_type == 0x9123683E)) {
				close(fd);
				unlink(dev);
				again = true;
				goto repeat;
			}
#endif
			ret = ftruncate(fd, 0);
			if (ret) {
				erofs_err("failed to ftruncate(%s).", dev);
				close(fd);
				return -errno;
			}
		}
		/* INT64_MAX is the limit of kernel vfs */
		sbi->devsz = INT64_MAX;
		sbi->devblksz = st.st_blksize;
		break;
	default:
		erofs_err("bad file type (%s, %o).", dev, st.st_mode);
		close(fd);
		return -EINVAL;
	}

	sbi->devname = strdup(dev);
	if (!sbi->devname) {
		close(fd);
		return -ENOMEM;
	}
	sbi->devfd = fd;

	erofs_info("successfully to open %s", dev);
	return 0;
}

void blob_closeall(struct erofs_sb_info *sbi)
{
	unsigned int i;

	for (i = 0; i < sbi->nblobs; ++i)
		close(sbi->blobfd[i]);
	sbi->nblobs = 0;
}

int blob_open_ro(struct erofs_sb_info *sbi, const char *dev)
{
	int fd = open(dev, O_RDONLY | O_BINARY);

	if (fd < 0) {
		erofs_err("failed to open(%s).", dev);
		return -errno;
	}

	sbi->blobfd[sbi->nblobs] = fd;
	erofs_info("successfully to open blob%u %s", sbi->nblobs, dev);
	++sbi->nblobs;
	return 0;
}

/* XXX: temporary soluation. Disk I/O implementation needs to be refactored. */
int dev_open_ro(struct erofs_sb_info *sbi, const char *dev)
{
	int fd = open(dev, O_RDONLY | O_BINARY);

	if (fd < 0) {
		erofs_err("failed to open(%s).", dev);
		return -errno;
	}

	sbi->devname = strdup(dev);
	if (!sbi->devname) {
		close(fd);
		return -ENOMEM;
	}
	sbi->devfd = fd;
	sbi->devsz = INT64_MAX;
	return 0;
}

int dev_write(struct erofs_sb_info *sbi, const void *buf, u64 offset, size_t len)
{
	int ret;

	if (cfg.c_dry_run)
		return 0;

	if (!buf) {
		erofs_err("buf is NULL");
		return -EINVAL;
	}

	if (offset >= sbi->devsz || len > sbi->devsz ||
	    offset > sbi->devsz - len) {
		erofs_err("Write posion[%" PRIu64 ", %zd] is too large beyond the end of device(%" PRIu64 ").",
			  offset, len, sbi->devsz);
		return -EINVAL;
	}

#ifdef HAVE_PWRITE64
	ret = pwrite64(sbi->devfd, buf, len, (off64_t)offset);
#else
	ret = pwrite(sbi->devfd, buf, len, (off_t)offset);
#endif
	if (ret != (int)len) {
		if (ret < 0) {
			erofs_err("Failed to write data into device - %s:[%" PRIu64 ", %zd].",
				  sbi->devname, offset, len);
			return -errno;
		}

		erofs_err("Writing data into device - %s:[%" PRIu64 ", %zd] - was truncated.",
			  sbi->devname, offset, len);
		return -ERANGE;
	}
	return 0;
}

int dev_fillzero(struct erofs_sb_info *sbi, u64 offset, size_t len, bool padding)
{
	static const char zero[EROFS_MAX_BLOCK_SIZE] = {0};
	int ret;

	if (cfg.c_dry_run)
		return 0;

#if defined(HAVE_FALLOCATE) && defined(FALLOC_FL_PUNCH_HOLE)
	if (!padding && fallocate(sbi->devfd, FALLOC_FL_PUNCH_HOLE |
				  FALLOC_FL_KEEP_SIZE, offset, len) >= 0)
		return 0;
#endif
	while (len > erofs_blksiz(sbi)) {
		ret = dev_write(sbi, zero, offset, erofs_blksiz(sbi));
		if (ret)
			return ret;
		len -= erofs_blksiz(sbi);
		offset += erofs_blksiz(sbi);
	}
	return dev_write(sbi, zero, offset, len);
}

int dev_fsync(struct erofs_sb_info *sbi)
{
	int ret;

	ret = fsync(sbi->devfd);
	if (ret) {
		erofs_err("Could not fsync device!!!");
		return -EIO;
	}
	return 0;
}

int dev_resize(struct erofs_sb_info *sbi, unsigned int blocks)
{
	int ret;
	struct stat st;
	u64 length;

	if (cfg.c_dry_run || sbi->devsz != INT64_MAX)
		return 0;

	ret = fstat(sbi->devfd, &st);
	if (ret) {
		erofs_err("failed to fstat.");
		return -errno;
	}

	length = (u64)blocks * erofs_blksiz(sbi);
	if (st.st_size == length)
		return 0;
	if (st.st_size > length)
		return ftruncate(sbi->devfd, length);

	length = length - st.st_size;
#if defined(HAVE_FALLOCATE)
	if (fallocate(sbi->devfd, 0, st.st_size, length) >= 0)
		return 0;
#endif
	return dev_fillzero(sbi, st.st_size, length, true);
}

int dev_read(struct erofs_sb_info *sbi, int device_id,
	     void *buf, u64 offset, size_t len)
{
	int read_count, fd;

	if (cfg.c_dry_run)
		return 0;

	offset += cfg.c_offset;

	if (!buf) {
		erofs_err("buf is NULL");
		return -EINVAL;
	}

	if (!device_id) {
		fd = sbi->devfd;
	} else {
		if (device_id > sbi->nblobs) {
			erofs_err("invalid device id %d", device_id);
			return -ENODEV;
		}
		fd = sbi->blobfd[device_id - 1];
	}

	while (len > 0) {
#ifdef HAVE_PREAD64
		read_count = pread64(fd, buf, len, (off64_t)offset);
#else
		read_count = pread(fd, buf, len, (off_t)offset);
#endif
		if (read_count < 1) {
			if (!read_count) {
				erofs_info("Reach EOF of device - %s:[%" PRIu64 ", %zd].",
					   sbi->devname, offset, len);
				memset(buf, 0, len);
				return 0;
			} else if (errno != EINTR) {
				erofs_err("Failed to read data from device - %s:[%" PRIu64 ", %zd].",
					  sbi->devname, offset, len);
				return -errno;
			}
		}
		offset += read_count;
		len -= read_count;
		buf += read_count;
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
	if (errno != ENOSYS && errno != EXDEV) {
		ret = -errno;
out:
		*off_in = off64_in;
		*off_out = off64_out;
		return ret;
	}
#endif
	return __erofs_copy_file_range(fd_in, off_in, fd_out, off_out, length);
}
