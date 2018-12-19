// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs_io.c
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "erofs_io.h"
#include "mkfs_erofs.h"

#define pr_fmt(fmt) "DEVICE IO: " FUNC_LINE_FMT fmt "\n"
#include "erofs_debug.h"

static const char *erofs_devname;
static int erofs_devfd = -1;
static u64 erofs_devsz;

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

	fd = open(dev, O_RDWR | O_CREAT, 0644);
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

	switch(st.st_mode & S_IFMT) {
	case S_IFBLK:
		erofs_devsz = st.st_size;
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
	erofs_devsz = round_down(erofs_devsz, EROFS_BLKSIZE);

	erofs_info("successfully to open %s", dev);
	return 0;
}

u64 dev_length(void)
{
	return erofs_devsz;
}

int dev_write(void *buf, u64 offset, size_t len)
{
	int ret;

	if (erofs_cfg.c_dry_run)
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

int dev_write_block(void *buf, u32 blkaddr)
{
	erofs_info("Write data to block %u", blkaddr);

	return dev_write(buf, blknr_to_addr(blkaddr), EROFS_BLKSIZE);
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
