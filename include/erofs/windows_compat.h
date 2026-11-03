/* SPDX-License-Identifier: GPL-2.0+ OR MIT */
#ifndef __EROFS_WINDOWS_COMPAT_H
#define __EROFS_WINDOWS_COMPAT_H

/* Native MinGW builds; Cygwin uses its own POSIX interfaces. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>
#include <direct.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#ifndef S_IFBLK
#define S_IFBLK 0060000
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_ISLNK
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif
#ifndef S_ISBLK
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif
#ifndef S_ISUID
#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISVTX 01000
#endif

struct iovec {
	void *iov_base;
	size_t iov_len;
};

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0x10000000
#endif

/* The CRT's stat has a truncated inode number and no block size. */
typedef struct {
	uint64_t st_ino;
	dev_t st_dev, st_rdev;
	mode_t st_mode;
	unsigned int st_nlink, st_uid, st_gid;
	off_t st_size;
	struct timespec st_atim, st_mtim, st_ctim;
	unsigned int st_blksize;
	uint64_t st_blocks;
} erofs_os_stat_t;

#ifndef st_atime
#define st_atime st_atim.tv_sec
#endif
#ifndef st_mtime
#define st_mtime st_mtim.tv_sec
#endif
#ifndef st_ctime
#define st_ctime st_ctim.tv_sec
#endif

int erofs_os_stat(const char *path, erofs_os_stat_t *st);
int erofs_os_lstat(const char *path, erofs_os_stat_t *st);
int erofs_os_fstat(int fd, erofs_os_stat_t *st);
int erofs_os_open(const char *path, int flags, ...);
int erofs_os_link(const char *oldpath, const char *newpath);
ssize_t erofs_os_pread(int fd, void *buf, size_t len, off_t offset);
ssize_t erofs_os_pwrite(int fd, const void *buf, size_t len, off_t offset);
char *erofs_os_realpath(const char *path, char *resolved);
char *erofs_os_strndup(const char *s, size_t len);
int erofs_win_random(void *buf, unsigned int len);
int erofs_os_getpagesize(void);
int erofs_win_unsupported(void);

static inline int erofs_os_fsync(int fd)
{
	return _commit(fd);
}
static inline int erofs_os_mkdir(const char *path, mode_t mode)
{
	return _mkdir(path);
}

static inline unsigned int erofs_os_getuid(void)
{
	return 0;
}

static inline unsigned int erofs_os_geteuid(void)
{
	return 0;
}

static inline unsigned int erofs_os_getgid(void)
{
	return 0;
}

static inline unsigned int erofs_os_getegid(void)
{
	return 0;
}

static inline int erofs_os_lchown(const char *path, unsigned int uid,
				  unsigned int gid)
{
	return erofs_win_unsupported();
}

static inline ssize_t erofs_os_readlink(const char *path, char *buf, size_t len)
{
	return erofs_win_unsupported();
}

static inline int erofs_os_symlink(const char *target, const char *path)
{
	return erofs_win_unsupported();
}

static inline int erofs_os_mknod(const char *path, mode_t mode, dev_t dev)
{
	return erofs_win_unsupported();
}

/* Linux device encoding is used for image metadata, not Windows devices. */
static inline unsigned int erofs_os_major(dev_t dev)
{
	return (dev >> 8) & 0xfff;
}

static inline unsigned int erofs_os_minor(dev_t dev)
{
	return (dev & 0xff) | ((dev >> 12) & 0xfff00);
}

static inline dev_t erofs_os_makedev(unsigned int maj, unsigned int min)
{
	return (min & 0xff) | ((maj & 0xfff) << 8) | ((min & 0xfff00) << 12);
}

#endif
