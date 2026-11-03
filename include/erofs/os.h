/* SPDX-License-Identifier: GPL-2.0+ OR MIT */
#ifndef __EROFS_OS_H
#define __EROFS_OS_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/*
 * The file position after erofs_os_pread() or erofs_os_pwrite() is undefined.
 * Use lseek() before subsequent read() or write().
 */
#if defined(_WIN32) && !defined(__CYGWIN__)
#include "windows_compat.h"
#else
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif

/* Keep the native stat layout on POSIX hosts. */
typedef struct stat erofs_os_stat_t;

#define erofs_os_stat		stat
#define erofs_os_lstat		lstat
#define erofs_os_fstat		fstat
#define erofs_os_open		open
#define erofs_os_link		link
#define erofs_os_pread		pread
#define erofs_os_pwrite		pwrite
#define erofs_os_realpath	realpath
#define erofs_os_strndup	strndup
#define erofs_os_getpagesize	getpagesize
#define erofs_os_fsync		fsync
#define erofs_os_mkdir		mkdir
#define erofs_os_getuid		getuid
#define erofs_os_geteuid	geteuid
#define erofs_os_getgid		getgid
#define erofs_os_getegid	getegid
#define erofs_os_lchown		lchown
#define erofs_os_readlink	readlink
#define erofs_os_symlink	symlink
#define erofs_os_mknod		mknod
#define erofs_os_major		major
#define erofs_os_minor		minor
#define erofs_os_makedev	makedev

#endif

/* Return a temporary file descriptor or a negative errno. */
int erofs_os_tmpfile(void);

#endif
