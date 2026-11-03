// SPDX-License-Identifier: GPL-2.0+ OR MIT
#include <config.h>
#include "erofs/os.h"
#include <bcrypt.h>
#include <string.h>

static int erofs_err_win_to_posix(DWORD error)
{
	switch (error) {
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
		return ENOENT;
	case ERROR_ACCESS_DENIED:
	case ERROR_SHARING_VIOLATION:
		return EACCES;
	case ERROR_INVALID_HANDLE:
		return EBADF;
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_OUTOFMEMORY:
		return ENOMEM;
	case ERROR_DISK_FULL:
		return ENOSPC;
	case ERROR_INVALID_PARAMETER:
		return EINVAL;
	case ERROR_FILE_EXISTS:
	case ERROR_ALREADY_EXISTS:
		return EEXIST;
	case ERROR_DIRECTORY:
		return ENOTDIR;
	default:
		return EIO;
	}
}

int erofs_win_unsupported(void)
{
	errno = EOPNOTSUPP;
	return -1;
}

/*
 * The unit of FILETIME is 100-nanoseconds since January 1, 1601, UTC.
 * Returns the 100-nanoseconds ("hekto nanoseconds") since the epoch.
 */
static inline long long filetime_to_hnsec(const FILETIME *ft)
{
	long long winTime = ((long long)ft->dwHighDateTime << 32) +
			   ft->dwLowDateTime;

	/* Windows to Unix Epoch conversion */
	return winTime - 116444736000000000LL;
}

static inline void filetime_to_timespec(const FILETIME *ft, struct timespec *ts)
{
	long long hnsec = filetime_to_hnsec(ft);

	ts->tv_sec = (time_t)(hnsec / 10000000);
	ts->tv_nsec = (hnsec % 10000000) * 100;
}

static int erofs_win_handle_stat(HANDLE h, erofs_os_stat_t *st)
{
	BY_HANDLE_FILE_INFORMATION info;
	DWORD type = GetFileType(h);

	if (type == FILE_TYPE_PIPE || type == FILE_TYPE_CHAR) {
		memset(st, 0, sizeof(*st));
		st->st_mode = (type == FILE_TYPE_PIPE ? S_IFIFO : S_IFCHR) | 0600;
		st->st_blksize = 4096;
		return 0;
	}

	if (!GetFileInformationByHandle(h, &info)) {
		errno = erofs_err_win_to_posix(GetLastError());
		return -1;
	}
	memset(st, 0, sizeof(*st));
	st->st_dev = info.dwVolumeSerialNumber;
	st->st_ino = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
	st->st_nlink = info.nNumberOfLinks;
	st->st_size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
	st->st_mode = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ?
		S_IFDIR | 0755 : S_IFREG | 0644;
	if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
		st->st_mode &= ~0222;
	filetime_to_timespec(&info.ftLastAccessTime, &st->st_atim);
	filetime_to_timespec(&info.ftLastWriteTime, &st->st_mtim);
	filetime_to_timespec(&info.ftCreationTime, &st->st_ctim);
	st->st_blksize = 4096;
	st->st_blocks = (st->st_size + 511) / 512;
	return 0;
}

int erofs_os_stat(const char *path, erofs_os_stat_t *st)
{
	HANDLE h;
	int ret;

	h = CreateFileA(path, FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		errno = erofs_err_win_to_posix(GetLastError());
		return -1;
	}
	ret = erofs_win_handle_stat(h, st);
	CloseHandle(h);
	return ret;
}

int erofs_os_fstat(int fd, erofs_os_stat_t *st)
{
	return erofs_win_handle_stat((HANDLE)_get_osfhandle(fd), st);
}

int erofs_os_lstat(const char *path, erofs_os_stat_t *st)
{
	DWORD attr = GetFileAttributesA(path);

	if (attr == INVALID_FILE_ATTRIBUTES) {
		errno = erofs_err_win_to_posix(GetLastError());
		return -1;
	}
	/* Do not follow junctions or symbolic links while walking a source tree. */
	if (attr & FILE_ATTRIBUTE_REPARSE_POINT)
		return erofs_win_unsupported();
	return erofs_os_stat(path, st);
}

int erofs_os_open(const char *path, int flags, ...)
{
	DWORD access = GENERIC_READ, creation = OPEN_EXISTING;
	HANDLE h;
	int fd;

	if ((flags & O_ACCMODE) == O_WRONLY)
		access = GENERIC_WRITE;
	else if ((flags & O_ACCMODE) == O_RDWR)
		access |= GENERIC_WRITE;
	if (flags & O_CREAT)
		creation = flags & O_EXCL ? CREATE_NEW : OPEN_ALWAYS;
	h = CreateFileA(path, access,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		creation, flags & O_NOFOLLOW ? FILE_FLAG_OPEN_REPARSE_POINT : 0,
		NULL);
	if (h == INVALID_HANDLE_VALUE) {
		errno = erofs_err_win_to_posix(GetLastError());
		return -1;
	}
	if (flags & O_NOFOLLOW) {
		BY_HANDLE_FILE_INFORMATION info;

		if (!GetFileInformationByHandle(h, &info)) {
			DWORD error = GetLastError();

			CloseHandle(h);
			errno = erofs_err_win_to_posix(error);
			return -1;
		}
		if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
			CloseHandle(h);
			errno = ELOOP;
			return -1;
		}
	}
	if ((flags & O_TRUNC) && !SetEndOfFile(h)) {
		DWORD error = GetLastError();

		CloseHandle(h);
		errno = erofs_err_win_to_posix(error);
		return -1;
	}
	fd = _open_osfhandle((intptr_t)h,
		(flags & (O_ACCMODE | O_APPEND)) | O_BINARY);
	if (fd < 0)
		CloseHandle(h);
	return fd;
}

int erofs_os_link(const char *oldpath, const char *newpath)
{
	if (CreateHardLinkA(newpath, oldpath, NULL))
		return 0;
	errno = erofs_err_win_to_posix(GetLastError());
	return -1;
}

static ssize_t erofs_win_pio(int fd, void *buf, size_t len, off_t offset,
			    int writing)
{
	OVERLAPPED ov = { .Offset = (DWORD)offset,
			  .OffsetHigh = (DWORD)((uint64_t)offset >> 32) };
	DWORD done = 0, error = ERROR_SUCCESS;
	HANDLE h = (HANDLE)_get_osfhandle(fd);
	BOOL ok;

	if (offset < 0) {
		errno = EINVAL;
		return -1;
	}
	if (h == INVALID_HANDLE_VALUE)
		return -1;
	if (len > INT_MAX)
		len = INT_MAX;
	ok = writing ? WriteFile(h, buf, len, &done, &ov) :
		       ReadFile(h, buf, len, &done, &ov);
	if (!ok)
		error = GetLastError();
	if (error == ERROR_HANDLE_EOF)
		return 0;
	if (error) {
		errno = erofs_err_win_to_posix(error);
		return -1;
	}
	return done;
}

ssize_t erofs_os_pread(int fd, void *buf, size_t len, off_t offset)
{
	return erofs_win_pio(fd, buf, len, offset, 0);
}

ssize_t erofs_os_pwrite(int fd, const void *buf, size_t len, off_t offset)
{
	return erofs_win_pio(fd, (void *)buf, len, offset, 1);
}

char *erofs_os_realpath(const char *path, char *resolved)
{
	char *p = _fullpath(resolved, path, resolved ? _MAX_PATH : 0);
	char *s;

	if (p)
		for (s = p; *s; ++s)
			if (*s == '\\')
				*s = '/';
	return p;
}

char *erofs_os_strndup(const char *s, size_t len)
{
	char *p;

	len = strnlen(s, len);
	p = malloc(len + 1);
	if (p) {
		memcpy(p, s, len);
		p[len] = '\0';
	}
	return p;
}

int erofs_win_random(void *buf, unsigned int len)
{
	if (BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
		errno = EIO;
		return -1;
	}
	return len;
}

int erofs_os_tmpfile(void)
{
	char path[MAX_PATH], name[MAX_PATH];
	HANDLE h;
	DWORD len;
	int fd;

	len = GetTempPathA(sizeof(path), path);
	if (!len) {
		errno = erofs_err_win_to_posix(GetLastError());
		return -errno;
	}
	if (len >= sizeof(path)) {
		errno = ENAMETOOLONG;
		return -errno;
	}
	if (!GetTempFileNameA(path, "ero", 0, name)) {
		errno = erofs_err_win_to_posix(GetLastError());
		return -errno;
	}
	h = CreateFileA(name, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY |
		FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();

		DeleteFileA(name);
		errno = erofs_err_win_to_posix(error);
		return -errno;
	}
	fd = _open_osfhandle((intptr_t)h, O_RDWR | O_BINARY);
	if (fd < 0) {
		CloseHandle(h);
		return -errno;
	}
	return fd;
}

int erofs_os_getpagesize(void)
{
	SYSTEM_INFO info;

	GetSystemInfo(&info);
	return info.dwPageSize;
}
