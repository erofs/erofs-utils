// SPDX-License-Identifier: GPL-2.0+
/*
 * stress test for EROFS filesystem
 * based on https://lore.kernel.org/r/20200206135631.1491-1-hsiangkao@aol.com
 *
 * Copyright (C) 2019-2022 Gao Xiang <xiang@kernel.org>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1 << PAGE_SHIFT)
#define MAX_CHUNKSIZE	(4 * 1024 * 1024)
#define MAX_SCAN_CHUNKSIZE	(256 * 1024)

bool superuser;
bool direct_io = false;
bool mmap_flag = false;
bool fadvise_flag = false;
unsigned int nprocs = 1, loops = 1, r_seed;
sig_atomic_t should_stop = 0;

enum {
	GETDENTS,
	READLINK,
	RANDSCAN_ALIGNED,
	RANDSCAN_UNALIGNED,
	RANDREAD,		/* oneshot randread */
	DROP_FILE_CACHE_RAND,
	DROP_FILE_CACHE_ALL,
	DROP_PAGE_CACHE,
	DROP_SLAB_CACHE,
	COMPACT_MEMORY,
};

const int globalop[] = {
	GETDENTS,
	GETDENTS,
	GETDENTS,
	READLINK,
	READLINK,
	READLINK,
	RANDSCAN_ALIGNED,
	RANDSCAN_UNALIGNED,
	RANDSCAN_UNALIGNED,
	RANDREAD,
	RANDREAD,
	RANDREAD,
	DROP_FILE_CACHE_ALL,
	DROP_PAGE_CACHE,
	DROP_SLAB_CACHE,
	COMPACT_MEMORY,
};

#define GLOBALOPS	(sizeof(globalop) / sizeof(globalop[0]))

int drop_caches(int mode)
{
	static const char *procfile[] = {
		[DROP_PAGE_CACHE] = "/proc/sys/vm/drop_caches",
		[DROP_SLAB_CACHE] = "/proc/sys/vm/drop_caches",
		[COMPACT_MEMORY] = "/proc/sys/vm/compact_memory",
	};
	static const char *val[] = {
		[DROP_PAGE_CACHE] = "1\n",
		[DROP_SLAB_CACHE] = "2\n",
		[COMPACT_MEMORY] = "1\n",
	};
	FILE *f;
	clock_t start;

	if (!superuser)
		return 0;
	if (!procfile[mode])
		return -EINVAL;

	printf("drop_caches(%u): %s=%s", getpid(), procfile[mode], val[mode]);

	f = fopen(procfile[mode], "w");
	if (!f)
		return -errno;

	start = clock();
	while (clock() < start + CLOCKS_PER_SEC) {
		fputs(val[mode], f);
		(void)sched_yield();
	}
	fclose(f);
	return 0;
}

int drop_file_cache(int fd, int mode)
{
	clock_t start;

	printf("drop_file_cache(%u)\n", getpid());
	start = clock();
	while (clock() < start + CLOCKS_PER_SEC / 2) {
		posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
		(void)sched_yield();
	}
	return 0;
}

struct fent {
	char *subpath;
	void *fd_ptr;
	void *chkfd_ptr;
	int  fd, chkfd;
};

#define FT_DIR	0
#define FT_DIRm	(1 << FT_DIR)
#define FT_REG	1
#define FT_REGm	(1 << FT_REG)
#define FT_SYM	2
#define FT_SYMm	(1 << FT_SYM)
#define FT_DEV	3
#define FT_DEVm	(1 << FT_DEV)
#define FT_nft	4
#define FT_ANYm	((1 << FT_nft) - 1)

#define	FLIST_SLOT_INCR	16

struct flist {
	int nfiles, nslots;
	struct fent *fents;
} flists[FT_nft];

struct fent *add_to_flist(int type, char *subpath)
{
	struct fent *fep;
	struct flist *ftp;

	ftp = &flists[type];
	if (ftp->nfiles >= ftp->nslots) {
		ftp->nslots += FLIST_SLOT_INCR;
		ftp->fents = realloc(ftp->fents,
				     ftp->nslots * sizeof(struct fent));
		if (!ftp->fents)
			return NULL;
	}
	fep = &ftp->fents[ftp->nfiles++];
	fep->subpath = strdup(subpath);
	fep->fd = -1;
	fep->chkfd = -1;
	return fep;
}

static inline bool is_dot_dotdot(const char *name)
{
	if (name[0] != '.')
		return false;

	return name[1] == '\0' || (name[1] == '.' && name[2] == '\0');
}

int walkdir(struct fent *ent)
{
	const char *dirpath = ent->subpath;
	int ret = 0;
	struct dirent *dp;
	DIR *_dir;

	_dir = opendir(dirpath);
	if (!_dir) {
		fprintf(stderr, "failed to opendir at %s: %d",
			dirpath, strerror(errno));
		return -errno;
	}

	while (1) {
		char subpath[PATH_MAX];
		struct stat st;

		/*
		 * set errno to 0 before calling readdir() in order to
		 * distinguish end of stream and from an error.
		 */
		errno = 0;
		dp = readdir(_dir);
		if (!dp)
			break;

		if (is_dot_dotdot(dp->d_name))
			continue;

		sprintf(subpath, "%s/%s", dirpath, dp->d_name);

		if (lstat(subpath, &st))
			continue;

		switch (st.st_mode & S_IFMT) {
		case S_IFDIR:
			ent = add_to_flist(FT_DIR, subpath);
			if (ent == NULL) {
				ret = -ENOMEM;
				goto err_closedir;
			}
			ret = walkdir(ent);
			if (ret)
				goto err_closedir;
			break;
		case S_IFREG:
			ent = add_to_flist(FT_REG, subpath);
			if (ent == NULL) {
				ret = -ENOMEM;
				goto err_closedir;
			}
			break;
		case S_IFLNK:
			ent = add_to_flist(FT_SYM, subpath);
			if (ent == NULL) {
				ret = -ENOMEM;
				goto err_closedir;
			}
			break;
		default:
			break;
		}
	}
	if (errno)
		ret = -errno;
err_closedir:
	closedir(_dir);
	return ret;
}

int init_filetable(int testdir_fd)
{
	struct fent *fent;

	fent = add_to_flist(FT_DIR, ".");
	if (!fent)
		return -ENOMEM;
	fchdir(testdir_fd);
	return walkdir(fent);
}

struct fent *getfent(int which, int r)
{
	int		totalsum = 0; /* total number of matching files */
	int		partialsum = 0; /* partial sum of matching files */
	struct flist	*flp;
	int		i, x;

	totalsum = 0;
	for (i = 0, flp = flists; i < FT_nft; ++i, ++flp)
		if (which & (1 << i))
			totalsum += flp->nfiles;

	if (!totalsum)
		return NULL;

	/*
	 * Now we have possible matches between 0..totalsum-1.
	 * And we use r to help us choose which one we want,
	 * which when bounded by totalsum becomes x.
	 */
	x = (int)(r % totalsum);

	for (i = 0, flp = flists; i < FT_nft; i++, flp++) {
		if (which & (1 << i)) {
			if (x < partialsum + flp->nfiles)
				return &flp->fents[x - partialsum];
			partialsum += flp->nfiles;
		}
	}
	fprintf(stderr, "%s failure\n", __func__);
	return NULL;
}

static int testdir_fd = -1, chkdir_fd = -1;

int tryopen(struct fent *fe)
{
	int err;
	uint64_t filesize;
	
	if (fe->fd < 0) {
		fe->fd = openat(testdir_fd, fe->subpath, direct_io ? O_RDONLY | O_DIRECT : O_RDONLY);
		if (fe->fd < 0)
			return -errno;

		/* use force_page_cache_readahead for every read request */
		posix_fadvise(fe->fd, 0, 0, POSIX_FADV_RANDOM);
		
		filesize = lseek64(fe->fd, 0, SEEK_END);
		if (mmap_flag) {
			fe->fd_ptr = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fe->fd, 0);
			if (fe->fd_ptr == MAP_FAILED) {
				fprintf(stderr, "%s failed mmap\n", __func__);
				return -errno;
			}
		}
	}

	if (chkdir_fd >= 0 && fe->chkfd < 0) {
		fe->chkfd = openat(chkdir_fd, fe->subpath, direct_io ? O_RDONLY | O_DIRECT : O_RDONLY);
		
		if (fe->chkfd > 0) {
			filesize = lseek64(fe->chkfd, 0, SEEK_END);
			if (mmap_flag) {
				fe->chkfd_ptr = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fe->chkfd, 0);
				if (fe->chkfd_ptr == MAP_FAILED) {
					fprintf(stderr, "%s failed mmap\n", __func__);
					return -errno;
				}
			}
		} else
			fe->chkfd_ptr = NULL;
	}
	return 0;
}

void mismatch_output(struct  fent *ent, uint64_t pos, uint64_t chunksize)
{
	int fd, ret;
	ssize_t nread, nread2;
	char filename[20];
	char *buf, *chkbuf;
	
	ret = posix_memalign(&buf, PAGE_SIZE, MAX_SCAN_CHUNKSIZE);
	if (ret) {
		fprintf(stderr, "posix_memalign failed: %s\n", strerror(ret));
		goto cleanup;
	}
	nread = pread64(ent->fd, buf, chunksize, pos);
	if (nread <= 0) {
		fprintf(stderr, "read file failed");
		goto cleanup;
	}
	
	ret = posix_memalign(&chkbuf, PAGE_SIZE, MAX_SCAN_CHUNKSIZE);
	if (ret) {
		fprintf(stderr, "posix_memalign failed: %s\n", strerror(ret));
		goto cleanup;
	}
	nread2 = pread64(ent->chkfd, chkbuf, chunksize, pos);
	if (nread2 <=0) {
		fprintf(stderr, "read file failed");
		goto cleanup;
	}
	
	sprintf(filename, "%d", getpid());
	strcat(filename, "_mismatch");
	fd = open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "error opening file");
		goto cleanup;
	}
	
	ret = write(fd, ent->subpath, strlen(ent->subpath));
	if (ret == -1) {
		fprintf(stderr, "error writing file");
		goto cleanup;
	}
	write(fd, "\n", 1);
	
	ret = write(fd, buf, nread);
	if (ret == -1) {
		fprintf(stderr, "error writing file");
		goto cleanup;
	}
	write(fd, "\n", 1);
	ret = write(fd, chkbuf, nread2);
	if (ret == -1) {
		fprintf(stderr, "error writing file");
		goto cleanup;
	}
cleanup:
	free(buf);
	free(chkbuf);
}

int doscan(struct fent *ent, uint64_t filesize, uint64_t chunksize)
{
	char *buf, *chkbuf;
	uint64_t pos;
	int err = 0;

	printf("doscan(%u): filesize: %llu, chunksize: %llu\n",
	       getpid(), (unsigned long long)filesize,
	       (unsigned long long)chunksize);
	
	err = posix_memalign(&buf, PAGE_SIZE, MAX_SCAN_CHUNKSIZE);
	if (err) {
		fprintf(stderr, "posix_memalign failed: %s\n", strerror(err));
		goto cleanup;
	}
	
	err = posix_memalign(&chkbuf, PAGE_SIZE, MAX_SCAN_CHUNKSIZE);
	if (err) {
		fprintf(stderr, "posix_memalign failed: %s\n", strerror(err));
		goto cleanup;
	}
	
	for (pos = 0; pos < filesize; pos += chunksize) {
		ssize_t nread, nread2;
		
		nread = pread64(ent->fd, buf, chunksize, pos);
		if (nread <= 0) {
			err = -errno;
			goto cleanup;
		}

		if (nread < chunksize && nread != filesize - pos) {
			err = -ERANGE;
			goto cleanup;
		}

		if (ent->chkfd < 0)
			continue;

		nread2 = pread64(ent->chkfd, chkbuf, chunksize, pos);
		if (nread2 <= 0) {
			err = -errno;
			goto cleanup;
		}

		if (nread != nread2) {
			err = -EFBIG;
			goto cleanup;
		}

		if (memcmp(buf, chkbuf, nread)) {
			fprintf(stderr, "doscan: %llu bytes mismatch @ %llu\n",
				(unsigned long long)chunksize,
				(unsigned long long)pos);
			mismatch_output(ent, pos, chunksize);
			err = -EBADMSG;
			goto cleanup;
		}
	}
	
cleanup:
	free(buf);
	free(chkbuf);
	return err;
}

int doscan_mmap(struct fent *ent, uint64_t filesize, uint64_t chunksize)
{
	uint64_t pos, nread;

	printf("doscan_mmap(%u): filesize: %llu, chunksize: %llu\n",
	       getpid(), (unsigned long long)filesize,
	       (unsigned long long)chunksize);
	       
	if (ent->chkfd >= 0 && lseek(ent->chkfd, 0, SEEK_END) != filesize)
		return -EFBIG;
	
	for (pos = 0; pos < filesize; pos += chunksize) {
		
		if (pos + chunksize < filesize)
			nread = chunksize;
		else
			nread = filesize - pos;
		
		if (ent->chkfd < 0)
			continue;
			
		if (memcmp(ent->fd_ptr + pos, ent->chkfd_ptr + pos, nread)) {
			fprintf(stderr, "doscan_mmap: %llu bytes mismatch @ %llu\n",
				(unsigned long long)chunksize,
				(unsigned long long)pos);
			mismatch_output(ent, pos, chunksize);
			return -EBADMSG;
		}
	}
	return 0;
}

int doscan_fadvise(struct fent *ent, uint64_t filesize, uint64_t chunksize)
{
	int err;
	uint64_t pos, nread;

	printf("doscan_fadvise(%u): filesize: %llu, chunksize: %llu\n",
	       getpid(), (unsigned long long)filesize,
	       (unsigned long long)chunksize);
	       
	if (ent->chkfd >= 0 && lseek(ent->chkfd, 0, SEEK_END) != filesize)
		return -EFBIG;
	
	for (pos = 0; pos < filesize; pos += chunksize) {
		
		if (pos + chunksize < filesize)
			nread = chunksize;
		else
			nread = filesize - pos;
		
		err = posix_fadvise(ent->fd, pos, nread, POSIX_FADV_WILLNEED);
		if (err) {
			perror("posix_fadvise");
			return -errno;;
		}
		
		if (ent->chkfd < 0)
			continue;
			
		err = posix_fadvise(ent->chkfd, pos, nread, POSIX_FADV_WILLNEED);
		if (err) {
			perror("posix_fadvise");
			return -errno;
		}
	}
	return 0;
}

int doscan_random(struct fent *ent, uint64_t filesize, uint64_t chunksize)
{
	bool flag = false;
	int err;
	int randnum;
	
	srand(time(NULL));
	while(true) {
		if (flag)
			break;
		
		randnum = rand() % 3 + 1;
		switch(randnum) {
		case 1:
			flag = true;
			err = doscan(ent, filesize, chunksize);
			break;
		case 2:
			if (mmap_flag) {
				flag = true;
				err = doscan_mmap(ent, filesize, chunksize);
			}
			break;
		case 3:
			if (fadvise_flag) {
				flag = true;
				err = doscan_fadvise(ent, filesize, chunksize);
			}
			break;
		default:
			break;
		}
	}
	return err;
}

int getdents_f(struct fent *fe)
{
	int dfd;
	DIR *dir;

	printf("getdents_f(%u): @ %s\n", getpid(), fe->subpath);
	dfd = openat(testdir_fd, fe->subpath, O_DIRECTORY);
	if (dfd < 0)
		return -errno;
	dir = fdopendir(dfd);

	while (readdir64(dir) != NULL)
		continue;
	closedir(dir);
	return 0;
}

int readlink_f(struct fent *fe)
{
	char buf1[PATH_MAX], buf2[PATH_MAX];
	ssize_t sz;

	printf("readlink_f(%u): @ %s\n", getpid(), fe->subpath);
	sz = readlinkat(testdir_fd, fe->subpath, buf1, PATH_MAX - 1);
	if (sz < 0)
		return -errno;

	if (chkdir_fd >= 0) {
		if (sz != readlinkat(testdir_fd, fe->subpath, buf2,
				     PATH_MAX - 1)) {
			fprintf(stderr, "doscan: symlink length mismatch @%s\n",
				fe->subpath);
			return -E2BIG;
		}
		if (memcmp(buf1, buf2, sz)) {
			fprintf(stderr, "doscan: symlink mismatch @%s\n",
				fe->subpath);
			return -EBADMSG;
		}
	}
	return 0;
}

int read_f(struct fent *ent, uint64_t filesize)
{
	char *buf, *chkbuf;
	uint64_t lr, off, len, trimmed;
	size_t nread, nread2;
	int err = 0;

	lr = ((uint64_t) random() << 32) + random();
	off = lr % filesize;
	len = (random() % MAX_CHUNKSIZE) + 1;
	trimmed = len;
	
	err = posix_memalign(&buf, PAGE_SIZE, MAX_SCAN_CHUNKSIZE);
	if (err) {
		fprintf(stderr, "posix_memalign failed: %s\n", strerror(err));
		goto cleanup;
	}
	
	err = posix_memalign(&chkbuf, PAGE_SIZE, MAX_SCAN_CHUNKSIZE);
	if (err) {
		fprintf(stderr, "posix_memalign failed: %s\n", strerror(err));
		goto cleanup;
	}
	
	if (off + len > filesize) {
		uint64_t a = filesize - off + 16 * getpagesize();

		if (len > a)
			len %= a;
		trimmed = len <= filesize - off ? len : filesize - off;
	}
	
	if (direct_io) {
		off = (((off - 1) >> PAGE_SHIFT) + 1)
			<< PAGE_SHIFT;
		trimmed = len = (((len - 1) >> PAGE_SHIFT) + 1)
			<< PAGE_SHIFT;
		if (!len || off + len > filesize)
			goto cleanup;
	}
	
	printf("read_f(%u): %llu bytes @ %llu\n", getpid(),
	       len | 0ULL, off | 0ULL);	

	nread = pread64(ent->fd, buf, len, off);
	if (nread != trimmed) {
		fprintf(stderr, "read_f(%d, %u): failed to read %llu bytes @ %llu\n",
			__LINE__, getpid(), len | 0ULL, off | 0ULL);
		err = -errno;
		goto cleanup;
	}

	if (ent->chkfd < 0)
		goto cleanup;

	nread2 = pread64(ent->chkfd, chkbuf, len, off);
	if (nread2 <= 0) {
		fprintf(stderr, "read_f(%d, %u): failed to read %llu bytes @ %llu\n",
			__LINE__, getpid(), len | 0ULL, off | 0ULL);
		err = -errno;
		goto cleanup;
	}

	if (nread != nread2) {
		fprintf(stderr, "read_f(%d, %u): size mismatch %llu bytes @ %llu\n",
			__LINE__, getpid(), len | 0ULL, off | 0ULL);
		mismatch_output(ent, off, len);
		err = -EFBIG;
		goto cleanup;
	}

	if (memcmp(buf, chkbuf, nread)) {
		fprintf(stderr, "read_f(%d, %u): data mismatch %llu bytes @ %llu\n",
			__LINE__, getpid(), len | 0ULL, off | 0ULL);
		mismatch_output(ent, off, len);
		err = -EBADMSG;
		goto cleanup;
	}
	
cleanup:
	free(buf);
	free(chkbuf);
	return err;
}

int read_f_mmap(struct fent *ent, uint64_t filesize)
{
	uint64_t lr, off, len, trimmed;
	
	lr = ((uint64_t) random() << 32) + random();
	off = lr % filesize;
	len = (random() % MAX_CHUNKSIZE) + 1;
	trimmed = len;
	
	if (off + len > filesize) {
		uint64_t a = filesize - off + 16 * getpagesize();

		if (len > a)
			len %= a;
		trimmed = len <= filesize - off ? len : filesize - off;
	}
	
	printf("read_f_mmap(%u): %llu bytes @ %llu\n", getpid(),
	       len | 0ULL, off | 0ULL);
	
	if (ent->chkfd >= 0 && lseek(ent->chkfd, 0, SEEK_END) != filesize)
		return -EFBIG;
	
	if (ent->chkfd < 0)
		return 0;
		
	if (memcmp(ent->fd_ptr + off, ent->chkfd_ptr + off, trimmed)) {
		fprintf(stderr, "read_f_mmap(%d, %u): data mismatch %llu bytes @ %llu\n",
			__LINE__, getpid(), len | 0ULL, off | 0ULL);
		mismatch_output(ent, off, len);
		return -EBADMSG;
	}
	return 0;
}

int read_f_fadvise(struct fent *ent, uint64_t filesize)
{
	int err;
	uint64_t lr, off, len, trimmed;
	
	lr = ((uint64_t) random() << 32) + random();
	off = lr % filesize;
	len = (random() % MAX_CHUNKSIZE) + 1;
	trimmed = len;
	
	if (off + len > filesize) {
		uint64_t a = filesize - off + 16 * getpagesize();

		if (len > a)
			len %= a;
		trimmed = len <= filesize - off ? len : filesize - off;
	}
	
	printf("read_f_fadvise(%u): %llu bytes @ %llu\n", getpid(),
	       len | 0ULL, off | 0ULL);
	
	err = posix_fadvise(ent->fd, off, trimmed, POSIX_FADV_WILLNEED);
	if (err) {
		perror("posix_fadvise");
		return -errno;
	}
	
	if (ent->chkfd >= 0 && lseek(ent->chkfd, 0, SEEK_END) != filesize)
		return -EFBIG;
	
	if (ent->chkfd < 0)
		return 0;
		
	err = posix_fadvise(ent->chkfd, off, trimmed, POSIX_FADV_WILLNEED);
	if (err) {
		perror("posix_fadvise");
		return -errno;
	}
	return 0;
}

int read_f_random(struct fent * ent, uint64_t filesize)
{
	bool flag = false;
	int err;
	int randnum;
	
	srand(time(NULL));
	while(true) {
		if (flag)
			break;
		
		randnum = rand() % 3 + 1;
		switch(randnum) {
		case 1:
			flag = true;
			err = read_f(ent, filesize);
			break;
		case 2:
			if (mmap_flag) {
				flag = true;
				err = read_f_mmap(ent, filesize);
			}
			break;
		case 3:
			if (fadvise_flag) {
				flag = true;
				err = read_f_fadvise(ent, filesize);
			}
			break;
		default:
			break;
		}
	}
	return err;
}

int testfd(struct fent *ent, int mode)
{
	const off64_t filesize = lseek64(ent->fd, 0, SEEK_END);
	uint64_t chunksize, maxchunksize;
	int err;

	if (!filesize)
		return 0;

	if (mode == RANDSCAN_ALIGNED && filesize > PAGE_SIZE) {
		maxchunksize = (filesize - PAGE_SIZE > MAX_SCAN_CHUNKSIZE ?
				MAX_SCAN_CHUNKSIZE : filesize - PAGE_SIZE);

		chunksize = random() * random() % maxchunksize;
		chunksize = (((chunksize - 1) >> PAGE_SHIFT) + 1)
			<< PAGE_SHIFT;
		if (!chunksize)
			chunksize = PAGE_SIZE;
		err = doscan_random(ent, filesize, chunksize);
		if (err)
			return err;
	} else if (mode == RANDSCAN_UNALIGNED && !direct_io) {
		chunksize = (random() * random() % MAX_SCAN_CHUNKSIZE) + 1;
		err = doscan_random(ent, filesize, chunksize);
		if (err)
			return err;
	} else if (mode == RANDREAD) {
		err = read_f_random(ent, filesize);
		if (err)
			return err;
	}
	return 0;
}

int doproc(int mode)
{
	struct fent *fe;
	int ret;
	if (mode <= GETDENTS) {
		fe = getfent(FT_DIRm, random());
		if (!fe)
			return 0;

		if (mode == GETDENTS)
			return getdents_f(fe);
	} else if (mode <= READLINK) {
		fe = getfent(FT_SYMm, random());
		if (!fe)
			return 0;

		if (mode == READLINK)
			return readlink_f(fe);
	}
	fe = getfent(FT_REGm, random());
	if (!fe)
		return 0;
	ret = tryopen(fe);
	if (ret)
		return ret;
	return testfd(fe, mode);
}

void randomdelay(void)
{
	uint64_t lr = ((uint64_t) random() << 32) + random();
	clock_t start;
	clock_t length = (lr % CLOCKS_PER_SEC) >> 1;

	start = clock();
	while (clock() < start + length)
		(void)sched_yield();
}

void sg_handler(int signum)
{
	switch (signum) {
	case SIGTERM:
		should_stop = 1;
		break;
	default:
		break;
	}
}

static int parse_options(int argc, char *argv[])
{
	char *testdir, *chkdir;
	int opt;

	while ((opt = getopt(argc, argv, "l:p:s:dmf")) != -1) {
		switch (opt) {
		case 'l':
			loops = atoi(optarg);
			if (loops < 0) {
				fprintf(stderr, "invalid loops %d\n", loops);
				return -EINVAL;
			}
			break;
		case 'p':
			nprocs = atoi(optarg);
			if (nprocs < 0) {
				fprintf(stderr, "invalid workers %d\n",
					nprocs);
				return -EINVAL;
			}
			break;
		case 's':
			r_seed = atoi(optarg);
			if (r_seed < 0) {
				fprintf(stderr, "invalid random seed %d\n",
					r_seed);
				return -EINVAL;
			}
			break;
		case 'd':
			direct_io = true;
			break;
		case 'm':
			mmap_flag = true;
			break;
		case 'f':
			fadvise_flag = true;
			break;
		default: /* '?' */
			return -EINVAL;
		}
	}

	if (optind >= argc)
		return -EINVAL;

	testdir = argv[optind++];
	if (testdir) {
		testdir_fd = open(testdir, O_PATH);
		if (testdir_fd < 0) {
			fprintf(stderr, "cannot open testdir fd @ %s: %s\n",
				testdir, strerror(errno));
			return 1;
		}
	}

	if (argc > optind) {
		chkdir = argv[optind++];

		chkdir_fd = open(chkdir, O_PATH);
		if (chkdir_fd < 0) {
			fprintf(stderr, "cannot open checkdir fd @ %s: %s\n",
				chkdir, strerror(errno));
			return 1;
		}
	}
	return 0;
}

void usage(void)
{
	fputs("usage: [options] TESTDIR [COMPRDIR]\n\n"
	      "stress test for EROFS filesystem\n"
	      " -l#     specifies the no. of times the testrun should loop.\n"
	      "         *use 0 for infinite (default 1)\n"
	      " -p#     specifies the no. of processes (default 1)\n"
	      " -s#     specifies the seed for the random generator (default random)\n"
	      " -d      using direct_io to start stress test\n"
	      " -m      using mmap to start stress test\n"
	      " -f      using fadvise to start stress test\n",
	      stderr);
}

int main(int argc, char *argv[])
{
	unsigned int i;
	int err, stat;
	int fd, chkfd;
	struct sigaction action;

	err = parse_options(argc, argv);
	if (err) {
		if (err == -EINVAL)
			usage();
		return 1;
	}

	err = init_filetable(testdir_fd);
	if (err) {
		fprintf(stderr, "cannot initialize file table: %s\n",
			strerror(errno));
		return 1;
	}

	superuser = (geteuid() == 0);
	setpgid(0, 0);
	action.sa_handler = sg_handler;
	action.sa_flags = 0;

	if (sigaction(SIGTERM, &action, 0)) {
		perror("sigaction failed");
		exit(1);
	}

	/* spawn nprocs processes */
	for (i = 0; i < nprocs; ++i) {
		if (fork() == 0) {
			bool infinite_loop = !loops;

			sigemptyset(&action.sa_mask);
			if (sigaction(SIGTERM, &action, 0)) {
				perror("sigaction failed");
				exit(1);
			}

			srandom((r_seed ? :
				 (time(NULL) ? : 1) * getpid()) * (i + 1));

			while (!should_stop && (infinite_loop || loops)) {
				int op = globalop[random() % GLOBALOPS];

				if (op == DROP_FILE_CACHE_RAND ||
				    op == DROP_FILE_CACHE_ALL) {
					err = drop_file_cache(fd, op);
				} else if (op <= RANDREAD) {
					randomdelay();
					err = doproc(op);
				} else {
					err = drop_caches(op);
				}

				if (err) {
					fprintf(stderr, "test failed (%u): %s\n",
						getpid(), strerror(-err));
					exit(1);
				}
				--loops;
			}
			return 0;
		}
	}

	err = 0;
	while (wait(&stat) > 0 && !should_stop) {
		if (!WIFEXITED(stat)) {
			err = 1;
			break;
		}

		if (WEXITSTATUS(stat)) {
			err = WEXITSTATUS(stat);
			break;
		}
	}
	action.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &action, 0);
	kill(-getpid(), SIGTERM);
	/* wait until all children exit */
	while (wait(&stat) > 0)
		continue;

	if (chkfd >= 0)
		close(chkfd);
	close(fd);
	return err;
}
