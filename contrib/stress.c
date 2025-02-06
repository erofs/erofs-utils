// SPDX-License-Identifier: GPL-2.0+
/*
 * stress test for EROFS filesystem
 *
 * Copyright (C) 2019-2025 Gao Xiang <xiang@kernel.org>
 */
#define _GNU_SOURCE
#include "erofs/defs.h"
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_CHUNKSIZE		(2 * 1024 * 1024)
#define MAX_SCAN_CHUNKSIZE	(256 * 1024)

bool superuser;
unsigned int nprocs = 1, loops = 1, r_seed;
unsigned int procid;
volatile sig_atomic_t should_stop;

enum {
	DROP_PAGE_CACHE,
	DROP_SLAB_CACHE,
	COMPACT_MEMORY,
};

enum {
	OP_GETDENTS,
	OP_READLINK,
	OP_SEQREAD_ALIGNED,
	OP_SEQREAD_UNALIGNED,
	OP_READ,
	OP_FADVISE,
	OP_DROP_CACHES,
};

struct opdesc {
	char	*name;
	int	(*func)(int op, unsigned int sn);
	int	freq;
	bool	requireroot;
};

extern struct opdesc ops[];

static int drop_caches_f(int op, unsigned int sn)
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
	int mode = random() % ARRAY_SIZE(val);
	FILE *f;
	clock_t start;

	if (!procfile[mode])
		return -EINVAL;

	printf("%d[%u]/%u %s: %s=%s", getpid(), procid, sn, __func__,
	       procfile[mode], val[mode]);

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

struct fent {
	char *subpath;
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

static struct fent *add_to_flist(int type, char *subpath)
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

static int walkdir(struct fent *ent)
{
	const char *dirpath = ent->subpath;
	int ret = 0;
	struct dirent *dp;
	DIR *_dir;

	_dir = opendir(dirpath);
	if (!_dir) {
		fprintf(stderr, "failed to opendir at %s: %s\n",
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

static int init_filetable(int testdir_fd)
{
	struct fent *fent;

	fent = add_to_flist(FT_DIR, ".");
	if (!fent)
		return -ENOMEM;
	if (fchdir(testdir_fd) < 0) {
		perror("failed to fchdir");
		return -errno;
	}
	return walkdir(fent);
}

static struct fent *getfent(int which, int r)
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

static int __getdents_f(unsigned int sn, struct fent *fe)
{
	int dfd;
	DIR *dir;

	dfd = openat(testdir_fd, fe->subpath, O_DIRECTORY);
	if (dfd < 0) {
		fprintf(stderr, "%d[%u]/%u getdents_f: failed to open directory %s",
			getpid(), procid, sn, fe->subpath);
		return -errno;
	}

	dir = fdopendir(dfd);
	while (readdir64(dir) != NULL)
		continue;
	closedir(dir);
	return 0;
}

static int getdents_f(int op, unsigned int sn)
{
	struct fent *fe;

	fe = getfent(FT_DIRm, random());
	if (!fe)
		return 0;
	printf("%d[%u]/%u %s: %s\n", getpid(), procid, sn, __func__,
	       fe->subpath);
	return __getdents_f(sn, fe);
}

static int readlink_f(int op, unsigned int sn)
{
	char buf1[PATH_MAX], buf2[PATH_MAX];
	struct fent *fe;
	ssize_t sz;

	fe = getfent(FT_SYMm, random());
	if (!fe)
		return 0;

	printf("%d[%u]/%u %s: %s\n", getpid(), procid, sn, __func__,
	       fe->subpath);
	sz = readlinkat(testdir_fd, fe->subpath, buf1, PATH_MAX - 1);
	if (sz < 0) {
		fprintf(stderr, "%d[%u]/%u %s: failed to readlinkat %s: %d",
			getpid(), procid, sn, __func__, fe->subpath, errno);
		return -errno;
	}

	if (chkdir_fd >= 0) {
		if (sz != readlinkat(testdir_fd, fe->subpath, buf2,
				     PATH_MAX - 1)) {
			fprintf(stderr, "%d[%u]/%u %s: symlink length mismatch @%s\n",
				getpid(), procid, sn, __func__, fe->subpath);
			return -E2BIG;
		}
		if (memcmp(buf1, buf2, sz)) {
			fprintf(stderr, "%d[%u]/%u %s: symlink mismatch @%s\n",
				getpid(), procid, sn, __func__, fe->subpath);
			return -EBADMSG;
		}
	}
	return 0;
}

static int tryopen(unsigned int sn, const char *op, struct fent *fe)
{
	if (fe->fd < 0) {
		fe->fd = openat(testdir_fd, fe->subpath, O_RDONLY);
		if (fe->fd < 0) {
			fprintf(stderr, "%d[%u]/%u %s: failed to open %s: %d",
				getpid(), procid, sn, op, fe->subpath, errno);
			return -errno;
		}
		/* use force_page_cache_readahead for every read request */
		posix_fadvise(fe->fd, 0, 0, POSIX_FADV_RANDOM);
	}

	if (chkdir_fd >= 0 && fe->chkfd < 0)
		fe->chkfd = openat(chkdir_fd, fe->subpath, O_RDONLY);
	return 0;
}

static int fadvise_f(int op, unsigned int sn)
{
	struct fent *fe;
	int ret;

	fe = getfent(FT_REGm, random());
	if (!fe)
		return 0;
	ret = tryopen(sn, __func__, fe);
	if (ret)
		return ret;

	printf("%d[%u]/%u %s: %s\n", getpid(), procid, sn,
	       __func__, fe->subpath);
	ret = posix_fadvise(fe->fd, 0, 0, POSIX_FADV_DONTNEED);
	if (!ret)
		return 0;
	fprintf(stderr, "%d(%u)/%u %s: posix_fadvise %s failed %d\n",
		getpid(), procid, sn, __func__, fe->subpath, errno);
	return -errno;
}

static int __read_f(unsigned int sn, struct fent *fe, uint64_t filesize)
{
	static char buf[MAX_CHUNKSIZE], chkbuf[MAX_CHUNKSIZE];
	uint64_t lr, off, len, trimmed;
	size_t nread, nread2;

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

	printf("%d[%u]/%u read_f: %llu bytes @ %llu\n", getpid(), procid, sn,
	       len | 0ULL, off | 0ULL);
	nread = pread64(fe->fd, buf, len, off);
	if (nread != trimmed) {
		fprintf(stderr, "%d[%u]/%u read_f: failed to read %llu bytes @ %llu of %s\n",
			getpid(), procid, sn, len | 0ULL, off | 0ULL,
			fe->subpath);
		return -errno;
	}

	if (fe->chkfd < 0)
		return 0;

	nread2 = pread64(fe->chkfd, chkbuf, len, off);
	if (nread2 <= 0) {
		fprintf(stderr, "%d[%u]/%u read_f: failed to check %llu bytes @ %llu of %s\n",
			getpid(), procid, sn, len | 0ULL, off | 0ULL,
			fe->subpath);
		return -errno;
	}

	if (nread != nread2) {
		fprintf(stderr, "%d[%u]/%u read_f: size mismatch %llu bytes @ %llu of %s\n",
			getpid(), procid, sn, len | 0ULL, off | 0ULL,
			fe->subpath);
		return -EFBIG;
	}

	if (memcmp(buf, chkbuf, nread)) {
		fprintf(stderr, "%d[%u]/%u read_f: data mismatch %llu bytes @ %llu of %s\n",
			getpid(), procid, sn, len | 0ULL, off | 0ULL,
			fe->subpath);
		return -EBADMSG;
	}
	return 0;
}

static int read_f(int op, unsigned int sn)
{
	struct fent *fe;
	ssize_t fsz;
	int ret;

	fe = getfent(FT_REGm, random());
	if (!fe)
		return 0;
	ret = tryopen(sn, __func__, fe);
	if (ret)
		return ret;

	fsz = lseek64(fe->fd, 0, SEEK_END);
	if (fsz <= 0) {
		if (!fsz) {
			printf("%d[%u]/%u %s: zero size @ %s\n",
			       getpid(), procid, sn, __func__, fe->subpath);
			return 0;
		}
		fprintf(stderr, "%d[%u]/%u %s: lseek64 %s failed %d\n",
			getpid(), procid, sn, __func__, fe->subpath, errno);
		return -errno;
	}
	return __read_f(sn, fe, fsz);
}

static int __doscan_f(unsigned int sn, const char *op, struct fent *fe,
		      uint64_t filesize, uint64_t chunksize)
{
	static char buf[MAX_SCAN_CHUNKSIZE], chkbuf[MAX_SCAN_CHUNKSIZE];
	uint64_t pos;

	printf("%d[%u]/%u %s: filesize %llu, chunksize %llu @ %s\n",
	       getpid(), procid, sn, op, (unsigned long long)filesize,
	       (unsigned long long)chunksize, fe->subpath);

	for (pos = 0; pos < filesize; pos += chunksize) {
		ssize_t nread, nread2;

		nread = pread64(fe->fd, buf, chunksize, pos);

		if (nread <= 0)
			return -errno;

		if (nread < chunksize && nread != filesize - pos)
			return -ERANGE;

		if (fe->chkfd < 0)
			continue;

		nread2 = pread64(fe->chkfd, chkbuf, chunksize, pos);
		if (nread2 <= 0)
			return -errno;

		if (nread != nread2)
			return -EFBIG;

		if (memcmp(buf, chkbuf, nread)) {
			fprintf(stderr, "%d[%u]/%u %s: %llu bytes mismatch @ %llu of %s\n",
				getpid(), procid, sn, op, chunksize | 0ULL,
				pos | 0ULL, fe->subpath);
			return -EBADMSG;
		}
	}
	return 0;
}

static int doscan_f(int op, unsigned int sn)
{
	struct fent *fe;
	uint64_t chunksize;
	ssize_t fsz;
	int ret;

	fe = getfent(FT_REGm, random());
	if (!fe)
		return 0;
	ret = tryopen(sn, __func__, fe);
	if (ret)
		return ret;

	fsz = lseek64(fe->fd, 0, SEEK_END);
	if (fsz <= 0) {
		if (!fsz) {
			printf("%d[%u]/%u %s: zero size @ %s\n",
			       getpid(), procid, sn, __func__, fe->subpath);
			return 0;
		}
		fprintf(stderr, "%d[%u]/%u %s: lseek64 %s failed %d\n",
			getpid(), procid, sn, __func__, fe->subpath, errno);
		return -errno;
	}
	chunksize = ((uint64_t)random() * random() % MAX_SCAN_CHUNKSIZE) + 1;
	return __doscan_f(sn, __func__, fe, fsz, chunksize);
}

static int doscan_aligned_f(int op, unsigned int sn)
{
	const int psz = getpagesize();
	struct fent *fe;
	uint64_t chunksize, maxchunksize;
	ssize_t fsz;
	int ret;

	fe = getfent(FT_REGm, random());
	if (!fe)
		return 0;
	ret = tryopen(sn, __func__, fe);
	if (ret)
		return ret;
	fsz = lseek64(fe->fd, 0, SEEK_END);
	if (fsz <= psz) {
		if (fsz >= 0) {
			printf("%d[%u]/%u %s: size too small %lld @ %s\n",
			       getpid(), procid, sn, __func__, fsz | 0LL,
			       fe->subpath);
			return 0;
		}
		fprintf(stderr, "%d[%u]/%u %s: lseek64 %s failed %d\n",
			getpid(), procid, sn, __func__, fe->subpath, errno);
		return -errno;
	}

	maxchunksize = (fsz - psz > MAX_SCAN_CHUNKSIZE ?
			MAX_SCAN_CHUNKSIZE : fsz - psz);
	chunksize = random() * random() % maxchunksize;
	chunksize = (((chunksize - 1) / psz) + 1) * psz;
	if (!chunksize)
		chunksize = psz;
	return __doscan_f(sn, __func__, fe, fsz, chunksize);
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

struct opdesc ops[] = {
	[OP_GETDENTS]		= { "getdents", getdents_f, 5, false },
	[OP_READLINK]		= { "readlink", readlink_f, 5, false },
	[OP_SEQREAD_ALIGNED]	= { "readscan_aligned", doscan_aligned_f, 10, false },
	[OP_SEQREAD_UNALIGNED]	= { "readscan_unaligned", doscan_f, 10, false },
	[OP_READ]		= { "read", read_f, 30, false},
	[OP_FADVISE]		= { "fadvise", fadvise_f, 3, false},
	[OP_DROP_CACHES]	= { "drop_caches", drop_caches_f, 1, true},
};

static int parse_options(int argc, char *argv[])
{
	char *testdir, *chkdir;
	int opt;

	while ((opt = getopt(argc, argv, "l:p:s:")) != -1) {
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

static void usage(void)
{
	fputs("usage: [options] TESTDIR [COMPRDIR]\n\n"
	      "Stress test for EROFS filesystem, where TESTDIR is the directory to test and\n"
	      "COMPRDIR (optional) serves as a directory for data comparison.\n"
	      " -l#     Number of times each worker should loop (0 for infinite, default: 1)\n"
	      " -p#     Number of parallel worker processes (default: 1)\n"
	      " -s#     Seed for random generator (default: random)\n",
	      stderr);
}

unsigned int *freq_table;
int freq_table_size;

static void doproc(void)
{
	unsigned int sn;

	srandom(r_seed + procid);
	for (sn = 0; !should_stop && (!loops || sn < loops); ++sn) {
		int op, err;

		op = freq_table[random() % freq_table_size];
		if (op >= ARRAY_SIZE(ops)) {
			fprintf(stderr, "%d[%u]/%u %s: internal error\n",
				getpid(), procid, sn, __func__);
			abort();
		}

		if (sn && op != OP_DROP_CACHES)
			randomdelay();
		err = ops[op].func(op, sn);
		if (err) {
			fprintf(stderr, "%d[%u]/%u test failed (%d): %s\n",
				getpid(), procid, sn, err, strerror(-err));
			exit(1);
		}
	}
}

static void make_freq_table(void)
{
	int f, i;
	struct opdesc *p;

	for (p = ops, f = 0; p < ops + ARRAY_SIZE(ops); p++) {
		if (!superuser && p->requireroot)
			continue;
		f += p->freq;
	}
	freq_table = malloc(f * sizeof(*freq_table));
	freq_table_size = f;
	for (p = ops, i = 0; p < ops + ARRAY_SIZE(ops); p++) {
		if (!superuser && p->requireroot)
			continue;
		for (f = 0; f < p->freq; f++, i++)
			freq_table[i] = p - ops;
	}
}

int main(int argc, char *argv[])
{
	unsigned int i;
	int err, stat;
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

	if (!r_seed)
		r_seed = (time(NULL) ? : 1);
	make_freq_table();

	/* spawn nprocs processes */
	for (i = 0; i < nprocs; ++i) {
		if (fork() == 0) {
			action.sa_handler = SIG_DFL;
			sigemptyset(&action.sa_mask);
			if (sigaction(SIGTERM, &action, 0)) {
				perror("sigaction failed");
				exit(1);
			}
			procid = i;
			doproc();
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
	return err;
}
