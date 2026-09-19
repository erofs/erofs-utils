// SPDX-License-Identifier: MIT
/*
 * Copyright 2021 Google LLC
 * Author: Daeho Jeong <daehojeong@google.com>
 */
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <utime.h>
#include <unistd.h>
#include <sys/stat.h>
#include "erofs/print.h"
#include "erofs/decompress.h"
#include "erofs/dir.h"
#include "erofs/xattr.h"
#include "erofs/internal.h"
#include "erofs/lock.h"
#include "erofs/cond.h"
#include "../lib/compressor.h"
#include "../lib/liberofs_compress.h"
#include "../lib/liberofs_sha256.h"

struct erofsfsck_dirstack {
	erofs_nid_t dirs[PATH_MAX];
	int top;
};

static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid,
	const char *path, struct erofsfsck_dirstack *dirstack);

#ifdef EROFS_MT_ENABLED
struct erofsfsck_inode_task {
	struct erofsfsck_inode_task *next;
	erofs_nid_t pnid;
	erofs_nid_t nid;
	char *path;
	struct erofsfsck_dirstack dirstack;
};

static erofs_mutex_t traverse_mtx;
static erofs_cond_t traverse_cond;
static erofs_cond_t traverse_cond_finish;
static erofs_mutex_t hardlink_mtx;
static erofs_mutex_t stats_mtx;

static struct erofsfsck_inode_task *traverse_head;
static struct erofsfsck_inode_task *traverse_tail;
static int traverse_pending_tasks;
static bool traverse_shutdown;
static pthread_t *traverse_workers;
static int traverse_num_workers;
static int traverse_final_err;
#endif

static char erofsfsck_nullstr[] = "";

struct erofsfsck_cfg {
	u64 physical_blocks;
	u64 logical_blocks;
	char *extract_path;
	char *digest_xattr_name;
	mode_t umask;
	bool superuser;
	bool corrupted;
	bool print_comp_ratio;
	bool check_decomp;
	bool force;
	bool overwrite;
	bool preserve_owner;
	bool preserve_perms;
	bool dump_xattrs;
	erofs_nid_t nid;
	const char *inode_path;
	bool nosbcrc;
};
static struct erofsfsck_cfg fsckcfg;

static struct option long_options[] = {
	{"version", no_argument, 0, 'V'},
	{"help", no_argument, 0, 'h'},
	{"extract", optional_argument, 0, 2},
	{"device", required_argument, 0, 3},
	{"force", no_argument, 0, 4},
	{"overwrite", no_argument, 0, 5},
	{"preserve", no_argument, 0, 6},
	{"preserve-owner", no_argument, 0, 7},
	{"preserve-perms", no_argument, 0, 8},
	{"no-preserve", no_argument, 0, 9},
	{"no-preserve-owner", no_argument, 0, 10},
	{"no-preserve-perms", no_argument, 0, 11},
	{"offset", required_argument, 0, 12},
	{"xattrs", no_argument, 0, 13},
	{"no-xattrs", no_argument, 0, 14},
	{"nid", required_argument, 0, 15},
	{"path", required_argument, 0, 16},
	{"no-sbcrc", no_argument, 0, 512},
	{"xattr-inode-digest", no_argument, 0, 17},
	{0, 0, 0, 0},
};

#define NR_HARDLINK_HASHTABLE	16384

struct erofsfsck_hardlink_entry {
	struct list_head list;
	erofs_nid_t nid;
	char *path;
};

static struct list_head erofsfsck_link_hashtable[NR_HARDLINK_HASHTABLE];

static void print_available_decompressors(FILE *f, const char *delim)
{
	int i = 0;
	bool comma = false;
	const struct erofs_algorithm *s;

	while ((s = z_erofs_list_available_compressors(&i)) != NULL) {
		if (comma)
			fputs(delim, f);
		fputs(s->name, f);
		comma = true;
	}
	fputc('\n', f);
}

static void usage(int argc, char **argv)
{
	//	"         1         2         3         4         5         6         7         8  "
	//	"12345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
	printf(
		"Usage: %s [OPTIONS] IMAGE\n"
		"Check erofs filesystem compatibility and integrity of IMAGE.\n"
		"\n"
		"This version of fsck.erofs is capable of checking images that use any of the\n"
		"following algorithms: ", argv[0]);
	print_available_decompressors(stdout, ", ");
	printf("\n"
		"General options:\n"
		" -V, --version          print the version number of fsck.erofs and exit\n"
		" -h, --help             display this help and exit\n"
		"\n"
		" -d<0-9>                set output verbosity; 0=quiet, 9=verbose (default=%i)\n"
		" -p                     print total compression ratio of all files\n"
		" --device=X             specify an extra device to be used together\n"
		" --extract[=X]          check if all files are well encoded, optionally\n"
		"                        extract to X\n"
		" --offset=#             skip # bytes at the beginning of IMAGE\n"
		" --nid=#                check or extract from the target inode of nid #\n"
		" --path=X               check or extract from the target inode of path X\n"
		" --no-sbcrc             bypass the superblock checksum verification\n"
		" --xattr-inode-digest   verify per-inode digests recorded as extended attributes\n"
		" --[no-]xattrs          whether to dump extended attributes (default off)\n"
		"\n"
		" -a, -A, -y             no-op, for compatibility with fsck of other filesystems\n"
		"\n"
		"Extraction options (--extract=X is required):\n"
		" --force                allow extracting to root\n"
		" --overwrite            overwrite files that already exist\n"
		" --[no-]preserve        same as --[no-]preserve-owner --[no-]preserve-perms\n"
		" --[no-]preserve-owner  whether to preserve the ownership from the\n"
		"                        filesystem (default for superuser), or to extract as\n"
		"                        yourself (default for ordinary users)\n"
		" --[no-]preserve-perms  whether to preserve the exact permissions from the\n"
		"                        filesystem without applying umask (default for\n"
		"                        superuser), or to modify the permissions by applying\n"
		"                        umask (default for ordinary users)\n",
		EROFS_WARN);
}

static void erofsfsck_print_version(void)
{
	printf("fsck.erofs (erofs-utils) %s\navailable decompressors: ",
	       cfg.c_version);
	print_available_decompressors(stdout, ", ");
}

static int erofsfsck_parse_options_cfg(int argc, char **argv)
{
	char *endptr;
	int opt, ret;
	bool has_opt_preserve = false;

	while ((opt = getopt_long(argc, argv, "Vd:phaAy",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'V':
			erofsfsck_print_version();
			exit(0);
		case 'd':
			ret = atoi(optarg);
			if (ret < EROFS_MSG_MIN || ret > EROFS_MSG_MAX) {
				erofs_err("invalid debug level %d", ret);
				return -EINVAL;
			}
			cfg.c_dbg_lvl = ret;
			break;
		case 'p':
			fsckcfg.print_comp_ratio = true;
			break;
		case 'h':
			usage(argc, argv);
			exit(0);
		case 'a':
		case 'A':
		case 'y':
			break;
		case 2:
			fsckcfg.check_decomp = true;
			if (optarg) {
				size_t len = strlen(optarg);

				if (len == 0) {
					erofs_err("empty value given for --extract=X");
					return -EINVAL;
				}

				/* remove trailing slashes except root */
				while (len > 1 && optarg[len - 1] == '/')
					len--;

				if (len >= PATH_MAX) {
					erofs_err("target directory name too long!");
					return -ENAMETOOLONG;
				}

				fsckcfg.extract_path = malloc(PATH_MAX + 1);
				if (!fsckcfg.extract_path)
					return -ENOMEM;
				strncpy(fsckcfg.extract_path, optarg, len);
				fsckcfg.extract_path[len] = '\0';
				/* if path is root, start writing from position 0 */
				if (len == 1 && fsckcfg.extract_path[0] == '/')
					len = 0;
			}
			break;
		case 3:
			ret = erofs_blob_open_ro(&g_sbi, optarg);
			if (ret)
				return ret;
			++g_sbi.extra_devices;
			break;
		case 4:
			fsckcfg.force = true;
			break;
		case 5:
			fsckcfg.overwrite = true;
			break;
		case 6:
			fsckcfg.preserve_owner = fsckcfg.preserve_perms = true;
			has_opt_preserve = true;
			break;
		case 7:
			fsckcfg.preserve_owner = true;
			has_opt_preserve = true;
			break;
		case 8:
			fsckcfg.preserve_perms = true;
			has_opt_preserve = true;
			break;
		case 9:
			fsckcfg.preserve_owner = fsckcfg.preserve_perms = false;
			has_opt_preserve = true;
			break;
		case 10:
			fsckcfg.preserve_owner = false;
			has_opt_preserve = true;
			break;
		case 11:
			fsckcfg.preserve_perms = false;
			has_opt_preserve = true;
			break;
		case 12:
			g_sbi.bdev.offset = strtoull(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid disk offset %s", optarg);
				return -EINVAL;
			}
			break;
		case 13:
			fsckcfg.dump_xattrs = true;
			break;
		case 14:
			fsckcfg.dump_xattrs = false;
			break;
		case 15:
			fsckcfg.nid = (erofs_nid_t)atoll(optarg);
			break;
		case 16:
			fsckcfg.inode_path = optarg;
			break;
		case 17:
			fsckcfg.digest_xattr_name = erofsfsck_nullstr;
			fsckcfg.check_decomp = true;
			break;
		case 512:
			fsckcfg.nosbcrc = true;
			break;
		default:
			return -EINVAL;
		}
	}

	if (fsckcfg.extract_path) {
		if (!strcmp(fsckcfg.extract_path, "/") && !fsckcfg.force) {
			erofs_err("--extract=/ must be used together with --force");
			return -EINVAL;
		}
	} else {
		if (fsckcfg.force) {
			erofs_err("--force must be used together with --extract=X");
			return -EINVAL;
		}
		if (fsckcfg.overwrite) {
			erofs_err("--overwrite must be used together with --extract=X");
			return -EINVAL;
		}
		if (has_opt_preserve) {
			erofs_err("--[no-]preserve[-owner/-perms] must be used together with --extract=X");
			return -EINVAL;
		}
	}

	if (optind >= argc) {
		erofs_err("missing argument: IMAGE");
		return -EINVAL;
	}

	cfg.c_img_path = strdup(argv[optind++]);
	if (!cfg.c_img_path)
		return -ENOMEM;

	if (optind < argc) {
		erofs_err("unexpected argument: %s", argv[optind]);
		return -EINVAL;
	}
	return 0;
}

static void erofsfsck_set_attributes(struct erofs_inode *inode, char *path)
{
	int ret;

	/* don't apply attributes when fsck is used without extraction */
	if (!fsckcfg.extract_path)
		return;

#ifdef HAVE_UTIMENSAT
	if (utimensat(AT_FDCWD, path, (struct timespec []) {
				[0] = { .tv_sec = inode->i_mtime,
					.tv_nsec = inode->i_mtime_nsec },
				[1] = { .tv_sec = inode->i_mtime,
					.tv_nsec = inode->i_mtime_nsec },
			}, AT_SYMLINK_NOFOLLOW) < 0)
#else
	if (utime(path, &((struct utimbuf){.actime = inode->i_mtime,
					   .modtime = inode->i_mtime})) < 0)
#endif
		erofs_warn("failed to set times: %s", path);

	if (fsckcfg.preserve_owner) {
		ret = lchown(path, inode->i_uid, inode->i_gid);
		if (ret < 0)
			erofs_warn("failed to change ownership: %s", path);
	}

	if (!S_ISLNK(inode->i_mode)) {
		if (fsckcfg.preserve_perms)
			ret = chmod(path, inode->i_mode);
		else
			ret = chmod(path, inode->i_mode & ~fsckcfg.umask);
		if (ret < 0)
			erofs_warn("failed to set permissions: %s", path);
	}
}

static int erofs_verify_xattr(struct erofs_inode *inode)
{
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int xattr_hdr_size = sizeof(struct erofs_xattr_ibody_header);
	unsigned int xattr_entry_size = sizeof(struct erofs_xattr_entry);
	struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
	unsigned int ofs, xattr_shared_count;
	struct erofs_xattr_ibody_header *ih;
	struct erofs_xattr_entry *entry;
	int remaining = inode->xattr_isize, ret = 0;
	erofs_off_t addr;
	char *ptr;
	int i;

	if (inode->xattr_isize == xattr_hdr_size) {
		erofs_err("xattr_isize %d of nid %llu is not supported yet",
			  inode->xattr_isize, inode->nid | 0ULL);
		return -EOPNOTSUPP;
	} else if (inode->xattr_isize < xattr_hdr_size) {
		if (!inode->xattr_isize)
			return 0;
		erofs_err("bogus xattr ibody @ nid %llu", inode->nid | 0ULL);
		return -EFSCORRUPTED;
	}

	addr = erofs_iloc(inode) + inode->inode_isize;
	ptr = erofs_read_metabuf(&buf, sbi, addr,
				 erofs_inode_in_metabox(inode));
	if (IS_ERR(ptr)) {
		ret = PTR_ERR(ptr);
		erofs_err("failed to read xattr header @ nid %llu: %d",
			  inode->nid | 0ULL, ret);
		goto out;
	}
	ih = (struct erofs_xattr_ibody_header *)ptr;
	xattr_shared_count = ih->h_shared_count;

	ofs = erofs_blkoff(sbi, addr) + xattr_hdr_size;
	addr += xattr_hdr_size;
	remaining -= xattr_hdr_size;
	for (i = 0; i < xattr_shared_count; ++i) {
		if (ofs >= erofs_blksiz(sbi)) {
			if (ofs != erofs_blksiz(sbi)) {
				erofs_err("unaligned xattr entry in xattr shared area @ nid %llu",
					  inode->nid | 0ULL);
				ret = -EFSCORRUPTED;
				goto out;
			}
			ofs = 0;
		}
		ofs += xattr_entry_size;
		addr += xattr_entry_size;
		remaining -= xattr_entry_size;
	}

	while (remaining > 0) {
		unsigned int entry_sz;

		ptr = erofs_read_metabuf(&buf, sbi, addr,
				 erofs_inode_in_metabox(inode));
		if (IS_ERR(ptr)) {
			ret = PTR_ERR(ptr);
			erofs_err("failed to read xattr entry @ nid %llu: %d",
				  inode->nid | 0ULL, ret);
			goto out;
		}

		entry = (struct erofs_xattr_entry *)ptr;
		entry_sz = erofs_xattr_entry_size(entry);
		if (remaining < entry_sz) {
			erofs_err("xattr on-disk corruption: xattr entry beyond xattr_isize @ nid %llu",
				  inode->nid | 0ULL);
			ret = -EFSCORRUPTED;
			goto out;
		}
		addr += entry_sz;
		remaining -= entry_sz;
	}
out:
	erofs_put_metabuf(&buf);
	return ret;
}

static int erofsfsck_dump_xattrs(struct erofs_inode *inode, const char *path)
{
	static bool ignore_xattrs = false;
	char *keylst, *key;
	ssize_t kllen;
	int ret;

	kllen = erofs_listxattr(inode, NULL, 0);
	if (kllen <= 0)
		return kllen;
	keylst = malloc(kllen);
	if (!keylst)
		return -ENOMEM;
	ret = erofs_listxattr(inode, keylst, kllen);
	if (ret != kllen) {
		erofs_err("failed to list xattrs @ nid %llu",
			  inode->nid | 0ULL);
		ret = -EINVAL;
		goto out;
	}
	ret = 0;
	for (key = keylst; key < keylst + kllen; key += strlen(key) + 1) {
		unsigned int index, len;
		void *value = NULL;
		size_t size = 0;

		ret = erofs_getxattr(inode, key, NULL, 0);
		if (ret <= 0) {
			DBG_BUGON(1);
			erofs_err("failed to get xattr value size of `%s` @ nid %llu",
				  key, inode->nid | 0ULL);
			break;
		}
		size = ret;
		value = malloc(size);
		if (!value) {
			ret = -ENOMEM;
			break;
		}
		ret = erofs_getxattr(inode, key, value, size);
		if (ret < 0) {
			erofs_err("failed to get xattr `%s` @ nid %llu, because of `%s`", key,
				  inode->nid | 0ULL, erofs_strerror(ret));
			free(value);
			break;
		}
		if (path)
			ret = erofs_sys_lsetxattr(path, key, value, size);
		else
			ret = 0;
		free(value);
		if (ret == -EPERM && !fsckcfg.superuser) {
			if (__erofs_unlikely(!erofs_xattr_prefix_matches(key,
					&index, &len))) {
				erofs_err("failed to match the prefix of `%s` @ nid %llu",
					  key, inode->nid | 0ULL);
				ret = -EINVAL;
				break;
			}
			if (index != EROFS_XATTR_INDEX_USER) {
				if (!ignore_xattrs) {
					erofs_warn("ignored xattr `%s` @ nid %llu, due to non-superuser",
						   key, inode->nid | 0ULL);
					ignore_xattrs = true;
				}
				ret = 0;
				continue;
			}

		}
		if (ret) {
			erofs_err("failed to set xattr `%s` @ nid %llu because of `%s`",
				  key, inode->nid | 0ULL, erofs_strerror(ret));
			break;
		}
	}
out:
	free(keylst);
	return ret;
}

static int erofs_verify_inode_data(struct erofs_inode *inode, int outfd,
				   struct sha256_state *digest)
{
	struct erofs_map_blocks map = {
		.buf = __EROFS_BUF_INITIALIZER,
	};
	bool needdecode = fsckcfg.check_decomp && !erofs_is_packed_inode(inode);
	int ret = 0;
	bool compressed;
	erofs_off_t pos = 0;
	u64 pchunk_len = 0;
	u64 raw_size = 0, buffer_size = 0;
	char *raw = NULL, *buffer = NULL;

	erofs_dbg("verify data chunk of nid(%llu): type(%d)",
		  inode->nid | 0ULL, inode->datalayout);

	compressed = erofs_inode_is_data_compressed(inode->datalayout);
	while (pos < inode->i_size) {
		unsigned int alloc_rawsize;

		map.m_la = pos;
		ret = erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_FIEMAP);
		if (ret)
			goto out;

		if (!compressed && map.m_llen != map.m_plen) {
			erofs_err("broken chunk length m_la %" PRIu64 " m_llen %" PRIu64 " m_plen %" PRIu64,
				  map.m_la, map.m_llen, map.m_plen);
			ret = -EFSCORRUPTED;
			goto out;
		}

		/* the last lcluster can be divided into 3 parts */
		if (map.m_la + map.m_llen > inode->i_size)
			map.m_llen = inode->i_size - map.m_la;

		pchunk_len += map.m_plen;
		pos += map.m_llen;

		/* should skip decomp? */
		if (map.m_la >= inode->i_size || !needdecode)
			continue;

		if (!(map.m_flags & EROFS_MAP_MAPPED)) {
			if (digest) {
				static const char zeros[4096];
				u64 remain = map.m_llen;

				while (remain > 0) {
					u64 chunk = remain > sizeof(zeros) ?
						    sizeof(zeros) : remain;
					erofs_sha256_process(digest,
						(const u8 *)zeros, chunk);
					remain -= chunk;
				}
			} else if (outfd >= 0) {
				ret = lseek(outfd, map.m_llen, SEEK_CUR);
				if (ret < 0) {
					ret = -errno;
					goto out;
				}
			}
			continue;
		}

		if (map.m_plen > Z_EROFS_PCLUSTER_MAX_SIZE) {
			if (compressed && !(map.m_flags & __EROFS_MAP_FRAGMENT)) {
				erofs_err("invalid pcluster size %" PRIu64 " @ offset %" PRIu64 " of nid %" PRIu64,
					  map.m_plen, map.m_la,
					  inode->nid | 0ULL);
				ret = -EFSCORRUPTED;
				goto out;
			}
			alloc_rawsize = Z_EROFS_PCLUSTER_MAX_SIZE;
		} else {
			alloc_rawsize = map.m_plen;
		}

		if (alloc_rawsize > raw_size) {
			char *newraw = realloc(raw, alloc_rawsize);

			if (!newraw) {
				ret = -ENOMEM;
				goto out;
			}
			raw = newraw;
			raw_size = alloc_rawsize;
		}

		if (compressed) {
			if (map.m_llen > buffer_size) {
				char *newbuffer;

				buffer_size = map.m_llen;
				newbuffer = realloc(buffer, buffer_size);
				if (!newbuffer) {
					ret = -ENOMEM;
					goto out;
				}
				buffer = newbuffer;
			}
			ret = z_erofs_read_one_data(inode, &map, raw, buffer,
						    0, map.m_llen, false);
			if (ret)
				goto out;

			if (digest)
				erofs_sha256_process(digest,
					(const u8 *)buffer, map.m_llen);
			if (outfd >= 0 && write(outfd, buffer, map.m_llen) < 0)
				goto fail_eio;
		} else {
			u64 p = 0;

			do {
				u64 count = min_t(u64, alloc_rawsize,
						  map.m_llen);

				ret = erofs_read_one_data(inode, &map, raw, p, count);
				if (ret)
					goto out;

				if (digest)
					erofs_sha256_process(digest,
						(const u8 *)raw, count);
				if (outfd >= 0 && write(outfd, raw, count) < 0)
					goto fail_eio;
				map.m_llen -= count;
				p += count;
			} while (map.m_llen);
		}
	}

	if (fsckcfg.print_comp_ratio) {
		u64 log_blocks = 0;
		if (!erofs_is_packed_inode(inode))
			log_blocks = BLK_ROUND_UP(inode->sbi, inode->i_size);
		u64 phys_blocks = BLK_ROUND_UP(inode->sbi, pchunk_len);

#ifdef EROFS_MT_ENABLED
		erofs_mutex_lock(&stats_mtx);
#endif
		fsckcfg.logical_blocks += log_blocks;
		fsckcfg.physical_blocks += phys_blocks;
#ifdef EROFS_MT_ENABLED
		erofs_mutex_unlock(&stats_mtx);
#endif
	}
out:
	if (raw)
		free(raw);
	if (buffer)
		free(buffer);
	return ret < 0 ? ret : 0;

fail_eio:
	erofs_err("I/O error occurred when verifying data chunk @ nid %llu",
		  inode->nid | 0ULL);
	ret = -EIO;
	goto out;
}

static inline int erofs_extract_dir(struct erofs_inode *inode, const char *path)
{
	int ret;

	erofs_dbg("create directory %s", path);

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(inode, -1, NULL);
	if (ret)
		return ret;

	/*
	 * Make directory with default user rwx permissions rather than
	 * the permissions from the filesystem, as these may not have
	 * write/execute permission.  These are fixed up later in
	 * erofsfsck_set_attributes().
	 */
	if (mkdir(path, 0700) < 0) {
		struct stat st;

		if (errno != EEXIST) {
			erofs_err("failed to create directory: %s (%s)",
				  path, strerror(errno));
			return -errno;
		}

		if (lstat(path, &st) ||
		    !S_ISDIR(st.st_mode)) {
			erofs_err("path is not a directory: %s", path);
			return -ENOTDIR;
		}

		/*
		 * Try to change permissions of existing directory so
		 * that we can write to it
		 */
		if (chmod(path, 0700) < 0) {
			erofs_err("failed to set permissions: %s (%s)",
				path, strerror(errno));
			return -errno;
		}
	}
	return 0;
}

static int erofsfsck_enqueue_task(erofs_nid_t pnid, erofs_nid_t nid,
	const char *path, struct erofsfsck_dirstack *dirstack)
{
#ifdef EROFS_MT_ENABLED
	if (traverse_num_workers > 1) {
		struct erofsfsck_inode_task *task = malloc(sizeof(*task));

		if (!task)
			return -ENOMEM;

		task->pnid = pnid;
		task->nid = nid;
		task->path = path ? strdup(path) : NULL;
		task->dirstack = *dirstack;
		task->next = NULL;

		erofs_mutex_lock(&traverse_mtx);
		if (traverse_final_err) {
			erofs_mutex_unlock(&traverse_mtx);
			if (task->path)
				free(task->path);
			free(task);
			return traverse_final_err;
		}

		if (!traverse_tail)
			traverse_head = traverse_tail = task;
		else {
			traverse_tail->next = task;
			traverse_tail = task;
		}
		traverse_pending_tasks++;
		erofs_cond_signal(&traverse_cond);
		erofs_mutex_unlock(&traverse_mtx);
		return 0;
	}
#endif
	int err = erofsfsck_check_inode(pnid, nid, path, dirstack);
#ifdef EROFS_MT_ENABLED
	if (err && !traverse_final_err)
		traverse_final_err = err;
#endif
	return err;
}

#ifdef EROFS_MT_ENABLED
static void *erofsfsck_traverse_worker(void *arg)
{
	while (1) {
		struct erofsfsck_inode_task *task;

		erofs_mutex_lock(&traverse_mtx);
		while (!traverse_head && !traverse_shutdown)
			erofs_cond_wait(&traverse_cond, &traverse_mtx);

		if (traverse_shutdown && !traverse_head) {
			erofs_mutex_unlock(&traverse_mtx);
			break;
		}

		task = traverse_head;
		traverse_head = task->next;
		if (!traverse_head)
			traverse_tail = NULL;
		erofs_mutex_unlock(&traverse_mtx);

		int err = erofsfsck_check_inode(task->pnid, task->nid, task->path, &task->dirstack);

		erofs_mutex_lock(&traverse_mtx);
		if (err && !traverse_final_err)
			traverse_final_err = err;
		traverse_pending_tasks--;
		if (traverse_pending_tasks == 0)
			erofs_cond_signal(&traverse_cond_finish);
		erofs_mutex_unlock(&traverse_mtx);

		if (task->path)
			free(task->path);
		free(task);
	}
	return NULL;
}
#endif

static int erofsfsck_traverse_mt_init(void)
{
#ifdef EROFS_MT_ENABLED
	erofs_mutex_init(&traverse_mtx);
	erofs_cond_init(&traverse_cond);
	erofs_cond_init(&traverse_cond_finish);
	erofs_mutex_init(&hardlink_mtx);
	erofs_mutex_init(&stats_mtx);

	traverse_num_workers = erofs_get_available_processors();
	if (traverse_num_workers <= 1)
		return 0;

	traverse_workers = calloc(traverse_num_workers, sizeof(pthread_t));
	if (!traverse_workers)
		return -ENOMEM;

	for (int i = 0; i < traverse_num_workers; i++)
		pthread_create(&traverse_workers[i], NULL, erofsfsck_traverse_worker, NULL);
#endif
	return 0;
}

static void erofsfsck_traverse_mt_exit(void)
{
#ifdef EROFS_MT_ENABLED
	if (traverse_workers) {
		erofs_mutex_lock(&traverse_mtx);
		traverse_shutdown = true;
		erofs_cond_broadcast(&traverse_cond);
		erofs_mutex_unlock(&traverse_mtx);

		for (int i = 0; i < traverse_num_workers; i++)
			pthread_join(traverse_workers[i], NULL);

		free(traverse_workers);
		traverse_workers = NULL;
	}
	erofs_mutex_destroy(&traverse_mtx);
	erofs_cond_destroy(&traverse_cond);
	erofs_cond_destroy(&traverse_cond_finish);
	erofs_mutex_destroy(&hardlink_mtx);
	erofs_mutex_destroy(&stats_mtx);
#endif
}

static int erofsfsck_traverse_mt_wait(void)
{
#ifdef EROFS_MT_ENABLED
	if (traverse_num_workers <= 1)
		return traverse_final_err;

	erofs_mutex_lock(&traverse_mtx);
	while (traverse_pending_tasks > 0)
		erofs_cond_wait(&traverse_cond_finish, &traverse_mtx);

	int err = traverse_final_err;

	erofs_mutex_unlock(&traverse_mtx);
	return err;
#else
	return 0;
#endif
}

static char *erofsfsck_hardlink_find(erofs_nid_t nid)
{
	struct list_head *head =
			&erofsfsck_link_hashtable[nid % NR_HARDLINK_HASHTABLE];
	struct erofsfsck_hardlink_entry *entry;
	char *path = NULL;

#ifdef EROFS_MT_ENABLED
	erofs_mutex_lock(&hardlink_mtx);
#endif
	list_for_each_entry(entry, head, list) {
		if (entry->nid == nid) {
			path = entry->path;
			break;
		}
	}
#ifdef EROFS_MT_ENABLED
	erofs_mutex_unlock(&hardlink_mtx);
#endif
	return path;

}

static int erofsfsck_hardlink_insert(erofs_nid_t nid, const char *path)
{
	struct erofsfsck_hardlink_entry *entry;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return -ENOMEM;

	entry->nid = nid;
	entry->path = strdup(path);
	if (!entry->path) {
		free(entry);
		return -ENOMEM;
	}

#ifdef EROFS_MT_ENABLED
	erofs_mutex_lock(&hardlink_mtx);
#endif

	list_add_tail(&entry->list,
		      &erofsfsck_link_hashtable[nid % NR_HARDLINK_HASHTABLE]);

#ifdef EROFS_MT_ENABLED
	erofs_mutex_unlock(&hardlink_mtx);
#endif

	return 0;
}

static void erofsfsck_hardlink_init(void)
{
	unsigned int i;

	for (i = 0; i < NR_HARDLINK_HASHTABLE; ++i)
		init_list_head(&erofsfsck_link_hashtable[i]);
}

static void erofsfsck_hardlink_exit(void)
{
	struct erofsfsck_hardlink_entry *entry, *n;
	struct list_head *head;
	unsigned int i;

	for (i = 0; i < NR_HARDLINK_HASHTABLE; ++i) {
		head = &erofsfsck_link_hashtable[i];

		list_for_each_entry_safe(entry, n, head, list) {
			if (entry->path)
				free(entry->path);
			free(entry);
		}
	}
}

static int erofsfsck_verify_file_digest(struct erofs_inode *inode,
					const u8 *digest)
{
	u8 stored[32 + sizeof("sha256:") - 1];
	int ret;

	ret = __erofs_getxattr(inode, fsckcfg.digest_xattr_name,
			       (char *)stored, sizeof(stored), true);
	if (ret == -ENODATA) {
		erofs_warn("no digest xattr for nid %llu, skipped",
			   inode->nid | 0ULL);
		return 0;
	} else if (ret < 0)
		return ret;

	if (ret != sizeof(stored) ||
	    memcmp(stored, "sha256:", sizeof("sha256:") - 1)) {
		erofs_err("unidentified digest xattr @ nid %llu (size=%d)",
			  inode->nid | 0ULL, ret);
		return -EFSCORRUPTED;
	}

	if (memcmp(digest, stored + sizeof("sha256:") - 1, 32)) {
		erofs_err("digest MISMATCH @ nid %llu",
			  inode->nid | 0ULL);
		return -EFSCORRUPTED;
	}
	return 0;
}

static int erofsfsck_calc_inode_data(struct erofs_inode *inode, int outfd)
{
	int ret;

	if (fsckcfg.digest_xattr_name &&
	    S_ISREG(inode->i_mode) && inode->i_size > 0) {
		struct sha256_state md;
		u8 out[32];

		erofs_sha256_init(&md);
		ret = erofs_verify_inode_data(inode, outfd, &md);
		erofs_sha256_done(&md, out);

		if (ret)
			return ret;
		return erofsfsck_verify_file_digest(inode, out);
	}
	return erofs_verify_inode_data(inode, outfd, NULL);
}

static inline int erofs_extract_file(struct erofs_inode *inode, const char *path)
{
	bool tryagain = true;
	int ret, fd;

	erofs_dbg("extract file to path: %s", path);

again:
	fd = open(path,
		  O_WRONLY | O_CREAT | O_NOFOLLOW |
			(fsckcfg.overwrite ? O_TRUNC : O_EXCL), 0700);
	if (fd < 0) {
		if (fsckcfg.overwrite && tryagain) {
			if (errno == EISDIR) {
				erofs_warn("try to forcely remove directory %s", path);
				if (rmdir(path) < 0) {
					erofs_err("failed to remove: %s (%s)", path,
						strerror(errno));
					return -EISDIR;
				}
			} else if (errno == EACCES &&
				   chmod(path, 0700) < 0) {
				erofs_err("failed to set permissions: %s (%s)", path,
					strerror(errno));
				return -errno;
			}
			tryagain = false;
			goto again;
		}
		erofs_err("failed to open: %s (%s)", path, strerror(errno));
		return -errno;
	}

	ret = erofsfsck_calc_inode_data(inode, fd);
	close(fd);
	return ret;
}

static inline int erofs_extract_symlink(struct erofs_inode *inode, const char *path)
{
	struct erofs_vfile vf;
	bool tryagain = true;
	erofs_off_t bufsz;
	int ret;
	char *buf = NULL;

	erofs_dbg("extract symlink to path: %s", path);

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(inode, -1, NULL);
	if (ret)
		return ret;

	if (check_add_overflow(inode->i_size, (erofs_off_t)1, &bufsz) ||
	    !(buf = malloc(bufsz))) {
		ret = -ENOMEM;
		goto out;
	}

	ret = erofs_iopen(&vf, inode);
	if (ret)
		goto out;

	ret = erofs_pread(&vf, buf, inode->i_size, 0);
	if (ret) {
		erofs_err("I/O error occurred when reading symlink @ nid %llu: %d",
			  inode->nid | 0ULL, ret);
		goto out;
	}

	buf[inode->i_size] = '\0';
again:
	if (symlink(buf, path) < 0) {
		if (errno == EEXIST && fsckcfg.overwrite && tryagain) {
			erofs_warn("try to forcely remove file %s", path);
			if (unlink(path) < 0) {
				erofs_err("failed to remove: %s", path);
				ret = -errno;
				goto out;
			}
			tryagain = false;
			goto again;
		}
		erofs_err("failed to create symlink: %s", path);
		ret = -errno;
	}
out:
	if (buf)
		free(buf);
	return ret;
}

static int erofs_extract_special(struct erofs_inode *inode, const char *path)
{
	bool tryagain = true;
	int ret;

	erofs_dbg("extract special to path: %s", path);

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(inode, -1, NULL);
	if (ret)
		return ret;

again:
	if (mknod(path, inode->i_mode, inode->u.i_rdev) < 0) {
		if (errno == EEXIST && fsckcfg.overwrite && tryagain) {
			erofs_warn("try to forcely remove file %s", path);
			if (unlink(path) < 0) {
				erofs_err("failed to remove: %s", path);
				return -errno;
			}
			tryagain = false;
			goto again;
		}
		if (errno == EEXIST || fsckcfg.superuser) {
			erofs_err("failed to create special file: %s", path);
			ret = -errno;
		} else {
			erofs_warn("failed to create special file: %s, skipped", path);
			ret = -ECANCELED;
		}
	}
	return ret;
}

struct erofsfsck_get_parent_ctx {
	struct erofs_dir_context ctx;
	erofs_nid_t pnid;
};

static int erofsfsck_get_parent_cb(struct erofs_dir_context *ctx)
{
	struct erofsfsck_get_parent_ctx *pctx = (void *)ctx;

	if (ctx->dot_dotdot && ctx->de_namelen == 2) {
		pctx->pnid = ctx->de_nid;
		return 1;
	}
	return 0;
}

struct erofsfsck_dir_ctx {
	struct erofs_dir_context ctx;
	const char *path;
	struct erofsfsck_dirstack *dirstack;
};

static int erofsfsck_dirent_iter(struct erofs_dir_context *ctx)
{
	struct erofsfsck_dir_ctx *fctx = (void *)ctx;
	int ret;
	char *newpath = NULL;

	if (ctx->dot_dotdot)
		return 0;

	if (fctx->path) {
		size_t prev_len = strlen(fctx->path);
		size_t curr_len = prev_len + ctx->de_namelen + 1;

		if (curr_len >= PATH_MAX) {
			erofs_err("unable to fsck since the path is too long (%llu)",
				(unsigned long long)curr_len);
			return -EOPNOTSUPP;
		}
		newpath = malloc(curr_len + 1);
		if (!newpath)
			return -ENOMEM;

		bool is_root = (fctx->path[0] == '/' && fctx->path[1] == '\0');
		size_t offset = prev_len;

		memcpy(newpath, fctx->path, prev_len);
		if (!is_root)
			newpath[offset++] = '/';

		memcpy(newpath + offset, ctx->dname, ctx->de_namelen);
		offset += ctx->de_namelen;
		newpath[offset] = '\0';
	}

	ret = erofsfsck_enqueue_task(ctx->dir->nid, ctx->de_nid, newpath, fctx->dirstack);
	if (newpath)
		free(newpath);
	return ret;
}

static int erofsfsck_extract_inode(struct erofs_inode *inode, const char *path)
{
	char *oldpath;
	int ret;

	if (!fsckcfg.extract_path || erofs_is_packed_inode(inode)) {
verify:
		/* verify data chunk layout */
		return erofsfsck_calc_inode_data(inode, -1);
	}

	oldpath = erofsfsck_hardlink_find(inode->nid);
	if (oldpath) {
		if (link(oldpath, path) == -1) {
			erofs_err("failed to extract hard link: %s (%s)", path, strerror(errno));
			return -errno;
		}
		return 0;
	}

	switch (inode->i_mode & S_IFMT) {
	case S_IFDIR:
		ret = erofs_extract_dir(inode, path);
		break;
	case S_IFREG:
		ret = erofs_extract_file(inode, path);
		break;
	case S_IFLNK:
		ret = erofs_extract_symlink(inode, path);
		break;
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		ret = erofs_extract_special(inode, path);
		break;
	default:
		erofs_warn("unsupported file type %o @ nid %llu, skipped extraction",
			inode->i_mode, inode->nid | 0ULL);
		goto verify;
	}

	if (ret && (ret != -ECANCELED || fsckcfg.digest_xattr_name))
		return ret;

	/* record nid and old path for hardlink */
	if (inode->i_nlink > 1 && !S_ISDIR(inode->i_mode))
		ret = erofsfsck_hardlink_insert(inode->nid, path);
	return ret;
}

static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid,
	const char *path, struct erofsfsck_dirstack *dirstack)
{
	int ret, i;
	struct erofs_inode inode = {.sbi = &g_sbi, .nid = nid};

	erofs_dbg("check inode: nid(%llu)", nid | 0ULL);
	ret = erofs_read_inode_from_disk(&inode);
	if (ret) {
		if (ret == -EIO)
			erofs_err("I/O error occurred when reading nid(%llu)",
				  nid | 0ULL);
		goto out;
	}

	if (!(fsckcfg.check_decomp && fsckcfg.dump_xattrs)) {
		/* verify xattr field */
		ret = erofs_verify_xattr(&inode);
		if (ret)
			goto out;
	}

	ret = erofsfsck_extract_inode(&inode, path);
	if (ret && ret != -ECANCELED)
		goto out;

	if (fsckcfg.check_decomp && fsckcfg.dump_xattrs) {
		ret = erofsfsck_dump_xattrs(&inode, path);
		if (ret)
			return ret;
	}

	if (S_ISDIR(inode.i_mode)) {
		struct erofsfsck_dir_ctx ctx = {
			.ctx.flags = EROFS_READDIR_VALID_PNID,
			.ctx.pnid = pnid,
			.ctx.dir = &inode,
			.ctx.cb = erofsfsck_dirent_iter,
			.path = path,
			.dirstack = dirstack,
		};
		struct erofsfsck_dirstack next_dirstack;

		if (dirstack->top >= ARRAY_SIZE(dirstack->dirs))
			return -ENAMETOOLONG;

		for (i = 0; i < dirstack->top; ++i) {
			if (inode.nid == dirstack->dirs[i])
				return -ELOOP;
		}

		next_dirstack = *dirstack;
		next_dirstack.dirs[next_dirstack.top++] = pnid;
		ctx.dirstack = &next_dirstack;

		ret = erofs_iterate_dir(&ctx.ctx, true);
		if (ret == -ECANCELED)
			ret = 0;
	}

	if (!ret && !erofs_is_packed_inode(&inode))
		erofsfsck_set_attributes(&inode, (char *)path);

out:
	if (ret && ret != -EIO) {
#ifdef EROFS_MT_ENABLED
		erofs_mutex_lock(&traverse_mtx);
#endif
		fsckcfg.corrupted = true;
#ifdef EROFS_MT_ENABLED
		erofs_mutex_unlock(&traverse_mtx);
#endif
	}
	return ret;
}

#ifdef FUZZING
int erofsfsck_fuzz_one(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
	int err;

	erofs_init_configure();

	fsckcfg.physical_blocks = 0;
	fsckcfg.logical_blocks = 0;
	fsckcfg.extract_path = NULL;
	fsckcfg.umask = umask(0);
	fsckcfg.superuser = geteuid() == 0;
	fsckcfg.corrupted = false;
	fsckcfg.print_comp_ratio = false;
	fsckcfg.check_decomp = false;
	fsckcfg.force = false;
	fsckcfg.overwrite = false;
	fsckcfg.preserve_owner = fsckcfg.superuser;
	fsckcfg.preserve_perms = fsckcfg.superuser;
	fsckcfg.dump_xattrs = false;
	fsckcfg.nid = 0;
	fsckcfg.inode_path = NULL;

	err = erofsfsck_parse_options_cfg(argc, argv);
	if (err) {
		if (err == -EINVAL)
			fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		goto exit;
	}

#ifdef FUZZING
	cfg.c_dbg_lvl = -1;
	fsckcfg.nosbcrc = true;
#endif

	err = erofs_dev_open(&g_sbi, cfg.c_img_path, O_RDONLY);
	if (err) {
		erofs_err("failed to open image file");
		goto exit;
	}

	err = erofs_read_superblock(&g_sbi);
	if (err) {
		erofs_err("failed to read superblock");
		goto exit_dev_close;
	}

	if (!fsckcfg.nosbcrc && erofs_sb_has_sb_chksum(&g_sbi) &&
	    erofs_superblock_csum_verify(&g_sbi)) {
		fsckcfg.corrupted = true;
		erofs_err("failed to verify superblock checksum");
		goto exit_put_super;
	}

	if (fsckcfg.digest_xattr_name == erofsfsck_nullstr) {
		fsckcfg.digest_xattr_name =
			erofs_xattr_get_ishare_prefix(&g_sbi);
		if (IS_ERR(fsckcfg.digest_xattr_name)) {
			err = PTR_ERR(fsckcfg.digest_xattr_name);
			erofs_err("failed to get ishare prefix: %s",
				  erofs_strerror(err));
			goto exit_put_super;
		}

		if (!fsckcfg.digest_xattr_name) {
			erofs_err("image has no inode digest xattrs (was --xattr-inode-digest used during mkfs?)");
			err = -ENODATA;
			goto exit_put_super;
		}
		erofs_info("verifying digests using xattr \"%s\"",
			   fsckcfg.digest_xattr_name);
	}

	if (fsckcfg.extract_path)
		erofsfsck_hardlink_init();

	err = erofsfsck_traverse_mt_init();
	if (err)
		goto exit_hardlink;

	if (fsckcfg.inode_path) {
		struct erofs_inode inode = { .sbi = &g_sbi };

		err = erofs_ilookup(fsckcfg.inode_path, &inode);
		if (err) {
			erofs_err("failed to lookup %s", fsckcfg.inode_path);
			goto exit_hardlink;
		}
		fsckcfg.nid = inode.nid;
	} else if (!fsckcfg.nid) {
		fsckcfg.nid = g_sbi.root_nid;
	}

	if (!fsckcfg.inode_path && fsckcfg.nid == g_sbi.root_nid) {
		if (erofs_sb_has_fragments(&g_sbi) && g_sbi.packed_nid > 0) {
			err = erofs_packedfile_init(&g_sbi, false);
			if (err) {
				erofs_err("failed to initialize packedfile: %s",
					  erofs_strerror(err));
				goto exit_mt_exit;
			}
			struct erofsfsck_dirstack empty_dirstack = {0};

			err = erofsfsck_enqueue_task(g_sbi.packed_nid, g_sbi.packed_nid,
				NULL, &empty_dirstack);
			if (err) {
				erofs_err("failed to verify packed file");
				goto exit_packedinode;
			}
		}
	}

	{
		erofs_nid_t pnid = fsckcfg.nid;


		if (fsckcfg.nid != g_sbi.root_nid) {
			struct erofs_inode inode = { .sbi = &g_sbi, .nid = fsckcfg.nid };

			if (!erofs_read_inode_from_disk(&inode) &&
			    S_ISDIR(inode.i_mode)) {
				struct erofsfsck_get_parent_ctx ctx = {
					.ctx.dir = &inode,
					.ctx.cb = erofsfsck_get_parent_cb,
				};

				if (erofs_iterate_dir(&ctx.ctx, false) == 1)
					pnid = ctx.pnid;
			}
		}
		struct erofsfsck_dirstack empty_dirstack = {0};

		err = erofsfsck_enqueue_task(pnid, fsckcfg.nid, fsckcfg.extract_path,
			&empty_dirstack);

		int wait_err = erofsfsck_traverse_mt_wait();

		if (wait_err && !err)
			err = wait_err;
	}

	if (fsckcfg.corrupted) {
		if (!fsckcfg.extract_path)
			erofs_err("Found some filesystem corruption");
		else
			erofs_err("Failed to extract filesystem");
		err = -EFSCORRUPTED;
	} else if (!err) {
		if (!fsckcfg.extract_path)
			erofs_info("No errors found");
		else
			erofs_info("Extracted filesystem successfully");

		if (fsckcfg.print_comp_ratio) {
			double comp_ratio =
				(double)fsckcfg.physical_blocks * 100 /
				(double)fsckcfg.logical_blocks;

			erofs_info("Compression ratio: %.2f(%%)", comp_ratio);
		}
	}

exit_packedinode:
	erofs_packedfile_exit(&g_sbi);
exit_mt_exit:
	erofsfsck_traverse_mt_exit();
exit_hardlink:
	if (fsckcfg.extract_path)
		erofsfsck_hardlink_exit();
exit_put_super:
	if (fsckcfg.digest_xattr_name != erofsfsck_nullstr)
		free(fsckcfg.digest_xattr_name);
	erofs_put_super(&g_sbi);
exit_dev_close:
	erofs_dev_close(&g_sbi);
exit:
	erofs_blob_closeall(&g_sbi);
	erofs_exit_configure();
	return err ? 1 : 0;
}

#ifdef FUZZING
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	int fd, ret;
	char filename[] = "/tmp/erofsfsck_libfuzzer_XXXXXX";
	char *argv[] = {
		"fsck.erofs",
		"--extract",
		filename,
	};

	fd = mkstemp(filename);
	if (fd < 0)
		return -errno;
	if (write(fd, Data, Size) != Size) {
		close(fd);
		return -EIO;
	}
	close(fd);
	ret = erofsfsck_fuzz_one(ARRAY_SIZE(argv), argv);
	unlink(filename);
	return ret ? -1 : 0;
}
#endif
