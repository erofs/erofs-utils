// SPDX-License-Identifier: GPL-2.0+
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
#include "erofs/io.h"
#include "erofs/compress.h"
#include "erofs/decompress.h"
#include "erofs/dir.h"

static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid);

struct erofsfsck_cfg {
	u64 physical_blocks;
	u64 logical_blocks;
	char *extract_path;
	size_t extract_pos;
	mode_t umask;
	bool superuser;
	bool corrupted;
	bool print_comp_ratio;
	bool check_decomp;
	bool force;
	bool overwrite;
	bool preserve_owner;
	bool preserve_perms;
};
static struct erofsfsck_cfg fsckcfg;

static struct option long_options[] = {
	{"help", no_argument, 0, 1},
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
	{0, 0, 0, 0},
};

static void print_available_decompressors(FILE *f, const char *delim)
{
	unsigned int i = 0;
	const char *s;

	while ((s = z_erofs_list_available_compressors(i)) != NULL) {
		if (i++)
			fputs(delim, f);
		fputs(s, f);
	}
	fputc('\n', f);
}

static void usage(void)
{
	fputs("usage: [options] IMAGE\n\n"
	      "Check erofs filesystem compatibility and integrity of IMAGE, and [options] are:\n"
	      " -V                     print the version number of fsck.erofs and exit\n"
	      " -d#                    set output message level to # (maximum 9)\n"
	      " -p                     print total compression ratio of all files\n"
	      " --device=X             specify an extra device to be used together\n"
	      " --extract[=X]          check if all files are well encoded, optionally extract to X\n"
	      " --help                 display this help and exit\n"
	      "\nExtraction options (--extract=X is required):\n"
	      " --force                allow extracting to root\n"
	      " --overwrite            overwrite files that already exist\n"
	      " --preserve             extract with the same ownership and permissions as on the filesystem\n"
	      "                        (default for superuser)\n"
	      " --preserve-owner       extract with the same ownership as on the filesystem\n"
	      " --preserve-perms       extract with the same permissions as on the filesystem\n"
	      " --no-preserve          extract as yourself and apply user's umask on permissions\n"
	      "                        (default for ordinary users)\n"
	      " --no-preserve-owner    extract as yourself\n"
	      " --no-preserve-perms    apply user's umask when extracting permissions\n"
	      "\nSupported algorithms are: ", stderr);
	print_available_decompressors(stderr, ", ");
}

static void erofsfsck_print_version(void)
{
	printf("fsck.erofs %s\n", cfg.c_version);
}

static int erofsfsck_parse_options_cfg(int argc, char **argv)
{
	int opt, ret;
	bool has_opt_preserve = false;

	while ((opt = getopt_long(argc, argv, "Vd:p",
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
		case 1:
			usage();
			exit(0);
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

				fsckcfg.extract_path = malloc(PATH_MAX);
				if (!fsckcfg.extract_path)
					return -ENOMEM;
				strncpy(fsckcfg.extract_path, optarg, len);
				fsckcfg.extract_path[len] = '\0';
				/* if path is root, start writing from position 0 */
				if (len == 1 && fsckcfg.extract_path[0] == '/')
					len = 0;
				fsckcfg.extract_pos = len;
			}
			break;
		case 3:
			ret = blob_open_ro(optarg);
			if (ret)
				return ret;
			++sbi.extra_devices;
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
		default:
			return -EINVAL;
		}
	}

	if (fsckcfg.extract_path) {
		if (!fsckcfg.extract_pos && !fsckcfg.force) {
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

	if (!S_ISLNK(inode->i_mode)) {
		if (fsckcfg.preserve_perms)
			ret = chmod(path, inode->i_mode);
		else
			ret = chmod(path, inode->i_mode & ~fsckcfg.umask);
		if (ret < 0)
			erofs_warn("failed to set permissions: %s", path);
	}

	if (fsckcfg.preserve_owner) {
		ret = lchown(path, inode->i_uid, inode->i_gid);
		if (ret < 0)
			erofs_warn("failed to change ownership: %s", path);
	}
}

static int erofs_check_sb_chksum(void)
{
	int ret;
	u8 buf[EROFS_BLKSIZ];
	u32 crc;
	struct erofs_super_block *sb;

	ret = blk_read(0, buf, 0, 1);
	if (ret) {
		erofs_err("failed to read superblock to check checksum: %d",
			  ret);
		return -1;
	}

	sb = (struct erofs_super_block *)(buf + EROFS_SUPER_OFFSET);
	sb->checksum = 0;

	crc = erofs_crc32c(~0, (u8 *)sb, EROFS_BLKSIZ - EROFS_SUPER_OFFSET);
	if (crc != sbi.checksum) {
		erofs_err("superblock chksum doesn't match: saved(%08xh) calculated(%08xh)",
			  sbi.checksum, crc);
		fsckcfg.corrupted = true;
		return -1;
	}
	return 0;
}

static int erofs_verify_xattr(struct erofs_inode *inode)
{
	unsigned int xattr_hdr_size = sizeof(struct erofs_xattr_ibody_header);
	unsigned int xattr_entry_size = sizeof(struct erofs_xattr_entry);
	erofs_off_t addr;
	unsigned int ofs, xattr_shared_count;
	struct erofs_xattr_ibody_header *ih;
	struct erofs_xattr_entry *entry;
	int i, remaining = inode->xattr_isize, ret = 0;
	char buf[EROFS_BLKSIZ];

	if (inode->xattr_isize == xattr_hdr_size) {
		erofs_err("xattr_isize %d of nid %llu is not supported yet",
			  inode->xattr_isize, inode->nid | 0ULL);
		ret = -EFSCORRUPTED;
		goto out;
	} else if (inode->xattr_isize < xattr_hdr_size) {
		if (inode->xattr_isize) {
			erofs_err("bogus xattr ibody @ nid %llu",
				  inode->nid | 0ULL);
			ret = -EFSCORRUPTED;
			goto out;
		}
	}

	addr = iloc(inode->nid) + inode->inode_isize;
	ret = dev_read(0, buf, addr, xattr_hdr_size);
	if (ret < 0) {
		erofs_err("failed to read xattr header @ nid %llu: %d",
			  inode->nid | 0ULL, ret);
		goto out;
	}
	ih = (struct erofs_xattr_ibody_header *)buf;
	xattr_shared_count = ih->h_shared_count;

	ofs = erofs_blkoff(addr) + xattr_hdr_size;
	addr += xattr_hdr_size;
	remaining -= xattr_hdr_size;
	for (i = 0; i < xattr_shared_count; ++i) {
		if (ofs >= EROFS_BLKSIZ) {
			if (ofs != EROFS_BLKSIZ) {
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

		ret = dev_read(0, buf, addr, xattr_entry_size);
		if (ret) {
			erofs_err("failed to read xattr entry @ nid %llu: %d",
				  inode->nid | 0ULL, ret);
			goto out;
		}

		entry = (struct erofs_xattr_entry *)buf;
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
	return ret;
}

static int erofs_verify_inode_data(struct erofs_inode *inode, int outfd)
{
	struct erofs_map_blocks map = {
		.index = UINT_MAX,
	};
	struct erofs_map_dev mdev;
	int ret = 0;
	bool compressed;
	erofs_off_t pos = 0;
	u64 pchunk_len = 0;
	unsigned int raw_size = 0, buffer_size = 0;
	char *raw = NULL, *buffer = NULL;

	erofs_dbg("verify data chunk of nid(%llu): type(%d)",
		  inode->nid | 0ULL, inode->datalayout);

	switch (inode->datalayout) {
	case EROFS_INODE_FLAT_PLAIN:
	case EROFS_INODE_FLAT_INLINE:
	case EROFS_INODE_CHUNK_BASED:
		compressed = false;
		break;
	case EROFS_INODE_FLAT_COMPRESSION_LEGACY:
	case EROFS_INODE_FLAT_COMPRESSION:
		compressed = true;
		break;
	default:
		erofs_err("unknown datalayout");
		return -EINVAL;
	}

	while (pos < inode->i_size) {
		map.m_la = pos;
		if (compressed)
			ret = z_erofs_map_blocks_iter(inode, &map,
					EROFS_GET_BLOCKS_FIEMAP);
		else
			ret = erofs_map_blocks(inode, &map,
					EROFS_GET_BLOCKS_FIEMAP);
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
		if (!(map.m_flags & EROFS_MAP_MAPPED) || !fsckcfg.check_decomp)
			continue;

		if (map.m_plen > raw_size) {
			raw_size = map.m_plen;
			raw = realloc(raw, raw_size);
			BUG_ON(!raw);
		}

		mdev = (struct erofs_map_dev) {
			.m_deviceid = map.m_deviceid,
			.m_pa = map.m_pa,
		};
		ret = erofs_map_dev(&sbi, &mdev);
		if (ret) {
			erofs_err("failed to map device of m_pa %" PRIu64 ", m_deviceid %u @ nid %llu: %d",
				  map.m_pa, map.m_deviceid, inode->nid | 0ULL,
				  ret);
			goto out;
		}

		if (compressed && map.m_llen > buffer_size) {
			buffer_size = map.m_llen;
			buffer = realloc(buffer, buffer_size);
			BUG_ON(!buffer);
		}

		ret = dev_read(mdev.m_deviceid, raw, mdev.m_pa, map.m_plen);
		if (ret < 0) {
			erofs_err("failed to read data of m_pa %" PRIu64 ", m_plen %" PRIu64 " @ nid %llu: %d",
				  mdev.m_pa, map.m_plen, inode->nid | 0ULL,
				  ret);
			goto out;
		}

		if (compressed) {
			struct z_erofs_decompress_req rq = {
				.in = raw,
				.out = buffer,
				.decodedskip = 0,
				.inputsize = map.m_plen,
				.decodedlength = map.m_llen,
				.alg = map.m_algorithmformat,
				.partial_decoding = 0
			};

			ret = z_erofs_decompress(&rq);
			if (ret < 0) {
				erofs_err("failed to decompress data of m_pa %" PRIu64 ", m_plen %" PRIu64 " @ nid %llu: %s",
					  mdev.m_pa, map.m_plen,
					  inode->nid | 0ULL, strerror(-ret));
				goto out;
			}
		}

		if (outfd >= 0 && write(outfd, compressed ? buffer : raw,
					map.m_llen) < 0) {
			erofs_err("I/O error occurred when verifying data chunk @ nid %llu",
				  inode->nid | 0ULL);
			ret = -EIO;
			goto out;
		}
	}

	if (fsckcfg.print_comp_ratio) {
		fsckcfg.logical_blocks +=
			DIV_ROUND_UP(inode->i_size, EROFS_BLKSIZ);
		fsckcfg.physical_blocks +=
			DIV_ROUND_UP(pchunk_len, EROFS_BLKSIZ);
	}
out:
	if (raw)
		free(raw);
	if (buffer)
		free(buffer);
	return ret < 0 ? ret : 0;
}

static inline int erofs_extract_dir(struct erofs_inode *inode)
{
	int ret;

	erofs_dbg("create directory %s", fsckcfg.extract_path);

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(inode, -1);
	if (ret)
		return ret;

	/*
	 * Make directory with default user rwx permissions rather than
	 * the permissions from the filesystem, as these may not have
	 * write/execute permission.  These are fixed up later in
	 * erofsfsck_set_attributes().
	 */
	if (mkdir(fsckcfg.extract_path, 0700) < 0) {
		struct stat st;

		if (errno != EEXIST) {
			erofs_err("failed to create directory: %s (%s)",
				  fsckcfg.extract_path, strerror(errno));
			return -errno;
		}

		if (lstat(fsckcfg.extract_path, &st) ||
		    !S_ISDIR(st.st_mode)) {
			erofs_err("path is not a directory: %s",
				  fsckcfg.extract_path);
			return -ENOTDIR;
		}

		/*
		 * Try to change permissions of existing directory so
		 * that we can write to it
		 */
		if (chmod(fsckcfg.extract_path, 0700) < 0) {
			erofs_err("failed to set permissions: %s (%s)",
				  fsckcfg.extract_path, strerror(errno));
			return -errno;
		}
	}
	return 0;
}

static inline int erofs_extract_file(struct erofs_inode *inode)
{
	bool tryagain = true;
	int ret, fd;

	erofs_dbg("extract file to path: %s", fsckcfg.extract_path);

again:
	fd = open(fsckcfg.extract_path,
		  O_WRONLY | O_CREAT | O_NOFOLLOW |
			(fsckcfg.overwrite ? O_TRUNC : O_EXCL), 0700);
	if (fd < 0) {
		if (fsckcfg.overwrite && tryagain) {
			if (errno == EISDIR) {
				erofs_warn("try to forcely remove directory %s",
					   fsckcfg.extract_path);
				if (rmdir(fsckcfg.extract_path) < 0) {
					erofs_err("failed to remove: %s (%s)",
						  fsckcfg.extract_path, strerror(errno));
					return -EISDIR;
				}
			} else if (errno == EACCES &&
				   chmod(fsckcfg.extract_path, 0700) < 0) {
				erofs_err("failed to set permissions: %s (%s)",
					  fsckcfg.extract_path, strerror(errno));
				return -errno;
			}
			tryagain = false;
			goto again;
		}
		erofs_err("failed to open: %s (%s)", fsckcfg.extract_path,
			  strerror(errno));
		return -errno;
	}

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(inode, fd);
	if (ret)
		return ret;

	if (close(fd))
		return -errno;
	return ret;
}

static inline int erofs_extract_symlink(struct erofs_inode *inode)
{
	bool tryagain = true;
	int ret;
	char *buf = NULL;

	erofs_dbg("extract symlink to path: %s", fsckcfg.extract_path);

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(inode, -1);
	if (ret)
		return ret;

	buf = malloc(inode->i_size + 1);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	ret = erofs_pread(inode, buf, inode->i_size, 0);
	if (ret) {
		erofs_err("I/O error occurred when reading symlink @ nid %llu: %d",
			  inode->nid | 0ULL, ret);
		goto out;
	}

	buf[inode->i_size] = '\0';
again:
	if (symlink(buf, fsckcfg.extract_path) < 0) {
		if (errno == EEXIST && fsckcfg.overwrite && tryagain) {
			erofs_warn("try to forcely remove file %s",
				   fsckcfg.extract_path);
			if (unlink(fsckcfg.extract_path) < 0) {
				erofs_err("failed to remove: %s",
					  fsckcfg.extract_path);
				ret = -errno;
				goto out;
			}
			tryagain = false;
			goto again;
		}
		erofs_err("failed to create symlink: %s",
			  fsckcfg.extract_path);
		ret = -errno;
	}
out:
	if (buf)
		free(buf);
	return ret;
}

static int erofs_extract_special(struct erofs_inode *inode)
{
	bool tryagain = true;
	int ret;

	erofs_dbg("extract special to path: %s", fsckcfg.extract_path);

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(inode, -1);
	if (ret)
		return ret;

again:
	if (mknod(fsckcfg.extract_path, inode->i_mode, inode->u.i_rdev) < 0) {
		if (errno == EEXIST && fsckcfg.overwrite && tryagain) {
			erofs_warn("try to forcely remove file %s",
				   fsckcfg.extract_path);
			if (unlink(fsckcfg.extract_path) < 0) {
				erofs_err("failed to remove: %s",
					  fsckcfg.extract_path);
				return -errno;
			}
			tryagain = false;
			goto again;
		}
		if (errno == EEXIST || fsckcfg.superuser) {
			erofs_err("failed to create special file: %s",
				  fsckcfg.extract_path);
			ret = -errno;
		} else {
			erofs_warn("failed to create special file: %s, skipped",
				   fsckcfg.extract_path);
			ret = -ECANCELED;
		}
	}
	return ret;
}

static int erofsfsck_dirent_iter(struct erofs_dir_context *ctx)
{
	int ret;
	size_t prev_pos = fsckcfg.extract_pos;

	if (ctx->dot_dotdot)
		return 0;

	if (fsckcfg.extract_path) {
		size_t curr_pos = prev_pos;

		fsckcfg.extract_path[curr_pos++] = '/';
		strncpy(fsckcfg.extract_path + curr_pos, ctx->dname,
			ctx->de_namelen);
		curr_pos += ctx->de_namelen;
		fsckcfg.extract_path[curr_pos] = '\0';
		fsckcfg.extract_pos = curr_pos;
	}

	ret = erofsfsck_check_inode(ctx->dir->nid, ctx->de_nid);

	if (fsckcfg.extract_path) {
		fsckcfg.extract_path[prev_pos] = '\0';
		fsckcfg.extract_pos = prev_pos;
	}
	return ret;
}

static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid)
{
	int ret;
	struct erofs_inode inode;

	erofs_dbg("check inode: nid(%llu)", nid | 0ULL);

	inode.nid = nid;
	ret = erofs_read_inode_from_disk(&inode);
	if (ret) {
		if (ret == -EIO)
			erofs_err("I/O error occurred when reading nid(%llu)",
				  nid | 0ULL);
		goto out;
	}

	/* verify xattr field */
	ret = erofs_verify_xattr(&inode);
	if (ret)
		goto out;

	if (fsckcfg.extract_path) {
		switch (inode.i_mode & S_IFMT) {
		case S_IFDIR:
			ret = erofs_extract_dir(&inode);
			break;
		case S_IFREG:
			ret = erofs_extract_file(&inode);
			break;
		case S_IFLNK:
			ret = erofs_extract_symlink(&inode);
			break;
		case S_IFCHR:
		case S_IFBLK:
		case S_IFIFO:
		case S_IFSOCK:
			ret = erofs_extract_special(&inode);
			break;
		default:
			/* TODO */
			goto verify;
		}
	} else {
verify:
		/* verify data chunk layout */
		ret = erofs_verify_inode_data(&inode, -1);
	}
	if (ret && ret != -ECANCELED)
		goto out;

	/* XXXX: the dir depth should be restricted in order to avoid loops */
	if (S_ISDIR(inode.i_mode)) {
		struct erofs_dir_context ctx = {
			.flags = EROFS_READDIR_VALID_PNID,
			.pnid = pnid,
			.dir = &inode,
			.cb = erofsfsck_dirent_iter,
		};

		ret = erofs_iterate_dir(&ctx, true);
	}

	if (!ret)
		erofsfsck_set_attributes(&inode, fsckcfg.extract_path);

	if (ret == -ECANCELED)
		ret = 0;
out:
	if (ret && ret != -EIO)
		fsckcfg.corrupted = true;
	return ret;
}

int main(int argc, char **argv)
{
	int err;

	erofs_init_configure();

	fsckcfg.physical_blocks = 0;
	fsckcfg.logical_blocks = 0;
	fsckcfg.extract_path = NULL;
	fsckcfg.extract_pos = 0;
	fsckcfg.umask = umask(0);
	fsckcfg.superuser = geteuid() == 0;
	fsckcfg.corrupted = false;
	fsckcfg.print_comp_ratio = false;
	fsckcfg.check_decomp = false;
	fsckcfg.force = false;
	fsckcfg.overwrite = false;
	fsckcfg.preserve_owner = fsckcfg.superuser;
	fsckcfg.preserve_perms = fsckcfg.superuser;

	err = erofsfsck_parse_options_cfg(argc, argv);
	if (err) {
		if (err == -EINVAL)
			usage();
		goto exit;
	}

	err = dev_open_ro(cfg.c_img_path);
	if (err) {
		erofs_err("failed to open image file");
		goto exit;
	}

	err = erofs_read_superblock();
	if (err) {
		erofs_err("failed to read superblock");
		goto exit_dev_close;
	}

	if (erofs_sb_has_sb_chksum() && erofs_check_sb_chksum()) {
		erofs_err("failed to verify superblock checksum");
		goto exit_dev_close;
	}

	err = erofsfsck_check_inode(sbi.root_nid, sbi.root_nid);
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

exit_dev_close:
	dev_close();
exit:
	blob_closeall();
	erofs_exit_configure();
	return err ? 1 : 0;
}
