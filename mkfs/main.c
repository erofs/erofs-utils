// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#define _GNU_SOURCE
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <limits.h>
#include <libgen.h>
#include <sys/stat.h>
#include <getopt.h>
#include "erofs/config.h"
#include "erofs/print.h"
#include "erofs/cache.h"
#include "erofs/inode.h"
#include "erofs/tar.h"
#include "erofs/io.h"
#include "erofs/compress.h"
#include "erofs/dedupe.h"
#include "erofs/xattr.h"
#include "erofs/exclude.h"
#include "erofs/block_list.h"
#include "erofs/compress_hints.h"
#include "erofs/blobchunk.h"
#include "erofs/fragments.h"
#include "../lib/liberofs_private.h"
#include "../lib/liberofs_uuid.h"

#define EROFS_SUPER_END (EROFS_SUPER_OFFSET + sizeof(struct erofs_super_block))

static struct option long_options[] = {
	{"help", no_argument, 0, 1},
	{"exclude-path", required_argument, NULL, 2},
	{"exclude-regex", required_argument, NULL, 3},
#ifdef HAVE_LIBSELINUX
	{"file-contexts", required_argument, NULL, 4},
#endif
	{"force-uid", required_argument, NULL, 5},
	{"force-gid", required_argument, NULL, 6},
	{"all-root", no_argument, NULL, 7},
#ifndef NDEBUG
	{"random-pclusterblks", no_argument, NULL, 8},
	{"random-algorithms", no_argument, NULL, 18},
#endif
	{"max-extent-bytes", required_argument, NULL, 9},
	{"compress-hints", required_argument, NULL, 10},
	{"chunksize", required_argument, NULL, 11},
	{"quiet", no_argument, 0, 12},
	{"blobdev", required_argument, NULL, 13},
	{"ignore-mtime", no_argument, NULL, 14},
	{"preserve-mtime", no_argument, NULL, 15},
	{"uid-offset", required_argument, NULL, 16},
	{"gid-offset", required_argument, NULL, 17},
	{"tar", optional_argument, NULL, 20},
	{"aufs", no_argument, NULL, 21},
	{"mount-point", required_argument, NULL, 512},
	{"xattr-prefix", required_argument, NULL, 19},
#ifdef WITH_ANDROID
	{"product-out", required_argument, NULL, 513},
	{"fs-config-file", required_argument, NULL, 514},
	{"block-list-file", required_argument, NULL, 515},
#endif
	{0, 0, 0, 0},
};

static void print_available_compressors(FILE *f, const char *delim)
{
	int i = 0;
	bool comma = false;
	const char *s;

	while ((s = z_erofs_list_available_compressors(&i)) != NULL) {
		if (comma)
			fputs(delim, f);
		fputs(s, f);
		comma = true;
	}
	fputc('\n', f);
}

static void usage(void)
{
	fputs("usage: [options] FILE DIRECTORY\n\n"
	      "Generate erofs image from DIRECTORY to FILE, and [options] are:\n"
	      " -b#                   set block size to # (# = page size by default)\n"
	      " -d#                   set output message level to # (maximum 9)\n"
	      " -x#                   set xattr tolerance to # (< 0, disable xattrs; default 2)\n"
	      " -zX[,Y][:..]          X=compressor (Y=compression level, optional)\n"
	      "                       alternative algorithms can be separated by colons(:)\n"
	      " -C#                   specify the size of compress physical cluster in bytes\n"
	      " -EX[,...]             X=extended options\n"
	      " -L volume-label       set the volume label (maximum 16)\n"
	      " -T#                   set a fixed UNIX timestamp # to all files\n"
	      " -UX                   use a given filesystem UUID\n"
	      " --all-root            make all files owned by root\n"
	      " --blobdev=X           specify an extra device X to store chunked data\n"
	      " --chunksize=#         generate chunk-based files with #-byte chunks\n"
	      " --compress-hints=X    specify a file to configure per-file compression strategy\n"
	      " --exclude-path=X      avoid including file X (X = exact literal path)\n"
	      " --exclude-regex=X     avoid including files that match X (X = regular expression)\n"
#ifdef HAVE_LIBSELINUX
	      " --file-contexts=X     specify a file contexts file to setup selinux labels\n"
#endif
	      " --force-uid=#         set all file uids to # (# = UID)\n"
	      " --force-gid=#         set all file gids to # (# = GID)\n"
	      " --uid-offset=#        add offset # to all file uids (# = id offset)\n"
	      " --gid-offset=#        add offset # to all file gids (# = id offset)\n"
	      " --help                display this help and exit\n"
	      " --ignore-mtime        use build time instead of strict per-file modification time\n"
	      " --max-extent-bytes=#  set maximum decompressed extent size # in bytes\n"
	      " --preserve-mtime      keep per-file modification time strictly\n"
	      " --aufs                replace aufs special files with overlayfs metadata\n"
	      " --tar=[fi]            generate an image from tarball(s)\n"
	      " --quiet               quiet execution (do not write anything to standard output.)\n"
#ifndef NDEBUG
	      " --random-pclusterblks randomize pclusterblks for big pcluster (debugging only)\n"
	      " --random-algorithms   randomize per-file algorithms (debugging only)\n"
#endif
	      " --xattr-prefix=X      X=extra xattr name prefix\n"
	      " --mount-point=X       X=prefix of target fs path (default: /)\n"
#ifdef WITH_ANDROID
	      "\nwith following android-specific options:\n"
	      " --product-out=X       X=product_out directory\n"
	      " --fs-config-file=X    X=fs_config file\n"
	      " --block-list-file=X   X=block_list file\n"
#endif
	      "\nAvailable compressors are: ", stderr);
	print_available_compressors(stderr, ", ");
}

static unsigned int pclustersize_packed, pclustersize_max;
static struct erofs_tarfile erofstar = {
	.global.xattrs = LIST_HEAD_INIT(erofstar.global.xattrs)
};
static bool tar_mode;

static int parse_extended_opts(const char *opts)
{
#define MATCH_EXTENTED_OPT(opt, token, keylen) \
	(keylen == sizeof(opt) - 1 && !memcmp(token, opt, sizeof(opt) - 1))

	const char *token, *next, *tokenend, *value __maybe_unused;
	unsigned int keylen, vallen;

	value = NULL;
	for (token = opts; *token != '\0'; token = next) {
		bool clear = false;
		const char *p = strchr(token, ',');

		next = NULL;
		if (p) {
			next = p + 1;
		} else {
			p = token + strlen(token);
			next = p;
		}

		tokenend = memchr(token, '=', p - token);
		if (tokenend) {
			keylen = tokenend - token;
			vallen = p - tokenend - 1;
			if (!vallen)
				return -EINVAL;

			value = tokenend + 1;
		} else {
			keylen = p - token;
			vallen = 0;
		}

		if (token[0] == '^') {
			if (keylen < 2)
				return -EINVAL;
			++token;
			--keylen;
			clear = true;
		}

		if (MATCH_EXTENTED_OPT("legacy-compress", token, keylen)) {
			if (vallen)
				return -EINVAL;
			/* disable compacted indexes and 0padding */
			cfg.c_legacy_compress = true;
		} else if (MATCH_EXTENTED_OPT("force-inode-compact", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_force_inodeversion = FORCE_INODE_COMPACT;
			cfg.c_ignore_mtime = true;
		} else if (MATCH_EXTENTED_OPT("force-inode-extended", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_force_inodeversion = FORCE_INODE_EXTENDED;
		} else if (MATCH_EXTENTED_OPT("nosbcrc", token, keylen)) {
			if (vallen)
				return -EINVAL;
			erofs_sb_clear_sb_chksum(&sbi);
		} else if (MATCH_EXTENTED_OPT("noinline_data", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_inline_data = false;
		} else if (MATCH_EXTENTED_OPT("inline_data", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_inline_data = !clear;
		} else if (MATCH_EXTENTED_OPT("force-inode-blockmap", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_force_chunkformat = FORCE_INODE_BLOCK_MAP;
		} else if (MATCH_EXTENTED_OPT("force-chunk-indexes", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_force_chunkformat = FORCE_INODE_CHUNK_INDEXES;
		} else if (MATCH_EXTENTED_OPT("ztailpacking", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_ztailpacking = !clear;
		} else if (MATCH_EXTENTED_OPT("all-fragments", token, keylen)) {
			cfg.c_all_fragments = true;
			goto handle_fragment;
		} else if (MATCH_EXTENTED_OPT("fragments", token, keylen)) {
			char *endptr;
			u64 i;

handle_fragment:
			cfg.c_fragments = true;
			if (vallen) {
				i = strtoull(value, &endptr, 0);
				if (endptr - value != vallen) {
					erofs_err("invalid pcluster size for the packed file %s",
						  next);
					return -EINVAL;
				}
				pclustersize_packed = i;
			}
		} else if (MATCH_EXTENTED_OPT("dedupe", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_dedupe = !clear;
		} else if (MATCH_EXTENTED_OPT("xattr-name-filter", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_xattr_name_filter = !clear;
		} else {
			erofs_err("unknown extended option %.*s",
				  p - token, token);
			return -EINVAL;
		}
	}
	return 0;
}

static int mkfs_parse_compress_algs(char *algs)
{
	unsigned int i;
	char *s;

	for (s = strtok(algs, ":"), i = 0; s; s = strtok(NULL, ":"), ++i) {
		const char *lv;

		if (i >= EROFS_MAX_COMPR_CFGS - 1) {
			erofs_err("too many algorithm types");
			return -EINVAL;
		}

		lv = strchr(s, ',');
		if (lv) {
			cfg.c_compr_level[i] = atoi(lv + 1);
			cfg.c_compr_alg[i] = strndup(s, lv - s);
		} else {
			cfg.c_compr_level[i] = -1;
			cfg.c_compr_alg[i] = strdup(s);
		}
	}
	return 0;
}

static int mkfs_parse_options_cfg(int argc, char *argv[])
{
	char *endptr;
	int opt, i;
	bool quiet = false;

	while ((opt = getopt_long(argc, argv, "C:E:L:T:U:b:d:x:z:",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'z':
			i = mkfs_parse_compress_algs(optarg);
			if (i)
				return i;
			break;

		case 'b':
			i = atoi(optarg);
			if (i < 512 || i > EROFS_MAX_BLOCK_SIZE) {
				erofs_err("invalid block size %s", optarg);
				return -EINVAL;
			}
			sbi.blkszbits = ilog2(i);
			break;

		case 'd':
			i = atoi(optarg);
			if (i < EROFS_MSG_MIN || i > EROFS_MSG_MAX) {
				erofs_err("invalid debug level %d", i);
				return -EINVAL;
			}
			cfg.c_dbg_lvl = i;
			break;

		case 'x':
			i = strtol(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid xattr tolerance %s", optarg);
				return -EINVAL;
			}
			cfg.c_inline_xattr_tolerance = i;
			break;

		case 'E':
			opt = parse_extended_opts(optarg);
			if (opt)
				return opt;
			break;

		case 'L':
			if (optarg == NULL ||
			    strlen(optarg) > sizeof(sbi.volume_name)) {
				erofs_err("invalid volume label");
				return -EINVAL;
			}
			strncpy(sbi.volume_name, optarg,
				sizeof(sbi.volume_name));
			break;

		case 'T':
			cfg.c_unix_timestamp = strtoull(optarg, &endptr, 0);
			if (cfg.c_unix_timestamp == -1 || *endptr != '\0') {
				erofs_err("invalid UNIX timestamp %s", optarg);
				return -EINVAL;
			}
			cfg.c_timeinherit = TIMESTAMP_FIXED;
			break;
		case 'U':
			if (erofs_uuid_parse(optarg, sbi.uuid)) {
				erofs_err("invalid UUID %s", optarg);
				return -EINVAL;
			}
			break;
		case 2:
			opt = erofs_parse_exclude_path(optarg, false);
			if (opt) {
				erofs_err("failed to parse exclude path: %s",
					  erofs_strerror(opt));
				return opt;
			}
			break;
		case 3:
			opt = erofs_parse_exclude_path(optarg, true);
			if (opt) {
				erofs_err("failed to parse exclude regex: %s",
					  erofs_strerror(opt));
				return opt;
			}
			break;

		case 4:
			opt = erofs_selabel_open(optarg);
			if (opt && opt != -EBUSY)
				return opt;
			break;
		case 5:
			cfg.c_uid = strtoul(optarg, &endptr, 0);
			if (cfg.c_uid == -1 || *endptr != '\0') {
				erofs_err("invalid uid %s", optarg);
				return -EINVAL;
			}
			break;
		case 6:
			cfg.c_gid = strtoul(optarg, &endptr, 0);
			if (cfg.c_gid == -1 || *endptr != '\0') {
				erofs_err("invalid gid %s", optarg);
				return -EINVAL;
			}
			break;
		case 7:
			cfg.c_uid = cfg.c_gid = 0;
			break;
#ifndef NDEBUG
		case 8:
			cfg.c_random_pclusterblks = true;
			break;
		case 18:
			cfg.c_random_algorithms = true;
			break;
#endif
		case 9:
			cfg.c_max_decompressed_extent_bytes =
				strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid maximum uncompressed extent size %s",
					  optarg);
				return -EINVAL;
			}
			break;
		case 10:
			cfg.c_compress_hints_file = optarg;
			break;
		case 512:
			cfg.mount_point = optarg;
			/* all trailing '/' should be deleted */
			opt = strlen(cfg.mount_point);
			if (opt && optarg[opt - 1] == '/')
				optarg[opt - 1] = '\0';
			break;
#ifdef WITH_ANDROID
		case 513:
			cfg.target_out_path = optarg;
			break;
		case 514:
			cfg.fs_config_file = optarg;
			break;
		case 515:
			cfg.block_list_file = optarg;
			break;
#endif
		case 'C':
			i = strtoull(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid physical clustersize %s",
					  optarg);
				return -EINVAL;
			}
			pclustersize_max = i;
			break;
		case 11:
			i = strtol(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid chunksize %s", optarg);
				return -EINVAL;
			}
			cfg.c_chunkbits = ilog2(i);
			if ((1 << cfg.c_chunkbits) != i) {
				erofs_err("chunksize %s must be a power of two",
					  optarg);
				return -EINVAL;
			}
			erofs_sb_set_chunked_file(&sbi);
			break;
		case 12:
			quiet = true;
			break;
		case 13:
			cfg.c_blobdev_path = optarg;
			break;
		case 14:
			cfg.c_ignore_mtime = true;
			break;
		case 15:
			cfg.c_ignore_mtime = false;
			break;
		case 16:
			errno = 0;
			cfg.c_uid_offset = strtoll(optarg, &endptr, 0);
			if (errno || *endptr != '\0') {
				erofs_err("invalid uid offset %s", optarg);
				return -EINVAL;
			}
			break;
		case 17:
			errno = 0;
			cfg.c_gid_offset = strtoll(optarg, &endptr, 0);
			if (errno || *endptr != '\0') {
				erofs_err("invalid gid offset %s", optarg);
				return -EINVAL;
			}
			break;
		case 19:
			errno = 0;
			opt = erofs_xattr_insert_name_prefix(optarg);
			if (opt) {
				erofs_err("failed to parse xattr name prefix: %s",
					  erofs_strerror(opt));
				return opt;
			}
			cfg.c_extra_ea_name_prefixes = true;
			break;
		case 20:
			if (optarg && (!strcmp(optarg, "i") ||
				!strcmp(optarg, "0") || !memcmp(optarg, "0,", 2))) {
				erofstar.index_mode = true;
				if (!memcmp(optarg, "0,", 2))
					erofstar.mapfile = strdup(optarg + 2);
			}
			tar_mode = true;
			break;
		case 21:
			erofstar.aufs = true;
			break;
		case 1:
			usage();
			exit(0);

		default: /* '?' */
			return -EINVAL;
		}
	}

	if (cfg.c_blobdev_path && cfg.c_chunkbits < sbi.blkszbits) {
		erofs_err("--blobdev must be used together with --chunksize");
		return -EINVAL;
	}

	/* TODO: can be implemented with (deviceslot) mapped_blkaddr */
	if (cfg.c_blobdev_path &&
	    cfg.c_force_chunkformat == FORCE_INODE_BLOCK_MAP) {
		erofs_err("--blobdev cannot work with block map currently");
		return -EINVAL;
	}

	if (optind >= argc) {
		erofs_err("missing argument: FILE");
		return -EINVAL;
	}

	cfg.c_img_path = strdup(argv[optind++]);
	if (!cfg.c_img_path)
		return -ENOMEM;

	if (optind >= argc) {
		if (!tar_mode) {
			erofs_err("missing argument: DIRECTORY");
			return -EINVAL;
		} else {
			erofstar.fd = STDIN_FILENO;
		}
	}else {
		cfg.c_src_path = realpath(argv[optind++], NULL);
		if (!cfg.c_src_path) {
			erofs_err("failed to parse source directory: %s",
				  erofs_strerror(-errno));
			return -ENOENT;
		}

		if (optind < argc) {
			erofs_err("unexpected argument: %s\n", argv[optind]);
			return -EINVAL;
		}
	}
	if (quiet) {
		cfg.c_dbg_lvl = EROFS_ERR;
		cfg.c_showprogress = false;
	}

	if (cfg.c_compr_alg[0] && erofs_blksiz(&sbi) != getpagesize())
		erofs_warn("Please note that subpage blocksize with compression isn't yet supported in kernel. "
			   "This compressed image will only work with bs = ps = %u bytes",
			   erofs_blksiz(&sbi));

	if (pclustersize_max) {
		if (pclustersize_max < erofs_blksiz(&sbi) ||
		    pclustersize_max % erofs_blksiz(&sbi)) {
			erofs_err("invalid physical clustersize %u",
				  pclustersize_max);
			return -EINVAL;
		}
		cfg.c_pclusterblks_max = pclustersize_max >> sbi.blkszbits;
		cfg.c_pclusterblks_def = cfg.c_pclusterblks_max;
	}
	if (cfg.c_chunkbits && cfg.c_chunkbits < sbi.blkszbits) {
		erofs_err("chunksize %u must be larger than block size",
			  1u << cfg.c_chunkbits);
		return -EINVAL;
	}

	if (pclustersize_packed) {
		if (pclustersize_max < erofs_blksiz(&sbi) ||
		    pclustersize_max % erofs_blksiz(&sbi)) {
			erofs_err("invalid pcluster size for the packed file %u",
				  pclustersize_packed);
			return -EINVAL;
		}
		cfg.c_pclusterblks_packed = pclustersize_packed >> sbi.blkszbits;
	}
	return 0;
}

int erofs_mkfs_update_super_block(struct erofs_buffer_head *bh,
				  erofs_nid_t root_nid,
				  erofs_blk_t *blocks,
				  erofs_nid_t packed_nid)
{
	struct erofs_super_block sb = {
		.magic     = cpu_to_le32(EROFS_SUPER_MAGIC_V1),
		.blkszbits = sbi.blkszbits,
		.inos   = cpu_to_le64(sbi.inos),
		.build_time = cpu_to_le64(sbi.build_time),
		.build_time_nsec = cpu_to_le32(sbi.build_time_nsec),
		.blocks = 0,
		.meta_blkaddr  = cpu_to_le32(sbi.meta_blkaddr),
		.xattr_blkaddr = cpu_to_le32(sbi.xattr_blkaddr),
		.xattr_prefix_count = sbi.xattr_prefix_count,
		.xattr_prefix_start = cpu_to_le32(sbi.xattr_prefix_start),
		.feature_incompat = cpu_to_le32(sbi.feature_incompat),
		.feature_compat = cpu_to_le32(sbi.feature_compat &
					      ~EROFS_FEATURE_COMPAT_SB_CHKSUM),
		.extra_devices = cpu_to_le16(sbi.extra_devices),
		.devt_slotoff = cpu_to_le16(sbi.devt_slotoff),
	};
	const u32 sb_blksize = round_up(EROFS_SUPER_END, erofs_blksiz(&sbi));
	char *buf;
	int ret;

	*blocks         = erofs_mapbh(NULL);
	sb.blocks       = cpu_to_le32(*blocks);
	sb.root_nid     = cpu_to_le16(root_nid);
	sb.packed_nid    = cpu_to_le64(packed_nid);
	memcpy(sb.uuid, sbi.uuid, sizeof(sb.uuid));
	memcpy(sb.volume_name, sbi.volume_name, sizeof(sb.volume_name));

	if (erofs_sb_has_compr_cfgs(&sbi))
		sb.u1.available_compr_algs = cpu_to_le16(sbi.available_compr_algs);
	else
		sb.u1.lz4_max_distance = cpu_to_le16(sbi.lz4_max_distance);

	buf = calloc(sb_blksize, 1);
	if (!buf) {
		erofs_err("failed to allocate memory for sb: %s",
			  erofs_strerror(-errno));
		return -ENOMEM;
	}
	memcpy(buf + EROFS_SUPER_OFFSET, &sb, sizeof(sb));

	ret = dev_write(&sbi, buf, erofs_btell(bh, false), EROFS_SUPER_END);
	free(buf);
	erofs_bdrop(bh, false);
	return ret;
}

static int erofs_mkfs_superblock_csum_set(void)
{
	int ret;
	u8 buf[EROFS_MAX_BLOCK_SIZE];
	u32 crc;
	unsigned int len;
	struct erofs_super_block *sb;

	ret = blk_read(&sbi, 0, buf, 0, erofs_blknr(&sbi, EROFS_SUPER_END) + 1);
	if (ret) {
		erofs_err("failed to read superblock to set checksum: %s",
			  erofs_strerror(ret));
		return ret;
	}

	/*
	 * skip the first 1024 bytes, to allow for the installation
	 * of x86 boot sectors and other oddities.
	 */
	sb = (struct erofs_super_block *)(buf + EROFS_SUPER_OFFSET);

	if (le32_to_cpu(sb->magic) != EROFS_SUPER_MAGIC_V1) {
		erofs_err("internal error: not an erofs valid image");
		return -EFAULT;
	}

	/* turn on checksum feature */
	sb->feature_compat = cpu_to_le32(le32_to_cpu(sb->feature_compat) |
					 EROFS_FEATURE_COMPAT_SB_CHKSUM);
	if (erofs_blksiz(&sbi) > EROFS_SUPER_OFFSET)
		len = erofs_blksiz(&sbi) - EROFS_SUPER_OFFSET;
	else
		len = erofs_blksiz(&sbi);
	crc = erofs_crc32c(~0, (u8 *)sb, len);

	/* set up checksum field to erofs_super_block */
	sb->checksum = cpu_to_le32(crc);

	ret = blk_write(&sbi, buf, 0, 1);
	if (ret) {
		erofs_err("failed to write checksummed superblock: %s",
			  erofs_strerror(ret));
		return ret;
	}

	erofs_info("superblock checksum 0x%08x written", crc);
	return 0;
}

static void erofs_mkfs_default_options(void)
{
	cfg.c_showprogress = true;
	cfg.c_legacy_compress = false;
	cfg.c_inline_data = true;
	cfg.c_xattr_name_filter = true;
	sbi.blkszbits = ilog2(min_t(u32, getpagesize(), EROFS_MAX_BLOCK_SIZE));
	sbi.feature_incompat = EROFS_FEATURE_INCOMPAT_ZERO_PADDING;
	sbi.feature_compat = EROFS_FEATURE_COMPAT_SB_CHKSUM |
			     EROFS_FEATURE_COMPAT_MTIME;

	/* generate a default uuid first */
	erofs_uuid_generate(sbi.uuid);
}

/* https://reproducible-builds.org/specs/source-date-epoch/ for more details */
int parse_source_date_epoch(void)
{
	char *source_date_epoch;
	unsigned long long epoch = -1ULL;
	char *endptr;

	source_date_epoch = getenv("SOURCE_DATE_EPOCH");
	if (!source_date_epoch)
		return 0;

	epoch = strtoull(source_date_epoch, &endptr, 10);
	if (epoch == -1ULL || *endptr != '\0') {
		erofs_err("environment variable $SOURCE_DATE_EPOCH %s is invalid",
			  source_date_epoch);
		return -EINVAL;
	}

	if (cfg.c_force_inodeversion != FORCE_INODE_EXTENDED)
		erofs_info("SOURCE_DATE_EPOCH is set, forcely generate extended inodes instead");

	cfg.c_force_inodeversion = FORCE_INODE_EXTENDED;
	cfg.c_unix_timestamp = epoch;
	cfg.c_timeinherit = TIMESTAMP_CLAMPING;
	return 0;
}

void erofs_show_progs(int argc, char *argv[])
{
	if (cfg.c_dbg_lvl >= EROFS_WARN)
		printf("%s %s\n", basename(argv[0]), cfg.c_version);
}

static void erofs_mkfs_showsummaries(erofs_blk_t nblocks)
{
	char uuid_str[37] = {};

	if (!(cfg.c_dbg_lvl > EROFS_ERR && cfg.c_showprogress))
		return;

	erofs_uuid_unparse_lower(sbi.uuid, uuid_str);

	fprintf(stdout, "------\nFilesystem UUID: %s\n"
		"Filesystem total blocks: %u (of %u-byte blocks)\n"
		"Filesystem total inodes: %llu\n"
		"Filesystem total metadata blocks: %u\n"
		"Filesystem total deduplicated bytes (of source files): %llu\n",
		uuid_str, nblocks, 1U << sbi.blkszbits, sbi.inos | 0ULL,
		erofs_total_metablocks(),
		sbi.saved_by_deduplication | 0ULL);
}

int main(int argc, char **argv)
{
	int err = 0;
	struct erofs_buffer_head *sb_bh;
	struct erofs_inode *root_inode, *packed_inode;
	erofs_nid_t root_nid, packed_nid;
	struct stat st;
	erofs_blk_t nblocks;
	struct timeval t;
	FILE *packedfile = NULL;

	erofs_init_configure();
	erofs_mkfs_default_options();

	err = mkfs_parse_options_cfg(argc, argv);
	erofs_show_progs(argc, argv);
	if (err) {
		if (err == -EINVAL)
			usage();
		return 1;
	}

	err = parse_source_date_epoch();
	if (err) {
		usage();
		return 1;
	}

	if (!tar_mode) {
		err = lstat(cfg.c_src_path, &st);
		if (err)
			return 1;
		if (!S_ISDIR(st.st_mode)) {
			erofs_err("root of the filesystem is not a directory - %s",
				  cfg.c_src_path);
			usage();
			return 1;
		}
		erofs_set_fs_root(cfg.c_src_path);
	} else if (cfg.c_src_path) {
		erofstar.fd = open(cfg.c_src_path, O_RDONLY);
		if (erofstar.fd < 0) {
			erofs_err("failed to open file: %s", cfg.c_src_path);
			usage();
			return 1;
		}
	}

	if (cfg.c_unix_timestamp != -1) {
		sbi.build_time      = cfg.c_unix_timestamp;
		sbi.build_time_nsec = 0;
	} else if (!gettimeofday(&t, NULL)) {
		sbi.build_time      = t.tv_sec;
		sbi.build_time_nsec = t.tv_usec;
	}

	err = dev_open(&sbi, cfg.c_img_path);
	if (err) {
		usage();
		return 1;
	}

#ifdef WITH_ANDROID
	if (cfg.fs_config_file &&
	    load_canned_fs_config(cfg.fs_config_file) < 0) {
		erofs_err("failed to load fs config %s", cfg.fs_config_file);
		return 1;
	}

	if (cfg.block_list_file &&
	    erofs_blocklist_open(cfg.block_list_file, false)) {
		erofs_err("failed to open %s", cfg.block_list_file);
		return 1;
	}
#endif
	erofs_show_config();
	if (cfg.c_fragments || cfg.c_extra_ea_name_prefixes) {
		if (!cfg.c_pclusterblks_packed)
			cfg.c_pclusterblks_packed = cfg.c_pclusterblks_def;

		packedfile = erofs_packedfile_init();
		if (IS_ERR(packedfile)) {
			erofs_err("failed to initialize packedfile");
			return 1;
		}
	}

	if (cfg.c_fragments) {
		err = z_erofs_fragments_init();
		if (err) {
			erofs_err("failed to initialize fragments");
			return 1;
		}
	}

#ifndef NDEBUG
	if (cfg.c_random_pclusterblks)
		srand(time(NULL));
#endif
	if (tar_mode && erofstar.index_mode) {
		if (erofstar.mapfile) {
			err = erofs_blocklist_open(erofstar.mapfile, true);
			if (err) {
				erofs_err("failed to open %s", erofstar.mapfile);
				goto exit;
			}
		} else {
			sbi.blkszbits = 9;
		}
	}

	sb_bh = erofs_buffer_init();
	if (IS_ERR(sb_bh)) {
		err = PTR_ERR(sb_bh);
		erofs_err("failed to initialize buffers: %s",
			  erofs_strerror(err));
		goto exit;
	}
	err = erofs_bh_balloon(sb_bh, EROFS_SUPER_END);
	if (err < 0) {
		erofs_err("failed to balloon erofs_super_block: %s",
			  erofs_strerror(err));
		goto exit;
	}

	/* make sure that the super block should be the very first blocks */
	(void)erofs_mapbh(sb_bh->block);
	if (erofs_btell(sb_bh, false) != 0) {
		erofs_err("failed to reserve erofs_super_block");
		goto exit;
	}

	err = erofs_load_compress_hints(&sbi);
	if (err) {
		erofs_err("failed to load compress hints %s",
			  cfg.c_compress_hints_file);
		goto exit;
	}

	err = z_erofs_compress_init(&sbi, sb_bh);
	if (err) {
		erofs_err("failed to initialize compressor: %s",
			  erofs_strerror(err));
		goto exit;
	}

	if (cfg.c_dedupe) {
		if (!cfg.c_compr_alg[0]) {
			erofs_err("Compression is not enabled.  Turn on chunk-based data deduplication instead.");
			cfg.c_chunkbits = sbi.blkszbits;
		} else {
			err = z_erofs_dedupe_init(erofs_blksiz(&sbi));
			if (err) {
				erofs_err("failed to initialize deduplication: %s",
					  erofs_strerror(err));
				goto exit;
			}
		}
	}

	if (cfg.c_chunkbits) {
		err = erofs_blob_init(cfg.c_blobdev_path);
		if (err)
			return 1;
	}

	if ((erofstar.index_mode && !erofstar.mapfile) || cfg.c_blobdev_path)
		err = erofs_mkfs_init_devices(&sbi, 1);
	if (err) {
		erofs_err("failed to generate device table: %s",
			  erofs_strerror(err));
		goto exit;
	}

	erofs_inode_manager_init();

	if (!tar_mode) {
		err = erofs_build_shared_xattrs_from_path(&sbi, cfg.c_src_path);
		if (err) {
			erofs_err("failed to build shared xattrs: %s",
				  erofs_strerror(err));
			goto exit;
		}

		if (cfg.c_extra_ea_name_prefixes)
			erofs_xattr_write_name_prefixes(&sbi, packedfile);

		root_inode = erofs_mkfs_build_tree_from_path(cfg.c_src_path);
		if (IS_ERR(root_inode)) {
			err = PTR_ERR(root_inode);
			goto exit;
		}
	} else {
		root_inode = erofs_new_inode();
		if (IS_ERR(root_inode)) {
			err = PTR_ERR(root_inode);
			goto exit;
		}
		root_inode->i_srcpath = strdup("/");
		root_inode->i_mode = S_IFDIR | 0777;
		root_inode->i_parent = root_inode;
		root_inode->i_mtime = sbi.build_time;
		root_inode->i_mtime_nsec = sbi.build_time_nsec;
		erofs_init_empty_dir(root_inode);

		while (!(err = tarerofs_parse_tar(root_inode, &erofstar)));

		if (err < 0)
			goto exit;

		err = tarerofs_dump_tree(root_inode);
		if (err < 0)
			goto exit;
	}
	root_nid = erofs_lookupnid(root_inode);
	erofs_iput(root_inode);

	if (erofstar.index_mode || cfg.c_chunkbits) {
		if (erofstar.index_mode && !erofstar.mapfile)
			sbi.devs[0].blocks =
				BLK_ROUND_UP(&sbi, erofstar.offset);
		err = erofs_mkfs_dump_blobs(&sbi);
		if (err)
			goto exit;
	}

	packed_nid = 0;
	if ((cfg.c_fragments || cfg.c_extra_ea_name_prefixes) &&
	    erofs_sb_has_fragments(&sbi)) {
		erofs_update_progressinfo("Handling packed_file ...");
		packed_inode = erofs_mkfs_build_packedfile();
		if (IS_ERR(packed_inode)) {
			err = PTR_ERR(packed_inode);
			goto exit;
		}
		packed_nid = erofs_lookupnid(packed_inode);
		erofs_iput(packed_inode);
	}

	/* flush all buffers except for the superblock */
	if (!erofs_bflush(NULL)) {
		err = -EIO;
		goto exit;
	}

	err = erofs_mkfs_update_super_block(sb_bh, root_nid, &nblocks,
					    packed_nid);
	if (err)
		goto exit;

	/* flush all remaining buffers */
	if (!erofs_bflush(NULL))
		err = -EIO;
	else
		err = dev_resize(&sbi, nblocks);

	if (!err && erofs_sb_has_sb_chksum(&sbi))
		err = erofs_mkfs_superblock_csum_set();
exit:
	z_erofs_compress_exit();
	z_erofs_dedupe_exit();
	erofs_blocklist_close();
	dev_close(&sbi);
	erofs_cleanup_compress_hints();
	erofs_cleanup_exclude_rules();
	if (cfg.c_chunkbits)
		erofs_blob_exit();
	if (cfg.c_fragments)
		z_erofs_fragments_exit();
	erofs_packedfile_exit();
	erofs_xattr_cleanup_name_prefixes();
	erofs_exit_configure();

	if (err) {
		erofs_err("\tCould not format the device : %s\n",
			  erofs_strerror(err));
		return 1;
	}
	erofs_update_progressinfo("Build completed.\n");
	erofs_mkfs_showsummaries(nblocks);
	return 0;
}
