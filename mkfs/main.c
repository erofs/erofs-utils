// SPDX-License-Identifier: GPL-2.0+
/*
 * mkfs/main.c
 *
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
#include "erofs/io.h"
#include "erofs/compress.h"
#include "erofs/xattr.h"
#include "erofs/exclude.h"

#ifdef HAVE_LIBUUID
#include <uuid.h>
#endif

#define EROFS_SUPER_END (EROFS_SUPER_OFFSET + sizeof(struct erofs_super_block))

static struct option long_options[] = {
	{"help", no_argument, 0, 1},
	{"exclude-path", required_argument, NULL, 2},
	{"exclude-regex", required_argument, NULL, 3},
#ifdef HAVE_LIBSELINUX
	{"file-contexts", required_argument, NULL, 4},
#endif
#ifdef WITH_ANDROID
	{"mount-point", required_argument, NULL, 10},
	{"product-out", required_argument, NULL, 11},
	{"fs-config-file", required_argument, NULL, 12},
#endif
	{0, 0, 0, 0},
};

static void print_available_compressors(FILE *f, const char *delim)
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
	fputs("usage: [options] FILE DIRECTORY\n\n"
	      "Generate erofs image from DIRECTORY to FILE, and [options] are:\n"
	      " -zX[,Y]            X=compressor (Y=compression level, optional)\n"
	      " -d#                set output message level to # (maximum 9)\n"
	      " -x#                set xattr tolerance to # (< 0, disable xattrs; default 2)\n"
	      " -EX[,...]          X=extended options\n"
	      " -T#                set a fixed UNIX timestamp # to all files\n"
#ifdef HAVE_LIBUUID
	      " -UX                use a given filesystem UUID\n"
#endif
	      " --exclude-path=X   avoid including file X (X = exact literal path)\n"
	      " --exclude-regex=X  avoid including files that match X (X = regular expression)\n"
#ifdef HAVE_LIBSELINUX
	      " --file-contexts=X  specify a file contexts file to setup selinux labels\n"
#endif
	      " --help             display this help and exit\n"
#ifdef WITH_ANDROID
	      "\nwith following android-specific options:\n"
	      " --mount-point=X    X=prefix of target fs path (default: /)\n"
	      " --product-out=X    X=product_out directory\n"
	      " --fs-config-file=X X=fs_config file\n"
#endif
	      "\nAvailable compressors are: ", stderr);
	print_available_compressors(stderr, ", ");
}

static int parse_extended_opts(const char *opts)
{
#define MATCH_EXTENTED_OPT(opt, token, keylen) \
	(keylen == sizeof(opt) - 1 && !memcmp(token, opt, sizeof(opt) - 1))

	const char *token, *next, *tokenend, *value __maybe_unused;
	unsigned int keylen, vallen;

	value = NULL;
	for (token = opts; *token != '\0'; token = next) {
		const char *p = strchr(token, ',');

		next = NULL;
		if (p)
			next = p + 1;
		else {
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

		if (MATCH_EXTENTED_OPT("legacy-compress", token, keylen)) {
			if (vallen)
				return -EINVAL;
			/* disable compacted indexes and 0padding */
			cfg.c_legacy_compress = true;
			erofs_sb_clear_lz4_0padding();
		}

		if (MATCH_EXTENTED_OPT("force-inode-compact", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_force_inodeversion = FORCE_INODE_COMPACT;
		}

		if (MATCH_EXTENTED_OPT("force-inode-extended", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_force_inodeversion = FORCE_INODE_EXTENDED;
		}

		if (MATCH_EXTENTED_OPT("nosbcrc", token, keylen)) {
			if (vallen)
				return -EINVAL;
			erofs_sb_clear_sb_chksum();
		}
	}
	return 0;
}

static int mkfs_parse_options_cfg(int argc, char *argv[])
{
	char *endptr;
	int opt, i;

	while((opt = getopt_long(argc, argv, "d:x:z:E:T:U:",
				 long_options, NULL)) != -1) {
		switch (opt) {
		case 'z':
			if (!optarg) {
				cfg.c_compr_alg_master = "(default)";
				break;
			}
			/* get specified compression level */
			for (i = 0; optarg[i] != '\0'; ++i) {
				if (optarg[i] == ',') {
					cfg.c_compr_level_master =
						atoi(optarg + i + 1);
					optarg[i] = '\0';
					break;
				}
			}
			cfg.c_compr_alg_master = strndup(optarg, i);
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
		case 'T':
			cfg.c_unix_timestamp = strtoull(optarg, &endptr, 0);
			if (cfg.c_unix_timestamp == -1 || *endptr != '\0') {
				erofs_err("invalid UNIX timestamp %s", optarg);
				return -EINVAL;
			}
			cfg.c_timeinherit = TIMESTAMP_FIXED;
			break;
#ifdef HAVE_LIBUUID
		case 'U':
			if (uuid_parse(optarg, sbi.uuid)) {
				erofs_err("invalid UUID %s", optarg);
				return -EINVAL;
			}
			break;
#endif
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
#ifdef WITH_ANDROID
		case 10:
			cfg.mount_point = optarg;
			/* all trailing '/' should be deleted */
			opt = strlen(cfg.mount_point);
			if (opt && optarg[opt - 1] == '/')
				optarg[opt - 1] = '\0';
			break;
		case 11:
			cfg.target_out_path = optarg;
			break;
		case 12:
			cfg.fs_config_file = optarg;
			break;
#endif
		case 1:
			usage();
			exit(0);

		default: /* '?' */
			return -EINVAL;
		}
	}

	if (optind >= argc)
		return -EINVAL;

	cfg.c_img_path = strdup(argv[optind++]);
	if (!cfg.c_img_path)
		return -ENOMEM;

	if (optind >= argc) {
		erofs_err("Source directory is missing");
		return -EINVAL;
	}

	cfg.c_src_path = realpath(argv[optind++], NULL);
	if (!cfg.c_src_path) {
		erofs_err("Failed to parse source directory: %s",
			  erofs_strerror(-errno));
		return -ENOENT;
	}

	if (optind < argc) {
		erofs_err("Unexpected argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	return 0;
}

int erofs_mkfs_update_super_block(struct erofs_buffer_head *bh,
				  erofs_nid_t root_nid,
				  erofs_blk_t *blocks)
{
	struct erofs_super_block sb = {
		.magic     = cpu_to_le32(EROFS_SUPER_MAGIC_V1),
		.blkszbits = LOG_BLOCK_SIZE,
		.inos   = 0,
		.build_time = cpu_to_le64(sbi.build_time),
		.build_time_nsec = cpu_to_le32(sbi.build_time_nsec),
		.blocks = 0,
		.meta_blkaddr  = sbi.meta_blkaddr,
		.xattr_blkaddr = sbi.xattr_blkaddr,
		.feature_incompat = cpu_to_le32(sbi.feature_incompat),
		.feature_compat = cpu_to_le32(sbi.feature_compat &
					      ~EROFS_FEATURE_COMPAT_SB_CHKSUM),
	};
	const unsigned int sb_blksize =
		round_up(EROFS_SUPER_END, EROFS_BLKSIZ);
	char *buf;

	*blocks         = erofs_mapbh(NULL, true);
	sb.blocks       = cpu_to_le32(*blocks);
	sb.root_nid     = cpu_to_le16(root_nid);
	memcpy(sb.uuid, sbi.uuid, sizeof(sb.uuid));

	buf = calloc(sb_blksize, 1);
	if (!buf) {
		erofs_err("Failed to allocate memory for sb: %s",
			  erofs_strerror(-errno));
		return -ENOMEM;
	}
	memcpy(buf + EROFS_SUPER_OFFSET, &sb, sizeof(sb));

	bh->fsprivate = buf;
	bh->op = &erofs_buf_write_bhops;
	return 0;
}

#define CRC32C_POLY_LE	0x82F63B78
static inline u32 crc32c(u32 crc, const u8 *in, size_t len)
{
	int i;

	while (len--) {
		crc ^= *in++;
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? CRC32C_POLY_LE : 0);
	}
	return crc;
}

static int erofs_mkfs_superblock_csum_set(void)
{
	int ret;
	u8 buf[EROFS_BLKSIZ];
	u32 crc;
	struct erofs_super_block *sb;

	ret = blk_read(buf, 0, 1);
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
	crc = crc32c(~0, (u8 *)sb, EROFS_BLKSIZ - EROFS_SUPER_OFFSET);

	/* set up checksum field to erofs_super_block */
	sb->checksum = cpu_to_le32(crc);

	ret = blk_write(buf, 0, 1);
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
	cfg.c_legacy_compress = false;
	sbi.feature_incompat = EROFS_FEATURE_INCOMPAT_LZ4_0PADDING;
	sbi.feature_compat = EROFS_FEATURE_COMPAT_SB_CHKSUM;

	/* generate a default uuid first */
#ifdef HAVE_LIBUUID
	do {
		uuid_generate(sbi.uuid);
	} while (uuid_is_null(sbi.uuid));
#endif
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
		erofs_err("Environment variable $SOURCE_DATE_EPOCH %s is invalid",
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

int main(int argc, char **argv)
{
	int err = 0;
	struct erofs_buffer_head *sb_bh;
	struct erofs_inode *root_inode;
	erofs_nid_t root_nid;
	struct stat64 st;
	erofs_blk_t nblocks;
	struct timeval t;
	char uuid_str[37] = "not available";

	erofs_init_configure();
	fprintf(stderr, "%s %s\n", basename(argv[0]), cfg.c_version);

	erofs_mkfs_default_options();

	err = mkfs_parse_options_cfg(argc, argv);
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

	err = lstat64(cfg.c_src_path, &st);
	if (err)
		return 1;
	if ((st.st_mode & S_IFMT) != S_IFDIR) {
		erofs_err("root of the filesystem is not a directory - %s",
			  cfg.c_src_path);
		usage();
		return 1;
	}

	if (cfg.c_unix_timestamp != -1) {
		sbi.build_time      = cfg.c_unix_timestamp;
		sbi.build_time_nsec = 0;
	} else if (!gettimeofday(&t, NULL)) {
		sbi.build_time      = t.tv_sec;
		sbi.build_time_nsec = t.tv_usec;
	}

	err = dev_open(cfg.c_img_path);
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
#endif

	erofs_show_config();
	erofs_set_fs_root(cfg.c_src_path);

	sb_bh = erofs_buffer_init();
	if (IS_ERR(sb_bh)) {
		err = PTR_ERR(sb_bh);
		erofs_err("Failed to initialize buffers: %s",
			  erofs_strerror(err));
		goto exit;
	}
	err = erofs_bh_balloon(sb_bh, EROFS_SUPER_END);
	if (err < 0) {
		erofs_err("Failed to balloon erofs_super_block: %s",
			  erofs_strerror(err));
		goto exit;
	}

	err = z_erofs_compress_init();
	if (err) {
		erofs_err("Failed to initialize compressor: %s",
			  erofs_strerror(err));
		goto exit;
	}

#ifdef HAVE_LIBUUID
	uuid_unparse_lower(sbi.uuid, uuid_str);
#endif
	erofs_info("filesystem UUID: %s", uuid_str);

	erofs_inode_manager_init();

	err = erofs_build_shared_xattrs_from_path(cfg.c_src_path);
	if (err) {
		erofs_err("Failed to build shared xattrs: %s",
			  erofs_strerror(err));
		goto exit;
	}

	root_inode = erofs_mkfs_build_tree_from_path(NULL, cfg.c_src_path);
	if (IS_ERR(root_inode)) {
		err = PTR_ERR(root_inode);
		goto exit;
	}

	root_nid = erofs_lookupnid(root_inode);
	erofs_iput(root_inode);

	err = erofs_mkfs_update_super_block(sb_bh, root_nid, &nblocks);
	if (err)
		goto exit;

	/* flush all remaining buffers */
	if (!erofs_bflush(NULL))
		err = -EIO;
	else
		err = dev_resize(nblocks);

	if (!err && erofs_sb_has_sb_chksum())
		err = erofs_mkfs_superblock_csum_set();
exit:
	z_erofs_compress_exit();
	dev_close();
	erofs_cleanup_exclude_rules();
	erofs_exit_configure();

	if (err) {
		erofs_err("\tCould not format the device : %s\n",
			  erofs_strerror(err));
		return 1;
	}
	return 0;
}
