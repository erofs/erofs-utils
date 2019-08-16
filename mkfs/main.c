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
#include "erofs/config.h"
#include "erofs/print.h"
#include "erofs/cache.h"
#include "erofs/inode.h"
#include "erofs/io.h"
#include "erofs/compress.h"

#define EROFS_SUPER_END (EROFS_SUPER_OFFSET + sizeof(struct erofs_super_block))

static void usage(void)
{
	fprintf(stderr, "usage: [options] FILE DIRECTORY\n\n");
	fprintf(stderr, "Generate erofs image from DIRECTORY to FILE, and [options] are:\n");
	fprintf(stderr, " -zX[,Y]   X=compressor (Y=compression level, optional)\n");
	fprintf(stderr, " -d#       set output message level to # (maximum 9)\n");
	fprintf(stderr, " -EX[,...] X=extended options\n");
}

static int parse_extended_opts(const char *opts)
{
#define MATCH_EXTENTED_OPT(opt, token, keylen) \
	(keylen == sizeof(opt) && !memcmp(token, opt, sizeof(opt)))

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
			sbi.requirements &= ~EROFS_REQUIREMENT_LZ4_0PADDING;
		}
	}
	return 0;
}

static int mkfs_parse_options_cfg(int argc, char *argv[])
{
	int opt, i;

	while ((opt = getopt(argc, argv, "d:z:E:")) != -1) {
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

		case 'E':
			opt = parse_extended_opts(optarg);
			if (opt)
				return opt;
			break;

		default: /* '?' */
			return -EINVAL;
		}
	}

	if (optind >= argc)
		return -EINVAL;

	cfg.c_img_path = strdup(argv[optind++]);
	if (!cfg.c_img_path)
		return -ENOMEM;

	if (optind > argc) {
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
				  erofs_nid_t root_nid)
{
	struct erofs_super_block sb = {
		.magic     = cpu_to_le32(EROFS_SUPER_MAGIC_V1),
		.blkszbits = LOG_BLOCK_SIZE,
		.inos   = 0,
		.blocks = 0,
		.meta_blkaddr  = sbi.meta_blkaddr,
		.xattr_blkaddr = 0,
		.requirements = cpu_to_le32(sbi.requirements),
	};
	const unsigned int sb_blksize =
		round_up(EROFS_SUPER_END, EROFS_BLKSIZ);
	char *buf;
	struct timeval t;

	if (!gettimeofday(&t, NULL)) {
		sb.build_time      = cpu_to_le64(t.tv_sec);
		sb.build_time_nsec = cpu_to_le32(t.tv_usec);
	}

	sb.blocks       = cpu_to_le32(erofs_mapbh(NULL, true));
	sb.root_nid     = cpu_to_le16(root_nid);

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

int main(int argc, char **argv)
{
	int err = 0;
	struct erofs_buffer_head *sb_bh;
	struct erofs_inode *root_inode;
	erofs_nid_t root_nid;
	struct stat64 st;

	erofs_init_configure();
	fprintf(stderr, "%s %s\n", basename(argv[0]), cfg.c_version);

	err = mkfs_parse_options_cfg(argc, argv);
	if (err) {
		if (err == -EINVAL)
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

	err = dev_open(cfg.c_img_path);
	if (err) {
		usage();
		return 1;
	}

	erofs_show_config();

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

	erofs_inode_manager_init();

	root_inode = erofs_mkfs_build_tree_from_path(NULL, cfg.c_src_path);
	if (IS_ERR(root_inode)) {
		err = PTR_ERR(root_inode);
		goto exit;
	}

	root_nid = erofs_lookupnid(root_inode);
	erofs_iput(root_inode);

	err = erofs_mkfs_update_super_block(sb_bh, root_nid);
	if (err)
		goto exit;

	/* flush all remaining buffers */
	if (!erofs_bflush(NULL))
		err = -EIO;
exit:
	z_erofs_compress_exit();
	dev_close();
	erofs_exit_configure();

	if (err) {
		erofs_err("\tCould not format the device : %s\n",
			  erofs_strerror(err));
		return 1;
	}
	return 0;
}
