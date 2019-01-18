// SPDX-License-Identifier: GPL-2.0+
/*
 * mkfs_main.c
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <linux/fs.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <libgen.h>
#include "mkfs_erofs.h"
#include "erofs_io.h"
#include "mkfs_inode.h"
#include "erofs_compressor.h"
#define pr_fmt(fmt) "MKFS: " FUNC_LINE_FMT fmt "\n"
#include "erofs_debug.h"

#define EROFS_SUPER_END (EROFS_SUPER_OFFSET + sizeof(struct erofs_super_block))
#define ROOT_INODE_NUM                (0) /*always 0 match at rank inode */
#define EROFS_META_BLK_ADDR_DEFAULT   (1)
#define EROFS_XATTR_BLK_ADDR_DEFAULT  (0)

static struct erofs_super_block erosb = {
	.magic     = cpu_to_le32(EROFS_SUPER_MAGIC_V1),
	.blkszbits = LOG_BLOCK_SIZE,
	.root_nid  = cpu_to_le16(ROOT_INODE_NUM),
	.inos   = 0,
	.blocks = 0,
	.meta_blkaddr  = cpu_to_le32(EROFS_META_BLK_ADDR_DEFAULT),
	.xattr_blkaddr = cpu_to_le32(EROFS_XATTR_BLK_ADDR_DEFAULT),

};
struct erofs_super_block *sb = &erosb;

static void usage(char *path)
{
	fprintf(stderr, "%s %s\n", basename(path), erofs_cfg.c_version);
	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "    [-z <compr_algri>] [-d <dbglvl>]\n");
	fprintf(stderr, "    [target path] [source directory]\n");
	exit(1);
}

u64 parse_num_from_str(const char *str)
{
	u64 num      = 0;
	char *endptr = NULL;

	num = strtoull(str, &endptr, 10);
	ASSERT(num != ULLONG_MAX);
	return num;
}

static void mkfs_parse_options_cfg(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "d:z::")) != -1) {
		switch (opt) {
		case 'z':
			if (optarg)
				erofs_cfg.c_alg_name = optarg;
			else
				erofs_cfg.c_alg_name = "lz4hc";
			break;

		case 'd':
			erofs_cfg.c_dbg_lvl = parse_num_from_str(optarg);
			break;

		default: /* '?' */
			usage(argv[0]);
		}
	}

	if (optind >= argc)
		usage(argv[0]);

	erofs_cfg.c_img_path = strdup(argv[optind++]);
	assert(erofs_cfg.c_img_path);

	if (optind < argc) {
		erofs_cfg.c_src_path = realpath(argv[optind++], NULL);
		if (!erofs_cfg.c_src_path) {
			perror("c_src_path realpath");
			usage(argv[0]);
		}
	} else {
		erofs_err("c_src_path is NULL");
		usage(argv[0]);
	}
	assert(erofs_cfg.c_src_path);

	if (optind < argc) {
		erofs_err(" Unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
	}

	assert(erofs_cfg.c_alg_name);
	erofs_compress_alg_init(erofs_cfg.c_alg_name);

	mkfs_dump_config();
}

int erofs_mkfs_update_super_block(erofs_nid_t root_nid)
{
	int ret;
	char *sb_buf;
	struct timeval t;
	const unsigned sb_blksize = BLK_ALIGN(EROFS_SUPER_END);

	if (!gettimeofday(&t, NULL)) {
		sb->build_time      = cpu_to_le64(t.tv_sec);
		sb->build_time_nsec = cpu_to_le32(t.tv_usec);
	}
	sb->meta_blkaddr = cpu_to_le32(erofs_blknr(sb_blksize));
	sb->blocks       = cpu_to_le32(erofs_get_total_blocks());
	sb->root_nid     = cpu_to_le16(root_nid);

	sb_buf = calloc(sb_blksize, 1);
	if (!sb_buf) {
		erofs_err("failed to allocate super buffer: %s", strerror(errno));
		return -ENOMEM;
	}

	memcpy(sb_buf + EROFS_SUPER_OFFSET, sb, sizeof(*sb));

	ret = dev_write(sb_buf, 0, sb_blksize);
	if (ret < 0) {
		erofs_err("failed to dev_write, ret=%d", ret);
		return -EIO;
	}
	free(sb_buf);
	return 0;
}

int main(int argc, char **argv)
{
	int err = 0;
	struct erofs_vnode *root_inode;
	erofs_nid_t root_nid;

	mkfs_init_configure();
	mkfs_parse_options_cfg(argc, argv);

	err = dev_open(erofs_cfg.c_img_path);
	if (err) {
		usage(argv[0]);
		return -1;
	}

	root_inode = mkfs_prepare_root_inode(erofs_cfg.c_src_path);
	if (!root_inode)
		goto exit;
	err = erofs_create_files_list(root_inode);
	if (err)
		goto exit;

	err = erofs_cache_init(erofs_blknr(BLK_ALIGN(EROFS_SUPER_END)));
	if (err)
		goto exit;

	err = mkfs_relocate_sub_inodes(root_inode);
	if (err)
		goto exit;

	err = mkfs_do_write_inodes_data(root_inode);
	if (err)
		goto exit;

	err = erofs_flush_all_blocks();
	if (err)
		goto exit;

	root_nid = mkfs_addr_to_nid(root_inode->i_base_addr);
	err = erofs_mkfs_update_super_block(root_nid);

	erofs_info("done");

exit:
	dev_close();
	mkfs_free_config();

	if (err)
		erofs_err("\tError: Could not format the device!!!\n");
	return err;
}
