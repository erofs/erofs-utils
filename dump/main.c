// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021-2022 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Wang Qi <mpiglet@outlook.com>
 *            Guo Xuenan <guoxuenan@huawei.com>
 */
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include "erofs/print.h"
#include "erofs/io.h"

#ifdef HAVE_LIBUUID
#include <uuid.h>
#endif

struct erofsdump_cfg {
	unsigned int totalshow;
	bool show_superblock;
};
static struct erofsdump_cfg dumpcfg;

static struct option long_options[] = {
	{"help", no_argument, 0, 1},
	{0, 0, 0, 0},
};

struct erofsdump_feature {
	bool compat;
	u32 flag;
	const char *name;
};

static struct erofsdump_feature feature_lists[] = {
	{ true, EROFS_FEATURE_COMPAT_SB_CHKSUM, "sb_csum" },
	{ false, EROFS_FEATURE_INCOMPAT_LZ4_0PADDING, "0padding" },
	{ false, EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER, "big_pcluster" },
	{ false, EROFS_FEATURE_INCOMPAT_CHUNKED_FILE, "chunked_file" },
};

static void usage(void)
{
	fputs("usage: [options] IMAGE\n\n"
	      "Dump erofs layout from IMAGE, and [options] are:\n"
	      " -V      print the version number of dump.erofs and exit.\n"
	      " -s      show information about superblock\n"
	      " --help  display this help and exit.\n",
	      stderr);
}

static void erofsdump_print_version(void)
{
	fprintf(stderr, "dump.erofs %s\n", cfg.c_version);
}

static int erofsdump_parse_options_cfg(int argc, char **argv)
{
	int opt;

	while ((opt = getopt_long(argc, argv, "Vs",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 's':
			dumpcfg.show_superblock = true;
			++dumpcfg.totalshow;
			break;
		case 'V':
			erofsdump_print_version();
			exit(0);
		case 1:
			usage();
			exit(0);
		default:
			return -EINVAL;
		}
	}

	if (optind >= argc)
		return -EINVAL;

	cfg.c_img_path = strdup(argv[optind++]);
	if (!cfg.c_img_path)
		return -ENOMEM;

	if (optind < argc) {
		erofs_err("unexpected argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	return 0;
}

static void erofsdump_show_superblock(void)
{
	time_t time = sbi.build_time;
	char uuid_str[37] = "not available";
	int i = 0;

	fprintf(stdout, "Filesystem magic number:                      0x%04X\n",
			EROFS_SUPER_MAGIC_V1);
	fprintf(stdout, "Filesystem blocks:                            %llu\n",
			sbi.blocks | 0ULL);
	fprintf(stdout, "Filesystem inode metadata start block:        %u\n",
			sbi.meta_blkaddr);
	fprintf(stdout, "Filesystem shared xattr metadata start block: %u\n",
			sbi.xattr_blkaddr);
	fprintf(stdout, "Filesystem root nid:                          %llu\n",
			sbi.root_nid | 0ULL);
	fprintf(stdout, "Filesystem inode count:                       %llu\n",
			sbi.inos | 0ULL);
	fprintf(stdout, "Filesystem created:                           %s",
			ctime(&time));
	fprintf(stdout, "Filesystem features:                          ");
	for (; i < ARRAY_SIZE(feature_lists); i++) {
		u32 feat = le32_to_cpu(feature_lists[i].compat ?
				       sbi.feature_compat :
				       sbi.feature_incompat);
		if (feat & feature_lists[i].flag)
			fprintf(stdout, "%s ", feature_lists[i].name);
	}
#ifdef HAVE_LIBUUID
	uuid_unparse_lower(sbi.uuid, uuid_str);
#endif
	fprintf(stdout, "\nFilesystem UUID:                              %s\n",
			uuid_str);
}

int main(int argc, char **argv)
{
	int err;

	erofs_init_configure();
	err = erofsdump_parse_options_cfg(argc, argv);
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
		goto exit;
	}

	if (!dumpcfg.totalshow) {
		dumpcfg.show_superblock = true;
		dumpcfg.totalshow = 1;
	}
	if (dumpcfg.show_superblock)
		erofsdump_show_superblock();

exit:
	erofs_exit_configure();
	return err;
}
