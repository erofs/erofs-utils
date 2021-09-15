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

static struct option long_options[] = {
	{"help", no_argument, 0, 1},
	{0, 0, 0, 0},
};

static void usage(void)
{
	fputs("usage: [options] IMAGE\n\n"
	      "Dump erofs layout from IMAGE, and [options] are:\n"
	      " -V      print the version number of dump.erofs and exit.\n"
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

	while ((opt = getopt_long(argc, argv, "V",
				  long_options, NULL)) != -1) {
		switch (opt) {
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

exit:
	erofs_exit_configure();
	return err;
}
