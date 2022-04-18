// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021-2022 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Wang Qi <mpiglet@outlook.com>
 *            Guo Xuenan <guoxuenan@huawei.com>
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <sys/stat.h>
#include "erofs/print.h"
#include "erofs/inode.h"
#include "erofs/io.h"
#include "erofs/dir.h"
#include "../lib/liberofs_private.h"

#ifdef HAVE_LIBUUID
#include <uuid.h>
#endif

struct erofsdump_cfg {
	unsigned int totalshow;
	bool show_inode;
	bool show_extent;
	bool show_superblock;
	bool show_statistics;
	bool show_subdirectories;
	erofs_nid_t nid;
	const char *inode_path;
};
static struct erofsdump_cfg dumpcfg;

static const char chart_format[] = "%-16s	%-11d %8.2f%% |%-50s|\n";
static const char header_format[] = "%-16s %11s %16s |%-50s|\n";
static char *file_types[] = {
	".txt", ".so", ".xml", ".apk",
	".odex", ".vdex", ".oat", ".rc",
	".otf", ".txt", "others",
};
#define OTHERFILETYPE	ARRAY_SIZE(file_types)
/* (1 << FILE_MAX_SIZE_BITS)KB */
#define	FILE_MAX_SIZE_BITS	16

static const char * const file_category_types[] = {
	[EROFS_FT_UNKNOWN] = "unknown type",
	[EROFS_FT_REG_FILE] = "regular file",
	[EROFS_FT_DIR] = "directory",
	[EROFS_FT_CHRDEV] = "char dev",
	[EROFS_FT_BLKDEV] = "block dev",
	[EROFS_FT_FIFO] = "FIFO file",
	[EROFS_FT_SOCK] = "SOCK file",
	[EROFS_FT_SYMLINK] = "symlink file",
};

struct erofs_statistics {
	unsigned long files;
	unsigned long compressed_files;
	unsigned long uncompressed_files;
	unsigned long files_total_size;
	unsigned long files_total_origin_size;
	double compress_rate;

	/* [statistics] # of files based on inode_info->flags */
	unsigned long file_category_stat[EROFS_FT_MAX];
	/* [statistics] # of files based on file name extensions */
	unsigned int file_type_stat[OTHERFILETYPE];
	/* [statistics] # of files based on the original size of files */
	unsigned int file_original_size[FILE_MAX_SIZE_BITS + 1];
	/* [statistics] # of files based on the compressed size of files */
	unsigned int file_comp_size[FILE_MAX_SIZE_BITS + 1];
};
static struct erofs_statistics stats;

static struct option long_options[] = {
	{"help", no_argument, NULL, 1},
	{"nid", required_argument, NULL, 2},
	{"device", required_argument, NULL, 3},
	{"path", required_argument, NULL, 4},
	{"ls", no_argument, NULL, 5},
	{0, 0, 0, 0},
};

struct erofsdump_feature {
	bool compat;
	u32 flag;
	const char *name;
};

static struct erofsdump_feature feature_lists[] = {
	{ true, EROFS_FEATURE_COMPAT_SB_CHKSUM, "sb_csum" },
	{ true, EROFS_FEATURE_COMPAT_MTIME, "mtime" },
	{ false, EROFS_FEATURE_INCOMPAT_LZ4_0PADDING, "0padding" },
	{ false, EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER, "big_pcluster" },
	{ false, EROFS_FEATURE_INCOMPAT_CHUNKED_FILE, "chunked_file" },
	{ false, EROFS_FEATURE_INCOMPAT_DEVICE_TABLE, "device_table" },
};

static int erofsdump_readdir(struct erofs_dir_context *ctx);

static void usage(void)
{
	fputs("usage: [options] IMAGE\n\n"
	      "Dump erofs layout from IMAGE, and [options] are:\n"
	      " -S              show statistic information of the image\n"
	      " -V              print the version number of dump.erofs and exit.\n"
	      " -e              show extent info (INODE required)\n"
	      " -s              show information about superblock\n"
	      " --device=X      specify an extra device to be used together\n"
	      " --ls            show directory contents (INODE required)\n"
	      " --nid=#         show the target inode info of nid #\n"
	      " --path=X        show the target inode info of path X\n"
	      " --help          display this help and exit.\n",
	      stderr);
}

static void erofsdump_print_version(void)
{
	printf("dump.erofs %s\n", cfg.c_version);
}

static int erofsdump_parse_options_cfg(int argc, char **argv)
{
	int opt, err;

	while ((opt = getopt_long(argc, argv, "SVes",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'e':
			dumpcfg.show_extent = true;
			++dumpcfg.totalshow;
			break;
		case 's':
			dumpcfg.show_superblock = true;
			++dumpcfg.totalshow;
			break;
		case 'S':
			dumpcfg.show_statistics = true;
			++dumpcfg.totalshow;
			break;
		case 'V':
			erofsdump_print_version();
			exit(0);
		case 2:
			dumpcfg.show_inode = true;
			dumpcfg.nid = (erofs_nid_t)atoll(optarg);
			++dumpcfg.totalshow;
			break;
		case 1:
			usage();
			exit(0);
		case 3:
			err = blob_open_ro(optarg);
			if (err)
				return err;
			++sbi.extra_devices;
			break;
		case 4:
			dumpcfg.inode_path = optarg;
			dumpcfg.show_inode = true;
			++dumpcfg.totalshow;
			break;
		case 5:
			dumpcfg.show_subdirectories = true;
			break;
		default:
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
		erofs_err("unexpected argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	return 0;
}

static int erofsdump_get_occupied_size(struct erofs_inode *inode,
		erofs_off_t *size)
{
	*size = 0;
	switch (inode->datalayout) {
	case EROFS_INODE_FLAT_INLINE:
	case EROFS_INODE_FLAT_PLAIN:
	case EROFS_INODE_CHUNK_BASED:
		stats.uncompressed_files++;
		*size = inode->i_size;
		break;
	case EROFS_INODE_FLAT_COMPRESSION_LEGACY:
	case EROFS_INODE_FLAT_COMPRESSION:
		stats.compressed_files++;
		*size = inode->u.i_blocks * EROFS_BLKSIZ;
		break;
	default:
		erofs_err("unknown datalayout");
		return -ENOTSUP;
	}
	return 0;
}

static void inc_file_extension_count(const char *dname, unsigned int len)
{
	char *postfix = memrchr(dname, '.', len);
	int type;

	if (!postfix) {
		type = OTHERFILETYPE - 1;
	} else {
		for (type = 0; type < OTHERFILETYPE - 1; ++type)
			if (!strncmp(postfix, file_types[type],
				     len - (postfix - dname)))
				break;
	}
	++stats.file_type_stat[type];
}

static void update_file_size_statatics(erofs_off_t occupied_size,
		erofs_off_t original_size)
{
	int occupied_size_mark, original_size_mark;

	original_size_mark = 0;
	occupied_size_mark = 0;
	occupied_size >>= 10;
	original_size >>= 10;

	while (occupied_size || original_size) {
		if (occupied_size) {
			occupied_size >>= 1;
			occupied_size_mark++;
		}
		if (original_size) {
			original_size >>= 1;
			original_size_mark++;
		}
	}

	if (original_size_mark >= FILE_MAX_SIZE_BITS)
		stats.file_original_size[FILE_MAX_SIZE_BITS]++;
	else
		stats.file_original_size[original_size_mark]++;

	if (occupied_size_mark >= FILE_MAX_SIZE_BITS)
		stats.file_comp_size[FILE_MAX_SIZE_BITS]++;
	else
		stats.file_comp_size[occupied_size_mark]++;
}

static int erofsdump_ls_dirent_iter(struct erofs_dir_context *ctx)
{
	char fname[EROFS_NAME_LEN + 1];

	strncpy(fname, ctx->dname, ctx->de_namelen);
	fname[ctx->de_namelen] = '\0';
	fprintf(stdout, "%10llu    %u  %s\n",  ctx->de_nid | 0ULL,
		ctx->de_ftype, fname);
	return 0;
}

static int erofsdump_dirent_iter(struct erofs_dir_context *ctx)
{
	/* skip "." and ".." dentry */
	if (ctx->dot_dotdot)
		return 0;

	return erofsdump_readdir(ctx);
}

static int erofsdump_readdir(struct erofs_dir_context *ctx)
{
	int err;
	erofs_off_t occupied_size = 0;
	struct erofs_inode vi = { .nid = ctx->de_nid };

	err = erofs_read_inode_from_disk(&vi);
	if (err) {
		erofs_err("failed to read file inode from disk");
		return err;
	}
	stats.files++;
	stats.file_category_stat[erofs_mode_to_ftype(vi.i_mode)]++;

	err = erofsdump_get_occupied_size(&vi, &occupied_size);
	if (err) {
		erofs_err("get file size failed");
		return err;
	}

	if (S_ISREG(vi.i_mode)) {
		stats.files_total_origin_size += vi.i_size;
		inc_file_extension_count(ctx->dname, ctx->de_namelen);
		stats.files_total_size += occupied_size;
		update_file_size_statatics(occupied_size, vi.i_size);
	}

	/* XXXX: the dir depth should be restricted in order to avoid loops */
	if (S_ISDIR(vi.i_mode)) {
		struct erofs_dir_context nctx = {
			.flags = ctx->dir ? EROFS_READDIR_VALID_PNID : 0,
			.pnid = ctx->dir ? ctx->dir->nid : 0,
			.dir = &vi,
			.cb = erofsdump_dirent_iter,
		};

		return erofs_iterate_dir(&nctx, false);
	}
	return 0;
}

static int erofsdump_map_blocks(struct erofs_inode *inode,
		struct erofs_map_blocks *map, int flags)
{
	if (erofs_inode_is_data_compressed(inode->datalayout))
		return z_erofs_map_blocks_iter(inode, map, flags);
	return erofs_map_blocks(inode, map, flags);
}

static void erofsdump_show_fileinfo(bool show_extent)
{
	const char *ext_fmt[] = {
		"%4d: %8" PRIu64 "..%8" PRIu64 " | %7" PRIu64 " : %10" PRIu64 "..%10" PRIu64 " | %7" PRIu64 "\n",
		"%4d: %8" PRIu64 "..%8" PRIu64 " | %7" PRIu64 " : %10" PRIu64 "..%10" PRIu64 " | %7" PRIu64 "  # device %u\n"
	};
	int err, i;
	erofs_off_t size;
	u16 access_mode;
	struct erofs_inode inode = { .nid = dumpcfg.nid };
	char path[PATH_MAX];
	char access_mode_str[] = "rwxrwxrwx";
	char timebuf[128] = {0};
	unsigned int extent_count = 0;
	struct erofs_map_blocks map = {
		.index = UINT_MAX,
		.m_la = 0,
	};

	if (dumpcfg.inode_path) {
		err = erofs_ilookup(dumpcfg.inode_path, &inode);
		if (err) {
			erofs_err("read inode failed @ %s", dumpcfg.inode_path);
			return;
		}
	} else {
		err = erofs_read_inode_from_disk(&inode);
		if (err) {
			erofs_err("read inode failed @ nid %llu",
				  inode.nid | 0ULL);
			return;
		}
	}

	err = erofs_get_occupied_size(&inode, &size);
	if (err) {
		erofs_err("get file size failed @ nid %llu", inode.nid | 0ULL);
		return;
	}

	err = erofs_get_pathname(inode.nid, path, sizeof(path));
	if (err < 0) {
		erofs_err("file path not found @ nid %llu", inode.nid | 0ULL);
		return;
	}

	strftime(timebuf, sizeof(timebuf),
		 "%Y-%m-%d %H:%M:%S", localtime((time_t *)&inode.i_mtime));
	access_mode = inode.i_mode & 0777;
	for (i = 8; i >= 0; i--)
		if (((access_mode >> i) & 1) == 0)
			access_mode_str[8 - i] = '-';
	fprintf(stdout, "File : %s\n", path);
	fprintf(stdout, "Size: %" PRIu64"  On-disk size: %" PRIu64 "  %s\n",
		inode.i_size, size,
		file_category_types[erofs_mode_to_ftype(inode.i_mode)]);
	fprintf(stdout, "NID: %" PRIu64 "   ", inode.nid);
	fprintf(stdout, "Links: %u   ", inode.i_nlink);
	fprintf(stdout, "Layout: %d   Compression ratio: %.2f%%\n",
		inode.datalayout,
		(double)(100 * size) / (double)(inode.i_size));
	fprintf(stdout, "Inode size: %d   ", inode.inode_isize);
	fprintf(stdout, "Extent size: %u   ", inode.extent_isize);
	fprintf(stdout,	"Xattr size: %u\n", inode.xattr_isize);
	fprintf(stdout, "Uid: %u   Gid: %u  ", inode.i_uid, inode.i_gid);
	fprintf(stdout, "Access: %04o/%s\n", access_mode, access_mode_str);
	fprintf(stdout, "Timestamp: %s.%09d\n", timebuf, inode.i_mtime_nsec);

	if (dumpcfg.show_subdirectories) {
		struct erofs_dir_context ctx = {
			.flags = EROFS_READDIR_VALID_PNID,
			.pnid = inode.nid,
			.dir = &inode,
			.cb = erofsdump_ls_dirent_iter,
			.de_nid = 0,
			.dname = "",
			.de_namelen = 0,
		};

		fprintf(stdout, "\n       NID TYPE  FILENAME\n");
		err = erofs_iterate_dir(&ctx, false);
		if (err) {
			erofs_err("failed to list directory contents");
			return;
		}
	}

	if (!dumpcfg.show_extent)
		return;

	fprintf(stdout, "\n Ext:   logical offset   |  length :     physical offset    |  length\n");
	while (map.m_la < inode.i_size) {
		struct erofs_map_dev mdev;

		err = erofsdump_map_blocks(&inode, &map,
				EROFS_GET_BLOCKS_FIEMAP);
		if (err) {
			erofs_err("failed to get file blocks range");
			return;
		}

		mdev = (struct erofs_map_dev) {
			.m_deviceid = map.m_deviceid,
			.m_pa = map.m_pa,
		};
		err = erofs_map_dev(&sbi, &mdev);
		if (err) {
			erofs_err("failed to map device");
			return;
		}

		fprintf(stdout, ext_fmt[!!mdev.m_deviceid], extent_count++,
			map.m_la, map.m_la + map.m_llen, map.m_llen,
			mdev.m_pa, mdev.m_pa + map.m_plen, map.m_plen,
			mdev.m_deviceid);
		map.m_la += map.m_llen;
	}
	fprintf(stdout, "%s: %d extents found\n", path, extent_count);
}

static void erofsdump_filesize_distribution(const char *title,
		unsigned int *file_counts, unsigned int len)
{
	char col1[30];
	unsigned int col2, i, lowerbound, upperbound;
	double col3;
	char col4[400];

	lowerbound = 0;
	upperbound = 1;
	fprintf(stdout, "\n%s file size distribution:\n", title);
	fprintf(stdout, header_format, ">=(KB) .. <(KB) ", "count",
			"ratio", "distribution");
	for (i = 0; i < len; i++) {
		memset(col1, 0, sizeof(col1));
		memset(col4, 0, sizeof(col4));
		if (i == len - 1)
			sprintf(col1, "%6d ..", lowerbound);
		else if (i <= 6)
			sprintf(col1, "%6d .. %-6d", lowerbound, upperbound);
		else

			sprintf(col1, "%6d .. %-6d", lowerbound, upperbound);
		col2 = file_counts[i];
		if (stats.file_category_stat[EROFS_FT_REG_FILE])
			col3 = (double)(100 * col2) /
				stats.file_category_stat[EROFS_FT_REG_FILE];
		else
			col3 = 0.0;
		memset(col4, '#', col3 / 2);
		fprintf(stdout, chart_format, col1, col2, col3, col4);
		lowerbound = upperbound;
		upperbound <<= 1;
	}
}

static void erofsdump_filetype_distribution(char **file_types, unsigned int len)
{
	char col1[30];
	unsigned int col2, i;
	double col3;
	char col4[401];

	fprintf(stdout, "\nFile type distribution:\n");
	fprintf(stdout, header_format, "type", "count", "ratio",
			"distribution");
	for (i = 0; i < len; i++) {
		memset(col1, 0, sizeof(col1));
		memset(col4, 0, sizeof(col4));
		sprintf(col1, "%-17s", file_types[i]);
		col2 = stats.file_type_stat[i];
		if (stats.file_category_stat[EROFS_FT_REG_FILE])
			col3 = (double)(100 * col2) /
				stats.file_category_stat[EROFS_FT_REG_FILE];
		else
			col3 = 0.0;
		memset(col4, '#', col3 / 2);
		fprintf(stdout, chart_format, col1, col2, col3, col4);
	}
}

static void erofsdump_file_statistic(void)
{
	unsigned int i;

	fprintf(stdout, "Filesystem total file count:		%lu\n",
			stats.files);
	for (i = 0; i < EROFS_FT_MAX; i++)
		fprintf(stdout, "Filesystem %s count:		%lu\n",
			file_category_types[i], stats.file_category_stat[i]);

	stats.compress_rate = (double)(100 * stats.files_total_size) /
		(double)(stats.files_total_origin_size);
	fprintf(stdout, "Filesystem compressed files:            %lu\n",
			stats.compressed_files);
	fprintf(stdout, "Filesystem uncompressed files:          %lu\n",
			stats.uncompressed_files);
	fprintf(stdout, "Filesystem total original file size:    %lu Bytes\n",
			stats.files_total_origin_size);
	fprintf(stdout, "Filesystem total file size:             %lu Bytes\n",
			stats.files_total_size);
	fprintf(stdout, "Filesystem compress rate:               %.2f%%\n",
			stats.compress_rate);
}

static void erofsdump_print_statistic(void)
{
	int err;
	struct erofs_dir_context ctx = {
		.flags = 0,
		.pnid = 0,
		.dir = NULL,
		.cb = erofsdump_dirent_iter,
		.de_nid = sbi.root_nid,
		.dname = "",
		.de_namelen = 0,
	};

	err = erofsdump_readdir(&ctx);
	if (err) {
		erofs_err("read dir failed");
		return;
	}
	erofsdump_file_statistic();
	erofsdump_filesize_distribution("Original",
			stats.file_original_size,
			ARRAY_SIZE(stats.file_original_size));
	erofsdump_filesize_distribution("On-disk",
			stats.file_comp_size,
			ARRAY_SIZE(stats.file_comp_size));
	erofsdump_filetype_distribution(file_types, OTHERFILETYPE);
}

static void erofsdump_show_superblock(void)
{
	time_t time = sbi.build_time;
	char uuid_str[37] = "not available";
	int i = 0;

	fprintf(stdout, "Filesystem magic number:                      0x%04X\n",
			EROFS_SUPER_MAGIC_V1);
	fprintf(stdout, "Filesystem blocks:                            %llu\n",
			sbi.total_blocks | 0ULL);
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
		goto exit_dev_close;
	}

	if (!dumpcfg.totalshow) {
		dumpcfg.show_superblock = true;
		dumpcfg.totalshow = 1;
	}
	if (dumpcfg.show_superblock)
		erofsdump_show_superblock();

	if (dumpcfg.show_statistics)
		erofsdump_print_statistic();

	if (dumpcfg.show_extent && !dumpcfg.show_inode) {
		usage();
		goto exit_dev_close;
	}

	if (dumpcfg.show_inode)
		erofsdump_show_fileinfo(dumpcfg.show_extent);

exit_dev_close:
	dev_close();
exit:
	blob_closeall();
	erofs_exit_configure();
	return err;
}
