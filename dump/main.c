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
	bool show_inode;
	bool show_superblock;
	bool show_statistics;
	erofs_nid_t nid;
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

static int erofs_read_dir(erofs_nid_t nid, erofs_nid_t parent_nid);
static inline int erofs_checkdirent(struct erofs_dirent *de,
		struct erofs_dirent *last_de,
		u32 maxsize, const char *dname);

static void usage(void)
{
	fputs("usage: [options] IMAGE\n\n"
	      "Dump erofs layout from IMAGE, and [options] are:\n"
	      " -S      show statistic information of the image\n"
	      " -V      print the version number of dump.erofs and exit.\n"
	      " -s      show information about superblock\n"
	      " --nid=# show the target inode info of nid #\n"
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

	while ((opt = getopt_long(argc, argv, "SVs",
				  long_options, NULL)) != -1) {
		switch (opt) {
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

static int erofs_get_occupied_size(struct erofs_inode *inode,
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
		return -1;
	}
	return 0;
}

static int erofs_getfile_extension(const char *filename)
{
	char *postfix = strrchr(filename, '.');
	int type = 0;

	if (!postfix)
		return OTHERFILETYPE - 1;
	for (type = 0; type < OTHERFILETYPE - 1; ++type) {
		if (strcmp(postfix, file_types[type]) == 0)
			break;
	}
	return type;
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

static inline int erofs_checkdirent(struct erofs_dirent *de,
		struct erofs_dirent *last_de,
		u32 maxsize, const char *dname)
{
	int dname_len;
	unsigned int nameoff = le16_to_cpu(de->nameoff);

	if (nameoff < sizeof(struct erofs_dirent) ||
			nameoff >= PAGE_SIZE) {
		erofs_err("invalid de[0].nameoff %u @ nid %llu",
				nameoff, de->nid | 0ULL);
		return -EFSCORRUPTED;
	}

	dname_len = (de + 1 >= last_de) ? strnlen(dname, maxsize - nameoff) :
				le16_to_cpu(de[1].nameoff) - nameoff;
	/* a corrupted entry is found */
	if (nameoff + dname_len > maxsize ||
			dname_len > EROFS_NAME_LEN) {
		erofs_err("bogus dirent @ nid %llu",
				le64_to_cpu(de->nid) | 0ULL);
		DBG_BUGON(1);
		return -EFSCORRUPTED;
	}
	if (de->file_type >= EROFS_FT_MAX) {
		erofs_err("invalid file type %llu", de->nid);
		return -EFSCORRUPTED;
	}
	return dname_len;
}

static int erofs_read_dirent(struct erofs_dirent *de,
		erofs_nid_t nid, erofs_nid_t parent_nid,
		const char *dname)
{
	int err;
	erofs_off_t occupied_size = 0;
	struct erofs_inode inode = { .nid = de->nid };

	stats.files++;
	stats.file_category_stat[de->file_type]++;
	err = erofs_read_inode_from_disk(&inode);
	if (err) {
		erofs_err("read file inode from disk failed!");
		return err;
	}

	err = erofs_get_occupied_size(&inode, &occupied_size);
	if (err) {
		erofs_err("get file size failed\n");
		return err;
	}

	if (de->file_type == EROFS_FT_REG_FILE) {
		stats.files_total_origin_size += inode.i_size;
		stats.file_type_stat[erofs_getfile_extension(dname)]++;
		stats.files_total_size += occupied_size;
		update_file_size_statatics(occupied_size, inode.i_size);
	}

	if ((de->file_type == EROFS_FT_DIR)
			&& de->nid != nid && de->nid != parent_nid) {
		err = erofs_read_dir(de->nid, nid);
		if (err) {
			erofs_err("parse dir nid %llu error occurred\n",
					de->nid);
			return err;
		}
	}
	return 0;
}

static int erofs_read_dir(erofs_nid_t nid, erofs_nid_t parent_nid)
{
	int err;
	erofs_off_t offset;
	char buf[EROFS_BLKSIZ];
	struct erofs_inode vi = { .nid = nid };

	err = erofs_read_inode_from_disk(&vi);
	if (err)
		return err;

	offset = 0;
	while (offset < vi.i_size) {
		erofs_off_t maxsize = min_t(erofs_off_t,
						vi.i_size - offset, EROFS_BLKSIZ);
		struct erofs_dirent *de = (void *)buf;
		struct erofs_dirent *end;
		unsigned int nameoff;

		err = erofs_pread(&vi, buf, maxsize, offset);
		if (err)
			return err;

		nameoff = le16_to_cpu(de->nameoff);
		end = (void *)buf + nameoff;
		while (de < end) {
			const char *dname;
			int ret;

			/* skip "." and ".." dentry */
			if (de->nid == nid || de->nid == parent_nid) {
				de++;
				continue;
			}

			dname = (char *)buf + nameoff;
			ret = erofs_checkdirent(de, end, maxsize, dname);
			if (ret < 0)
				return ret;
			ret = erofs_read_dirent(de, nid, parent_nid, dname);
			if (ret < 0)
				return ret;
			++de;
		}
		offset += maxsize;
	}
	return 0;
}

static int erofs_get_pathname(erofs_nid_t nid, erofs_nid_t parent_nid,
		erofs_nid_t target, char *path, unsigned int pos)
{
	int err;
	erofs_off_t offset;
	char buf[EROFS_BLKSIZ];
	struct erofs_inode inode = { .nid = nid };

	path[pos++] = '/';
	if (target == sbi.root_nid)
		return 0;

	err = erofs_read_inode_from_disk(&inode);
	if (err) {
		erofs_err("read inode failed @ nid %llu", nid | 0ULL);
		return err;
	}

	offset = 0;
	while (offset < inode.i_size) {
		erofs_off_t maxsize = min_t(erofs_off_t,
					inode.i_size - offset, EROFS_BLKSIZ);
		struct erofs_dirent *de = (void *)buf;
		struct erofs_dirent *end;
		unsigned int nameoff;

		err = erofs_pread(&inode, buf, maxsize, offset);
		if (err)
			return err;

		nameoff = le16_to_cpu(de->nameoff);
		end = (void *)buf + nameoff;
		while (de < end) {
			const char *dname;
			int len;

			nameoff = le16_to_cpu(de->nameoff);
			dname = (char *)buf + nameoff;
			len = erofs_checkdirent(de, end, maxsize, dname);
			if (len < 0)
				return len;

			if (de->nid == target) {
				memcpy(path + pos, dname, len);
				path[pos + len] = '\0';
				return 0;
			}

			if (de->file_type == EROFS_FT_DIR &&
					de->nid != parent_nid &&
					de->nid != nid) {
				memcpy(path + pos, dname, len);
				err = erofs_get_pathname(de->nid, nid,
						target, path, pos + len);
				if (!err)
					return 0;
				memset(path + pos, 0, len);
			}
			++de;
		}
		offset += maxsize;
	}
	return -1;
}

static void erofsdump_show_fileinfo(void)
{
	int err, i;
	erofs_off_t size;
	u16 access_mode;
	struct erofs_inode inode = { .nid = dumpcfg.nid };
	char path[PATH_MAX + 1] = {0};
	char access_mode_str[] = "rwxrwxrwx";
	char timebuf[128] = {0};

	err = erofs_read_inode_from_disk(&inode);
	if (err) {
		erofs_err("read inode failed @ nid %llu", inode.nid | 0ULL);
		return;
	}

	err = erofs_get_occupied_size(&inode, &size);
	if (err) {
		erofs_err("get file size failed @ nid %llu", inode.nid | 0ULL);
		return;
	}

	err = erofs_get_pathname(sbi.root_nid, sbi.root_nid,
				 inode.nid, path, 0);
	if (err < 0) {
		erofs_err("file path not found @ nid %llu", inode.nid | 0ULL);
		return;
	}

	strftime(timebuf, sizeof(timebuf),
		 "%Y-%m-%d %H:%M:%S", localtime((time_t *)&inode.i_ctime));
	access_mode = inode.i_mode & 0777;
	for (i = 8; i >= 0; i--)
		if (((access_mode >> i) & 1) == 0)
			access_mode_str[8 - i] = '-';
	fprintf(stdout, "File : %s\n", path);
	fprintf(stdout, "NID: %" PRIu64 "  ", inode.nid);
	fprintf(stdout, "Links: %u  ", inode.i_nlink);
	fprintf(stdout, "Layout: %d\n", inode.datalayout);
	fprintf(stdout, "Inode size: %d   ", inode.inode_isize);
	fprintf(stdout, "Extent size: %u   ", inode.extent_isize);
	fprintf(stdout,	"Xattr size: %u\n", inode.xattr_isize);
	fprintf(stdout, "File size: %" PRIu64"  ", inode.i_size);
	fprintf(stdout,	"On-disk size: %" PRIu64 "  ", size);
	fprintf(stdout, "Compression ratio: %.2f%%\n",
			(double)(100 * size) / (double)(inode.i_size));
	fprintf(stdout, "Uid: %u   Gid: %u  ", inode.i_uid, inode.i_gid);
	fprintf(stdout, "Access: %04o/%s\n", access_mode, access_mode_str);
	fprintf(stdout, "Timestamp: %s.%09d\n", timebuf, inode.i_ctime_nsec);
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

	err = erofs_read_dir(sbi.root_nid, sbi.root_nid);
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

	if (dumpcfg.show_statistics)
		erofsdump_print_statistic();

	if (dumpcfg.show_inode)
		erofsdump_show_fileinfo();

exit:
	erofs_exit_configure();
	return err;
}
