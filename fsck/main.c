// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2021 Google LLC
 * Author: Daeho Jeong <daehojeong@google.com>
 */
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <sys/stat.h>
#include "erofs/print.h"
#include "erofs/io.h"
#include "erofs/decompress.h"
#include "erofs/dir.h"

static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid);

struct erofsfsck_cfg {
	bool corrupted;
	bool print_comp_ratio;
	bool check_decomp;
	u64 physical_blocks;
	u64 logical_blocks;
};
static struct erofsfsck_cfg fsckcfg;

static struct option long_options[] = {
	{"help", no_argument, 0, 1},
	{"extract", no_argument, 0, 2},
	{"device", required_argument, 0, 3},
	{0, 0, 0, 0},
};

static void usage(void)
{
	fputs("usage: [options] IMAGE\n\n"
	      "Check erofs filesystem integrity of IMAGE, and [options] are:\n"
	      " -V              print the version number of fsck.erofs and exit.\n"
	      " -d#             set output message level to # (maximum 9)\n"
	      " -p              print total compression ratio of all files\n"
	      " --device=X      specify an extra device to be used together\n"
	      " --extract       check if all files are well encoded\n"
	      " --help          display this help and exit.\n",
	      stderr);
}

static void erofsfsck_print_version(void)
{
	fprintf(stderr, "fsck.erofs %s\n", cfg.c_version);
}

static int erofsfsck_parse_options_cfg(int argc, char **argv)
{
	int opt, ret;

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
			break;
		case 3:
			ret = blob_open_ro(optarg);
			if (ret)
				return ret;
			++sbi.extra_devices;
			break;
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
		erofs_err("unexpected argument: %s", argv[optind]);
		return -EINVAL;
	}
	return 0;
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

static int verify_uncompressed_inode(struct erofs_inode *inode)
{
	struct erofs_map_blocks map = {
		.index = UINT_MAX,
	};
	int ret;
	erofs_off_t ptr = 0;
	u64 i_blocks = DIV_ROUND_UP(inode->i_size, EROFS_BLKSIZ);

	while (ptr < inode->i_size) {
		map.m_la = ptr;
		ret = erofs_map_blocks(inode, &map, 0);
		if (ret)
			return ret;

		if (map.m_plen != map.m_llen || ptr != map.m_la) {
			erofs_err("broken data chunk layout m_la %" PRIu64 " ptr %" PRIu64 " m_llen %" PRIu64 " m_plen %" PRIu64,
				  map.m_la, ptr, map.m_llen, map.m_plen);
			return -EFSCORRUPTED;
		}

		if (!(map.m_flags & EROFS_MAP_MAPPED) && !map.m_llen) {
			/* reached EOF */
			ptr = inode->i_size;
			continue;
		}

		ptr += map.m_llen;
	}

	if (fsckcfg.print_comp_ratio) {
		fsckcfg.logical_blocks += i_blocks;
		fsckcfg.physical_blocks += i_blocks;
	}

	return 0;
}

static int verify_compressed_inode(struct erofs_inode *inode)
{
	struct erofs_map_blocks map = {
		.index = UINT_MAX,
	};
	struct erofs_map_dev mdev;
	int ret = 0;
	u64 pchunk_len = 0;
	erofs_off_t end = inode->i_size;
	unsigned int raw_size = 0, buffer_size = 0;
	char *raw = NULL, *buffer = NULL;

	while (end > 0) {
		map.m_la = end - 1;

		ret = z_erofs_map_blocks_iter(inode, &map, 0);
		if (ret)
			goto out;

		if (end > map.m_la + map.m_llen) {
			erofs_err("broken compressed chunk layout m_la %" PRIu64 " m_llen %" PRIu64 " end %" PRIu64,
				  map.m_la, map.m_llen, end);
			ret = -EFSCORRUPTED;
			goto out;
		}

		pchunk_len += map.m_plen;
		end = map.m_la;

		if (!fsckcfg.check_decomp || !(map.m_flags & EROFS_MAP_MAPPED))
			continue;

		if (map.m_plen > raw_size) {
			raw_size = map.m_plen;
			raw = realloc(raw, raw_size);
			BUG_ON(!raw);
		}

		if (map.m_llen > buffer_size) {
			buffer_size = map.m_llen;
			buffer = realloc(buffer, buffer_size);
			BUG_ON(!buffer);
		}

		mdev = (struct erofs_map_dev) {
			.m_deviceid = map.m_deviceid,
			.m_pa = map.m_pa,
		};
		ret = erofs_map_dev(&sbi, &mdev);
		if (ret) {
			erofs_err("failed to map device of m_pa %" PRIu64 ", m_deviceid %u @ nid %llu: %d",
				  map.m_pa, map.m_deviceid, inode->nid | 0ULL, ret);
			goto out;
		}

		ret = dev_read(mdev.m_deviceid, raw, mdev.m_pa, map.m_plen);
		if (ret < 0) {
			erofs_err("failed to read compressed data of m_pa %" PRIu64 ", m_plen %" PRIu64 " @ nid %llu: %d",
				  mdev.m_pa, map.m_plen, inode->nid | 0ULL, ret);
			goto out;
		}

		ret = z_erofs_decompress(&(struct z_erofs_decompress_req) {
					.in = raw,
					.out = buffer,
					.decodedskip = 0,
					.inputsize = map.m_plen,
					.decodedlength = map.m_llen,
					.alg = map.m_algorithmformat,
					.partial_decoding = 0
					 });

		if (ret < 0) {
			erofs_err("failed to decompress data of m_pa %" PRIu64 ", m_plen %" PRIu64 " @ nid %llu: %d",
				  mdev.m_pa, map.m_plen, inode->nid | 0ULL, ret);
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

static int erofs_verify_inode_data(struct erofs_inode *inode)
{
	int ret;

	erofs_dbg("verify data chunk of nid(%llu): type(%d)",
		  inode->nid | 0ULL, inode->datalayout);

	switch (inode->datalayout) {
	case EROFS_INODE_FLAT_PLAIN:
	case EROFS_INODE_FLAT_INLINE:
	case EROFS_INODE_CHUNK_BASED:
		ret = verify_uncompressed_inode(inode);
		break;
	case EROFS_INODE_FLAT_COMPRESSION_LEGACY:
	case EROFS_INODE_FLAT_COMPRESSION:
		ret = verify_compressed_inode(inode);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret == -EIO)
		erofs_err("I/O error occurred when verifying data chunk of nid(%llu)",
			  inode->nid | 0ULL);

	return ret;
}

static int erofsfsck_dirent_iter(struct erofs_dir_context *ctx)
{
	if (ctx->dot_dotdot)
		return 0;

	return erofsfsck_check_inode(ctx->dir->nid, ctx->de_nid);
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

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(&inode);
	if (ret)
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
out:
	if (ret && ret != -EIO)
		fsckcfg.corrupted = true;
	return ret;
}

int main(int argc, char **argv)
{
	int err;

	erofs_init_configure();

	fsckcfg.corrupted = false;
	fsckcfg.print_comp_ratio = false;
	fsckcfg.check_decomp = false;
	fsckcfg.logical_blocks = 0;
	fsckcfg.physical_blocks = 0;

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
		erofs_err("Found some filesystem corruption");
		err = -EFSCORRUPTED;
	} else if (!err) {
		erofs_info("No error found");
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
