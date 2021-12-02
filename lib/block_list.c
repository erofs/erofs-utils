// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C), 2021, Coolpad Group Limited.
 * Created by Yue Hu <huyue2@yulong.com>
 */
#ifdef WITH_ANDROID
#include <stdio.h>
#include <sys/stat.h>
#include "erofs/block_list.h"

#define EROFS_MODNAME	"erofs block_list"
#include "erofs/print.h"

static FILE *block_list_fp;

int erofs_droid_blocklist_fopen(void)
{
	block_list_fp = fopen(cfg.block_list_file, "w");

	if (!block_list_fp)
		return -1;
	return 0;
}

void erofs_droid_blocklist_fclose(void)
{
	if (!block_list_fp)
		return;

	fclose(block_list_fp);
	block_list_fp = NULL;
}

static void blocklist_write(const char *path, erofs_blk_t blk_start,
			    erofs_blk_t nblocks, bool first_extent,
			    bool last_extent)
{
	const char *fspath = erofs_fspath(path);

	if (first_extent) {
		fprintf(block_list_fp, "/%s", cfg.mount_point);

		if (fspath[0] != '/')
			fprintf(block_list_fp, "/");

		fprintf(block_list_fp, "%s", fspath);
	}

	if (nblocks == 1)
		fprintf(block_list_fp, " %u", blk_start);
	else
		fprintf(block_list_fp, " %u-%u", blk_start,
			blk_start + nblocks - 1);

	if (last_extent)
		fprintf(block_list_fp, "\n");
}

void erofs_droid_blocklist_write_extent(struct erofs_inode *inode,
					erofs_blk_t blk_start,
					erofs_blk_t nblocks, bool first_extent,
					bool last_extent)
{
	if (!block_list_fp || !cfg.mount_point)
		return;

	if (!nblocks) {
		if (last_extent)
			fprintf(block_list_fp, "\n");
		return;
	}

	blocklist_write(inode->i_srcpath, blk_start, nblocks, first_extent,
			last_extent);
}

void erofs_droid_blocklist_write(struct erofs_inode *inode,
				 erofs_blk_t blk_start, erofs_blk_t nblocks)
{
	if (!block_list_fp || !cfg.mount_point || !nblocks)
		return;

	blocklist_write(inode->i_srcpath, blk_start, nblocks,
			true, !inode->idata_size);
}

void erofs_droid_blocklist_write_tail_end(struct erofs_inode *inode,
					  erofs_blk_t blkaddr)
{
	if (!block_list_fp || !cfg.mount_point)
		return;

	/* XXX: a bit hacky.. may need a better approach */
	if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode))
		return;

	/* XXX: another hack, which means it has been outputed before */
	if (erofs_blknr(inode->i_size)) {
		if (blkaddr == NULL_ADDR)
			fprintf(block_list_fp, "\n");
		else
			fprintf(block_list_fp, " %u\n", blkaddr);
		return;
	}
	if (blkaddr != NULL_ADDR)
		blocklist_write(inode->i_srcpath, blkaddr, 1, true, true);
}
#endif
