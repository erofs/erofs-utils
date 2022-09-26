// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C), 2022, Coolpad Group Limited.
 * Created by Yue Hu <huyue2@coolpad.com>
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include "erofs/err.h"
#include "erofs/inode.h"
#include "erofs/compress.h"
#include "erofs/print.h"
#include "erofs/fragments.h"

static FILE *packedfile;
const char *frags_packedname = "packed_file";

int z_erofs_pack_fragments(struct erofs_inode *inode, void *data,
			   unsigned int len)
{
	inode->z_advise |= Z_EROFS_ADVISE_FRAGMENT_PCLUSTER;
	inode->fragmentoff = ftell(packedfile);
	inode->fragment_size = len;
	/*
	 * If the packed inode is larger than 4GiB, the full fragmentoff
	 * will be recorded by switching to the noncompact layout anyway.
	 */
	if (inode->fragmentoff >> 32)
		inode->datalayout = EROFS_INODE_FLAT_COMPRESSION_LEGACY;

	if (fwrite(data, len, 1, packedfile) != 1)
		return -EIO;

	erofs_sb_set_fragments();

	erofs_dbg("Recording %u fragment data at %lu", inode->fragment_size,
		  inode->fragmentoff);
	return len;
}

struct erofs_inode *erofs_mkfs_build_fragments(void)
{
	fflush(packedfile);

	return erofs_mkfs_build_special_from_fd(fileno(packedfile),
						frags_packedname);
}

void erofs_fragments_exit(void)
{
	if (packedfile)
		fclose(packedfile);
}

int erofs_fragments_init(void)
{
#ifdef HAVE_TMPFILE64
	packedfile = tmpfile64();
#else
	packedfile = tmpfile();
#endif
	if (!packedfile)
		return -ENOMEM;
	return 0;
}
