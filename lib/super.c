// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/super.c
 *
 * Created by Li Guifu <blucerlee@gmail.com>
 */
#include <string.h>
#include <stdlib.h>
#include <asm-generic/errno-base.h>

#include "erofs/io.h"
#include "erofs/print.h"

static bool check_layout_compatibility(struct erofs_sb_info *sbi,
				       struct erofs_super_block *dsb)
{
	const unsigned int feature = le32_to_cpu(dsb->feature_incompat);

	sbi->feature_incompat = feature;

	/* check if current kernel meets all mandatory requirements */
	if (feature & (~EROFS_ALL_FEATURE_INCOMPAT)) {
		erofs_err("unidentified incompatible feature %x, please upgrade kernel version",
			  feature & ~EROFS_ALL_FEATURE_INCOMPAT);
		return false;
	}
	return true;
}

int erofs_read_superblock(void)
{
	char data[EROFS_BLKSIZ];
	struct erofs_super_block *dsb;
	unsigned int blkszbits;
	int ret;

	ret = blk_read(data, 0, 1);
	if (ret < 0) {
		erofs_err("cannot read erofs superblock: %d", ret);
		return -EIO;
	}
	dsb = (struct erofs_super_block *)(data + EROFS_SUPER_OFFSET);

	ret = -EINVAL;
	if (le32_to_cpu(dsb->magic) != EROFS_SUPER_MAGIC_V1) {
		erofs_err("cannot find valid erofs superblock");
		return ret;
	}

	sbi.feature_compat = le32_to_cpu(dsb->feature_compat);

	blkszbits = dsb->blkszbits;
	/* 9(512 bytes) + LOG_SECTORS_PER_BLOCK == LOG_BLOCK_SIZE */
	if (blkszbits != LOG_BLOCK_SIZE) {
		erofs_err("blksize %u isn't supported on this platform",
			  1 << blkszbits);
		return ret;
	}

	if (!check_layout_compatibility(&sbi, dsb))
		return ret;

	sbi.blocks = le32_to_cpu(dsb->blocks);
	sbi.meta_blkaddr = le32_to_cpu(dsb->meta_blkaddr);
	sbi.xattr_blkaddr = le32_to_cpu(dsb->xattr_blkaddr);
	sbi.islotbits = EROFS_ISLOTBITS;
	sbi.root_nid = le16_to_cpu(dsb->root_nid);
	sbi.inos = le64_to_cpu(dsb->inos);

	sbi.build_time = le64_to_cpu(dsb->build_time);
	sbi.build_time_nsec = le32_to_cpu(dsb->build_time_nsec);

	memcpy(&sbi.uuid, dsb->uuid, sizeof(dsb->uuid));
	return 0;
}

