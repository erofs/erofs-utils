// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Created by Li Guifu <blucerlee@gmail.com>
 */
#include <string.h>
#include <stdlib.h>
#include "erofs/print.h"
#include "erofs/xattr.h"
#include "erofs/cache.h"

static bool check_layout_compatibility(struct erofs_sb_info *sbi,
				       struct erofs_super_block *dsb)
{
	const unsigned int feature = le32_to_cpu(dsb->feature_incompat);

	sbi->feature_incompat = feature;

	/* check if current kernel meets all mandatory requirements */
	if (feature & ~EROFS_ALL_FEATURE_INCOMPAT) {
		erofs_err("unidentified incompatible feature %x, please upgrade kernel version",
			  feature & ~EROFS_ALL_FEATURE_INCOMPAT);
		return false;
	}
	return true;
}

static int erofs_init_devices(struct erofs_sb_info *sbi,
			      struct erofs_super_block *dsb)
{
	unsigned int ondisk_extradevs, i;
	erofs_off_t pos;

	sbi->total_blocks = sbi->primarydevice_blocks;

	if (!erofs_sb_has_device_table(sbi))
		ondisk_extradevs = 0;
	else
		ondisk_extradevs = le16_to_cpu(dsb->extra_devices);

	if (sbi->extra_devices &&
	    ondisk_extradevs != sbi->extra_devices) {
		erofs_err("extra devices don't match (ondisk %u, given %u)",
			  ondisk_extradevs, sbi->extra_devices);
		return -EINVAL;
	}
	if (!ondisk_extradevs)
		return 0;

	sbi->extra_devices = ondisk_extradevs;
	sbi->device_id_mask = roundup_pow_of_two(ondisk_extradevs + 1) - 1;
	sbi->devs = calloc(ondisk_extradevs, sizeof(*sbi->devs));
	if (!sbi->devs)
		return -ENOMEM;
	pos = le16_to_cpu(dsb->devt_slotoff) * EROFS_DEVT_SLOT_SIZE;
	for (i = 0; i < ondisk_extradevs; ++i) {
		struct erofs_deviceslot dis;
		int ret;

		ret = erofs_dev_read(sbi, 0, &dis, pos, sizeof(dis));
		if (ret < 0) {
			free(sbi->devs);
			sbi->devs = NULL;
			return ret;
		}

		sbi->devs[i].mapped_blkaddr = le32_to_cpu(dis.mapped_blkaddr);
		sbi->devs[i].blocks = le32_to_cpu(dis.blocks);
		memcpy(sbi->devs[i].tag, dis.tag, sizeof(dis.tag));
		sbi->total_blocks += sbi->devs[i].blocks;
		pos += EROFS_DEVT_SLOT_SIZE;
	}
	return 0;
}

int erofs_read_superblock(struct erofs_sb_info *sbi)
{
	u8 data[EROFS_MAX_BLOCK_SIZE];
	struct erofs_super_block *dsb;
	int ret;

	sbi->blkszbits = ilog2(EROFS_MAX_BLOCK_SIZE);
	ret = erofs_blk_read(sbi, 0, data, 0, erofs_blknr(sbi, sizeof(data)));
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

	sbi->feature_compat = le32_to_cpu(dsb->feature_compat);

	sbi->blkszbits = dsb->blkszbits;
	if (sbi->blkszbits < 9 ||
	    sbi->blkszbits > ilog2(EROFS_MAX_BLOCK_SIZE)) {
		erofs_err("blksize %llu isn't supported on this platform",
			  erofs_blksiz(sbi) | 0ULL);
		return ret;
	} else if (!check_layout_compatibility(sbi, dsb)) {
		return ret;
	}

	sbi->sb_size = 128 + dsb->sb_extslots * EROFS_SB_EXTSLOT_SIZE;
	if (sbi->sb_size > (1 << sbi->blkszbits) - EROFS_SUPER_OFFSET) {
		erofs_err("invalid sb_extslots %u (more than a fs block)",
			  dsb->sb_extslots);
		return -EINVAL;
	}
	sbi->primarydevice_blocks = le32_to_cpu(dsb->blocks);
	sbi->meta_blkaddr = le32_to_cpu(dsb->meta_blkaddr);
	sbi->xattr_blkaddr = le32_to_cpu(dsb->xattr_blkaddr);
	sbi->xattr_prefix_start = le32_to_cpu(dsb->xattr_prefix_start);
	sbi->xattr_prefix_count = dsb->xattr_prefix_count;
	sbi->islotbits = EROFS_ISLOTBITS;
	sbi->root_nid = le16_to_cpu(dsb->root_nid);
	sbi->packed_nid = le64_to_cpu(dsb->packed_nid);
	sbi->inos = le64_to_cpu(dsb->inos);
	sbi->checksum = le32_to_cpu(dsb->checksum);

	sbi->build_time = le64_to_cpu(dsb->build_time);
	sbi->build_time_nsec = le32_to_cpu(dsb->build_time_nsec);

	memcpy(&sbi->uuid, dsb->uuid, sizeof(dsb->uuid));

	ret = z_erofs_parse_cfgs(sbi, dsb);
	if (ret)
		return ret;

	ret = erofs_init_devices(sbi, dsb);
	if (ret)
		return ret;

	ret = erofs_xattr_prefixes_init(sbi);
	if (ret && sbi->devs) {
		free(sbi->devs);
		sbi->devs = NULL;
	}
	return ret;
}

void erofs_put_super(struct erofs_sb_info *sbi)
{
	if (sbi->devs) {
		free(sbi->devs);
		sbi->devs = NULL;
	}
	erofs_xattr_prefixes_cleanup(sbi);
	if (sbi->bmgr) {
		erofs_buffer_exit(sbi->bmgr);
		sbi->bmgr = NULL;
	}
}

int erofs_writesb(struct erofs_sb_info *sbi, struct erofs_buffer_head *sb_bh,
		  erofs_blk_t *blocks)
{
	struct erofs_super_block sb = {
		.magic     = cpu_to_le32(EROFS_SUPER_MAGIC_V1),
		.blkszbits = sbi->blkszbits,
		.root_nid  = cpu_to_le16(sbi->root_nid),
		.inos      = cpu_to_le64(sbi->inos),
		.build_time = cpu_to_le64(sbi->build_time),
		.build_time_nsec = cpu_to_le32(sbi->build_time_nsec),
		.meta_blkaddr  = cpu_to_le32(sbi->meta_blkaddr),
		.xattr_blkaddr = cpu_to_le32(sbi->xattr_blkaddr),
		.xattr_prefix_count = sbi->xattr_prefix_count,
		.xattr_prefix_start = cpu_to_le32(sbi->xattr_prefix_start),
		.feature_incompat = cpu_to_le32(sbi->feature_incompat),
		.feature_compat = cpu_to_le32(sbi->feature_compat &
					      ~EROFS_FEATURE_COMPAT_SB_CHKSUM),
		.extra_devices = cpu_to_le16(sbi->extra_devices),
		.devt_slotoff = cpu_to_le16(sbi->devt_slotoff),
		.packed_nid = cpu_to_le64(sbi->packed_nid),
	};
	const u32 sb_blksize = round_up(EROFS_SUPER_END, erofs_blksiz(sbi));
	char *buf;
	int ret;

	*blocks         = erofs_mapbh(sbi->bmgr, NULL);
	sb.blocks       = cpu_to_le32(*blocks);
	memcpy(sb.uuid, sbi->uuid, sizeof(sb.uuid));
	memcpy(sb.volume_name, sbi->volume_name, sizeof(sb.volume_name));

	if (erofs_sb_has_compr_cfgs(sbi))
		sb.u1.available_compr_algs = cpu_to_le16(sbi->available_compr_algs);
	else
		sb.u1.lz4_max_distance = cpu_to_le16(sbi->lz4.max_distance);

	buf = calloc(sb_blksize, 1);
	if (!buf) {
		erofs_err("failed to allocate memory for sb: %s",
			  erofs_strerror(-errno));
		return -ENOMEM;
	}
	memcpy(buf + EROFS_SUPER_OFFSET, &sb, sizeof(sb));

	ret = erofs_dev_write(sbi, buf, sb_bh ? erofs_btell(sb_bh, false) : 0,
			      EROFS_SUPER_END);
	free(buf);
	if (sb_bh)
		erofs_bdrop(sb_bh, false);
	return ret;
}

struct erofs_buffer_head *erofs_reserve_sb(struct erofs_bufmgr *bmgr)
{
	struct erofs_buffer_head *bh;
	int err;

	bh = erofs_balloc(bmgr, META, 0, 0, 0);
	if (IS_ERR(bh)) {
		erofs_err("failed to allocate super: %s",
			  erofs_strerror(PTR_ERR(bh)));
		return bh;
	}
	bh->op = &erofs_skip_write_bhops;
	err = erofs_bh_balloon(bh, EROFS_SUPER_END);
	if (err < 0) {
		erofs_err("failed to balloon super: %s", erofs_strerror(err));
		goto err_bdrop;
	}

	/* make sure that the super block should be the very first blocks */
	(void)erofs_mapbh(NULL, bh->block);
	if (erofs_btell(bh, false) != 0) {
		erofs_err("failed to pin super block @ 0");
		err = -EFAULT;
		goto err_bdrop;
	}
	return bh;
err_bdrop:
	erofs_bdrop(bh, true);
	return ERR_PTR(err);
}

int erofs_enable_sb_chksum(struct erofs_sb_info *sbi, u32 *crc)
{
	int ret;
	u8 buf[EROFS_MAX_BLOCK_SIZE];
	unsigned int len;
	struct erofs_super_block *sb;

	ret = erofs_blk_read(sbi, 0, buf, 0, erofs_blknr(sbi, EROFS_SUPER_END) + 1);
	if (ret) {
		erofs_err("failed to read superblock to set checksum: %s",
			  erofs_strerror(ret));
		return ret;
	}

	/*
	 * skip the first 1024 bytes, to allow for the installation
	 * of x86 boot sectors and other oddities.
	 */
	sb = (struct erofs_super_block *)(buf + EROFS_SUPER_OFFSET);

	if (le32_to_cpu(sb->magic) != EROFS_SUPER_MAGIC_V1) {
		erofs_err("internal error: not an erofs valid image");
		return -EFAULT;
	}

	/* turn on checksum feature */
	sb->feature_compat = cpu_to_le32(le32_to_cpu(sb->feature_compat) |
					 EROFS_FEATURE_COMPAT_SB_CHKSUM);
	if (erofs_blksiz(sbi) > EROFS_SUPER_OFFSET)
		len = erofs_blksiz(sbi) - EROFS_SUPER_OFFSET;
	else
		len = erofs_blksiz(sbi);
	*crc = erofs_crc32c(~0, (u8 *)sb, len);

	/* set up checksum field to erofs_super_block */
	sb->checksum = cpu_to_le32(*crc);

	ret = erofs_blk_write(sbi, buf, 0, 1);
	if (ret) {
		erofs_err("failed to write checksummed superblock: %s",
			  erofs_strerror(ret));
		return ret;
	}

	return 0;
}
