// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include "erofs/internal.h"

static int erofs_vmdk_desc_add_extent(FILE *f, u64 sectors,
				      const char *filename, u64 offset)
{
	static const char extent_line_fmt[] =
		"RW %" PRIu64 " FLAT \"%s\" %" PRIu64 "\n";

	while (sectors) {
		u64 count = min_t(u64, sectors, 0x80000000 >> 9);
		int ret;

		ret = fprintf(f, extent_line_fmt, count, filename, offset);
		if (ret < 0)
			return -errno;
		offset += count;
		sectors -= count;
	}
	return 0;
}

int erofs_dump_vmdk_desc(FILE *f, struct erofs_sb_info *sbi)
{
	static const char desc_template_1[] =
		"# Disk DescriptorFile\n"
		"version=1\n"
		"CID=%" PRIx32 "\n"
		"parentCID=%" PRIx32 "\n"
		"createType=\"%s\"\n"
		"\n"
		"# Extent description\n";
	static const char desc_template_2[] =
		"\n"
		"# The Disk Data Base\n"
		"#DDB\n"
		"\n"
		"ddb.virtualHWVersion = \"%s\"\n"
		"ddb.geometry.cylinders = \"%" PRIu64 "\"\n"
		"ddb.geometry.heads = \"%" PRIu32 "\"\n"
		"ddb.geometry.sectors = \"63\"\n"
		"ddb.adapterType = \"%s\"\n";
	static const char subformat[] = "twoGbMaxExtentFlat";
	static const char adapter_type[] = "ide";
	u32 cid = ((u32 *)sbi->uuid)[0] ^ ((u32 *)sbi->uuid)[1] ^
		((u32 *)sbi->uuid)[2] ^ ((u32 *)sbi->uuid)[3];
	u32 parent_cid = 0xffffffff;
	u32 number_heads = 16;
	char *hw_version = "4";
	u64 total_sectors, sectors;
	int ret, i;

	fprintf(f, desc_template_1, cid, parent_cid, subformat);
	sectors = sbi->primarydevice_blocks << (sbi->blkszbits - 9);
	ret = erofs_vmdk_desc_add_extent(f, sectors, (char *)sbi->devname, 0);
	if (ret)
		return ret;
	total_sectors = sectors;
	for (i = 0; i < sbi->extra_devices; ++i) {
		const char *name = sbi->devs[i].src_path ?:
				(const char *)sbi->devs[i].tag;

		sectors = (u64)sbi->devs[i].blocks << (sbi->blkszbits - 9);
		ret = erofs_vmdk_desc_add_extent(f, sectors, name, 0);
		if (ret)
			return ret;
		total_sectors += sectors;
	}

	fprintf(f, desc_template_2, hw_version,
		(u64)DIV_ROUND_UP(total_sectors, 63ULL * number_heads),
		number_heads, adapter_type);
	return 0;
}
