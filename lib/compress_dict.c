// SPDX-License-Identifier: GPL-2.0+
#include <stdlib.h>
#define ZDICT_STATIC_LINKING_ONLY
#include <zdict.h>
#include "erofs/dict.h"
#include "erofs/io.h"
#include "erofs/print.h"
#include "erofs/cache.h"

unsigned int erofsdict_generate(struct erofs_inode *inode,
		struct erofsdict_item **dictp, int dictcapacity,
		int fd, unsigned int segblks,
		struct erofs_buffer_head **bhp)
{
	u64 segmentsize = blknr_to_addr(segblks);
	unsigned int segs = DIV_ROUND_UP(inode->i_size, segmentsize);
	u8 *samplebuffer;
	struct erofsdict_item *dict;
	struct erofs_buffer_head *bh;
	size_t insize;
	unsigned int i;

	samplebuffer = (u8 *)malloc(segmentsize);
	if (!samplebuffer)
		return 0;

	dict = calloc(segs, sizeof(struct erofsdict_item));
	if (!dict) {
		free(samplebuffer);
		return 0;
	}

	/* allocate dictionary buffer */
	bh = erofs_balloc(DATA, 0, 0, 0);
	if (IS_ERR(bh)) {
		free(dict);
		free(samplebuffer);
		return 0;
	}

	erofs_mapbh(bh->block);
	bh->op = &erofs_skip_write_bhops;

	erofs_dbg("Generating dictionary segments for %s", inode->i_srcpath);

	for(i = 0; (insize = read(fd, samplebuffer, segmentsize)) > 0; ++i) {
		erofs_blk_t blkaddr;
		int ret;
		size_t samplesizes[1024], dictsize;
		unsigned int nsamples;

		if (i >= segs)
			break;

		dict[i].blkaddr = 0;	/* no dictionary */
		DBG_BUGON(dict[i].buffer);
		dict[i].buffer = malloc(dictcapacity);
		if (!dict[i].buffer)
			continue;

		for (nsamples = 0; nsamples < 32; ++nsamples)
			samplesizes[nsamples] = insize / 32;

		dictsize = ZDICT_trainFromBuffer(dict[i].buffer,
				dictcapacity, samplebuffer,
				samplesizes, nsamples);

		if (ZDICT_isError(dictsize)) {
			free(dict[i].buffer);
			dict[i].buffer = NULL;
			continue;
		}
		dict[i].dictsize = roundup(dictsize, EROFS_BLKSIZ);

		blkaddr = erofs_blknr(erofs_btell(bh, true));
		ret = dev_write(dict[i].buffer, blknr_to_addr(blkaddr),
				dict[i].dictsize);
		if (ret)
			continue;


		ret = erofs_bh_balloon(bh, dict[i].dictsize);
		DBG_BUGON(ret != EROFS_BLKSIZ);

		dict->blkaddr = blkaddr;
		erofs_dbg("Generated %lu bytes for dictionary segment %u @ blkaddr %u",
			  dictsize | 0UL, i, blkaddr);
	}
	lseek(fd, 0, SEEK_SET);
	free(samplebuffer);
	*dictp = dict;
	*bhp = bh;
	return i;
}

void erofsdict_free(struct erofsdict_item *dict, unsigned int segs)
{
	unsigned int i;

	for (i = 0; i < segs; ++i) {
		if (dict[i].buffer) {
			DBG_BUGON(!dict[i].dictsize);
			free(dict[i].buffer);
		}
	}
	free(dict);
}
