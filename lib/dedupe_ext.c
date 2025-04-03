// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include "erofs/dedupe.h"
#include "liberofs_xxhash.h"
#include <stdlib.h>

struct z_erofs_dedupe_ext_item {
	struct list_head list;
	struct z_erofs_dedupe_ext_item *revoke;
	struct z_erofs_inmem_extent e;
	u64		xxh64;
};

static struct list_head dupl_ext[65536];
static struct z_erofs_dedupe_ext_item *revoke_list;

int z_erofs_dedupe_ext_insert(struct z_erofs_inmem_extent *e,
			      u64 hash)
{
	struct z_erofs_dedupe_ext_item *item;
	struct list_head *p;

	item = malloc(sizeof(struct z_erofs_dedupe_ext_item));
	if (!item)
		return -ENOMEM;
	item->e = *e;
	item->xxh64 = hash;

	p = &dupl_ext[hash & (ARRAY_SIZE(dupl_ext) - 1)];
	list_add_tail(&item->list, p);
	item->revoke = revoke_list;
	revoke_list = item;
	return 0;
}

erofs_blk_t z_erofs_dedupe_ext_match(struct erofs_sb_info *sbi,
				     u8 *encoded, unsigned int len,
				     bool raw, u64 *hash)
{
	struct z_erofs_dedupe_ext_item *item;
	struct list_head *p;
	u64 _xxh64;
	char *memb;
	int ret;

	*hash = _xxh64 = xxh64(encoded, len, 0);
	p = &dupl_ext[_xxh64 & (ARRAY_SIZE(dupl_ext) - 1)];
	list_for_each_entry(item, p, list) {
		if (item->xxh64 == _xxh64 && item->e.plen == len &&
		    item->e.raw == raw) {
			memb = malloc(len);
			if (!memb)
				break;
			ret = erofs_dev_read(sbi, 0, memb, item->e.pstart, len);
			if (ret < 0 || memcmp(memb, encoded, len)) {
				free(memb);
				break;
			}
			free(memb);
			return item->e.pstart;
		}
	}
	return EROFS_NULL_ADDR;
}

void z_erofs_dedupe_ext_commit(bool drop)
{
	if (drop) {
		struct z_erofs_dedupe_ext_item *item, *n;

		for (item = revoke_list; item; item = n) {
			n = item->revoke;
			list_del(&item->list);
			free(item);
		}
	}
	revoke_list = NULL;
}

int z_erofs_dedupe_ext_init(void)
{
	struct list_head *p;

	for (p = dupl_ext; p < dupl_ext + ARRAY_SIZE(dupl_ext); ++p)
		init_list_head(p);
	return 0;
}

void z_erofs_dedupe_ext_exit(void)
{
	struct z_erofs_dedupe_ext_item *item, *n;
	struct list_head *p;

	if (!dupl_ext[0].next)
		return;
	z_erofs_dedupe_commit(true);
	for (p = dupl_ext; p < dupl_ext + ARRAY_SIZE(dupl_ext); ++p) {
		list_for_each_entry_safe(item, n, p, list) {
			list_del(&item->list);
			free(item);
		}
	}
}
