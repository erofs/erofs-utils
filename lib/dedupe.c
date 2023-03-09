// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2022 Alibaba Cloud
 */
#include "erofs/dedupe.h"
#include "erofs/print.h"
#include "rb_tree.h"
#include "rolling_hash.h"
#include "sha256.h"

unsigned long erofs_memcmp2(const u8 *s1, const u8 *s2,
			    unsigned long sz)
{
	unsigned long n = sz;

	if (sz >= sizeof(long) && ((long)s1 & (sizeof(long) - 1)) ==
			((long)s2 & (sizeof(long) - 1))) {
		const unsigned long *a1, *a2;

		while ((long)s1 & (sizeof(long) - 1)) {
			if (*s1 != *s2)
				break;
			++s1;
			++s2;
			--sz;
		}

		a1 = (const unsigned long *)s1;
		a2 = (const unsigned long *)s2;
		while (sz >= sizeof(long)) {
			if (*a1 != *a2)
				break;
			++a1;
			++a2;
			sz -= sizeof(long);
		}
		s1 = (const u8 *)a1;
		s2 = (const u8 *)a2;
	}
	while (sz) {
		if (*s1 != *s2)
			break;
		++s1;
		++s2;
		--sz;
	}
	return n - sz;
}

static unsigned int window_size, rollinghash_rm;
static struct rb_tree *dedupe_tree, *dedupe_subtree;

struct z_erofs_dedupe_item {
	long long	hash;
	u8		prefix_sha256[32];

	erofs_blk_t	compressed_blkaddr;
	unsigned int	compressed_blks;

	int		original_length;
	bool		partial, raw;
	u8		extra_data[];
};

static int z_erofs_dedupe_rbtree_cmp(struct rb_tree *self,
		struct rb_node *node_a, struct rb_node *node_b)
{
	struct z_erofs_dedupe_item *e_a = node_a->value;
	struct z_erofs_dedupe_item *e_b = node_b->value;

	return (e_a->hash > e_b->hash) - (e_a->hash < e_b->hash);
}

int z_erofs_dedupe_match(struct z_erofs_dedupe_ctx *ctx)
{
	struct z_erofs_dedupe_item e_find;
	u8 *cur;
	bool initial = true;

	if (!dedupe_tree)
		return -ENOENT;

	if (ctx->cur > ctx->end - window_size)
		cur = ctx->end - window_size;
	else
		cur = ctx->cur;

	/* move backward byte-by-byte */
	for (; cur >= ctx->start; --cur) {
		struct z_erofs_dedupe_item *e;
		unsigned int extra;
		u8 sha256[32];

		if (initial) {
			/* initial try */
			e_find.hash = erofs_rolling_hash_init(cur, window_size, true);
			initial = false;
		} else {
			e_find.hash = erofs_rolling_hash_advance(e_find.hash,
				rollinghash_rm, cur[window_size], cur[0]);
		}

		e = rb_tree_find(dedupe_tree, &e_find);
		if (!e) {
			e = rb_tree_find(dedupe_subtree, &e_find);
			if (!e)
				continue;
		}

		erofs_sha256(cur, window_size, sha256);
		if (memcmp(sha256, e->prefix_sha256, sizeof(sha256)))
			continue;

		extra = min_t(unsigned int, ctx->end - cur - window_size,
			      e->original_length - window_size);
		extra = erofs_memcmp2(cur + window_size, e->extra_data, extra);
		if (window_size + extra <= ctx->cur - cur)
			continue;
		ctx->cur = cur;
		ctx->e.length = window_size + extra;
		ctx->e.partial = e->partial ||
			(window_size + extra < e->original_length);
		ctx->e.raw = e->raw;
		ctx->e.blkaddr = e->compressed_blkaddr;
		ctx->e.compressedblks = e->compressed_blks;
		return 0;
	}
	return -ENOENT;
}

int z_erofs_dedupe_insert(struct z_erofs_inmem_extent *e,
			  void *original_data)
{
	struct z_erofs_dedupe_item *di;

	if (!dedupe_subtree || e->length < window_size)
		return 0;

	di = malloc(sizeof(*di) + e->length - window_size);
	if (!di)
		return -ENOMEM;

	di->original_length = e->length;
	erofs_sha256(original_data, window_size, di->prefix_sha256);
	di->hash = erofs_rolling_hash_init(original_data,
			window_size, true);
	memcpy(di->extra_data, original_data + window_size,
	       e->length - window_size);
	di->compressed_blkaddr = e->blkaddr;
	di->compressed_blks = e->compressedblks;
	di->partial = e->partial;
	di->raw = e->raw;

	/* with the same rolling hash */
	if (!rb_tree_insert(dedupe_subtree, di))
		free(di);
	return 0;
}

static void z_erofs_dedupe_node_free_cb(struct rb_tree *self,
					struct rb_node *node)
{
	free(node->value);
	rb_tree_node_dealloc_cb(self, node);
}

void z_erofs_dedupe_commit(bool drop)
{
	if (!dedupe_subtree)
		return;
	if (!drop) {
		struct rb_iter iter;
		struct z_erofs_dedupe_item *di;

		di = rb_iter_first(&iter, dedupe_subtree);
		while (di) {
			if (!rb_tree_insert(dedupe_tree, di))
				DBG_BUGON(1);
			di = rb_iter_next(&iter);
		}
		/*rb_iter_dealloc(iter);*/
		rb_tree_dealloc(dedupe_subtree, rb_tree_node_dealloc_cb);
	} else {
		rb_tree_dealloc(dedupe_subtree, z_erofs_dedupe_node_free_cb);
	}
	dedupe_subtree = rb_tree_create(z_erofs_dedupe_rbtree_cmp);
}

int z_erofs_dedupe_init(unsigned int wsiz)
{
	dedupe_tree = rb_tree_create(z_erofs_dedupe_rbtree_cmp);
	if (!dedupe_tree)
		return -ENOMEM;

	dedupe_subtree = rb_tree_create(z_erofs_dedupe_rbtree_cmp);
	if (!dedupe_subtree) {
		rb_tree_dealloc(dedupe_subtree, NULL);
		return -ENOMEM;
	}
	window_size = wsiz;
	rollinghash_rm = erofs_rollinghash_calc_rm(window_size);
	return 0;
}

void z_erofs_dedupe_exit(void)
{
	z_erofs_dedupe_commit(true);
	rb_tree_dealloc(dedupe_subtree, NULL);
	rb_tree_dealloc(dedupe_tree, z_erofs_dedupe_node_free_cb);
}
