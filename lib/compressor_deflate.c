// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2023, Alibaba Cloud
 * Copyright (C) 2023, Gao Xiang <xiang@kernel.org>
 */
#include "erofs/internal.h"
#include "erofs/print.h"
#include "erofs/config.h"
#include "compressor.h"

void *kite_deflate_init(int level, unsigned int dict_size);
void kite_deflate_end(void *s);
int kite_deflate_destsize(void *s, const u8 *in, u8 *out,
			  unsigned int *srcsize, unsigned int target_dstsize);

static int deflate_compress_destsize(const struct erofs_compress *c,
				     const void *src, unsigned int *srcsize,
				     void *dst, unsigned int dstsize)
{
	int rc = kite_deflate_destsize(c->private_data, src, dst,
				       srcsize, dstsize);

	if (rc <= 0)
		return -EFAULT;
	return rc;
}

static int compressor_deflate_exit(struct erofs_compress *c)
{
	if (!c->private_data)
		return -EINVAL;

	kite_deflate_end(c->private_data);
	return 0;
}

static int compressor_deflate_init(struct erofs_compress *c)
{
	c->private_data = NULL;

	erofs_warn("EXPERIMENTAL DEFLATE algorithm in use. Use at your own risk!");
	erofs_warn("*Carefully* check filesystem data correctness to avoid corruption!");
	erofs_warn("Please send a report to <linux-erofs@lists.ozlabs.org> if something is wrong.");
	return 0;
}

static int erofs_compressor_deflate_setlevel(struct erofs_compress *c,
					     int compression_level)
{
	void *s;

	if (c->private_data) {
		kite_deflate_end(c->private_data);
		c->private_data = NULL;
	}

	if (compression_level < 0)
		compression_level = erofs_compressor_deflate.default_level;

	s = kite_deflate_init(compression_level, cfg.c_dict_size);
	if (IS_ERR(s))
		return PTR_ERR(s);

	c->private_data = s;
	c->compression_level = compression_level;
	return 0;
}

const struct erofs_compressor erofs_compressor_deflate = {
	.default_level = 1,
	.best_level = 9,
	.init = compressor_deflate_init,
	.exit = compressor_deflate_exit,
	.setlevel = erofs_compressor_deflate_setlevel,
	.compress_destsize = deflate_compress_destsize,
};
