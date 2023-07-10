// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include "erofs/internal.h"
#include "erofs/print.h"
#include "erofs/config.h"
#include <libdeflate.h>
#include "compressor.h"

static int libdeflate_compress_destsize(const struct erofs_compress *c,
				        const void *src, unsigned int *srcsize,
				        void *dst, unsigned int dstsize)
{
	static size_t last_uncompressed_size = 0;
	size_t l = 0; /* largest input that fits so far */
	size_t l_csize = 0;
	size_t r = *srcsize + 1; /* smallest input that doesn't fit so far */
	size_t m;
	u8 tmpbuf[dstsize + 9];

	if (last_uncompressed_size)
		m = last_uncompressed_size * 15 / 16;
	else
		m = dstsize * 4;
	for (;;) {
		size_t csize;

		m = max(m, l + 1);
		m = min(m, r - 1);

		csize = libdeflate_deflate_compress(c->private_data, src, m,
						    tmpbuf, dstsize + 9);
		/*printf("Tried %zu => %zu\n", m, csize);*/
		if (csize > 0 && csize <= dstsize) {
			/* Fits */
			memcpy(dst, tmpbuf, csize);
			l = m;
			l_csize = csize;
			if (r <= l + 1 || csize +
				(22 - 2*(int)c->compression_level) >= dstsize)
				break;
			/*
			 * Estimate needed input prefix size based on current
			 * compression ratio.
			 */
			m = (dstsize * m) / csize;
		} else {
			/* Doesn't fit */
			r = m;
			if (r <= l + 1)
				break;
			m = (l + r) / 2;
		}
	}

	/*
	 * Since generic EROFS on-disk compressed data will be filled with
	 * leading 0s (but no more than one block, 4KB for example, even the
	 * whole pcluster is 128KB) if not filled, it will be used to identify
	 * the actual compressed length as well without taking more reserved
	 * compressed bytes or some extra metadata to record this.
	 *
	 * DEFLATE streams can also be used in this way, if it starts from a
	 * non-last stored block, flag an unused bit instead to avoid the zero
	 * byte. It's still a valid one according to the DEFLATE specification.
	 */
	if (l_csize && !((u8 *)dst)[0])
	       ((u8 *)dst)[0] = 1 << (2 + 1);

	/*printf("Choosing %zu => %zu\n", l, l_csize);*/
	*srcsize = l;
	last_uncompressed_size = l;
	return l_csize;
}

static int compressor_libdeflate_exit(struct erofs_compress *c)
{
	if (!c->private_data)
		return -EINVAL;

	libdeflate_free_compressor(c->private_data);
	return 0;
}

static int compressor_libdeflate_init(struct erofs_compress *c)
{
	c->alg = &erofs_compressor_libdeflate;
	c->private_data = NULL;

	erofs_warn("EXPERIMENTAL libdeflate compressor in use. Use at your own risk!");
	return 0;
}

static int erofs_compressor_libdeflate_setlevel(struct erofs_compress *c,
						int compression_level)
{
	if (compression_level < 0)
		compression_level = erofs_compressor_deflate.default_level;

	libdeflate_free_compressor(c->private_data);
	c->private_data = libdeflate_alloc_compressor(compression_level);
	if (!c->private_data)
		return -ENOMEM;
	c->compression_level = compression_level;
	return 0;
}

const struct erofs_compressor erofs_compressor_libdeflate = {
	.name = "libdeflate",
	.default_level = 1,
	.best_level = 12,
	.init = compressor_libdeflate_init,
	.exit = compressor_libdeflate_exit,
	.setlevel = erofs_compressor_libdeflate_setlevel,
	.compress_destsize = libdeflate_compress_destsize,
};
