// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/tests/src/badlz4.c
 *
 * Copyright (C) 2020 Gao Xiang <xiang@kernel.org>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lz4.h>
#include "config.h"

/* check if the target lz4 version is broken */
int test_LZ4_decompress_safe_partial(void)
{
	const unsigned int BUFFER_SIZE = 2048;
	static const char source[] =
	  "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod\n"
	  "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim\n"
	  "veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea\n"
	  "commodo consequat. Duis aute irure dolor in reprehenderit in voluptate\n"
	  "velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat\n"
	  "cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id\n"
	  "est laborum.\n"
	  "\n"
	  "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium\n"
	  "doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore\n"
	  "veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim\n"
	  "ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia\n"
	  "consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque\n"
	  "porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur,\n"
	  "adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore\n"
	  "et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis\n"
	  "nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid\n"
	  "ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea\n"
	  "voluptate velit esse quam nihil molestiae consequatur, vel illum qui\n"
	  "dolorem eum fugiat quo voluptas nulla pariatur?\n";
	const unsigned int srcLen = sizeof(source) - 1;
	char cmpBuffer[BUFFER_SIZE], outBuffer[BUFFER_SIZE];
	int cmpSize, i;

	cmpSize = LZ4_compress_default(source, cmpBuffer, srcLen, BUFFER_SIZE);
	for (i = cmpSize; i < cmpSize + 10; ++i) {
		int res = LZ4_decompress_safe_partial(cmpBuffer, outBuffer, i,
						      srcLen, BUFFER_SIZE);
		if ((res < 0) || (res != srcLen) || memcmp(source, outBuffer, srcLen)) {
			printf("test decompress-partial error\n");
			return 1;
		}
	}
	printf("test decompress-partial OK\n");
	return 0;
}

int test_LZ4_compress_HC_destSize(int inlen)
{
#if LZ4HC_ENABLED
#define LZ4_HC_STATIC_LINKING_ONLY (1)
#include <lz4hc.h>
	char buf[1642496];
	int SrcSize = inlen;
	char dst[4116];
	int compressed;

	void *ctx = LZ4_createStreamHC();

	memset(buf, 0, inlen);
	compressed = LZ4_compress_HC_destSize(ctx, buf, dst, &SrcSize,
					      sizeof(dst), 1);
	LZ4_freeStreamHC(ctx);
	if (SrcSize <= sizeof(dst)) {
		printf("test LZ4_compress_HC_destSize(%d) error (%d < %d)\n",
		       inlen, SrcSize, (int)sizeof(dst));
		return 1;
	}
	printf("test LZ4_compress_HC_destSize(%d) OK\n", inlen);
#endif
	return 0;
}

int main(void)
{
	int error = test_LZ4_compress_HC_destSize(1024 * 1024) |
		test_LZ4_decompress_safe_partial();

	if (error)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

