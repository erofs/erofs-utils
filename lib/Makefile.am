# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

noinst_LTLIBRARIES = liberofs.la
liberofs_la_SOURCES = config.c io.c cache.c super.c inode.c xattr.c exclude.c \
		      namei.c data.c compress.c compressor.c zmap.c decompress.c
liberofs_la_CFLAGS = -Wall -Werror -I$(top_srcdir)/include
if ENABLE_LZ4
liberofs_la_CFLAGS += ${LZ4_CFLAGS}
liberofs_la_SOURCES += compressor_lz4.c
if ENABLE_LZ4HC
liberofs_la_SOURCES += compressor_lz4hc.c
endif
endif

