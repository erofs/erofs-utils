# SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0

noinst_LTLIBRARIES = liberofs.la
noinst_HEADERS = $(top_srcdir)/include/erofs_fs.h \
      $(top_srcdir)/include/erofs/blobchunk.h \
      $(top_srcdir)/include/erofs/block_list.h \
      $(top_srcdir)/include/erofs/cache.h \
      $(top_srcdir)/include/erofs/compress.h \
      $(top_srcdir)/include/erofs/config.h \
      $(top_srcdir)/include/erofs/decompress.h \
      $(top_srcdir)/include/erofs/defs.h \
      $(top_srcdir)/include/erofs/err.h \
      $(top_srcdir)/include/erofs/exclude.h \
      $(top_srcdir)/include/erofs/flex-array.h \
      $(top_srcdir)/include/erofs/hashmap.h \
      $(top_srcdir)/include/erofs/hashtable.h \
      $(top_srcdir)/include/erofs/inode.h \
      $(top_srcdir)/include/erofs/internal.h \
      $(top_srcdir)/include/erofs/io.h \
      $(top_srcdir)/include/erofs/list.h \
      $(top_srcdir)/include/erofs/print.h \
      $(top_srcdir)/include/erofs/trace.h \
      $(top_srcdir)/include/erofs/xattr.h \
      $(top_srcdir)/include/erofs/compress_hints.h \
      $(top_srcdir)/lib/liberofs_private.h

noinst_HEADERS += compressor.h
liberofs_la_SOURCES = config.c io.c cache.c super.c inode.c xattr.c exclude.c \
		      namei.c data.c compress.c compressor.c zmap.c decompress.c \
		      compress_hints.c hashmap.c sha256.c blobchunk.c dir.c
liberofs_la_CFLAGS = -Wall -I$(top_srcdir)/include
if ENABLE_LZ4
liberofs_la_CFLAGS += ${LZ4_CFLAGS}
liberofs_la_SOURCES += compressor_lz4.c
if ENABLE_LZ4HC
liberofs_la_SOURCES += compressor_lz4hc.c
endif
endif
if ENABLE_LIBLZMA
liberofs_la_CFLAGS += ${liblzma_CFLAGS}
liberofs_la_SOURCES += compressor_liblzma.c
endif
