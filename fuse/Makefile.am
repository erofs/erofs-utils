# SPDX-License-Identifier: GPL-2.0+

AUTOMAKE_OPTIONS = foreign
noinst_HEADERS = $(top_srcdir)/fuse/macosx.h
bin_PROGRAMS     = erofsfuse
erofsfuse_SOURCES = main.c
erofsfuse_CFLAGS = -Wall -I$(top_srcdir)/include
erofsfuse_CFLAGS += ${libfuse2_CFLAGS} ${libfuse3_CFLAGS} ${libselinux_CFLAGS}
erofsfuse_LDADD = $(top_builddir)/lib/liberofs.la ${libfuse2_LIBS} ${libfuse3_LIBS} ${liblz4_LIBS} \
	${libselinux_LIBS} ${liblzma_LIBS} ${zlib_LIBS} ${libdeflate_LIBS} ${libzstd_LIBS} \
	${libqpl_LIBS}
