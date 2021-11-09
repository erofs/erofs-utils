# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS     = fsck.erofs
AM_CPPFLAGS = ${libuuid_CFLAGS}
fsck_erofs_SOURCES = main.c
fsck_erofs_CFLAGS = -Wall -Werror -I$(top_srcdir)/include
fsck_erofs_LDADD = $(top_builddir)/lib/liberofs.la ${libselinux_LIBS} \
	${libuuid_LIBS} ${liblz4_LIBS} ${liblzma_LIBS}
