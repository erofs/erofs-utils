# SPDX-License-Identifier: GPL-2.0+

AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS     = mkfs.erofs
AM_CPPFLAGS = ${libuuid_CFLAGS} ${libselinux_CFLAGS}
mkfs_erofs_SOURCES = main.c
mkfs_erofs_CFLAGS = -Wall -Werror -I$(top_srcdir)/include
mkfs_erofs_LDADD = ${libuuid_LIBS} $(top_builddir)/lib/liberofs.la ${libselinux_LIBS} \
	${liblz4_LIBS} ${liblzma_LIBS}
