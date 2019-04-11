# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS     = mkfs.erofs
mkfs_erofs_SOURCES = main.c
mkfs_erofs_CFLAGS = -Wall -Werror -I$(top_srcdir)/include
mkfs_erofs_LDADD = $(top_builddir)/lib/liberofs.la

