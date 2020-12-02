# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS	= foreign
check_PROGRAMS		=
noinst_PROGRAMS		= fssum

fssum_CFLAGS = -Wall -I$(top_srcdir)/include
fssum_LDADD = $(top_builddir)/lib/liberofs.la
fssum_SOURCES = fssum.c

if ENABLE_LZ4
check_PROGRAMS += badlz4
badlz4_SOURCES = badlz4.c
badlz4_CFLAGS = ${liblz4_CFLAGS}
badlz4_LDADD = ${liblz4_LIBS}
endif
