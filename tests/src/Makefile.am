# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS	= foreign
noinst_PROGRAMS		= fssum

fssum_CFLAGS = -Wall -I$(top_srcdir)/include
fssum_LDADD = $(top_builddir)/lib/liberofs.la
fssum_SOURCES = fssum.c

