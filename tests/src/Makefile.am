# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS	= foreign
check_PROGRAMS		=
noinst_PROGRAMS		= fssum

noinst_HEADERS = md5.h
fssum_SOURCES = md5.c fssum.c

if ENABLE_LZ4
check_PROGRAMS += badlz4
badlz4_SOURCES = badlz4.c
badlz4_LDADD = ${liblz4_LIBS}
endif

noinst_HEADERS += internal.h cachefiles.h
check_PROGRAMS += cachefilesd2
cachefilesd2_SOURCES = libcachefilesd.c cachefilesd2.c

check_PROGRAMS += fscache004
fscache004_SOURCES = libcachefilesd.c fscache004.c
