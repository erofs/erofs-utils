# SPDX-License-Identifier: MIT
# Makefile.am

AUTOMAKE_OPTIONS	= foreign

if OS_LINUX
noinst_PROGRAMS		= stress

stress_CFLAGS = -Wall -I$(top_srcdir)/include
stress_SOURCES = stress.c
endif
