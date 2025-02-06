#!/bin/sh
[ "x$CC" = 'x' ] && CC=gcc
cd $(dirname $0)
if [ -f ../config.h ]; then
	$CC -o stress -DHAVE_CONFIG_H -I.. -I../include stress.c
else
	$CC -o stress -DHAVE_LINUX_TYPES_H -I../include stress.c
fi
