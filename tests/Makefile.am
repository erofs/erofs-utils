# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS = serial-tests
SUBDIRS = src

TESTS =

TESTS_ENVIRONMENT = \
	if [ -z $$SCRATCH_MNT ]; then \
		export SCRATCH_MNT=/tmp/erofstest/scratch;	\
		mkdir -p $$SCRATCH_MNT 2>/dev/null; \
	fi; \
	if [ -z $$TEST_MNT ]; then \
		export TEST_MNT=/tmp/erofstest/test;	\
		mkdir -p $$TEST_MNT 2>/dev/null; \
	fi; \
	if [ -z $$RESULT_DIR ]; then \
		export RESULT_DIR=`pwd`/results;	\
		mkdir -p $$RESULT_DIR/erofs 2>/dev/null; \
		mkdir -p $$RESULT_DIR/fscache 2>/dev/null; \
	fi; \
	[ -z $$MKFS_EROFS_PROG ] && export MKFS_EROFS_PROG=../mkfs/mkfs.erofs; \
	[ -z $$FSCK_EROFS_PROG ] && export FSCK_EROFS_PROG=../fsck/fsck.erofs; \
	[ -z $$EROFSFUSE_PROG ] && export EROFSFUSE_PROG=../fuse/erofsfuse;

if ENABLE_LZ4
TESTS_ENVIRONMENT += export lz4_on=1;
endif
if ENABLE_LZ4HC
TESTS_ENVIRONMENT += export lz4hc_on=1;
endif

# 001 - test if unknown algorithm is specificed
TESTS += erofs/001

# 002 - mkfs & test short symlink (fast symlink)
TESTS += erofs/002

# 003 - mkfs & test long symlink (non-fast symlink)
TESTS += erofs/003

# 004 - mkfs & test character/block device
TESTS += erofs/004

# 005 - mkfs & test pipe
TESTS += erofs/005

# 006 - verify the uncompressed image
TESTS += erofs/006

# 008 - verify lz4 compressed image
TESTS += erofs/008

# 009 - verify lz4hc compressed image
TESTS += erofs/009

# 010 - (legacy image) verify lz4 compressed image
TESTS += erofs/010

# 011 - (legacy image) verify lz4hc compressed image
TESTS += erofs/011


EXTRA_DIST = common/rc erofs

clean-local: clean-local-check
.PHONY: clean-local-check
clean-local-check:
	-rm -rf results
