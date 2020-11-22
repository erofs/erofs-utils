# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS = serial-tests
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

EXTRA_DIST = common/rc

clean-local: clean-local-check
.PHONY: clean-local-check
clean-local-check:
	-rm -rf results
