# SPDX-License-Identifier: MIT

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = man lib mkfs dump fsck
if ENABLE_FUSE
SUBDIRS += fuse
endif
SUBDIRS += mount contrib

# Testcases are handled in the end
SUBDIRS += tests
