# SPDX-License-Identifier: GPL-2.0+

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = man lib mkfs dump fsck

if ENABLE_FUSE
if ENABLE_RUST
SUBDIRS += rust/fuse
else
SUBDIRS += fuse
endif
endif
