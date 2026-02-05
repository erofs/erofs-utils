# SPDX-License-Identifier: GPL-2.0+

dist_man_MANS = mkfs.erofs.1 dump.erofs.1 fsck.erofs.1

EXTRA_DIST = erofsfuse.1 mount.erofs.8
if ENABLE_FUSE
man_MANS = erofsfuse.1
endif

if OS_LINUX
man_MANS = mount.erofs.8
endif
