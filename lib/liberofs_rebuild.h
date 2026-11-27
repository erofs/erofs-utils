/* SPDX-License-Identifier: GPL-2.0+ OR MIT */
#ifndef __EROFS_LIB_LIBEROFS_REBUILD_H
#define __EROFS_LIB_LIBEROFS_REBUILD_H

#include "erofs/internal.h"

enum erofs_rebuild_datamode {
	EROFS_REBUILD_DATA_BLOB_INDEX,
	EROFS_REBUILD_DATA_RESVSP,
	EROFS_REBUILD_DATA_FULL,
};

struct erofs_rebuild_params {
	struct erofs_inode *mergeroot;
	struct erofs_sb_info *sbi;
	enum erofs_rebuild_datamode datamode;
	bool force_omit_fsmeta;	/* reject data references to the primary device */
};

struct erofs_dentry *erofs_rebuild_get_dentry(struct erofs_inode *pwd,
		char *path, bool aufs, bool *whout, bool *opq, bool to_head);

int erofs_rebuild_load_tree(struct erofs_rebuild_params *params);

int erofs_rebuild_load_basedir(struct erofs_inode *dir, u64 *nr_subdirs,
			       unsigned int *i_nlink);
#endif
