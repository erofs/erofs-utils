/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_REBUILD_H
#define __EROFS_REBUILD_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "internal.h"

struct erofs_dentry *erofs_rebuild_get_dentry(struct erofs_inode *pwd,
		char *path, bool aufs, bool *whout, bool *opq);

#ifdef __cplusplus
}
#endif

#endif
