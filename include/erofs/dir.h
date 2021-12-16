/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_DIR_H
#define __EROFS_DIR_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "internal.h"

#define EROFS_READDIR_VALID_PNID	0x0001
#define EROFS_READDIR_DOTDOT_FOUND	0x0002
#define EROFS_READDIR_DOT_FOUND		0x0004

#define EROFS_READDIR_ALL_SPECIAL_FOUND	\
	(EROFS_READDIR_DOTDOT_FOUND | EROFS_READDIR_DOT_FOUND)

struct erofs_dir_context;

/* callback function for iterating over inodes of EROFS */
typedef int (*erofs_readdir_cb)(struct erofs_dir_context *);

/*
 * Callers could use a wrapper to contain extra information.
 *
 * Note that callback can reuse `struct erofs_dir_context' with care
 * to avoid stack overflow due to deep recursion:
 *  - if fsck is true, |pnid|, |flags|, (optional)|cb| SHOULD be saved
 *    to ensure the original state;
 *  - if fsck is false, EROFS_READDIR_VALID_PNID SHOULD NOT be
 *    set if |pnid| is inaccurate.
 *
 * Another way is to allocate a `struct erofs_dir_context' wraper
 * with `struct inode' on heap, and chain them together for
 * multi-level traversal to completely avoid recursion.
 *
 * |dname| may be WITHOUT the trailing '\0' and it's ONLY valid in
 * the callback context. |de_namelen| is the exact dirent name length.
 */
struct erofs_dir_context {
	struct erofs_inode *dir;
	erofs_readdir_cb cb;
	erofs_nid_t pnid;		/* optional */

	/* [OUT] the dirent which is under processing */
	const char *dname;		/* please see the comment above */
	erofs_nid_t de_nid;
	u8 de_namelen, de_ftype, flags;
	bool dot_dotdot;
};

/* Iterate over inodes that are in directory */
int erofs_iterate_dir(struct erofs_dir_context *ctx, bool fsck);

#ifdef __cplusplus
}
#endif

#endif
