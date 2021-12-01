/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Originally contributed by an anonymous person,
 * heavily changed by Li Guifu <blucerlee@gmail.com>
 *                and Gao Xiang <xiang@kernel.org>
 */
#ifndef __EROFS_XATTR_H
#define __EROFS_XATTR_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "internal.h"

#define EROFS_INODE_XATTR_ICOUNT(_size)	({\
	u32 __size = le16_to_cpu(_size); \
	((__size) == 0) ? 0 : \
	(_size - sizeof(struct erofs_xattr_ibody_header)) / \
	sizeof(struct erofs_xattr_entry) + 1; })

#ifndef XATTR_USER_PREFIX
#define XATTR_USER_PREFIX	"user."
#endif
#ifndef XATTR_USER_PREFIX_LEN
#define XATTR_USER_PREFIX_LEN (sizeof(XATTR_USER_PREFIX) - 1)
#endif
#ifndef XATTR_SECURITY_PREFIX
#define XATTR_SECURITY_PREFIX	"security."
#endif
#ifndef XATTR_SECURITY_PREFIX_LEN
#define XATTR_SECURITY_PREFIX_LEN (sizeof(XATTR_SECURITY_PREFIX) - 1)
#endif
#ifndef XATTR_TRUSTED_PREFIX
#define XATTR_TRUSTED_PREFIX	"trusted."
#endif
#ifndef XATTR_TRUSTED_PREFIX_LEN
#define XATTR_TRUSTED_PREFIX_LEN (sizeof(XATTR_TRUSTED_PREFIX) - 1)
#endif
#ifndef XATTR_NAME_POSIX_ACL_ACCESS
#define XATTR_NAME_POSIX_ACL_ACCESS "system.posix_acl_access"
#endif
#ifndef XATTR_NAME_POSIX_ACL_DEFAULT
#define XATTR_NAME_POSIX_ACL_DEFAULT "system.posix_acl_default"
#endif

int erofs_prepare_xattr_ibody(struct erofs_inode *inode);
char *erofs_export_xattr_ibody(struct list_head *ixattrs, unsigned int size);
int erofs_build_shared_xattrs_from_path(const char *path);

#ifdef __cplusplus
}
#endif

#endif
