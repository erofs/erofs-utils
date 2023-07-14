/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
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

#ifndef ENOATTR
#define ENOATTR	ENODATA
#endif

static inline unsigned int inlinexattr_header_size(struct erofs_inode *vi)
{
	return sizeof(struct erofs_xattr_ibody_header) +
		sizeof(u32) * vi->xattr_shared_count;
}

static inline erofs_blk_t xattrblock_addr(unsigned int xattr_id)
{
	return sbi.xattr_blkaddr +
		((xattr_id * sizeof(__u32)) >> sbi.blkszbits);
}

static inline unsigned int xattrblock_offset(unsigned int xattr_id)
{
	return (xattr_id * sizeof(__u32)) & (erofs_blksiz() - 1);
}

#define EROFS_INODE_XATTR_ICOUNT(_size)	({\
	u32 __size = le16_to_cpu(_size); \
	((__size) == 0) ? 0 : \
	(_size - sizeof(struct erofs_xattr_ibody_header)) / \
	sizeof(struct erofs_xattr_entry) + 1; })

#ifndef XATTR_SYSTEM_PREFIX
#define XATTR_SYSTEM_PREFIX	"system."
#endif
#ifndef XATTR_SYSTEM_PREFIX_LEN
#define XATTR_SYSTEM_PREFIX_LEN (sizeof(XATTR_SYSTEM_PREFIX) - 1)
#endif
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

int erofs_scan_file_xattrs(struct erofs_inode *inode);
int erofs_prepare_xattr_ibody(struct erofs_inode *inode);
char *erofs_export_xattr_ibody(struct list_head *ixattrs, unsigned int size);
int erofs_build_shared_xattrs_from_path(const char *path);

int erofs_xattr_insert_name_prefix(const char *prefix);
void erofs_xattr_cleanup_name_prefixes(void);
int erofs_xattr_write_name_prefixes(FILE *f);

int erofs_setxattr(struct erofs_inode *inode, char *key,
		   const void *value, size_t size);

#ifdef __cplusplus
}
#endif

#endif
