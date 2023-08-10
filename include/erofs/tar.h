/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_TAR_H
#define __EROFS_TAR_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/stat.h>

#include "internal.h"

struct erofs_pax_header {
	struct stat st;
	bool use_mtime;
	bool use_size;
	bool use_uid;
	bool use_gid;
	char *path, *link;
};

struct erofs_tarfile {
	struct erofs_pax_header global;
	char *mapfile;

	int fd;
	u64 offset;
	bool index_mode, aufs;
};

int tarerofs_parse_tar(struct erofs_inode *root, struct erofs_tarfile *tar);

#ifdef __cplusplus
}
#endif

#endif
