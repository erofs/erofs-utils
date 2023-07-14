/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_TAR_H
#define __EROFS_TAR_H

#include <sys/stat.h>

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

	int fd;
	u64 offset;
	bool index_mode, aufs;
};

int tarerofs_init_empty_dir(struct erofs_inode *inode);
int tarerofs_parse_tar(struct erofs_inode *root, struct erofs_tarfile *tar);
int tarerofs_reserve_devtable(unsigned int devices);
int tarerofs_write_devtable(struct erofs_tarfile *tar);

#endif
