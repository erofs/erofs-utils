/* SPDX-License-Identifier: GPL-2.0+ OR MIT */
#ifndef __EROFS_LIB_LIBEROFS_FILE_DELTA_H
#define __EROFS_LIB_LIBEROFS_FILE_DELTA_H

#include "erofs/internal.h"

/* A logical replacement; gaps between extents inherit the parent contents. */
struct erofs_delta_map {
	erofs_off_t offset, length;
	/* Borrowed raw container, never a guest-addressed view. NULL for ZERO. */
	struct erofs_vfile *vf;
	erofs_off_t sourceoffset;
};

struct erofs_file_delta;

struct erofs_file_delta_ops {
	/*
	 * Maximum power-of-two boundary alignment in bytes; 0 means no updates.
	 * EOF need not be aligned. BIT_ULL(63) means no boundary constraint.
	 */
	erofs_off_t (*get_alignment)(struct erofs_file_delta *fdl);
	/*
	 * Find a replacement at or after map->offset; length 0 means none.
	 * Mappings remain stable until close; callers may scan them again.
	 */
	int (*map)(struct erofs_file_delta *fdl, struct erofs_delta_map *map);
	void (*close)(struct erofs_file_delta *fdl);
	const char *name;		/* delta format name */
};

struct erofs_file_delta {
	const struct erofs_file_delta_ops *ops;
	u8 private[0];
};

/* The caller retains ownership of vf. Return ERR_PTR() on failure. */
struct erofs_file_delta *erofs_dm_persistent_open(struct erofs_vfile *vf);

#endif
