// SPDX-License-Identifier: GPL-2.0+ OR MIT
#include <config.h>
#include <limits.h>
#include "erofs/print.h"
#include "liberofs_file_delta.h"

#define EROFS_DM_SNAP_MAGIC	0x70416e53U
#define EROFS_DM_DISK_VERSION	1U
#define EROFS_DM_SECTOR_SIZE	512U

struct erofs_dm_disk_header {
	__le32 magic;
	__le32 valid;
	__le32 version;
	__le32 chunk_size;
} __packed;

struct erofs_dm_disk_exception {
	__le64 old_chunk;
	__le64 new_chunk;
} __packed;

struct erofs_dm_exception {
	erofs_off_t offset, source_offset;
};

struct erofs_dm_snap_persistent {
	struct erofs_file_delta fdl;
	struct {
		/* Sorted by logical file offset after opening the snapshot. */
		struct erofs_dm_exception *entries;
		size_t count, capacity;
	} exceptions;
	struct erofs_vfile *vf;
	erofs_off_t target_size, chunk_bytes, boundary;
};

static const struct erofs_file_delta_ops erofs_file_delta_dm_persistent_ops;

static int erofs_dm_exception_cmp(const void *a, const void *b)
{
	const struct erofs_dm_exception *ea = a, *eb = b;

	return cmpsgn(ea->offset, eb->offset);
}

static int erofs_dm_add_exception(struct erofs_dm_snap_persistent *dsp,
				 erofs_off_t offset,
				 erofs_off_t source_offset)
{
	struct erofs_dm_exception *p;
	size_t capacity;

	if (dsp->exceptions.count == dsp->exceptions.capacity) {
		capacity = dsp->exceptions.capacity ? dsp->exceptions.capacity * 2 : 64;
		if (capacity < dsp->exceptions.capacity)
			return -E2BIG;
		if (capacity > SIZE_MAX / sizeof(*p))
			return -E2BIG;
		p = realloc(dsp->exceptions.entries, capacity * sizeof(*p));
		if (!p)
			return -ENOMEM;
		dsp->exceptions.entries = p;
		dsp->exceptions.capacity = capacity;
	}
	dsp->exceptions.entries[dsp->exceptions.count++] = (struct erofs_dm_exception) {
		.offset = offset,
		.source_offset = source_offset,
	};
	dsp->boundary |= offset | (offset + dsp->chunk_bytes);
	return 0;
}

static int erofs_dm_parse_exceptions(struct erofs_dm_snap_persistent *dsp)
{
	erofs_off_t chunk_bytes = dsp->chunk_bytes;
	/* Read metadata in bounded batches, independently of the dm chunk size. */
	struct erofs_dm_disk_exception buf[256];
	u64 per_area = chunk_bytes / sizeof(buf[0]), stride = per_area + 1;
	erofs_off_t metadata_chunk = 1, metadata_offset, offset, source_offset;
	u64 i, j, nr;
	size_t n;
	int ret;

	for (;;) {
		/* Chunk 0 is the header; metadata areas start at 1 + n * stride. */
		if (metadata_chunk > UINT64_MAX / chunk_bytes) {
			ret = -EFSCORRUPTED;
			goto out;
		}
		metadata_offset = metadata_chunk * chunk_bytes;
		for (i = 0; i < per_area; i += nr) {
			nr = min_t(u64, per_area - i, ARRAY_SIZE(buf));
			ret = erofs_pread(dsp->vf, buf, nr * sizeof(buf[0]),
					  metadata_offset + i * sizeof(buf[0]));
			if (ret)
				goto out;
			for (j = 0; j < nr; ++j) {
				u64 old_chunk, new_chunk;

				old_chunk = le64_to_cpu(buf[j].old_chunk);
				new_chunk = le64_to_cpu(buf[j].new_chunk);

				/* The first zero new_chunk terminates the exception table. */
				if (!new_chunk)
					goto terminated;
				if (new_chunk % stride == 1) {
					ret = -EFSCORRUPTED;
					goto out;
				}
				if (old_chunk >= UINT64_MAX / chunk_bytes) {
					ret = -EFSCORRUPTED;
					goto out;
				}
				offset = old_chunk * chunk_bytes;
				dsp->target_size = max(dsp->target_size, offset + chunk_bytes);
				if (new_chunk > UINT64_MAX / chunk_bytes) {
					ret = -EFSCORRUPTED;
					goto out;
				}
				source_offset = new_chunk * chunk_bytes;
				ret = erofs_dm_add_exception(dsp, offset,
							     source_offset);
				if (ret)
					goto out;
			}
		}
		if (check_add_overflow(metadata_chunk, stride, &metadata_chunk)) {
			ret = -EFSCORRUPTED;
			goto out;
		}
	}
terminated:
	/* Exceptions are stored in commit order, not logical file order. */
	if (dsp->exceptions.count > 1)
		qsort(dsp->exceptions.entries, dsp->exceptions.count,
		      sizeof(*dsp->exceptions.entries), erofs_dm_exception_cmp);
	/*
	 * The kernel reuses existing exceptions on repeated writes, but its
	 * loader does not reject duplicate origin chunks.  Reject them here
	 * rather than choosing an ambiguous mapping.
	 */
	for (n = 1; n < dsp->exceptions.count; ++n) {
		if (dsp->exceptions.entries[n - 1].offset == dsp->exceptions.entries[n].offset)
			return -EINVAL;
	}
	ret = 0;
out:
	return ret;
}

static erofs_off_t erofs_dm_persistent_get_alignment(struct erofs_file_delta *fdl)
{
	struct erofs_dm_snap_persistent *dsp =
		container_of(fdl, struct erofs_dm_snap_persistent, fdl);
	erofs_off_t boundary = dsp->boundary;

	if (!dsp->exceptions.count)
		return 0;
	return boundary ? (boundary & -boundary) : BIT_ULL(63);
}

static int erofs_dm_persistent_map(struct erofs_file_delta *fdl,
				   struct erofs_delta_map *map)
{
	struct erofs_dm_snap_persistent *dsp =
		container_of(fdl, struct erofs_dm_snap_persistent, fdl);
	const struct erofs_dm_exception *e;
	erofs_off_t offset = map->offset, end;
	size_t lo = 0, hi = dsp->exceptions.count;

	map->length = 0;
	map->vf = NULL;
	map->sourceoffset = 0;
	if (offset >= dsp->target_size)
		return 0;

	/* Find the first replacement whose end is past the requested offset. */
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		e = &dsp->exceptions.entries[mid];
		if (offset >= e->offset && offset - e->offset >= dsp->chunk_bytes)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == dsp->exceptions.count)
		return 0;
	e = &dsp->exceptions.entries[lo];
	end = e->offset + dsp->chunk_bytes;
	map->offset = max(offset, e->offset);
	map->length = end - map->offset;
	map->vf = dsp->vf;
	map->sourceoffset = e->source_offset + map->offset - e->offset;
	return 0;
}

static void erofs_dm_persistent_close(struct erofs_file_delta *fdl)
{
	struct erofs_dm_snap_persistent *dsp =
		container_of(fdl, struct erofs_dm_snap_persistent, fdl);

	free(dsp->exceptions.entries);
	free(dsp);
}

struct erofs_file_delta *erofs_dm_persistent_open(struct erofs_vfile *vf)
{
	struct erofs_dm_disk_header header;
	struct erofs_dm_snap_persistent *dsp;
	erofs_off_t chunk_bytes;
	u32 sectors;
	int ret;

	BUILD_BUG_ON(sizeof(header) != 16);
	BUILD_BUG_ON(sizeof(struct erofs_dm_disk_exception) != 16);
	ret = erofs_pread(vf, &header, sizeof(header), 0);
	if (ret)
		return ERR_PTR(ret);
	if (le32_to_cpu(header.magic) != EROFS_DM_SNAP_MAGIC ||
	    le32_to_cpu(header.version) != EROFS_DM_DISK_VERSION)
		return ERR_PTR(-EFSCORRUPTED);
	if (le32_to_cpu(header.valid) != 1)
		return ERR_PTR(-EINVAL);
	sectors = le32_to_cpu(header.chunk_size);
	if (!sectors || (sectors & (sectors - 1)) || sectors > (INT_MAX >> 9))
		return ERR_PTR(-EFSCORRUPTED);
	chunk_bytes = (erofs_off_t)sectors * EROFS_DM_SECTOR_SIZE;
	dsp = calloc(1, sizeof(*dsp));
	if (!dsp)
		return ERR_PTR(-ENOMEM);
	dsp->fdl.ops = &erofs_file_delta_dm_persistent_ops;
	dsp->vf = vf;
	dsp->chunk_bytes = chunk_bytes;
	ret = erofs_dm_parse_exceptions(dsp);
	if (ret) {
		erofs_dm_persistent_close(&dsp->fdl);
		return ERR_PTR(ret);
	}
	return &dsp->fdl;
}

static const struct erofs_file_delta_ops erofs_file_delta_dm_persistent_ops = {
	.get_alignment = erofs_dm_persistent_get_alignment,
	.map = erofs_dm_persistent_map,
	.close = erofs_dm_persistent_close,
	.name = "dm-persistent",
};
