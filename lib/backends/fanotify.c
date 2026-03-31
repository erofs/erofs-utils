// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "erofs/err.h"
#include "erofs/print.h"
#include "liberofs_fanotify.h"

int erofs_fanotify_init_precontent(void)
{
	int fan_fd;

	fan_fd = fanotify_init(EROFS_FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
			       O_RDONLY | O_LARGEFILE);
	if (fan_fd < 0) {
		erofs_err("fanotify_init failed: %s", strerror(errno));
		return -errno;
	}

	return fan_fd;
}

int erofs_fanotify_mark_file(int fan_fd, const char *path)
{
	int err;

	err = fanotify_mark(fan_fd, FAN_MARK_ADD, EROFS_FAN_PRE_ACCESS,
			    AT_FDCWD, path);
	if (err < 0) {
		erofs_err("fanotify_mark failed for %s: %s", path, strerror(errno));
		return -errno;
	}

	erofs_dbg("Marked %s for EROFS_FAN_PRE_ACCESS monitoring", path);
	return 0;
}

static int erofs_fanotify_parse_range_event(const struct fanotify_event_metadata *meta,
					    u64 *offset, u64 *count)
{
	const struct fanotify_event_info_header *info_hdr;
	const erofs_fanotify_event_info_range_t *range_info;
	const char *ptr, *end;

	if (meta->metadata_len > meta->event_len) {
		erofs_err("Invalid fanotify metadata length");
		return -EIO;
	}

	if (meta->vers != FANOTIFY_METADATA_VERSION) {
		erofs_err("Unsupported fanotify metadata version %d", meta->vers);
		return -EINVAL;
	}

	/* Initialize range to full file (will be overridden if range info present) */
	*offset = 0;
	*count = 0;

	/* Parse additional info records for range information */
	ptr = (const char *)meta + meta->metadata_len;
	end = (const char *)meta + meta->event_len;

	while (ptr < end) {
		size_t info_len;

		if (end - ptr < sizeof(*info_hdr)) {
			erofs_err("Incomplete fanotify event info header");
			return -EIO;
		}
		info_hdr = (const struct fanotify_event_info_header *)ptr;
		info_len = info_hdr->len;
		if (info_len < sizeof(*info_hdr) || ptr + info_len > end) {
			erofs_err("Invalid fanotify event info length");
			return -EIO;
		}

		if (info_hdr->info_type == EROFS_FAN_EVENT_INFO_TYPE_RANGE) {
			if (info_len < sizeof(*range_info)) {
				erofs_err("Incomplete fanotify range info");
				return -EIO;
			}
			range_info = (const erofs_fanotify_event_info_range_t *)ptr;
			*offset = range_info->offset;
			*count = range_info->count;
			break;
		}

		ptr += info_hdr->len;
	}

	return 0;
}

static int erofs_fanotify_respond(int fan_fd, int event_fd, bool allow)
{
	struct fanotify_response response = {
		.fd = event_fd,
		.response = allow ? FAN_ALLOW : FAN_DENY,
	};
	ssize_t ret;

	ret = write(fan_fd, &response, sizeof(response));
	if (ret != sizeof(response)) {
		erofs_err("Failed to respond to fanotify event: %s",
			  ret < 0 ? strerror(errno) : "short write");
		return ret < 0 ? -errno : -EIO;
	}

	return 0;
}

static bool erofs_fanotify_range_in_sparse(int fd, u64 offset, size_t length)
{
	off_t data_start, hole_start;

	data_start = lseek(fd, offset, SEEK_DATA);
	if (data_start < 0)
		return false;
	if ((u64)data_start != offset)
		return false;

	hole_start = lseek(fd, offset, SEEK_HOLE);
	if (hole_start < 0)
		return false;
	if ((u64)hole_start < offset + length)
		return false;

	return true;
}

static int erofs_fanotify_handle_range(struct erofs_fanotify_ctx *ctx,
				       u64 offset, u64 count)
{
	size_t length = count;
	ssize_t read_len, written;

	if (offset >= ctx->image_size)
		return 0;

	if (length == 0)
		length = min_t(u64, 4 * 1024 * 1024, ctx->image_size - offset);
	if (offset + length > ctx->image_size)
		length = ctx->image_size - offset;

	if (erofs_fanotify_range_in_sparse(ctx->sparse_fd, offset, length)) {
		erofs_dbg("Range [%llu, %llu) already local, skipping fetch",
			  (unsigned long long)offset,
			  (unsigned long long)(offset + length));
		return 0;
	}

	if (ctx->fetch_buf_size < length) {
		void *newbuf = realloc(ctx->fetch_buf, length);

		if (!newbuf) {
			erofs_err("Failed to allocate %zu bytes", length);
			return -ENOMEM;
		}
		ctx->fetch_buf = newbuf;
		ctx->fetch_buf_size = length;
	}

	erofs_dbg("Fetching range [%llu, %llu)",
		  (unsigned long long)offset,
		  (unsigned long long)(offset + length));

	read_len = erofs_io_pread(&ctx->vd, ctx->fetch_buf, length, offset);
	if (read_len < 0) {
		erofs_err("Failed to fetch range [%llu, %llu): %s",
			  (unsigned long long)offset,
			  (unsigned long long)(offset + length),
			  erofs_strerror(read_len));
		return read_len;
	}

	written = pwrite(ctx->sparse_fd, ctx->fetch_buf, read_len, offset);
	if (written != read_len) {
		erofs_err("Failed to write to sparse file at offset %llu: %s",
			  (unsigned long long)offset,
			  written < 0 ? strerror(errno) : "short write");
		return written < 0 ? -errno : -EIO;
	}

	fsync(ctx->sparse_fd);
	return 0;
}

static int erofs_fanotify_handle_event(struct erofs_fanotify_ctx *ctx,
				       struct fanotify_event_metadata *meta)
{
	u64 offset, count;
	bool allow_access = true;
	int err = 0, resp_err;

	erofs_dbg("Handling fanotify event: mask=0x%llx fd=%d pid=%d",
		  (unsigned long long)meta->mask, meta->fd, meta->pid);

	if ((meta->mask & EROFS_FAN_PRE_ACCESS)) {
		err = erofs_fanotify_parse_range_event(meta, &offset, &count);
		if (err < 0) {
			allow_access = false;
			goto response;
		}

		err = erofs_fanotify_handle_range(ctx, offset, count);
		if (err < 0)
			allow_access = false;
	}

response:
	resp_err = erofs_fanotify_respond(ctx->fan_fd, meta->fd, allow_access);
	if (meta->fd >= 0)
		close(meta->fd);
	return resp_err ? resp_err : err;
}

int erofs_fanotify_loop(struct erofs_fanotify_ctx *ctx)
{
	char event_buf[4096] __attribute__((aligned(8)));
	struct pollfd pfd = {
		.fd = ctx->fan_fd,
		.events = POLLIN,
	};
	int err = 0;

	if (!ctx)
		return -EINVAL;

	while (1) {
		struct fanotify_event_metadata *meta;
		ssize_t len, remaining;

		len = read(ctx->fan_fd, event_buf, sizeof(event_buf));
		if (len <= 0) {
			if (len < 0) {
				if (errno == EAGAIN) {
					if (poll(&pfd, 1, -1) < 0) {
						if (errno == EINTR)
							continue;
						err = -errno;
						break;
					}
					continue;
				}
				if (errno == EINTR)
					continue;
				err = -errno;
				if (err == -EPIPE) {
					err = 0;
					break;
				}
				erofs_err("Failed to read fanotify events: %s",
					  strerror(errno));
				break;
			}
			erofs_err("Unexpected EOF on fanotify fd");
			err = -EIO;
			break;
		}

		remaining = len;
		for (meta = (struct fanotify_event_metadata *)event_buf;
		     FAN_EVENT_OK(meta, remaining);
		     meta = FAN_EVENT_NEXT(meta, remaining)) {
			err = erofs_fanotify_handle_event(ctx, meta);
			if (err < 0)
				break;
		}
		if (err)
			break;
		if (remaining) {
			erofs_err("Invalid or incomplete fanotify event buffer");
			err = -EIO;
			break;
		}
	}

	return err;
}
