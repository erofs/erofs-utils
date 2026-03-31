/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_LIB_LIBEROFS_FANOTIFY_H
#define __EROFS_LIB_LIBEROFS_FANOTIFY_H

#include "erofs/defs.h"
#include "erofs/io.h"
#include <sys/fanotify.h>

/* FAN_PRE_ACCESS may not be defined in older headers */
#ifndef FAN_PRE_ACCESS
#define EROFS_FAN_PRE_ACCESS	0x00100000
#else
#define EROFS_FAN_PRE_ACCESS	FAN_PRE_ACCESS
#endif

#ifndef FAN_CLASS_PRE_CONTENT
#define EROFS_FAN_CLASS_PRE_CONTENT	0x00000008
#else
#define EROFS_FAN_CLASS_PRE_CONTENT	FAN_CLASS_PRE_CONTENT
#endif

#ifndef FAN_EVENT_INFO_TYPE_RANGE
#define EROFS_FAN_EVENT_INFO_TYPE_RANGE	6
#else
#define EROFS_FAN_EVENT_INFO_TYPE_RANGE	FAN_EVENT_INFO_TYPE_RANGE
#endif

/* Provide a local alias for fanotify_event_info_range compatibility. */
#ifndef HAVE_STRUCT_FANOTIFY_EVENT_INFO_RANGE
typedef struct erofs_fanotify_event_info_range {
	struct fanotify_event_info_header hdr;
	__u32 pad;
	__u64 offset;
	__u64 count;
} erofs_fanotify_event_info_range_t;
#else
typedef struct fanotify_event_info_range erofs_fanotify_event_info_range_t;
#endif

struct erofs_fanotify_ctx {
	struct erofs_vfile vd;
	int sparse_fd;
	int fan_fd;
	char *sparse_path;
	void *fetch_buf;
	size_t fetch_buf_size;
	u64 image_size;
};

/* Initialize fanotify with EROFS_FAN_CLASS_PRE_CONTENT */
int erofs_fanotify_init_precontent(void);

/* Mark file for EROFS_FAN_PRE_ACCESS monitoring */
int erofs_fanotify_mark_file(int fan_fd, const char *path);

/* Run the fanotify event loop for a sparse-file backed OCI context. */
int erofs_fanotify_loop(struct erofs_fanotify_ctx *ctx);

#endif
