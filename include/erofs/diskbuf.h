/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_DISKBUF_H
#define __EROFS_DISKBUF_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "erofs/defs.h"

struct erofs_diskbuf {
	void *sp;		/* internal stream pointer */
	u64 offset;		/* internal offset */
};

int erofs_diskbuf_getfd(struct erofs_diskbuf *db, u64 *off);

int erofs_diskbuf_reserve(struct erofs_diskbuf *db, int sid, u64 *off);
void erofs_diskbuf_commit(struct erofs_diskbuf *db, u64 len);
void erofs_diskbuf_close(struct erofs_diskbuf *db);

int erofs_diskbuf_init(unsigned int nstrms);
void erofs_diskbuf_exit(void);

#ifdef __cplusplus
}
#endif

#endif
