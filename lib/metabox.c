// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include <stdlib.h>
#include "erofs/cache.h"
#include "erofs/inode.h"
#include "liberofs_private.h"
#include "liberofs_metabox.h"

const char *erofs_metabox_identifier = "metabox";

struct erofs_metaboxmgr {
	struct erofs_vfile vf;
	struct erofs_bufmgr *bmgr;
};

int erofs_metabox_init(struct erofs_sb_info *sbi)
{
	struct erofs_metaboxmgr *m2gr;
	int ret;

	m2gr = malloc(sizeof(*m2gr));
	if (!m2gr)
		return -ENOMEM;

	ret = erofs_tmpfile();
	if (ret < 0)
		goto out_err;

	m2gr->vf = (struct erofs_vfile){ .fd = ret };
	m2gr->bmgr = erofs_buffer_init(sbi, 0, &m2gr->vf);
	if (m2gr->bmgr) {
		erofs_sb_set_metabox(sbi);
		sbi->m2gr = m2gr;
		return 0;
	}
	ret = -ENOMEM;
out_err:
	free(m2gr);
	return ret;
}

struct erofs_bufmgr *erofs_metabox_bmgr(struct erofs_sb_info *sbi)
{
	return sbi->m2gr ? sbi->m2gr->bmgr : NULL;
}

int erofs_metabox_iflush(struct erofs_sb_info *sbi)
{
	struct erofs_metaboxmgr *m2gr = sbi->m2gr;
	struct erofs_inode *inode;
	int err;

	if (!m2gr || !erofs_sb_has_metabox(sbi))
		return -EINVAL;

	err = erofs_bflush(m2gr->bmgr, NULL);
	if (err)
		return err;

	if (erofs_io_lseek(&m2gr->vf, 0, SEEK_END) <= 0)
		return 0;
	inode = erofs_mkfs_build_special_from_fd(sbi, m2gr->vf.fd,
						 EROFS_METABOX_INODE);
	sbi->metabox_nid = erofs_lookupnid(inode);
	erofs_iput(inode);
	return 0;
}
