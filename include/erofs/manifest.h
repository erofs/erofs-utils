/* SPDX-License-Identifier: GPL-2.0+ OR MIT */
#ifndef __EROFS_MANIFEST_H
#define __EROFS_MANIFEST_H

#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct erofs_importer;
int erofs_manifest_load(struct erofs_importer *im, FILE *fp);

#ifdef __cplusplus
}
#endif

#endif
