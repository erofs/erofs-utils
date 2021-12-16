/* SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0 */

#ifdef HAVE_LIBSELINUX
#include <selinux/selinux.h>
#include <selinux/label.h>
#endif

#ifdef WITH_ANDROID
#include <selinux/android.h>
#include <private/android_filesystem_config.h>
#include <private/canned_fs_config.h>
#include <private/fs_config.h>
#endif

#ifndef HAVE_MEMRCHR
static inline void *memrchr(const void *s, int c, size_t n)
{
	const unsigned char *p = (const unsigned char *)s;

	for (p += n; n > 0; n--)
		if (*--p == c)
			return (void*)p;
	return NULL;
}
#endif
