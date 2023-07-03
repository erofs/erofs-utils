// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2023 Norbert Lange <nolange79@gmail.com>
 */

#include <string.h>
#include <errno.h>

#include "erofs/config.h"
#include "erofs/defs.h"
#include "liberofs_uuid.h"

#ifdef HAVE_LIBUUID
#include <uuid.h>
#else

#include <stdlib.h>
#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#else
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#endif

/* Flags to be used, will be modified if kernel does not support them */
static unsigned int erofs_grnd_flag =
#ifdef GRND_INSECURE
	GRND_INSECURE;
#else
	0x0004;
#endif

static int s_getrandom(void *out, unsigned size, bool insecure)
{
	unsigned int kflags = erofs_grnd_flag;
	unsigned int flags = insecure ? kflags : 0;

	for (;;)
	{
#ifdef HAVE_SYS_RANDOM_H
		ssize_t r = getrandom(out, size, flags);
#else
		ssize_t r = (ssize_t)syscall(__NR_getrandom, out, size, flags);
#endif
		int err;

		if (r == size)
			break;
		err = errno;
		if (err != EINTR) {
			if (err == EINVAL && kflags) {
				// Kernel likely does not support GRND_INSECURE
				erofs_grnd_flag = 0;
				kflags = 0;
				continue;
			}
			return -err;
		}
	}
	return 0;
}
#endif

void erofs_uuid_generate(unsigned char *out)
{
#ifdef HAVE_LIBUUID
	uuid_t new_uuid;

	do {
		uuid_generate(new_uuid);
	} while (uuid_is_null(new_uuid));
#else
	unsigned char new_uuid[16];
	int res __maybe_unused;

	res = s_getrandom(new_uuid, sizeof(new_uuid), true);
	BUG_ON(res != 0);

	// UID type + version bits
	new_uuid[0] = (new_uuid[4 + 2] & 0x0f) | 0x40;
	new_uuid[1] = (new_uuid[4 + 2 + 2] & 0x3f) | 0x80;
#endif
	memcpy(out, new_uuid, sizeof(new_uuid));
}

int erofs_uuid_parse(const char *in, unsigned char *uu) {
#ifdef HAVE_LIBUUID
	return uuid_parse((char *)in, uu);
#else
	unsigned char new_uuid[16];
	unsigned int hypens = ((1U << 3) | (1U << 5) | (1U << 7) | (1U << 9));
	int i;

	for (i = 0; i < sizeof(new_uuid); hypens >>= 1, i++)
	{
		char c[] = { in[0], in[1], '\0' };
		char* endptr = c;
		unsigned long val = strtoul(c, &endptr, 16);

		if (endptr - c != 2)
			return -EINVAL;

		in += 2;

		if ((hypens & 1U) != 0) {
			if (*in++ != '-')
				return -EINVAL;
		}
		new_uuid[i] = (unsigned char)val;
	}

	if (*in != '\0')
		return -EINVAL;
	memcpy(uu, new_uuid, sizeof(new_uuid));
	return 0;
#endif
}
