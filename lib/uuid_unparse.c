// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2023 Norbert Lange <nolange79@gmail.com>
 */

#include <stdio.h>

#include "erofs/config.h"
#include "liberofs_uuid.h"

void erofs_uuid_unparse_lower(const unsigned char *buf, char *out) {
	sprintf(out, "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
			(buf[0] << 8) | buf[1],
			(buf[2] << 8) | buf[3],
			(buf[4] << 8) | buf[5],
			(buf[6] << 8) | buf[7],
			(buf[8] << 8) | buf[9],
			(buf[10] << 8) | buf[11],
			(buf[12] << 8) | buf[13],
			(buf[14] << 8) | buf[15]);
}
