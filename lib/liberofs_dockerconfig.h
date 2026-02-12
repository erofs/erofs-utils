/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2026 Tencent, Inc.
 *             http://www.tencent.com/
 */
#ifndef __EROFS_DOCKER_CONFIG_H
#define __EROFS_DOCKER_CONFIG_H

#include "erofs/internal.h"

#define DOCKER_REGISTRY "docker.io"
#define DOCKER_API_REGISTRY "registry-1.docker.io"
#define DOCKER_HUB_AUTH_KEY "https://index.docker.io/v1/"

struct erofs_docker_credential {
	char *username;
	char *password;
};

/**
 * erofs_docker_config_lookup - look up registry credentials from Docker config
 * @registry: the registry hostname (e.g. "index.docker.io")
 * @cred: output credential structure
 */
int erofs_docker_config_lookup(const char *registry,
			       struct erofs_docker_credential *cred);

void erofs_docker_credential_free(struct erofs_docker_credential *cred);

#endif
