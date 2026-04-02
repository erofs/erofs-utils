// SPDX-License-Identifier: GPL-2.0+ OR MIT
/*
 * Copyright (C) 2026 Tencent, Inc.
 *             http://www.tencent.com/
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "erofs/defs.h"
#ifdef HAVE_JSON_C_JSON_H
#include <json-c/json.h>
#endif
#include "erofs/print.h"
#include "liberofs_base64.h"
#include "liberofs_dockerconfig.h"

#ifndef HAVE_JSON_C_JSON_H

int erofs_docker_config_lookup(const char *registry,
			       struct erofs_docker_credential *cred)
{
	(void)registry;
	(void)cred;
	return -EOPNOTSUPP;
}

void erofs_docker_credential_free(struct erofs_docker_credential *cred)
{
	(void)cred;
}

#else /* HAVE_JSON_C_JSON_H */

static char *docker_config_path(void)
{
	const char *dir;
	char *path = NULL;

	dir = getenv("DOCKER_CONFIG");
	if (dir) {
		if (!*dir)
			return NULL;
		if (asprintf(&path, "%s/config.json", dir) < 0)
			return NULL;
		return path;
	}

	dir = getenv("HOME");
	if (!dir || !*dir) {
		erofs_dbg("HOME is not set, cannot locate docker config");
		return NULL;
	}

	if (asprintf(&path, "%s/.docker/config.json", dir) < 0)
		return NULL;
	return path;
}

static char *read_file_to_string(const char *path)
{
	FILE *fp;
	struct stat st;
	char *buf;
	size_t nread;

	if (stat(path, &st) < 0)
		return NULL;

	if (st.st_size <= 0 || st.st_size > (1 << 22))
		return NULL;

	fp = fopen(path, "r");
	if (!fp)
		return NULL;

	buf = malloc(st.st_size + 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}

	nread = fread(buf, 1, st.st_size, fp);
	fclose(fp);

	if ((off_t)nread != st.st_size) {
		free(buf);
		return NULL;
	}
	buf[nread] = '\0';
	return buf;
}

/*
 * Check if @key (an auths entry key) matches @registry.
 *
 * For Docker Hub: @registry is docker.io or registry-1.docker.io.
 * The auths key in config.json is always "https://index.docker.io/v1/".
 * For other registries: the auths key is an exact match against @registry.
 */
static bool registry_match(const char *key, const char *registry)
{
	if (!key || !registry)
		return false;

	if (!strcasecmp(registry, DOCKER_REGISTRY) ||
	    !strcasecmp(registry, DOCKER_API_REGISTRY))
		return !strcmp(key, DOCKER_HUB_AUTH_KEY);

	return !strcasecmp(key, registry);
}

static int decode_auth_field(const char *b64, char **out_user, char **out_pass)
{
	int b64_len = strlen(b64);
	int decoded_max = b64_len;
	u8 *decoded;
	int decoded_len;
	char *colon;

	decoded = malloc(decoded_max + 1);
	if (!decoded)
		return -ENOMEM;

	decoded_len = erofs_base64_decode(b64, b64_len, decoded);
	if (decoded_len <= 0) {
		free(decoded);
		return -EINVAL;
	}
	decoded[decoded_len] = '\0';

	colon = strchr((char *)decoded, ':');
	if (!colon) {
		erofs_free_sensitive(decoded, decoded_len);
		return -EINVAL;
	}

	*colon = '\0';
	*out_user = strdup((char *)decoded);
	*out_pass = strdup(colon + 1);

	erofs_free_sensitive(decoded, decoded_len);

	if (!*out_user || !*out_pass) {
		free(*out_user);
		free(*out_pass);
		*out_user = NULL;
		*out_pass = NULL;
		return -ENOMEM;
	}
	return 0;
}

int erofs_docker_config_lookup(const char *registry,
			       struct erofs_docker_credential *cred)
{
	char *path = NULL;
	char *content = NULL;
	struct json_object *root = NULL, *auths_obj = NULL;
	int ret = -ENOENT;

	memset(cred, 0, sizeof(*cred));

	path = docker_config_path();
	if (!path)
		return -ENOENT;

	content = read_file_to_string(path);
	if (!content) {
		erofs_dbg("cannot read docker config: %s", path);
		free(path);
		return -ENOENT;
	}
	free(path);

	root = json_tokener_parse(content);
	erofs_free_sensitive(content, strlen(content));

	if (!root) {
		erofs_warn("failed to parse docker config.json");
		return -EINVAL;
	}

	if (!json_object_object_get_ex(root, "auths", &auths_obj)) {
		erofs_dbg("no \"auths\" in docker config.json");
		json_object_put(root);
		return -ENOENT;
	}

	struct json_object_iterator it = json_object_iter_begin(auths_obj);
	struct json_object_iterator end = json_object_iter_end(auths_obj);

	while (!json_object_iter_equal(&it, &end)) {
		const char *key = json_object_iter_peek_name(&it);
		struct json_object *entry, *auth_field;
		const char *b64;

		if (!registry_match(key, registry)) {
			json_object_iter_next(&it);
			continue;
		}

		entry = json_object_iter_peek_value(&it);
		if (json_object_object_get_ex(entry, "auth", &auth_field)) {
			b64 = json_object_get_string(auth_field);
			if (b64 && *b64) {
				ret = decode_auth_field(b64, &cred->username,
							&cred->password);
				if (!ret)
					erofs_dbg("found docker credentials for %s",
						  registry);
			}
		}
		break;
	}

	json_object_put(root);
	return ret;
}

void erofs_docker_credential_free(struct erofs_docker_credential *cred)
{
	if (cred->username) {
		erofs_free_sensitive(cred->username, strlen(cred->username));
		cred->username = NULL;
	}
	if (cred->password) {
		erofs_free_sensitive(cred->password, strlen(cred->password));
		cred->password = NULL;
	}
}

#endif /* HAVE_JSON_C_JSON_H */
