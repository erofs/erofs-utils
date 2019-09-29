// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs_utils/lib/xattr.c
 *
 * Originally contributed by an anonymous person,
 * heavily changed by Li Guifu <blucerlee@gmail.com>
 *                and Gao Xiang <hsiangkao@aol.com>
 */
#include <stdlib.h>
#include <sys/xattr.h>
#ifdef HAVE_LINUX_XATTR_H
#include <linux/xattr.h>
#endif
#include "erofs/print.h"
#include "erofs/hashtable.h"
#include "erofs/xattr.h"

#define EA_HASHTABLE_BITS 16

struct xattr_item {
	const char *kvbuf;
	unsigned int hash[2], len[2], count;
	u8 prefix;
	struct hlist_node node;
};

struct inode_xattr_node {
	struct list_head list;
	struct xattr_item *item;
};

static DECLARE_HASHTABLE(ea_hashtable, EA_HASHTABLE_BITS);

static struct xattr_prefix {
	const char *prefix;
	u16 prefix_len;
} xattr_types[] = {
	[EROFS_XATTR_INDEX_USER] = {
		XATTR_USER_PREFIX,
		XATTR_USER_PREFIX_LEN
	}, [EROFS_XATTR_INDEX_POSIX_ACL_ACCESS] = {
		XATTR_NAME_POSIX_ACL_ACCESS,
		sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1
	}, [EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT] = {
		XATTR_NAME_POSIX_ACL_DEFAULT,
		sizeof(XATTR_NAME_POSIX_ACL_DEFAULT) - 1
	}, [EROFS_XATTR_INDEX_TRUSTED] = {
		XATTR_TRUSTED_PREFIX,
		XATTR_TRUSTED_PREFIX_LEN
	}, [EROFS_XATTR_INDEX_SECURITY] = {
		XATTR_SECURITY_PREFIX,
		XATTR_SECURITY_PREFIX_LEN
	}
};

static unsigned int BKDRHash(char *str, unsigned int len)
{
	const unsigned int seed = 131313;
	unsigned int hash = 0;

	while (len) {
		hash = hash * seed + (*str++);
		--len;
	}
	return hash;
}

static unsigned int xattr_item_hash(u8 prefix, char *buf,
				    unsigned int len[2], unsigned int hash[2])
{
	hash[0] = BKDRHash(buf, len[0]);	/* key */
	hash[1] = BKDRHash(buf + len[0], len[1]);	/* value */

	return prefix ^ hash[0] ^ hash[1];
}

static unsigned int put_xattritem(struct xattr_item *item)
{
	if (item->count > 1)
		return --item->count;
	free(item);
	return 0;
}

static struct xattr_item *get_xattritem(u8 prefix, char *kvbuf,
					unsigned int len[2])
{
	struct xattr_item *item;
	unsigned int hash[2], hkey;

	hkey = xattr_item_hash(prefix, kvbuf, len, hash);

	hash_for_each_possible(ea_hashtable, item, node, hkey) {
		if (prefix == item->prefix &&
		    item->len[0] == len[0] && item->len[1] == len[1] &&
		    item->hash[0] == hash[0] && item->hash[1] == hash[1] &&
		    !memcmp(kvbuf, item->kvbuf, len[0] + len[1])) {
			free(kvbuf);
			++item->count;
			return item;
		}
	}

	item = malloc(sizeof(*item));
	if (!item) {
		free(kvbuf);
		return ERR_PTR(-ENOMEM);
	}
	INIT_HLIST_NODE(&item->node);
	item->count = 1;
	item->kvbuf = kvbuf;
	item->len[0] = len[0];
	item->len[1] = len[1];
	item->hash[0] = hash[0];
	item->hash[1] = hash[1];
	item->prefix = prefix;
	hash_add(ea_hashtable, &item->node, hkey);
	return item;
}

static bool match_prefix(const char *key, u8 *index, u16 *len)
{
	struct xattr_prefix *p;

	for (p = xattr_types; p < xattr_types + ARRAY_SIZE(xattr_types); ++p) {
		if (p->prefix && !strncmp(p->prefix, key, p->prefix_len)) {
			*len = p->prefix_len;
			*index = p - xattr_types;
			return true;
		}
	}
	return false;
}

static struct xattr_item *parse_one_xattr(const char *path, const char *key,
					  unsigned int keylen)
{
	ssize_t ret;
	u8 prefix;
	u16 prefixlen;
	unsigned int len[2];
	char *kvbuf;

	erofs_dbg("parse xattr [%s] of %s", path, key);

	if (!match_prefix(key, &prefix, &prefixlen))
		return ERR_PTR(-ENODATA);

	DBG_BUGON(keylen < prefixlen);

	/* determine length of the value */
	ret = lgetxattr(path, key, NULL, 0);
	if (ret < 0)
		return ERR_PTR(-errno);
	len[1] = ret;

	/* allocate key-value buffer */
	len[0] = keylen - prefixlen;

	kvbuf = malloc(len[0] + len[1]);
	if (!kvbuf)
		return ERR_PTR(-ENOMEM);

	memcpy(kvbuf, key + prefixlen, len[0]);
	if (len[1]) {
		/* copy value to buffer */
		ret = lgetxattr(path, key, kvbuf + len[0], len[1]);
		if (ret < 0) {
			free(kvbuf);
			return ERR_PTR(-errno);
		}
		if (len[1] != ret) {
			erofs_err("size of xattr value got changed just now (%u-> %ld)",
				  len[1], (long)ret);
			len[1] = ret;
		}
	}
	return get_xattritem(prefix, kvbuf, len);
}

static int inode_xattr_add(struct list_head *hlist, struct xattr_item *item)
{
	struct inode_xattr_node *node = malloc(sizeof(*node));

	if (!node)
		return -ENOMEM;
	init_list_head(&node->list);
	node->item = item;
	list_add(&node->list, hlist);
	return 0;
}

static int read_xattrs_from_file(const char *path, struct list_head *ixattrs)
{
	int ret = 0;
	char *keylst, *key;
	ssize_t kllen = llistxattr(path, NULL, 0);

	if (kllen < 0 && errno != ENODATA) {
		erofs_err("llistxattr to get the size of names for %s failed",
			  path);
		return -errno;
	}
	if (kllen <= 1)
		return 0;

	keylst = malloc(kllen);
	if (!keylst)
		return -ENOMEM;

	/* copy the list of attribute keys to the buffer.*/
	kllen = llistxattr(path, keylst, kllen);
	if (kllen < 0) {
		erofs_err("llistxattr to get names for %s failed", path);
		ret = -errno;
		goto err;
	}

	/*
	 * loop over the list of zero terminated strings with the
	 * attribute keys. Use the remaining buffer length to determine
	 * the end of the list.
	 */
	key = keylst;
	while (kllen > 0) {
		unsigned int keylen = strlen(key);
		struct xattr_item *item = parse_one_xattr(path, key, keylen);

		if (IS_ERR(item)) {
			ret = PTR_ERR(item);
			goto err;
		}

		if (ixattrs) {
			ret = inode_xattr_add(ixattrs, item);
			if (ret < 0)
				goto err;
		}
		kllen -= keylen + 1;
		key += keylen + 1;
	}
err:
	free(keylst);
	return ret;

}

int erofs_prepare_xattr_ibody(const char *path, struct list_head *ixattrs)
{
	int ret;
	struct inode_xattr_node *node;

	/* check if xattr is disabled */
	if (cfg.c_inline_xattr_tolerance < 0)
		return 0;

	ret = read_xattrs_from_file(path, ixattrs);
	if (ret < 0)
		return ret;

	if (list_empty(ixattrs))
		return 0;

	/* get xattr ibody size */
	ret = sizeof(struct erofs_xattr_ibody_header);
	list_for_each_entry(node, ixattrs, list) {
		const struct xattr_item *item = node->item;

		ret += sizeof(struct erofs_xattr_entry);
		ret = EROFS_XATTR_ALIGN(ret + item->len[0] + item->len[1]);
	}
	return ret;
}

char *erofs_export_xattr_ibody(struct list_head *ixattrs, unsigned int size)
{
	struct inode_xattr_node *node, *n;
	struct erofs_xattr_ibody_header *header;
	unsigned int p;
	char *buf = calloc(1, size);

	if (!buf)
		return ERR_PTR(-ENOMEM);

	header = (struct erofs_xattr_ibody_header *)buf;
	header->h_shared_count = 0;

	p = sizeof(struct erofs_xattr_ibody_header);
	list_for_each_entry_safe(node, n, ixattrs, list) {
		struct xattr_item *const item = node->item;
		const struct erofs_xattr_entry entry = {
			.e_name_index = item->prefix,
			.e_name_len = item->len[0],
			.e_value_size = cpu_to_le16(item->len[1])
		};

		memcpy(buf + p, &entry, sizeof(entry));
		p += sizeof(struct erofs_xattr_entry);
		memcpy(buf + p, item->kvbuf, item->len[0] + item->len[1]);
		p = EROFS_XATTR_ALIGN(p + item->len[0] + item->len[1]);

		list_del(&node->list);
		free(node);
		put_xattritem(item);
	}
	DBG_BUGON(p > size);
	return buf;
}

