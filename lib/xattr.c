// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Originally contributed by an anonymous person,
 * heavily changed by Li Guifu <blucerlee@gmail.com>
 *                and Gao Xiang <hsiangkao@aol.com>
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/xattr.h>
#ifdef HAVE_LINUX_XATTR_H
#include <linux/xattr.h>
#endif
#include <sys/stat.h>
#include <dirent.h>
#include "erofs/print.h"
#include "erofs/hashtable.h"
#include "erofs/xattr.h"
#include "erofs/cache.h"
#include "erofs/io.h"
#include "liberofs_private.h"

#define EA_HASHTABLE_BITS 16

struct xattr_item {
	const char *kvbuf;
	unsigned int hash[2], len[2], count;
	int shared_xattr_id;
	u8 prefix;
	struct hlist_node node;
};

struct inode_xattr_node {
	struct list_head list;
	struct xattr_item *item;
};

static DECLARE_HASHTABLE(ea_hashtable, EA_HASHTABLE_BITS);

static LIST_HEAD(shared_xattrs_list);
static unsigned int shared_xattrs_count, shared_xattrs_size;

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
	item->shared_xattr_id = -1;
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
#ifdef HAVE_LGETXATTR
	ret = lgetxattr(path, key, NULL, 0);
#elif defined(__APPLE__)
	ret = getxattr(path, key, NULL, 0, 0, XATTR_NOFOLLOW);
#else
	return ERR_PTR(-EOPNOTSUPP);
#endif
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
#ifdef HAVE_LGETXATTR
		ret = lgetxattr(path, key, kvbuf + len[0], len[1]);
#elif defined(__APPLE__)
		ret = getxattr(path, key, kvbuf + len[0], len[1], 0,
			       XATTR_NOFOLLOW);
#else
		free(kvbuf);
		return ERR_PTR(-EOPNOTSUPP);
#endif
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

static struct xattr_item *erofs_get_selabel_xattr(const char *srcpath,
						  mode_t mode)
{
#ifdef HAVE_LIBSELINUX
	if (cfg.sehnd) {
		char *secontext;
		int ret;
		unsigned int len[2];
		char *kvbuf, *fspath;

#ifdef WITH_ANDROID
		if (cfg.mount_point)
			ret = asprintf(&fspath, "/%s/%s", cfg.mount_point,
				       erofs_fspath(srcpath));
		else
#endif
			ret = asprintf(&fspath, "/%s", erofs_fspath(srcpath));
		if (ret <= 0)
			return ERR_PTR(-ENOMEM);

		ret = selabel_lookup(cfg.sehnd, &secontext, fspath, mode);
		free(fspath);

		if (ret) {
			ret = -errno;
			if (ret != -ENOENT) {
				erofs_err("failed to lookup selabel for %s: %s",
					  srcpath, erofs_strerror(ret));
				return ERR_PTR(ret);
			}
			/* secontext = "u:object_r:unlabeled:s0"; */
			return NULL;
		}

		len[0] = sizeof("selinux") - 1;
		len[1] = strlen(secontext);
		kvbuf = malloc(len[0] + len[1] + 1);
		if (!kvbuf) {
			freecon(secontext);
			return ERR_PTR(-ENOMEM);
		}
		sprintf(kvbuf, "selinux%s", secontext);
		freecon(secontext);
		return get_xattritem(EROFS_XATTR_INDEX_SECURITY, kvbuf, len);
	}
#endif
	return NULL;
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

static int shared_xattr_add(struct xattr_item *item)
{
	struct inode_xattr_node *node = malloc(sizeof(*node));

	if (!node)
		return -ENOMEM;

	init_list_head(&node->list);
	node->item = item;
	list_add(&node->list, &shared_xattrs_list);

	shared_xattrs_size += sizeof(struct erofs_xattr_entry);
	shared_xattrs_size = EROFS_XATTR_ALIGN(shared_xattrs_size +
					       item->len[0] + item->len[1]);
	return ++shared_xattrs_count;
}

static int erofs_xattr_add(struct list_head *ixattrs, struct xattr_item *item)
{
	if (ixattrs)
		return inode_xattr_add(ixattrs, item);

	if (item->count == cfg.c_inline_xattr_tolerance + 1) {
		int ret = shared_xattr_add(item);

		if (ret < 0)
			return ret;
	}
	return 0;
}

static bool erofs_is_skipped_xattr(const char *key)
{
#ifdef HAVE_LIBSELINUX
	/* if sehnd is valid, selabels will be overridden */
	if (cfg.sehnd && !strcmp(key, XATTR_SECURITY_PREFIX "selinux"))
		return true;
#endif
	return false;
}

static int read_xattrs_from_file(const char *path, mode_t mode,
				 struct list_head *ixattrs)
{
#ifdef HAVE_LLISTXATTR
	ssize_t kllen = llistxattr(path, NULL, 0);
#elif defined(__APPLE__)
	ssize_t kllen = listxattr(path, NULL, 0, XATTR_NOFOLLOW);
#else
	ssize_t kllen = 0;
#endif
	int ret;
	char *keylst, *key, *klend;
	unsigned int keylen;
	struct xattr_item *item;

	if (kllen < 0 && errno != ENODATA) {
		erofs_err("llistxattr to get the size of names for %s failed",
			  path);
		return -errno;
	}

	ret = 0;
	if (kllen <= 1)
		goto out;

	keylst = malloc(kllen);
	if (!keylst)
		return -ENOMEM;

	/* copy the list of attribute keys to the buffer.*/
#ifdef HAVE_LLISTXATTR
	kllen = llistxattr(path, keylst, kllen);
#elif defined(__APPLE__)
	kllen = listxattr(path, keylst, kllen, XATTR_NOFOLLOW);
	if (kllen < 0) {
		erofs_err("llistxattr to get names for %s failed", path);
		ret = -errno;
		goto err;
	}
#else
	ret = -EOPNOTSUPP;
	goto err;
#endif
	/*
	 * loop over the list of zero terminated strings with the
	 * attribute keys. Use the remaining buffer length to determine
	 * the end of the list.
	 */
	klend = keylst + kllen;
	ret = 0;

	for (key = keylst; key != klend; key += keylen + 1) {
		keylen = strlen(key);
		if (erofs_is_skipped_xattr(key))
			continue;

		item = parse_one_xattr(path, key, keylen);
		if (IS_ERR(item)) {
			ret = PTR_ERR(item);
			goto err;
		}

		ret = erofs_xattr_add(ixattrs, item);
		if (ret < 0)
			goto err;
	}
	free(keylst);

out:
	/* if some selabel is avilable, need to add right now */
	item = erofs_get_selabel_xattr(path, mode);
	if (IS_ERR(item))
		return PTR_ERR(item);
	if (item)
		ret = erofs_xattr_add(ixattrs, item);
	return ret;

err:
	free(keylst);
	return ret;
}

#ifdef WITH_ANDROID
static int erofs_droid_xattr_set_caps(struct erofs_inode *inode)
{
	const u64 capabilities = inode->capabilities;
	char *kvbuf;
	unsigned int len[2];
	struct vfs_cap_data caps;
	struct xattr_item *item;

	if (!capabilities)
		return 0;

	len[0] = sizeof("capability") - 1;
	len[1] = sizeof(caps);

	kvbuf = malloc(len[0] + len[1]);
	if (!kvbuf)
		return -ENOMEM;

	memcpy(kvbuf, "capability", len[0]);
	caps.magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE;
	caps.data[0].permitted = (u32) capabilities;
	caps.data[0].inheritable = 0;
	caps.data[1].permitted = (u32) (capabilities >> 32);
	caps.data[1].inheritable = 0;
	memcpy(kvbuf + len[0], &caps, len[1]);

	item = get_xattritem(EROFS_XATTR_INDEX_SECURITY, kvbuf, len);
	if (IS_ERR(item))
		return PTR_ERR(item);
	if (!item)
		return 0;

	return erofs_xattr_add(&inode->i_xattrs, item);
}
#else
static int erofs_droid_xattr_set_caps(struct erofs_inode *inode)
{
	return 0;
}
#endif

int erofs_prepare_xattr_ibody(struct erofs_inode *inode)
{
	int ret;
	struct inode_xattr_node *node;
	struct list_head *ixattrs = &inode->i_xattrs;

	/* check if xattr is disabled */
	if (cfg.c_inline_xattr_tolerance < 0)
		return 0;

	ret = read_xattrs_from_file(inode->i_srcpath, inode->i_mode, ixattrs);
	if (ret < 0)
		return ret;

	ret = erofs_droid_xattr_set_caps(inode);
	if (ret < 0)
		return ret;

	if (list_empty(ixattrs))
		return 0;

	/* get xattr ibody size */
	ret = sizeof(struct erofs_xattr_ibody_header);
	list_for_each_entry(node, ixattrs, list) {
		const struct xattr_item *item = node->item;

		if (item->shared_xattr_id >= 0) {
			ret += sizeof(__le32);
			continue;
		}
		ret += sizeof(struct erofs_xattr_entry);
		ret = EROFS_XATTR_ALIGN(ret + item->len[0] + item->len[1]);
	}
	inode->xattr_isize = ret;
	return ret;
}

static int erofs_count_all_xattrs_from_path(const char *path)
{
	int ret;
	DIR *_dir;
	struct stat64 st;

	_dir = opendir(path);
	if (!_dir) {
		erofs_err("failed to opendir at %s: %s",
			  path, erofs_strerror(errno));
		return -errno;
	}

	ret = 0;
	while (1) {
		struct dirent *dp;
		char buf[PATH_MAX];

		/*
		 * set errno to 0 before calling readdir() in order to
		 * distinguish end of stream and from an error.
		 */
		errno = 0;
		dp = readdir(_dir);
		if (!dp)
			break;

		if (is_dot_dotdot(dp->d_name) ||
		    !strncmp(dp->d_name, "lost+found", strlen("lost+found")))
			continue;

		ret = snprintf(buf, PATH_MAX, "%s/%s", path, dp->d_name);

		if (ret < 0 || ret >= PATH_MAX) {
			/* ignore the too long path */
			ret = -ENOMEM;
			goto fail;
		}

		ret = lstat64(buf, &st);
		if (ret) {
			ret = -errno;
			goto fail;
		}

		ret = read_xattrs_from_file(buf, st.st_mode, NULL);
		if (ret)
			goto fail;

		if (!S_ISDIR(st.st_mode))
			continue;

		ret = erofs_count_all_xattrs_from_path(buf);
		if (ret)
			goto fail;
	}

	if (errno)
		ret = -errno;

fail:
	closedir(_dir);
	return ret;
}

static void erofs_cleanxattrs(bool sharedxattrs)
{
	unsigned int i;
	struct xattr_item *item;
	struct hlist_node *tmp;

	hash_for_each_safe(ea_hashtable, i, tmp, item, node) {
		if (sharedxattrs && item->shared_xattr_id >= 0)
			continue;

		hash_del(&item->node);
		free(item);
	}

	if (sharedxattrs)
		return;

	shared_xattrs_size = shared_xattrs_count = 0;
}

static bool erofs_bh_flush_write_shared_xattrs(struct erofs_buffer_head *bh)
{
	void *buf = bh->fsprivate;
	int err = dev_write(buf, erofs_btell(bh, false), shared_xattrs_size);

	if (err)
		return false;
	free(buf);
	return erofs_bh_flush_generic_end(bh);
}

static struct erofs_bhops erofs_write_shared_xattrs_bhops = {
	.flush = erofs_bh_flush_write_shared_xattrs,
};

static int comp_xattr_item(const void *a, const void *b)
{
	const struct xattr_item *ia, *ib;
	unsigned int la, lb;
	int ret;

	ia = (*((const struct inode_xattr_node **)a))->item;
	ib = (*((const struct inode_xattr_node **)b))->item;
	la = ia->len[0] + ia->len[1];
	lb = ib->len[0] + ib->len[1];

	ret = strncmp(ia->kvbuf, ib->kvbuf, min(la, lb));
	if (ret != 0)
		return ret;

	return la > lb;
}

int erofs_build_shared_xattrs_from_path(const char *path)
{
	int ret;
	struct erofs_buffer_head *bh;
	struct inode_xattr_node *node, *n, **sorted_n;
	char *buf;
	unsigned int p, i;
	erofs_off_t off;

	/* check if xattr or shared xattr is disabled */
	if (cfg.c_inline_xattr_tolerance < 0 ||
	    cfg.c_inline_xattr_tolerance == INT_MAX)
		return 0;

	if (shared_xattrs_size || shared_xattrs_count) {
		DBG_BUGON(1);
		return -EINVAL;
	}

	ret = erofs_count_all_xattrs_from_path(path);
	if (ret)
		return ret;

	if (!shared_xattrs_size)
		goto out;

	buf = calloc(1, shared_xattrs_size);
	if (!buf)
		return -ENOMEM;

	bh = erofs_balloc(XATTR, shared_xattrs_size, 0, 0);
	if (IS_ERR(bh)) {
		free(buf);
		return PTR_ERR(bh);
	}
	bh->op = &erofs_skip_write_bhops;

	erofs_mapbh(bh->block);
	off = erofs_btell(bh, false);

	sbi.xattr_blkaddr = off / EROFS_BLKSIZ;
	off %= EROFS_BLKSIZ;
	p = 0;

	sorted_n = malloc(shared_xattrs_count * sizeof(n));
	if (!sorted_n)
		return -ENOMEM;
	i = 0;
	list_for_each_entry_safe(node, n, &shared_xattrs_list, list) {
		list_del(&node->list);
		sorted_n[i++] = node;
	}
	DBG_BUGON(i != shared_xattrs_count);
	qsort(sorted_n, shared_xattrs_count, sizeof(n), comp_xattr_item);

	for (i = 0; i < shared_xattrs_count; i++) {
		struct inode_xattr_node *const tnode = sorted_n[i];
		struct xattr_item *const item = tnode->item;
		const struct erofs_xattr_entry entry = {
			.e_name_index = item->prefix,
			.e_name_len = item->len[0],
			.e_value_size = cpu_to_le16(item->len[1])
		};

		item->shared_xattr_id = (off + p) /
			sizeof(struct erofs_xattr_entry);

		memcpy(buf + p, &entry, sizeof(entry));
		p += sizeof(struct erofs_xattr_entry);
		memcpy(buf + p, item->kvbuf, item->len[0] + item->len[1]);
		p = EROFS_XATTR_ALIGN(p + item->len[0] + item->len[1]);
		free(tnode);
	}

	free(sorted_n);
	bh->fsprivate = buf;
	bh->op = &erofs_write_shared_xattrs_bhops;
out:
	erofs_cleanxattrs(true);
	return 0;
}

char *erofs_export_xattr_ibody(struct list_head *ixattrs, unsigned int size)
{
	struct inode_xattr_node *node, *n;
	struct erofs_xattr_ibody_header *header;
	LIST_HEAD(ilst);
	unsigned int p;
	char *buf = calloc(1, size);

	if (!buf)
		return ERR_PTR(-ENOMEM);

	header = (struct erofs_xattr_ibody_header *)buf;
	header->h_shared_count = 0;

	p = sizeof(struct erofs_xattr_ibody_header);
	list_for_each_entry_safe(node, n, ixattrs, list) {
		struct xattr_item *const item = node->item;

		list_del(&node->list);

		/* move inline xattrs to the onstack list */
		if (item->shared_xattr_id < 0) {
			list_add(&node->list, &ilst);
			continue;
		}

		*(__le32 *)(buf + p) = cpu_to_le32(item->shared_xattr_id);
		p += sizeof(__le32);
		++header->h_shared_count;
		free(node);
		put_xattritem(item);
	}

	list_for_each_entry_safe(node, n, &ilst, list) {
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
