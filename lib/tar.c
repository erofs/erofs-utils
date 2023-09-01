// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef HAVE_LINUX_AUFS_TYPE_H
#include <linux/aufs_type.h>
#else
#define AUFS_WH_PFX		".wh."
#define AUFS_DIROPQ_NAME	AUFS_WH_PFX ".opq"
#define AUFS_WH_DIROPQ		AUFS_WH_PFX AUFS_DIROPQ_NAME
#endif
#include "erofs/print.h"
#include "erofs/cache.h"
#include "erofs/inode.h"
#include "erofs/list.h"
#include "erofs/tar.h"
#include "erofs/io.h"
#include "erofs/xattr.h"
#include "erofs/blobchunk.h"

#define OVL_XATTR_NAMESPACE "overlay."
#define OVL_XATTR_TRUSTED_PREFIX XATTR_TRUSTED_PREFIX OVL_XATTR_NAMESPACE
#define OVL_XATTR_OPAQUE_POSTFIX "opaque"
#define OVL_XATTR_OPAQUE OVL_XATTR_TRUSTED_PREFIX OVL_XATTR_OPAQUE_POSTFIX

#define EROFS_WHITEOUT_DEV	0

static char erofs_libbuf[16384];

struct tar_header {
	char name[100];		/*   0-99 */
	char mode[8];		/* 100-107 */
	char uid[8];		/* 108-115 */
	char gid[8];		/* 116-123 */
	char size[12];		/* 124-135 */
	char mtime[12];		/* 136-147 */
	char chksum[8];		/* 148-155 */
	char typeflag;		/* 156-156 */
	char linkname[100];	/* 157-256 */
	char magic[6];		/* 257-262 */
	char version[2];	/* 263-264 */
	char uname[32];		/* 265-296 */
	char gname[32];		/* 297-328 */
	char devmajor[8];	/* 329-336 */
	char devminor[8];	/* 337-344 */
	char prefix[155];	/* 345-499 */
	char padding[12];	/* 500-512 (pad to exactly the 512 byte) */
};

s64 erofs_read_from_fd(int fd, void *buf, u64 bytes)
{
	s64 i = 0;

	while (bytes) {
		int len = bytes > INT_MAX ? INT_MAX : bytes;
		int ret;

		ret = read(fd, buf + i, len);
		if (ret < 1) {
			if (ret == 0) {
				break;
			} else if (errno != EINTR) {
				erofs_err("failed to read : %s\n",
					  strerror(errno));
				return -errno;
			}
		}
		bytes -= ret;
		i += ret;
        }
        return i;
}

/*
 * skip this many bytes of input. Return 0 for success, >0 means this much
 * left after input skipped.
 */
u64 erofs_lskip(int fd, u64 sz)
{
	s64 cur = lseek(fd, 0, SEEK_CUR);

	if (cur >= 0) {
		s64 end = lseek(fd, 0, SEEK_END) - cur;

		if (end > 0 && end < sz)
			return sz - end;

		end = cur + sz;
		if (end == lseek(fd, end, SEEK_SET))
			return 0;
	}

	while (sz) {
		int try = min_t(u64, sz, sizeof(erofs_libbuf));
		int or;

		or = read(fd, erofs_libbuf, try);
		if (or <= 0)
			break;
		else
			sz -= or;
	}
	return sz;
}

static long long tarerofs_otoi(const char *ptr, int len)
{
	char inp[32];
	char *endp = inp;
	long long val;

	memcpy(inp, ptr, len);
	inp[len] = '\0';

	errno = 0;
	val = strtol(ptr, &endp, 8);
	if ((!val && endp == inp) |
	     (*endp && *endp != ' '))
		errno = -EINVAL;
	return val;
}

static long long tarerofs_parsenum(const char *ptr, int len)
{
	/*
	 * For fields containing numbers or timestamps that are out of range
	 * for the basic format, the GNU format uses a base-256 representation
	 * instead of an ASCII octal number.
	 */
	if (*(char *)ptr == '\200') {
		long long res = 0;

		while (--len)
			res = (res << 8) + (u8)*(++ptr);
		return res;
	}
	return tarerofs_otoi(ptr, len);
}

static struct erofs_dentry *tarerofs_mkdir(struct erofs_inode *dir, const char *s)
{
	struct erofs_inode *inode;
	struct erofs_dentry *d;

	inode = erofs_new_inode();
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	inode->i_mode = S_IFDIR | 0755;
	inode->i_parent = dir;
	inode->i_uid = getuid();
	inode->i_gid = getgid();
	inode->i_mtime = inode->sbi->build_time;
	inode->i_mtime_nsec = inode->sbi->build_time_nsec;
	erofs_init_empty_dir(inode);

	d = erofs_d_alloc(dir, s);
	if (!IS_ERR(d)) {
		d->type = EROFS_FT_DIR;
		d->inode = inode;
	}
	return d;
}

static struct erofs_dentry *tarerofs_get_dentry(struct erofs_inode *pwd, char *path,
					        bool aufs, bool *whout, bool *opq)
{
	struct erofs_dentry *d = NULL;
	unsigned int len = strlen(path);
	char *s = path;

	*whout = false;
	*opq = false;

	while (s < path + len) {
		char *slash = memchr(s, '/', path + len - s);
		if (slash) {
			if (s == slash) {
				while (*++s == '/');	/* skip '//...' */
				continue;
			}
			*slash = '\0';
		}

		if (!memcmp(s, ".", 2)) {
			/* null */
		} else if (!memcmp(s, "..", 3)) {
			pwd = pwd->i_parent;
		} else {
			struct erofs_inode *inode = NULL;

			if (aufs && !slash) {
				if (!memcmp(s, AUFS_WH_DIROPQ, sizeof(AUFS_WH_DIROPQ))) {
					*opq = true;
					break;
				}
				if (!memcmp(s, AUFS_WH_PFX, sizeof(AUFS_WH_PFX) - 1)) {
					s += sizeof(AUFS_WH_PFX) - 1;
					*whout = true;
				}
			}

			list_for_each_entry(d, &pwd->i_subdirs, d_child) {
				if (!strcmp(d->name, s)) {
					if (d->type != EROFS_FT_DIR && slash)
						return ERR_PTR(-EIO);
					inode = d->inode;
					break;
				}
			}

			if (inode) {
				pwd = inode;
			} else if (!slash) {
				d = erofs_d_alloc(pwd, s);
				if (IS_ERR(d))
					return d;
				d->type = EROFS_FT_UNKNOWN;
				d->inode = pwd;
			} else {
				d = tarerofs_mkdir(pwd, s);
				if (IS_ERR(d))
					return d;
				pwd = d->inode;
			}
		}
		if (slash) {
			*slash = '/';
			s = slash + 1;
		} else {
			break;
		}
	}
	return d;
}

struct tarerofs_xattr_item {
	struct list_head list;
	char *kv;
	unsigned int len, namelen;
};

int tarerofs_insert_xattr(struct list_head *xattrs,
			  char *kv, int namelen, int len, bool skip)
{
	struct tarerofs_xattr_item *item;
	char *nv;

	DBG_BUGON(namelen >= len);
	list_for_each_entry(item, xattrs, list) {
		if (!strncmp(item->kv, kv, namelen + 1)) {
			if (skip)
				return 0;
			goto found;
		}
	}

	item = malloc(sizeof(*item));
	if (!item)
		return -ENOMEM;
	item->kv = NULL;
	item->namelen = namelen;
	namelen = 0;
	list_add_tail(&item->list, xattrs);
found:
	nv = realloc(item->kv, len);
	if (!nv)
		return -ENOMEM;
	item->kv = nv;
	item->len = len;
	memcpy(nv + namelen, kv + namelen, len - namelen);
	return 0;
}

int tarerofs_merge_xattrs(struct list_head *dst, struct list_head *src)
{
	struct tarerofs_xattr_item *item;

	list_for_each_entry(item, src, list) {
		int ret;

		ret = tarerofs_insert_xattr(dst, item->kv, item->namelen,
					    item->len, true);
		if (ret)
			return ret;
	}
	return 0;
}

void tarerofs_remove_xattrs(struct list_head *xattrs)
{
	struct tarerofs_xattr_item *item, *n;

	list_for_each_entry_safe(item, n, xattrs, list) {
		DBG_BUGON(!item->kv);
		free(item->kv);
		list_del(&item->list);
		free(item);
	}
}

int tarerofs_apply_xattrs(struct erofs_inode *inode, struct list_head *xattrs)
{
	struct tarerofs_xattr_item *item;
	int ret;

	list_for_each_entry(item, xattrs, list) {
		const char *v = item->kv + item->namelen + 1;
		unsigned int vsz = item->len - item->namelen - 1;

		if (item->len <= item->namelen - 1) {
			DBG_BUGON(item->len < item->namelen - 1);
			continue;
		}
		item->kv[item->namelen] = '\0';
		erofs_dbg("Recording xattr(%s)=\"%s\" (of %u bytes) to file %s",
			  item->kv, v, vsz, inode->i_srcpath);
		ret = erofs_setxattr(inode, item->kv, v, vsz);
		if (ret == -ENODATA)
			erofs_err("Failed to set xattr(%s)=%s to file %s",
				  item->kv, v, inode->i_srcpath);
		else if (ret)
			return ret;
	}
	return 0;
}

static const char lookup_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

static int base64_decode(const char *src, int len, u8 *dst)
{
	int i, bits = 0, ac = 0;
	const char *p;
	u8 *cp = dst;

	if(!(len % 4)) {
		/* Check for and ignore any end padding */
		if (src[len - 2] == '=' && src[len - 1] == '=')
			len -= 2;
		else if (src[len - 1] == '=')
			--len;
	}

	for (i = 0; i < len; i++) {
		p = strchr(lookup_table, src[i]);
		if (p == NULL || src[i] == 0)
			return -2;
		ac += (p - lookup_table) << bits;
		bits += 6;
		if (bits >= 8) {
			*cp++ = ac & 0xff;
			ac >>= 8;
			bits -= 8;
		}
	}
	if (ac)
		return -1;
	return cp - dst;
}

int tarerofs_parse_pax_header(int fd, struct erofs_pax_header *eh, u32 size)
{
	char *buf, *p;
	int ret;

	buf = malloc(size);
	if (!buf)
		return -ENOMEM;
	p = buf;

	ret = erofs_read_from_fd(fd, buf, size);
	if (ret != size)
		goto out;

	while (p < buf + size) {
		char *kv, *value;
		int len, n;
		/* extended records are of the format: "LEN NAME=VALUE\n" */
		ret = sscanf(p, "%d %n", &len, &n);
		if (ret < 1 || len <= n || len > buf + size - p) {
			ret = -EIO;
			goto out;
		}
		kv = p + n;
		p += len;
		len -= n;

		if (p[-1] != '\n') {
			ret = -EIO;
			goto out;
		}
		p[-1] = '\0';

		value = memchr(kv, '=', p - kv);
		if (!value) {
			ret = -EIO;
			goto out;
		} else {
			long long lln;

			value++;

			if (!strncmp(kv, "path=", sizeof("path=") - 1)) {
				int j = p - 1 - value;
				free(eh->path);
				eh->path = strdup(value);
				while (eh->path[j - 1] == '/')
					eh->path[--j] = '\0';
			} else if (!strncmp(kv, "linkpath=",
					sizeof("linkpath=") - 1)) {
				free(eh->link);
				eh->link = strdup(value);
			} else if (!strncmp(kv, "mtime=",
					sizeof("mtime=") - 1)) {
				ret = sscanf(value, "%lld %n", &lln, &n);
				if(ret < 1) {
					ret = -EIO;
					goto out;
				}
				eh->st.st_mtime = lln;
				if (value[n] == '.') {
					ret = sscanf(value + n + 1, "%d", &n);
					if (ret < 1) {
						ret = -EIO;
						goto out;
					}
#if ST_MTIM_NSEC
					ST_MTIM_NSEC(&eh->st) = n;
#endif
				}
				eh->use_mtime = true;
			} else if (!strncmp(kv, "size=",
					sizeof("size=") - 1)) {
				ret = sscanf(value, "%lld %n", &lln, &n);
				if(ret < 1 || value[n] != '\0') {
					ret = -EIO;
					goto out;
				}
				eh->st.st_size = lln;
				eh->use_size = true;
			} else if (!strncmp(kv, "uid=", sizeof("uid=") - 1)) {
				ret = sscanf(value, "%lld %n", &lln, &n);
				if(ret < 1 || value[n] != '\0') {
					ret = -EIO;
					goto out;
				}
				eh->st.st_uid = lln;
				eh->use_uid = true;
			} else if (!strncmp(kv, "gid=", sizeof("gid=") - 1)) {
				ret = sscanf(value, "%lld %n", &lln, &n);
				if(ret < 1 || value[n] != '\0') {
					ret = -EIO;
					goto out;
				}
				eh->st.st_gid = lln;
				eh->use_gid = true;
			} else if (!strncmp(kv, "SCHILY.xattr.",
				   sizeof("SCHILY.xattr.") - 1)) {
				char *key = kv + sizeof("SCHILY.xattr.") - 1;

				--len; /* p[-1] == '\0' */
				ret = tarerofs_insert_xattr(&eh->xattrs, key,
						value - key - 1,
						len - (key - kv), false);
				if (ret)
					goto out;
			} else if (!strncmp(kv, "LIBARCHIVE.xattr.",
				   sizeof("LIBARCHIVE.xattr.") - 1)) {
				char *key;
				key = kv + sizeof("LIBARCHIVE.xattr.") - 1;

				--len; /* p[-1] == '\0' */
				ret = base64_decode(value, len - (value - kv),
						    (u8 *)value);
				if (ret < 0) {
					ret = -EFSCORRUPTED;
					goto out;
				}

				ret = tarerofs_insert_xattr(&eh->xattrs, key,
						value - key - 1,
						value - key + ret, false);
				if (ret)
					goto out;
			} else {
				erofs_info("unrecognized pax keyword \"%s\", ignoring", kv);
			}
		}
	}
	ret = 0;
out:
	free(buf);
	return ret;
}

void tarerofs_remove_inode(struct erofs_inode *inode)
{
	struct erofs_dentry *d;

	--inode->i_nlink;
	if (!S_ISDIR(inode->i_mode))
		return;

	/* remove all subdirss */
	list_for_each_entry(d, &inode->i_subdirs, d_child) {
		if (!is_dot_dotdot(d->name))
			tarerofs_remove_inode(d->inode);
		erofs_iput(d->inode);
		d->inode = NULL;
	}
	--inode->i_parent->i_nlink;
}

static int tarerofs_write_file_data(struct erofs_inode *inode,
				    struct erofs_tarfile *tar)
{
	unsigned int j, rem;
	char buf[65536];

	if (!inode->i_tmpfile) {
		inode->i_tmpfile = tmpfile();
		if (!inode->i_tmpfile)
			return -ENOSPC;
	}

	for (j = inode->i_size; j; ) {
		rem = min_t(unsigned int, sizeof(buf), j);

		if (erofs_read_from_fd(tar->fd, buf, rem) != rem ||
		    fwrite(buf, rem, 1, inode->i_tmpfile) != 1)
			return -EIO;
		j -= rem;
	}
	fseek(inode->i_tmpfile, 0, SEEK_SET);
	inode->with_tmpfile = true;
	return 0;
}

static int tarerofs_write_file_index(struct erofs_inode *inode,
		struct erofs_tarfile *tar, erofs_off_t data_offset)
{
	int ret;

	ret = tarerofs_write_chunkes(inode, data_offset);
	if (ret)
		return ret;
	if (erofs_lskip(tar->fd, inode->i_size))
		return -EIO;
	return 0;
}

int tarerofs_parse_tar(struct erofs_inode *root, struct erofs_tarfile *tar)
{
	char path[PATH_MAX];
	struct erofs_pax_header eh = tar->global;
	struct erofs_sb_info *sbi = root->sbi;
	bool e, whout, opq;
	struct stat st;
	erofs_off_t tar_offset, data_offset;

	struct tar_header th;
	struct erofs_dentry *d;
	struct erofs_inode *inode;
	unsigned int j, csum, cksum;
	int ckksum, ret, rem;

	if (eh.path)
		eh.path = strdup(eh.path);
	if (eh.link)
		eh.link = strdup(eh.link);
	init_list_head(&eh.xattrs);

restart:
	rem = tar->offset & 511;
	if (rem) {
		if (erofs_lskip(tar->fd, 512 - rem)) {
			ret = -EIO;
			goto out;
		}
		tar->offset += 512 - rem;
	}

	tar_offset = tar->offset;
	ret = erofs_read_from_fd(tar->fd, &th, sizeof(th));
	if (ret != sizeof(th))
		goto out;
	tar->offset += sizeof(th);
	if (*th.name == '\0') {
		if (e) {	/* end of tar 2 empty blocks */
			ret = 1;
			goto out;
		}
		e = true;	/* empty jump to next block */
		goto restart;
	}

	if (strncmp(th.magic, "ustar", 5)) {
		erofs_err("invalid tar magic @ %llu", tar_offset);
		ret = -EIO;
		goto out;
	}

	/* chksum field itself treated as ' ' */
	csum = tarerofs_otoi(th.chksum, sizeof(th.chksum));
	if (errno) {
		erofs_err("invalid chksum @ %llu", tar_offset);
		ret = -EBADMSG;
		goto out;
	}
	cksum = 0;
	for (j = 0; j < 8; ++j)
		cksum += (unsigned int)' ';
	ckksum = cksum;
	for (j = 0; j < 148; ++j) {
		cksum += (unsigned int)((u8*)&th)[j];
		ckksum += (int)((char*)&th)[j];
	}
	for (j = 156; j < 500; ++j) {
		cksum += (unsigned int)((u8*)&th)[j];
		ckksum += (int)((char*)&th)[j];
	}
	if (csum != cksum && csum != ckksum) {
		erofs_err("chksum mismatch @ %llu", tar_offset);
		ret = -EBADMSG;
		goto out;
	}

	st.st_mode = tarerofs_otoi(th.mode, sizeof(th.mode));
	if (errno)
		goto invalid_tar;

	if (eh.use_uid) {
		st.st_uid = eh.st.st_uid;
	} else {
		st.st_uid = tarerofs_parsenum(th.uid, sizeof(th.uid));
		if (errno)
			goto invalid_tar;
	}

	if (eh.use_gid) {
		st.st_gid = eh.st.st_gid;
	} else {
		st.st_gid = tarerofs_parsenum(th.gid, sizeof(th.gid));
		if (errno)
			goto invalid_tar;
	}

	if (eh.use_size) {
		st.st_size = eh.st.st_size;
	} else {
		st.st_size = tarerofs_parsenum(th.size, sizeof(th.size));
		if (errno)
			goto invalid_tar;
	}

	if (eh.use_mtime) {
		st.st_mtime = eh.st.st_mtime;
#if ST_MTIM_NSEC
		ST_MTIM_NSEC(&st) = ST_MTIM_NSEC(&eh.st);
#endif
	} else {
		st.st_mtime = tarerofs_parsenum(th.mtime, sizeof(th.mtime));
		if (errno)
			goto invalid_tar;
	}

	if (th.typeflag <= '7' && !eh.path) {
		eh.path = path;
		j = 0;
		if (*th.prefix) {
			memcpy(path, th.prefix, sizeof(th.prefix));
			path[sizeof(th.prefix)] = '\0';
			j = strlen(path);
			if (path[j - 1] != '/') {
				path[j] = '/';
				path[++j] = '\0';
			}
		}
		memcpy(path + j, th.name, sizeof(th.name));
		path[j + sizeof(th.name)] = '\0';
		j = strlen(path);
		while (path[j - 1] == '/')
			path[--j] = '\0';
	}

	data_offset = tar->offset;
	tar->offset += st.st_size;
	if (th.typeflag == '0' || th.typeflag == '7' || th.typeflag == '1') {
		st.st_mode |= S_IFREG;
	} else if (th.typeflag == '2') {
		st.st_mode |= S_IFLNK;
	} else if (th.typeflag == '3') {
		st.st_mode |= S_IFCHR;
	} else if (th.typeflag == '4') {
		st.st_mode |= S_IFBLK;
	} else if (th.typeflag == '5') {
		st.st_mode |= S_IFDIR;
	} else if (th.typeflag == '6') {
		st.st_mode |= S_IFIFO;
	} else if (th.typeflag == 'g') {
		ret = tarerofs_parse_pax_header(tar->fd, &tar->global, st.st_size);
		if (ret)
			goto out;
		if (tar->global.path) {
			free(eh.path);
			eh.path = strdup(tar->global.path);
		}
		if (tar->global.link) {
			free(eh.link);
			eh.link = strdup(tar->global.link);
		}
		goto restart;
	} else if (th.typeflag == 'x') {
		ret = tarerofs_parse_pax_header(tar->fd, &eh, st.st_size);
		if (ret)
			goto out;
		goto restart;
	} else if (th.typeflag == 'L') {
		free(eh.path);
		eh.path = malloc(st.st_size + 1);
		if (st.st_size != erofs_read_from_fd(tar->fd, eh.path,
						     st.st_size))
			goto invalid_tar;
		eh.path[st.st_size] = '\0';
		goto restart;
	} else if (th.typeflag == 'K') {
		free(eh.link);
		eh.link = malloc(st.st_size + 1);
		if (st.st_size > PATH_MAX || st.st_size !=
		    erofs_read_from_fd(tar->fd, eh.link, st.st_size))
			goto invalid_tar;
		eh.link[st.st_size] = '\0';
		goto restart;
	} else {
		erofs_info("unrecognized typeflag %xh @ %llu - ignoring",
			   th.typeflag, tar_offset);
		(void)erofs_lskip(tar->fd, st.st_size);
		ret = 0;
		goto out;
	}

	st.st_rdev = 0;
	if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) {
		int major, minor;

		major = tarerofs_parsenum(th.devmajor, sizeof(th.devmajor));
		if (errno) {
			erofs_err("invalid device major @ %llu", tar_offset);
			goto out;
		}

		minor = tarerofs_parsenum(th.devminor, sizeof(th.devminor));
		if (errno) {
			erofs_err("invalid device minor @ %llu", tar_offset);
			goto out;
		}

		st.st_rdev = (major << 8) | (minor & 0xff) | ((minor & ~0xff) << 12);
	} else if (th.typeflag == '1' || th.typeflag == '2') {
		if (!eh.link)
			eh.link = strndup(th.linkname, sizeof(th.linkname));
	}

	if (tar->index_mode && !tar->mapfile &&
	    erofs_blkoff(sbi, data_offset)) {
		erofs_err("invalid tar data alignment @ %llu", tar_offset);
		ret = -EIO;
		goto out;
	}

	erofs_dbg("parsing %s (mode %05o)", eh.path, st.st_mode);

	d = tarerofs_get_dentry(root, eh.path, tar->aufs, &whout, &opq);
	if (IS_ERR(d)) {
		ret = PTR_ERR(d);
		goto out;
	}

	if (!d) {
		/* some tarballs include '.' which indicates the root directory */
		if (!S_ISDIR(st.st_mode)) {
			ret = -ENOTDIR;
			goto out;
		}
		inode = root;
	} else if (opq) {
		DBG_BUGON(d->type == EROFS_FT_UNKNOWN);
		DBG_BUGON(!d->inode);
		ret = erofs_setxattr(d->inode, OVL_XATTR_OPAQUE, "y", 1);
		goto out;
	} else if (th.typeflag == '1') {	/* hard link cases */
		struct erofs_dentry *d2;
		bool dumb;

		if (S_ISDIR(st.st_mode)) {
			ret = -EISDIR;
			goto out;
		}

		if (d->type != EROFS_FT_UNKNOWN) {
			tarerofs_remove_inode(d->inode);
			erofs_iput(d->inode);
		}
		d->inode = NULL;

		d2 = tarerofs_get_dentry(root, eh.link, tar->aufs, &dumb, &dumb);
		if (IS_ERR(d2)) {
			ret = PTR_ERR(d2);
			goto out;
		}
		if (d2->type == EROFS_FT_UNKNOWN) {
			ret = -ENOENT;
			goto out;
		}
		if (S_ISDIR(d2->inode->i_mode)) {
			ret = -EISDIR;
			goto out;
		}
		inode = erofs_igrab(d2->inode);
		d->inode = inode;
		d->type = d2->type;
		++inode->i_nlink;
		ret = 0;
		goto out;
	} else if (d->type != EROFS_FT_UNKNOWN) {
		if (d->type != EROFS_FT_DIR || !S_ISDIR(st.st_mode)) {
			struct erofs_inode *parent = d->inode->i_parent;

			tarerofs_remove_inode(d->inode);
			erofs_iput(d->inode);
			d->inode = parent;
			goto new_inode;
		}
		inode = d->inode;
	} else {
new_inode:
		inode = erofs_new_inode();
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			goto out;
		}
		inode->i_parent = d->inode;
		d->inode = inode;
		d->type = erofs_mode_to_ftype(st.st_mode);
	}

	if (whout) {
		inode->i_mode = (inode->i_mode & ~S_IFMT) | S_IFCHR;
		inode->u.i_rdev = EROFS_WHITEOUT_DEV;
		d->type = EROFS_FT_CHRDEV;
	} else {
		inode->i_mode = st.st_mode;
		if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode))
			inode->u.i_rdev = erofs_new_encode_dev(st.st_rdev);
	}
	inode->i_srcpath = strdup(eh.path);
	inode->i_uid = st.st_uid;
	inode->i_gid = st.st_gid;
	inode->i_size = st.st_size;
	inode->i_mtime = st.st_mtime;

	if (!S_ISDIR(inode->i_mode)) {
		if (S_ISLNK(inode->i_mode)) {
			inode->i_size = strlen(eh.link);
			inode->i_link = malloc(inode->i_size + 1);
			memcpy(inode->i_link, eh.link, inode->i_size + 1);
		} else if (inode->i_size) {
			if (tar->index_mode)
				ret = tarerofs_write_file_index(inode, tar,
								data_offset);
			else
				ret = tarerofs_write_file_data(inode, tar);
			if (ret) {
				erofs_iput(inode);
				goto out;
			}
		}
		inode->i_nlink++;
	} else if (!inode->i_nlink) {
		ret = erofs_init_empty_dir(inode);
		if (ret)
			goto out;
	}

	ret = tarerofs_merge_xattrs(&eh.xattrs, &tar->global.xattrs);
	if (ret)
		goto out;

	ret = tarerofs_apply_xattrs(inode, &eh.xattrs);

out:
	if (eh.path != path)
		free(eh.path);
	free(eh.link);
	tarerofs_remove_xattrs(&eh.xattrs);
	return ret;

invalid_tar:
	erofs_err("invalid tar @ %llu", tar_offset);
	ret = -EIO;
	goto out;
}
