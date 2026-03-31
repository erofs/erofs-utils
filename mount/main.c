// SPDX-License-Identifier: GPL-2.0+
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>
#include "erofs/config.h"
#include "erofs/print.h"
#include "erofs/err.h"
#include "erofs/io.h"
#include "../lib/liberofs_nbd.h"
#include "../lib/liberofs_oci.h"
#include "../lib/liberofs_gzran.h"
#ifdef EROFS_FANOTIFY_ENABLED
#include "../lib/liberofs_fanotify.h"
#endif

#ifdef HAVE_LINUX_LOOP_H
#include <linux/loop.h>
#else
#define LOOP_CTL_GET_FREE	0x4C82
#define LOOP_SET_FD		0x4C00
#define LOOP_SET_STATUS		0x4C02
enum {
	LO_FLAGS_AUTOCLEAR = 4,
};
struct loop_info {
	char	pad[44];
	int	lo_flags;
	char    pad1[120];
};
#endif
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif

/* Device boundary probe */
#define EROFSMOUNT_NBD_DISK_SIZE	(INT64_MAX >> 9)
#define EROFSMOUNT_CACHE_DIR	"/var/cache/erofsmount"
#define EROFSMOUNT_RUNTIME_DIR	"/run/erofsmount"
#define EROFSMOUNT_FANOTIFY_STATE_DIR	EROFSMOUNT_RUNTIME_DIR "/fanotify"

#ifdef EROFS_FANOTIFY_ENABLED
#define EROFSMOUNT_FANOTIFY_HELP	", fanotify"
#else
#define EROFSMOUNT_FANOTIFY_HELP	""
#endif

enum erofs_backend_drv {
	EROFSAUTO,
	EROFSLOCAL,
	EROFSFUSE,
	EROFSNBD,
	EROFSFANOTIFY,
};

enum erofsmount_mode {
	EROFSMOUNT_MODE_MOUNT,
	EROFSMOUNT_MODE_UMOUNT,
	EROFSMOUNT_MODE_DISCONNECT,
	EROFSMOUNT_MODE_REATTACH,
};

static struct erofsmount_cfg {
	char *device;
	char *target;
	char *options;
	char *full_options;		/* used for erofsfuse */
	char *fstype;
	long flags;
	enum erofs_backend_drv backend;
	enum erofsmount_mode mountmode;
	bool force_loopdev;
} mountcfg = {
	.full_options = "ro",
	.flags = MS_RDONLY,		/* default mountflags */
	.fstype = "erofs",
};

enum erofsmount_source_type {
	EROFSMOUNT_SOURCE_LOCAL,
	EROFSMOUNT_SOURCE_OCI,
};

static struct erofsmount_source {
	enum erofsmount_source_type type;
	union {
		const char *device_path;
		struct ocierofs_config ocicfg;
	};
} mountsrc;

static void usage(int argc, char **argv)
{
	printf("Usage: %s [OPTIONS] SOURCE [MOUNTPOINT]\n"
		"Manage EROFS filesystem.\n"
		"\n"
		"General options:\n"
		" -V, --version         print the version number of mount.erofs and exit\n"
		" -h, --help            display this help and exit\n"
		" -d <0-9>              set output verbosity; 0=quiet, 9=verbose (default=%i)\n"
		" -o options            comma-separated list of mount options\n"
		" -t type[.subtype]     filesystem type (and optional subtype)\n"
		"                       subtypes: fuse, local, nbd" EROFSMOUNT_FANOTIFY_HELP "\n"
		" -u                    unmount the filesystem\n"
		"    --disconnect       abort an existing NBD device forcibly\n"
		"    --reattach         reattach to an existing NBD device\n"
#ifdef OCIEROFS_ENABLED
		"\n"
		"OCI-specific options (EXPERIMENTAL, with -o):\n"
		"   oci.blob=<digest>   specify OCI blob digest (sha256:...)\n"
		"   oci.layer=<index>   specify OCI layer index\n"
		"   oci.platform=<name> specify platform (default: linux/amd64)\n"
		"   oci.username=<user> username for authentication (optional)\n"
		"   oci.password=<pass> password for authentication (optional)\n"
		"   oci.tarindex=<path> path to tarball index file (optional)\n"
		"   oci.zinfo=<path>    path to gzip zinfo file (optional)\n"
		"   oci.insecure        use HTTP instead of HTTPS (optional)\n"
#endif
		, argv[0], EROFS_WARN);
}

static void version(void)
{
	printf("mount.erofs (erofs-utils) %s\n", cfg.c_version);
}

#ifdef OCIEROFS_ENABLED
static int erofsmount_parse_oci_option(const char *option)
{
	struct ocierofs_config *oci_cfg = &mountsrc.ocicfg;
	const char *p;
	long idx;

	if ((p = strstr(option, "oci.blob=")) != NULL) {
		p += strlen("oci.blob=");
		free(oci_cfg->blob_digest);

		if (oci_cfg->layer_index >= 0) {
			erofs_err("invalid options: oci.blob and oci.layer cannot be set together");
			return -EINVAL;
		}

		if (!strncmp(p, "sha256:", 7)) {
			oci_cfg->blob_digest = strdup(p);
			if (!oci_cfg->blob_digest)
				return -ENOMEM;
		} else if (asprintf(&oci_cfg->blob_digest, "sha256:%s", p) < 0) {
			return -ENOMEM;
		}
	} else if ((p = strstr(option, "oci.layer=")) != NULL) {
		p += strlen("oci.layer=");
		if (oci_cfg->blob_digest) {
			erofs_err("invalid options: oci.layer and oci.blob cannot be set together");
			return -EINVAL;
		}
		idx = strtol(p, NULL, 10);
		if (idx < 0)
			return -EINVAL;
		oci_cfg->layer_index = (int)idx;
	} else if ((p = strstr(option, "oci.platform=")) != NULL) {
		p += strlen("oci.platform=");
		free(oci_cfg->platform);
		oci_cfg->platform = strdup(p);
		if (!oci_cfg->platform)
			return -ENOMEM;
	} else if ((p = strstr(option, "oci.username=")) != NULL) {
		p += strlen("oci.username=");
		free(oci_cfg->username);
		oci_cfg->username = strdup(p);
		if (!oci_cfg->username)
			return -ENOMEM;
	} else if ((p = strstr(option, "oci.password=")) != NULL) {
		p += strlen("oci.password=");
		free(oci_cfg->password);
		oci_cfg->password = strdup(p);
		if (!oci_cfg->password)
			return -ENOMEM;
	} else if ((p = strstr(option, "oci.tarindex=")) != NULL) {
		p += strlen("oci.tarindex=");
		free(oci_cfg->tarindex_path);
		oci_cfg->tarindex_path = strdup(p);
		if (!oci_cfg->tarindex_path)
			return -ENOMEM;
	} else if ((p = strstr(option, "oci.zinfo=")) != NULL) {
		p += strlen("oci.zinfo=");
		free(oci_cfg->zinfo_path);
		oci_cfg->zinfo_path = strdup(p);
		if (!oci_cfg->zinfo_path)
			return -ENOMEM;
	} else if ((p = strstr(option, "oci.insecure")) != NULL) {
		oci_cfg->insecure = true;
	} else {
		return -EINVAL;
	}
	return 0;
}
#else
static int erofsmount_parse_oci_option(const char *option)
{
	return -EINVAL;
}
#endif

static long erofsmount_parse_flagopts(char *s, long flags, char **more)
{
	static const struct {
		char *name;
		long flags;
	} opts[] = {
		{"defaults", 0}, {"quiet", 0}, // NOPs
		{"user", 0}, {"nouser", 0}, // checked in fstab, ignored in -o
		{"ro", MS_RDONLY}, {"rw", ~(long)MS_RDONLY},
		{"nosuid", MS_NOSUID}, {"suid", ~(long)MS_NOSUID},
		{"nodev", MS_NODEV}, {"dev", ~(long)MS_NODEV},
		{"noexec", MS_NOEXEC}, {"exec", ~(long)MS_NOEXEC},
		{"sync", MS_SYNCHRONOUS}, {"async", ~(long)MS_SYNCHRONOUS},
		{"noatime", MS_NOATIME}, {"atime", ~(long)MS_NOATIME},
		{"norelatime", ~(long)MS_RELATIME}, {"relatime", MS_RELATIME},
		{"nodiratime", MS_NODIRATIME}, {"diratime", ~(long)MS_NODIRATIME},
		{"loud", ~(long)MS_SILENT},
		{"remount", MS_REMOUNT}, {"move", MS_MOVE},
		// mand dirsync rec iversion strictatime
	};

	for (;;) {
		char *comma;
		int i;
		int err;

		comma = strchr(s, ',');
		if (comma)
			*comma = '\0';

		if (!strcmp(s, "loop")) {
			mountcfg.force_loopdev = true;
		} else if (strncmp(s, "oci", 3) == 0) {
			/* Initialize ocicfg here iff != EROFSMOUNT_SOURCE_OCI */
			if (mountsrc.type != EROFSMOUNT_SOURCE_OCI) {
				erofs_warn("EXPERIMENTAL OCI mount support in use, use at your own risk.");
				erofs_warn("Note that runtime performance is still unoptimized.");
				mountsrc.type = EROFSMOUNT_SOURCE_OCI;
				mountsrc.ocicfg.layer_index = -1;
			}
			err = erofsmount_parse_oci_option(s);
			if (err < 0)
				return err;
		} else {
			for (i = 0; i < ARRAY_SIZE(opts); ++i) {
				if (!strcasecmp(s, opts[i].name)) {
					if (opts[i].flags < 0)
						flags &= opts[i].flags;
					else
						flags |= opts[i].flags;
					break;
				}
			}

			if (more && i >= ARRAY_SIZE(opts)) {
				int sl = strlen(s);
				char *new = *more;

				i = new ? strlen(new) : 0;
				new = realloc(new, i + strlen(s) + 2);
				if (!new)
					return -ENOMEM;
				if (i)
					new[i++] = ',';
				memcpy(new + i, s, sl);
				new[i + sl] = '\0';
				*more = new;
			}
		}

		if (!comma)
			break;
		*comma = ',';
		s = comma + 1;
	}
	return flags;
}

static int erofsmount_parse_options(int argc, char **argv)
{
	static const struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"version", no_argument, 0, 'V'},
		{"reattach", no_argument, 0, 512},
		{"disconnect", no_argument, 0, 513},
		{0, 0, 0, 0},
	};
	char *dot;
	long ret;
	int opt;
	int i;

	mountsrc.ocicfg.layer_index = -1;

	while ((opt = getopt_long(argc, argv, "VNfhd:no:st:uv",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argc, argv);
			exit(0);
		case 'V':
			version();
			exit(0);
		case 'd':
			i = atoi(optarg);
			if (i < EROFS_MSG_MIN || i > EROFS_MSG_MAX) {
				erofs_err("invalid debug level %d", i);
				return -EINVAL;
			}
			cfg.c_dbg_lvl = i;
			break;
		case 'o':
			mountcfg.full_options = optarg;
			ret = erofsmount_parse_flagopts(optarg, mountcfg.flags,
							&mountcfg.options);
			if (ret < 0)
				return (int)ret;
			mountcfg.flags = ret;
			break;
		case 't':
			dot = strchr(optarg, '.');
			if (dot) {
				if (!strcmp(dot + 1, "fuse")) {
					mountcfg.backend = EROFSFUSE;
				} else if (!strcmp(dot + 1, "local")) {
					mountcfg.backend = EROFSLOCAL;
				} else if (!strcmp(dot + 1, "nbd")) {
					mountcfg.backend = EROFSNBD;
				} else if (!strcmp(dot + 1, "fanotify")) {
#ifdef EROFS_FANOTIFY_ENABLED
					mountcfg.backend = EROFSFANOTIFY;
#else
					erofs_err("fanotify backend support is not built-in");
					return -EINVAL;
#endif
				} else {
					erofs_err("invalid filesystem subtype `%s`", dot + 1);
					return -EINVAL;
				}
				*dot = '\0';
			}
			mountcfg.fstype = optarg;
			break;
		case 'u':
			mountcfg.mountmode = EROFSMOUNT_MODE_UMOUNT;
			break;
		case 512:
			mountcfg.mountmode = EROFSMOUNT_MODE_REATTACH;
			break;
		case 513:
			mountcfg.mountmode = EROFSMOUNT_MODE_DISCONNECT;
			break;
		default:
			return -EINVAL;
		}
	}
	if (mountcfg.mountmode == EROFSMOUNT_MODE_MOUNT) {
		if (optind >= argc) {
			erofs_err("missing argument: DEVICE");
			return -EINVAL;
		}

		mountcfg.device = strdup(argv[optind++]);
		if (!mountcfg.device)
			return -ENOMEM;
	}
	if (optind >= argc) {
		if (mountcfg.mountmode == EROFSMOUNT_MODE_MOUNT)
			erofs_err("missing argument: MOUNTPOINT");
		else
			erofs_err("missing argument: TARGET");
		return -EINVAL;
	}

	mountcfg.target = strdup(argv[optind++]);
	if (!mountcfg.target)
		return -ENOMEM;

	if (optind < argc) {
		erofs_err("unexpected argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	return 0;
}

static int erofsmount_fuse(const char *source, const char *mountpoint,
			   const char *fstype, const char *options)
{
	char *command;
	int err;

	if (strcmp(fstype, "erofs")) {
		fprintf(stderr, "unsupported filesystem type `%s`\n",
			mountcfg.fstype);
		return -ENODEV;
	}

	err = asprintf(&command, "erofsfuse -o%s %s %s", options,
		       source, mountpoint);
	if (err < 0)
		return -ENOMEM;

	/* execvp() doesn't work for external mount helpers here */
	err = execl("/bin/sh", "/bin/sh", "-c", command, NULL);
	if (err < 0) {
		perror("failed to execute /bin/sh");
		return -errno;
	}
	return 0;
}

struct erofsmount_tarindex_priv {
	struct erofs_vfile tarindex_vf;
	struct erofs_vfile *zinfo_vf;
	u64 tarindex_size;
};

static ssize_t erofsmount_tarindex_pread(struct erofs_vfile *vf, void *buf,
					 size_t count, u64 offset)
{
	struct erofsmount_tarindex_priv *tp;
	ssize_t local_read = 0, remote_read = 0;
	u64 index_part, tardata_part, remote_offset;

	tp = *(struct erofsmount_tarindex_priv **)vf->payload;
	DBG_BUGON(!tp);

	/* Handle device boundary probe requests */
	if (offset >= EROFSMOUNT_NBD_DISK_SIZE)
		return 0;

	if (offset > tp->tarindex_size) {
		remote_offset = offset - tp->tarindex_size;
		index_part = 0;
	} else {
		index_part = min_t(u64, count, tp->tarindex_size - offset);
		remote_offset = 0;
	}
	tardata_part = count - index_part;
	if (index_part) {
		local_read = erofs_io_pread(&tp->tarindex_vf, buf,
					    index_part, offset);
		if (local_read < 0)
			return local_read;
	}
	if (tardata_part) {
		remote_read = erofs_io_pread(tp->zinfo_vf, buf + local_read,
					     tardata_part, remote_offset);
		if (remote_read < 0)
			return remote_read;
	}
	return local_read + remote_read;
}

static void erofsmount_tarindex_close(struct erofs_vfile *vf)
{
	struct erofsmount_tarindex_priv *tp;

	tp = *(struct erofsmount_tarindex_priv **)vf->payload;
	DBG_BUGON(!tp);

	if (tp->tarindex_size > 0)
		erofs_io_close(&tp->tarindex_vf);
	if (tp->zinfo_vf)
		erofs_io_close(tp->zinfo_vf);
	free(tp);
}

static struct erofs_vfops tarindex_vfile_ops = {
	.pread = erofsmount_tarindex_pread,
	.close = erofsmount_tarindex_close,
};

static int load_file_to_buf(const char *path, void **out, unsigned int *out_len)
{
	void *buf = NULL;
	FILE *fp;
	int ret = 0;
	long sz;
	size_t num;

	fp = fopen(path, "rb");
	if (!fp)
		return -errno;

	if (fseek(fp, 0, SEEK_END) != 0) {
		ret = -errno;
		goto out;
	}
	sz = ftell(fp);
	if (sz < 0) {
		ret = -errno;
		goto out;
	}
	rewind(fp);
	if (!sz) {
		ret = -EINVAL;
		goto out;
	}

	buf = malloc((size_t)sz);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	num = fread(buf, 1, (size_t)sz, fp);
	if (num != (size_t)sz) {
		ret = -EIO;
		goto out;
	}
	*out = buf;
	*out_len = (unsigned int)sz;
	buf = NULL;
out:
	if (ret < 0 && buf)
		free(buf);
	fclose(fp);
	return ret;
}

static int erofsmount_init_gzran(struct erofs_vfile **zinfo_vf,
				  const struct ocierofs_config *oci_cfg,
				  const char *zinfo_path)
{
	int err = 0;
	void *zinfo_data = NULL;
	unsigned int zinfo_len = 0;
	struct erofs_vfile *oci_vf = NULL;

	oci_vf = malloc(sizeof(*oci_vf));
	if (!oci_vf) {
		err = -ENOMEM;
		goto cleanup;
	}

	err = ocierofs_io_open(oci_vf, oci_cfg);
	if (err) {
		free(oci_vf);
		goto cleanup;
	}

	/* If no zinfo_path, return oci_vf directly for tar format */
	if (!zinfo_path) {
		*zinfo_vf = oci_vf;
		return 0;
	}

	err = load_file_to_buf(zinfo_path, &zinfo_data, &zinfo_len);
	if (err) {
		erofs_io_close(oci_vf);
		free(oci_vf);
		return err;
	}

	*zinfo_vf = erofs_gzran_zinfo_open(oci_vf, zinfo_data, zinfo_len);
	if (IS_ERR(*zinfo_vf)) {
		err = PTR_ERR(*zinfo_vf);
		*zinfo_vf = NULL;
		erofs_io_close(oci_vf);
		free(oci_vf);
		goto cleanup;
	}

	free(zinfo_data);
	return 0;

cleanup:
	if (zinfo_data)
		free(zinfo_data);
	return err;
}

/*
 * Create tarindex source for gzran+oci hybrid mode with three scenarios:
 * 1. tarindex + zinfo: Remote data is tar.gzip format
 * 2. tarindex only: Remote data is tar format
 */
static int erofsmount_tarindex_open(struct erofs_vfile *out_vf,
				    const struct ocierofs_config *oci_cfg,
				    const char *tarindex_path,
				    const char *zinfo_path)
{
	struct erofsmount_tarindex_priv *tp;
	int err;
	struct stat st;
	struct erofs_vfile *vf;

	tp = calloc(1, sizeof(*tp));
	if (!tp)
		return -ENOMEM;
	vf = &tp->tarindex_vf;
	vf->fd = -1;

	if (tarindex_path) {
		err = open(tarindex_path, O_RDONLY);
		if (err < 0) {
			err = -errno;
			goto err_out;
		}
		vf->fd = err;
		if (fstat(vf->fd, &st) < 0) {
			err = -errno;
			goto err_out;
		}
		tp->tarindex_size = st.st_size;
	}

	err = erofsmount_init_gzran(&tp->zinfo_vf, oci_cfg, zinfo_path);
	if (err)
		goto err_out;
	out_vf->ops = &tarindex_vfile_ops;
	out_vf->fd = 0;
	out_vf->offset = 0;
	*(struct erofsmount_tarindex_priv **)out_vf->payload = tp;
	return 0;

err_out:
	if (vf->fd >= 0)
		close(vf->fd);
	free(tp);
	return err;
}

struct erofsmount_nbd_ctx {
	struct erofs_vfile vd;		/* virtual device */
	struct erofs_vfile sk;		/* socket file */
};

static void *erofsmount_nbd_loopfn(void *arg)
{
	struct erofsmount_nbd_ctx *ctx = arg;
	int err;

	while (1) {
		struct erofs_nbd_request rq;
		ssize_t written;
		off_t pos;

		err = erofs_nbd_get_request(ctx->sk.fd, &rq);
		if (err < 0) {
			if (err == -EPIPE)
				err = 0;
			break;
		}

		if (rq.type != EROFS_NBD_CMD_READ) {
			err = erofs_nbd_send_reply_header(ctx->sk.fd,
						rq.cookie, -EIO);
			if (err)
				break;
		}

		erofs_nbd_send_reply_header(ctx->sk.fd, rq.cookie, 0);
		pos = rq.from;
		do {
			written = erofs_io_sendfile(&ctx->sk, &ctx->vd, &pos, rq.len);
			if (written == -EINTR) {
				err = written;
				goto out;
			}
		} while (written < 0);
		err = __erofs_0write(ctx->sk.fd, rq.len - written);
		if (err) {
			if (err > 0)
				err = -EIO;
			break;
		}
	}
out:
	erofs_io_close(&ctx->vd);
	erofs_io_close(&ctx->sk);
	return (void *)(uintptr_t)err;
}

static int erofsmount_startnbd(int nbdfd, struct erofsmount_source *source)
{
	struct erofsmount_nbd_ctx ctx = {};
	uintptr_t retcode;
	pthread_t th;
	int err, err2;

	if (source->type == EROFSMOUNT_SOURCE_OCI) {
		if (source->ocicfg.tarindex_path || source->ocicfg.zinfo_path) {
			err = erofsmount_tarindex_open(&ctx.vd, &source->ocicfg,
						       source->ocicfg.tarindex_path,
						       source->ocicfg.zinfo_path);
			if (err)
				goto out_closefd;
		} else {
			err = ocierofs_io_open(&ctx.vd, &source->ocicfg);
			if (err)
				goto out_closefd;
		}
	} else {
		err = open(source->device_path, O_RDONLY);
		if (err < 0) {
			err = -errno;
			goto out_closefd;
		}
		ctx.vd.fd = err;
	}

	err = erofs_nbd_connect(nbdfd, 9, EROFSMOUNT_NBD_DISK_SIZE);
	if (err < 0) {
		erofs_io_close(&ctx.vd);
		goto out_closefd;
	}
	ctx.sk.fd = err;

	err = -pthread_create(&th, NULL, erofsmount_nbd_loopfn, &ctx);
	if (err) {
		erofs_io_close(&ctx.vd);
		erofs_io_close(&ctx.sk);
		goto out_closefd;
	}

	err = erofs_nbd_do_it(nbdfd);
	err2 = -pthread_join(th, (void **)&retcode);
	if (!err2 && retcode) {
		erofs_err("NBD worker failed with %s",
		          erofs_strerror(retcode));
		err2 = retcode;
	}
	return err ?: err2;
out_closefd:
	close(nbdfd);
	return err;
}

#ifdef OCIEROFS_ENABLED
static int erofsmount_write_recovery_oci(FILE *f, struct erofsmount_source *source)
{
	char *b64cred = NULL;
	const char *platform;
	int ret;

	if (source->ocicfg.username || source->ocicfg.password) {
		b64cred = ocierofs_encode_userpass(source->ocicfg.username,
						   source->ocicfg.password);
		if (IS_ERR(b64cred))
			return PTR_ERR(b64cred);
	}

	platform = source->ocicfg.platform;
	if (!platform || !*platform)
		platform = ocierofs_get_platform_spec();

	if ((source->ocicfg.tarindex_path || source->ocicfg.zinfo_path) &&
	    source->ocicfg.blob_digest && *source->ocicfg.blob_digest) {
		ret = fprintf(f, "TARINDEX_OCI_BLOB %s %s %s %s %s %s\n",
			      source->ocicfg.image_ref ?: "",
			      platform ?: "",
			      source->ocicfg.blob_digest,
			      b64cred ?: "",
			      source->ocicfg.tarindex_path ?: "",
			      source->ocicfg.zinfo_path ?: "");
		free(b64cred);
		return ret < 0 ? -ENOMEM : 0;
	}

	if (source->ocicfg.blob_digest && *source->ocicfg.blob_digest) {
		ret = fprintf(f, "OCI_NATIVE_BLOB %s %s %s %s\n",
			      source->ocicfg.image_ref ?: "",
			      platform ?: "",
			      source->ocicfg.blob_digest,
			      b64cred ?: "");
		free(b64cred);
		return ret < 0 ? -ENOMEM : 0;
	}

	if (source->ocicfg.layer_index >= 0) {
		ret = fprintf(f, "OCI_LAYER %s %s %d %s\n",
			      source->ocicfg.image_ref ?: "",
			      platform ?: "",
			      source->ocicfg.layer_index,
			      b64cred ?: "");
		free(b64cred);
		return ret < 0 ? -ENOMEM : 0;
	}

	free(b64cred);
	return -EINVAL;
}
#else
static int erofsmount_write_recovery_oci(FILE *f, struct erofsmount_source *source)
{
	return -EOPNOTSUPP;
}
#endif

static int erofsmount_write_recovery_local(FILE *f, struct erofsmount_source *source)
{
	char *realp;
	int err;

	realp = realpath(source->device_path, NULL);
	if (!realp)
		return -errno;

	/* TYPE<LOCAL> <SOURCE PATH>\n(more..) */
	err = fprintf(f, "LOCAL %s\n", realp) < 0;
	free(realp);
	return err ? -ENOMEM : 0;
}

static char *erofsmount_write_recovery_info(struct erofsmount_source *source)
{
	char recp[] = "/var/run/erofs/mountnbd_XXXXXX";
	int fd, err;
	FILE *f;

	fd = mkstemp(recp);
	if (fd < 0 && errno == ENOENT) {
		err = mkdir("/var/run/erofs", 0700);
		if (err)
			return ERR_PTR(-errno);
		fd = mkstemp(recp);
	}
	if (fd < 0)
		return ERR_PTR(-errno);

	f = fdopen(fd, "w+");
	if (!f) {
		close(fd);
		return ERR_PTR(-errno);
	}

	if (source->type == EROFSMOUNT_SOURCE_OCI)
		err = erofsmount_write_recovery_oci(f, source);
	else
		err = erofsmount_write_recovery_local(f, source);

	fclose(f);
	if (err)
		return ERR_PTR(err);
	return strdup(recp) ?: ERR_PTR(-ENOMEM);
}

#ifdef OCIEROFS_ENABLED
/* Parse input string in format: "image_ref platform layer [b64cred]" */
static int erofsmount_parse_recovery_ocilayer(struct ocierofs_config *oci_cfg,
					      char *source)
{
	char *tokens[4] = {0};
	int token_count = 0;
	char *p = source;
	int err;
	char *endptr;
	unsigned long v;

	while (token_count < 4 && (p = strchr(p, ' ')) != NULL) {
		*p++ = '\0';
		while (*p == ' ')
			p++;
		if (*p == '\0')
			break;
		tokens[token_count++] = p;
	}

	if (token_count < 2)
		return -EINVAL;

	oci_cfg->image_ref = source;
	oci_cfg->platform = tokens[0];

	v = strtoul(tokens[1], &endptr, 10);
	if (endptr == tokens[1] || *endptr != '\0')
		return -EINVAL;
	oci_cfg->layer_index = (int)v;
	free(oci_cfg->blob_digest);
	oci_cfg->blob_digest = NULL;

	if (token_count > 2) {
		err = ocierofs_decode_userpass(tokens[2], &oci_cfg->username,
					       &oci_cfg->password);
		if (err)
			return err;
	}
	return 0;
}

static int erofsmount_parse_recovery_ociblob(struct ocierofs_config *oci_cfg,
					    char *source)
{
	char *tokens[4] = {0};
	int token_count = 0;
	char *p = source;
	int err;

	while (token_count < 4 && (p = strchr(p, ' ')) != NULL) {
		*p++ = '\0';
		while (*p == ' ')
			p++;
		if (*p == '\0')
			break;
		tokens[token_count++] = p;
	}

	if (token_count < 2)
		return -EINVAL;

	oci_cfg->image_ref = source;
	oci_cfg->platform = tokens[0];

	{
		const char *digest = tokens[1];
		const char *hex;

		if (!digest || strncmp(digest, "sha256:", 7) != 0)
			return -EINVAL;
		hex = digest + 7;
		if (strlen(hex) != 64)
			return -EINVAL;
		free(oci_cfg->blob_digest);
		oci_cfg->blob_digest = strdup(digest);
		if (!oci_cfg->blob_digest)
			return -ENOMEM;
	}
	oci_cfg->layer_index = -1;

	if (token_count > 2) {
		err = ocierofs_decode_userpass(tokens[2], &oci_cfg->username,
			       &oci_cfg->password);
		if (err)
			return err;
	}
	return 0;
}

static int erofsmount_reattach_oci(struct erofs_vfile *vf,
				   const char *type, char *source)
{
	struct ocierofs_config oci_cfg = {};
	int err;

	if (!strcmp(type, "OCI_LAYER"))
		err = erofsmount_parse_recovery_ocilayer(&oci_cfg, source);
	else if (!strcmp(type, "OCI_NATIVE_BLOB"))
		err = erofsmount_parse_recovery_ociblob(&oci_cfg, source);
	else
		return -EOPNOTSUPP;

	if (err)
		return err;

	return ocierofs_io_open(vf, &oci_cfg);
}
#else
static int erofsmount_reattach_oci(struct erofs_vfile *vf,
				   const char *type, char *source)
{
	return -EOPNOTSUPP;
}
#endif

static int erofsmount_reattach_gzran_oci(struct erofsmount_nbd_ctx *ctx,
					 char *source)
{
	char *tokens[6] = {0}, *p = source, *space, *oci_source;
	char *meta_path = NULL, *zinfo_path = NULL;
	int token_count = 0, err;
	const char *b64cred;
	struct erofs_vfile temp_vd;
	struct ocierofs_config oci_cfg = {};

	while (token_count < 5) {
		space = strchr(p, ' ');
		if (!space)
			break;

		*space = '\0';
		p = space + 1;
		tokens[token_count++] = p;
	}

	if (token_count < 4)
		return -EINVAL;

	b64cred = (token_count > 2 && tokens[2]) ? tokens[2] : "";

	err = asprintf(&oci_source, "%s %s %s %s",
		       source, tokens[0], tokens[1], b64cred);
	if (err < 0)
		return -ENOMEM;

	err = erofsmount_reattach_oci(&ctx->vd, "OCI_NATIVE_BLOB", oci_source);
	free(oci_source);
	if (err)
		return err;

	temp_vd = ctx->vd;
	oci_cfg.image_ref = strdup(source);
	if (!oci_cfg.image_ref) {
		erofs_io_close(&temp_vd);
		return -ENOMEM;
	}

	if (token_count > 3 && tokens[3] && *tokens[3])
		meta_path = tokens[3];
	if (token_count > 4 && tokens[4] && *tokens[4])
		zinfo_path = tokens[4];

	err = erofsmount_tarindex_open(&ctx->vd, &oci_cfg,
				       meta_path, zinfo_path);
	free(oci_cfg.image_ref);
	erofs_io_close(&temp_vd);
	return err;
}

static int erofsmount_nbd_fix_backend_linkage(int num, char **recp)
{
	char *newrecp;
	int err;

	if (!*recp)
		return 0;
	newrecp = erofs_nbd_get_identifier(num);
	if (!IS_ERR(newrecp) && newrecp) {
		err = strcmp(newrecp, *recp) ? -EFAULT : 0;
		free(newrecp);
		return err;
	}

	if (asprintf(&newrecp, "/var/run/erofs/mountnbd_nbd%d", num) <= 0)
		return -ENOMEM;

	if (rename(*recp, newrecp) < 0) {
		err = -errno;
		free(newrecp);
		return err;
	}
	free(*recp);
	*recp = newrecp;
	return 0;
}

static int erofsmount_startnbd_nl(pid_t *pid, struct erofsmount_source *source)
{
	int pipefd[2], err, num;

	err = pipe(pipefd);
	if (err < 0)
		return -errno;

	if ((*pid = fork()) == 0) {
		struct erofsmount_nbd_ctx ctx = {};
		char *recp;

		/* Otherwise, NBD disconnect sends SIGPIPE, skipping cleanup */
		if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
			exit(EXIT_FAILURE);

		if (source->type == EROFSMOUNT_SOURCE_OCI) {
			if (source->ocicfg.tarindex_path || source->ocicfg.zinfo_path) {
				err = erofsmount_tarindex_open(&ctx.vd, &source->ocicfg,
							       source->ocicfg.tarindex_path,
							       source->ocicfg.zinfo_path);
				if (err)
					exit(EXIT_FAILURE);
			} else {
				err = ocierofs_io_open(&ctx.vd, &source->ocicfg);
				if (err)
					exit(EXIT_FAILURE);
			}
		} else {
			err = open(source->device_path, O_RDONLY);
			if (err < 0)
				exit(EXIT_FAILURE);
			ctx.vd.fd = err;
		}
		recp = erofsmount_write_recovery_info(source);
		if (IS_ERR(recp)) {
			erofs_io_close(&ctx.vd);
			exit(EXIT_FAILURE);
		}

		num = -1;
		err = erofs_nbd_nl_connect(&num, 9, EROFSMOUNT_NBD_DISK_SIZE, recp);
		if (err >= 0) {
			ctx.sk.fd = err;
			err = erofsmount_nbd_fix_backend_linkage(num, &recp);
			if (err) {
				erofs_io_close(&ctx.sk);
			} else {
				err = write(pipefd[1], &num, sizeof(int));
				if (err < 0)
					err = -errno;
				close(pipefd[1]);
				close(pipefd[0]);
				if (err >= sizeof(int)) {
					err = (int)(uintptr_t)erofsmount_nbd_loopfn(&ctx);
					goto out_fork;
				}
			}
		}
		erofs_io_close(&ctx.vd);
out_fork:
		(void)unlink(recp);
		free(recp);
		exit(err ? EXIT_FAILURE : EXIT_SUCCESS);
	}
	close(pipefd[1]);
	err = read(pipefd[0], &num, sizeof(int));
	close(pipefd[0]);
	if (err < sizeof(int))
		return -EPIPE;
	return num;
}

static int erofsmount_reattach(const char *target)
{
	char *identifier, *line, *source, *recp = NULL;
	struct erofsmount_nbd_ctx ctx = {};
	int nbdnum, err;
	struct stat st;
	size_t n;
	FILE *f;

	err = lstat(target, &st);
	if (err < 0)
		return -errno;

	if (!S_ISBLK(st.st_mode) || major(st.st_rdev) != EROFS_NBD_MAJOR)
		return -ENOTBLK;

	nbdnum = erofs_nbd_get_index_from_minor(minor(st.st_rdev));
	if (nbdnum < 0)
		return nbdnum;
	identifier = erofs_nbd_get_identifier(nbdnum);
	if (IS_ERR(identifier)) {
		identifier = NULL;
	} else if (identifier && *identifier == '\0') {
		free(identifier);
		identifier = NULL;
	}

	if (!identifier &&
	    (asprintf(&recp, "/var/run/erofs/mountnbd_nbd%d", nbdnum) <= 0)) {
		err = -ENOMEM;
		goto err_identifier;
	}

	f = fopen(identifier ?: recp, "r");
	if (!f) {
		err = -errno;
		free(recp);
		goto err_identifier;
	}
	free(recp);

	line = NULL;
	if ((err = getline(&line, &n, f)) <= 0) {
		err = -errno;
		fclose(f);
		goto err_identifier;
	}
	fclose(f);
	if (err && line[err - 1] == '\n')
		line[err - 1] = '\0';

	source = strchr(line, ' ');
	if (!source) {
		erofs_err("invalid source recorded in recovery file: %s", line);
		err = -EINVAL;
		goto err_line;
	} else {
		*(source++) = '\0';
	}

	if (!strcmp(line, "LOCAL")) {
		err = open(source, O_RDONLY);
		if (err < 0) {
			err = -errno;
			goto err_line;
		}
		ctx.vd.fd = err;
	} else if (!strcmp(line, "TARINDEX_OCI_BLOB")) {
		err = erofsmount_reattach_gzran_oci(&ctx, source);
		if (err)
			goto err_line;
	} else if (!strcmp(line, "OCI_LAYER") || !strcmp(line, "OCI_NATIVE_BLOB")) {
		err = erofsmount_reattach_oci(&ctx.vd, line, source);
		if (err)
			goto err_line;
	} else {
		err = -EOPNOTSUPP;
		erofs_err("unsupported source type %s recorded in recovery file", line);
		goto err_line;
	}

	err = erofs_nbd_nl_reconnect(nbdnum, identifier);
	if (err >= 0) {
		ctx.sk.fd = err;
		if (fork() == 0) {
			free(line);
			free(identifier);
			if ((uintptr_t)erofsmount_nbd_loopfn(&ctx))
				return EXIT_FAILURE;
			return EXIT_SUCCESS;
		}
		erofs_io_close(&ctx.sk);
		err = 0;
	}
	erofs_io_close(&ctx.vd);
err_line:
	free(line);
err_identifier:
	free(identifier);
	return err;
}

static int erofsmount_nbd(struct erofsmount_source *source,
			  const char *mountpoint, const char *fstype,
			  int flags, const char *options)
{
	bool is_netlink = false;
	char nbdpath[32], *id;
	int num, nbdfd = -1;
	pid_t pid = 0;
	long err;

	if (strcmp(fstype, "erofs")) {
		fprintf(stderr, "unsupported filesystem type `%s`\n",
			mountcfg.fstype);
		return -ENODEV;
	}
	flags |= MS_RDONLY;

	err = erofsmount_startnbd_nl(&pid, source);
	if (err < 0) {
		erofs_info("Fall back to ioctl-based NBD; failover is unsupported");
		num = erofs_nbd_devscan();
		if (num < 0)
			return num;

		(void)snprintf(nbdpath, sizeof(nbdpath), "/dev/nbd%d", num);
		nbdfd = open(nbdpath, O_RDWR);
		if (nbdfd < 0)
			return -errno;

		if ((pid = fork()) == 0)
			return erofsmount_startnbd(nbdfd, source) ?
				EXIT_FAILURE : EXIT_SUCCESS;
	} else {
		num = err;
		(void)snprintf(nbdpath, sizeof(nbdpath), "/dev/nbd%d", num);
		is_netlink = true;
	}

	while (1) {
		err = erofs_nbd_in_service(num);
		if (err == -ENOENT || err == -ENOTCONN) {
			err = waitpid(pid, NULL, WNOHANG);
			if (err < 0) {
				err = -errno;
				break;
			} else if (err > 0) {
				/* child process exited unexpectedly */
				err = -EIO;
				break;
			}

			usleep(50000);
			continue;
		}
		if (err >= 0)
			err = (err != pid ? -EBUSY : 0);
		break;
	}
	if (!err) {
		if (mount(nbdpath, mountpoint, fstype, flags, options) < 0) {
			err = -errno;
			if (is_netlink)
				erofs_nbd_nl_disconnect(num);
			else
				erofs_nbd_disconnect(nbdfd);
		}

		if (!err && is_netlink) {
			id = erofs_nbd_get_identifier(num);

			err = IS_ERR(id) ? PTR_ERR(id) :
				erofs_nbd_nl_reconfigure(num, id, true);
			if (err)
				erofs_warn("failed to turn on autoclear for nbd%d: %s",
					   num, erofs_strerror(err));
			if (!IS_ERR(id))
				free(id);
		}
	}
	if (!is_netlink) {
		DBG_BUGON(nbdfd < 0);
		close(nbdfd);
	}
	return err;
}

#define EROFSMOUNT_LOOPDEV_RETRIES	3

static int erofsmount_loopmount(const char *source, const char *mountpoint,
				const char *fstype, int flags,
				const char *options)
{
	int fd, dfd, num;
	struct loop_info li = {};
	bool ro = flags & MS_RDONLY;
	char device[32];

	fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	num = ioctl(fd, LOOP_CTL_GET_FREE);
	if (num < 0)
		return -errno;
	close(fd);

	snprintf(device, sizeof(device), "/dev/loop%d", num);
	for (num = 0; num < EROFSMOUNT_LOOPDEV_RETRIES; ++num) {
		fd = open(device, (ro ? O_RDONLY : O_RDWR) | O_CLOEXEC);
		if (fd >= 0)
			break;
		usleep(50000);
	}
	if (fd < 0)
		return -errno;

	dfd = open(source, (ro ? O_RDONLY : O_RDWR));
	if (dfd < 0)
		goto out_err;

	num = ioctl(fd, LOOP_SET_FD, dfd);
	if (num < 0) {
		close(dfd);
		goto out_err;
	}
	close(dfd);

	li.lo_flags = LO_FLAGS_AUTOCLEAR;
	num = ioctl(fd, LOOP_SET_STATUS, &li);
	if (num < 0)
		goto out_err;
	num = mount(device, mountpoint, fstype, flags, options);
	if (num < 0)
		goto out_err;
	close(fd);
	return 0;
out_err:
	close(fd);
	return -errno;
}

#ifdef EROFS_FANOTIFY_ENABLED
struct erofsmount_fanotify_state {
	pid_t pid;
	char *mountpoint;
	char *source;
};

static void erofsmount_free_fanotify_state(struct erofsmount_fanotify_state *state)
{
	free(state->mountpoint);
	free(state->source);
	state->mountpoint = NULL;
	state->source = NULL;
}

static int erofsmount_write_fanotify_state(const char *state_path, pid_t pid,
					   const char *mountpoint,
					   const char *source)
{
	struct erofsmount_fanotify_state state;
	char *tmp_path = NULL;
	FILE *f = NULL;
	int fd = -1, err;

	if (mkdir(EROFSMOUNT_RUNTIME_DIR, 0700) < 0 && errno != EEXIST)
		return -errno;
	if (mkdir(EROFSMOUNT_FANOTIFY_STATE_DIR, 0700) < 0 &&
	    errno != EEXIST)
		return -errno;

	state.pid = pid;
	state.mountpoint = (char *)mountpoint;
	state.source = (char *)source;

	if (asprintf(&tmp_path, "%s.tmpXXXXXX", state_path) < 0)
		return -ENOMEM;

	fd = mkstemp(tmp_path);
	if (fd < 0) {
		err = -errno;
		goto out;
	}

	f = fdopen(fd, "w");
	if (!f) {
		err = -errno;
		goto out;
	}
	fd = -1;

	if (fprintf(f, "%d\n%s\n%s\n", state.pid, state.mountpoint,
		    state.source) < 0 || fflush(f) == EOF) {
		err = errno ? -errno : -EIO;
		goto out;
	}

	if (fsync(fileno(f)) < 0) {
		err = -errno;
		goto out;
	}

	if (fclose(f) < 0) {
		err = -errno;
		f = NULL;
		goto out;
	}
	f = NULL;

	if (rename(tmp_path, state_path) < 0) {
		err = -errno;
		goto out;
	}

	err = 0;
out:
	if (f)
		fclose(f);
	else if (fd >= 0)
		close(fd);
	if (err && tmp_path)
		unlink(tmp_path);
	free(tmp_path);
	return err;
}

static int erofsmount_read_fanotify_state(const char *state_path,
					  struct erofsmount_fanotify_state *state)
{
	FILE *f;
	size_t n = 0;
	int err = 0;

	memset(state, 0, sizeof(*state));

	f = fopen(state_path, "r");
	if (!f)
		return -errno;

	if (fscanf(f, "%d", &state->pid) != 1)
		err = -EINVAL;
	else if (fgetc(f) != '\n')
		err = -EINVAL;
	else if (getline(&state->mountpoint, &n, f) < 0)
		err = feof(f) ? -EINVAL : -errno;
	else if (getline(&state->source, &n, f) < 0)
		err = feof(f) ? -EINVAL : -errno;
	fclose(f);
	if (err) {
		erofsmount_free_fanotify_state(state);
		return err;
	}

	state->mountpoint[strcspn(state->mountpoint, "\n")] = '\0';
	state->source[strcspn(state->source, "\n")] = '\0';
	return err;
}

static int erofsmount_cleanup_fanotify_worker(const char *mountpoint,
					      const char *source)
{
	DIR *dir;
	struct dirent *de;
	int err = 0;

	dir = opendir(EROFSMOUNT_FANOTIFY_STATE_DIR);
	if (!dir) {
		if (errno == ENOENT)
			return 0;
		return -errno;
	}

	while ((de = readdir(dir)) != NULL) {
		struct erofsmount_fanotify_state state;
		char *state_path;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		if (!strstr(de->d_name, ".state"))
			continue;
		if (asprintf(&state_path, "%s/%s", EROFSMOUNT_FANOTIFY_STATE_DIR,
			     de->d_name) < 0) {
			err = -ENOMEM;
			goto out;
		}

		err = erofsmount_read_fanotify_state(state_path, &state);
		if (err == -ENOENT) {
			free(state_path);
			err = 0;
			continue;
		}
		if (err) {
			free(state_path);
			goto out;
		}
		if (strcmp(state.mountpoint, mountpoint) ||
		    strcmp(state.source, source)) {
			erofsmount_free_fanotify_state(&state);
			free(state_path);
			continue;
		}
		if (kill(state.pid, SIGTERM) < 0 && errno != ESRCH)
			err = -errno;
		else if (unlink(state_path) < 0 && errno != ENOENT)
			err = -errno;
		erofsmount_free_fanotify_state(&state);
		free(state_path);
		goto out;
	}
out:
	closedir(dir);
	if (!err)
		return 0;
	return err;
}

static int erofsmount_create_sparse_file(struct erofs_fanotify_ctx *ctx,
					 u64 size, const char *blob_digest)
{
	char filepath[PATH_MAX];
	const char *hex_digest;
	int fd, err;

	/* Extract hex part from "sha256:xxxx..." */
	if (!blob_digest || strncmp(blob_digest, "sha256:", 7) != 0)
		return -EINVAL;
	hex_digest = blob_digest + 7;

	/* Construct file path using blob SHA256 */
	snprintf(filepath, sizeof(filepath), EROFSMOUNT_CACHE_DIR "/%s",
		 hex_digest);

	/* Try to open existing file or create new one */
	fd = open(filepath, O_RDWR | O_CREAT, 0600);
	if (fd < 0 && errno == ENOENT) {
		err = mkdir(EROFSMOUNT_CACHE_DIR, 0700);
		if (err)
			return -errno;
		fd = open(filepath, O_RDWR | O_CREAT, 0600);
	}
	if (fd < 0)
		return -errno;

	ctx->sparse_path = strdup(filepath);
	if (!ctx->sparse_path) {
		err = -ENOMEM;
		goto err_path;
	}

	/* Set file size (creates sparse file) */
	if (ftruncate(fd, size) < 0) {
		err = -errno;
		goto err_ftruncate;
	}

	ctx->sparse_fd = fd;
	ctx->image_size = size;

	erofs_dbg("Created local sparse file %s (size: %llu bytes)",
		  ctx->sparse_path, (unsigned long long)size);
	return 0;

err_ftruncate:
	free(ctx->sparse_path);
	ctx->sparse_path = NULL;
err_path:
	close(fd);
	unlink(filepath);
	return err;
}

static int erofsmount_resolve_fanotify_blob(const struct ocierofs_config *oci_cfg,
					    char **digest, u64 *image_size)
{
	struct ocierofs_ctx oci_ctx = {};
	int err, i = -1;

	err = ocierofs_ctx_init(&oci_ctx, oci_cfg);
	if (err)
		return err;

	if (oci_ctx.blob_digest) {
		for (i = 0; i < oci_ctx.layer_count; ++i) {
			if (!strcmp(oci_ctx.layers[i]->digest, oci_ctx.blob_digest))
				break;
		}
		if (i >= oci_ctx.layer_count) {
			err = -ENOENT;
			goto out;
		}
	} else if (oci_ctx.layer_count == 1) {
		i = 0;
	} else {
		erofs_err("fanotify backend requires exactly one OCI blob; use oci.blob= or oci.layer=");
		err = -EINVAL;
		goto out;
	}

	*digest = strdup(oci_ctx.layers[i]->digest);
	if (!*digest) {
		err = -ENOMEM;
		goto out;
	}
	*image_size = oci_ctx.layers[i]->size;
	err = 0;

out:
	ocierofs_ctx_cleanup(&oci_ctx);
	return err;
}

static void erofsmount_fanotify_ctx_cleanup(struct erofs_fanotify_ctx *ctx)
{
	if (ctx->fan_fd >= 0)
		close(ctx->fan_fd);
	if (ctx->sparse_fd >= 0)
		close(ctx->sparse_fd);
	if (ctx->vd.ops || ctx->vd.fd >= 0)
		erofs_io_close(&ctx->vd);
	free(ctx->fetch_buf);
	free(ctx->sparse_path);
}

static int erofsmount_fanotify_child(struct erofs_fanotify_ctx *ctx,
				     int pipefd)
{
	int err;

	ctx->fan_fd = erofs_fanotify_init_precontent();
	if (ctx->fan_fd < 0) {
		err = ctx->fan_fd;
		goto notify;
	}

	err = erofs_fanotify_mark_file(ctx->fan_fd, ctx->sparse_path);
	if (err)
		goto notify;

	err = 0;
notify:
	write(pipefd, &err, sizeof(err));
	close(pipefd);

	if (err)
		return err;

	return erofs_fanotify_loop(ctx);
}

static int erofsmount_fanotify(struct erofsmount_source *source,
			       const char *mountpoint, const char *fstype,
			       int flags, const char *options)
{
	struct erofs_fanotify_ctx ctx = {
		.vd = {.fd = -1},
		.sparse_fd = -1,
		.fan_fd = -1,
	};
	struct ocierofs_config layer_cfg;
	char *blob_digest = NULL;
	char *state_mountpoint = NULL;
	char *state_path = NULL;
	pid_t pid = -1;
	int pipefd[2];
	int err, child_err;
	u64 image_size;

	if (strcmp(fstype, "erofs")) {
		fprintf(stderr, "unsupported filesystem type `%s`\n", fstype);
		return -ENODEV;
	}
	flags |= MS_RDONLY;

	if (source->ocicfg.tarindex_path || source->ocicfg.zinfo_path) {
		erofs_err("fanotify backend does not support tarindex or zinfo");
		return -EOPNOTSUPP;
	}

	state_mountpoint = realpath(mountpoint, NULL);
	if (!state_mountpoint) {
		err = -errno;
		goto out;
	}

	err = erofsmount_resolve_fanotify_blob(&source->ocicfg, &blob_digest,
					       &image_size);
	if (err)
		goto out;

	layer_cfg = source->ocicfg;
	layer_cfg.blob_digest = blob_digest;
	layer_cfg.layer_index = -1;

	err = ocierofs_io_open(&ctx.vd, &layer_cfg);
	if (err)
		goto out;

	err = erofsmount_create_sparse_file(&ctx, image_size, blob_digest);
	if (err)
		goto out;

	/* Create pipe for parent-child communication */
	if (pipe(pipefd) < 0) {
		err = -errno;
		goto out;
	}

	pid = fork();
	if (pid < 0) {
		err = -errno;
		close(pipefd[0]);
		close(pipefd[1]);
		goto out;
	}

	if (pid == 0) {
		close(pipefd[0]);
		err = erofsmount_fanotify_child(&ctx, pipefd[1]);
		erofsmount_fanotify_ctx_cleanup(&ctx);
		exit(err ? EXIT_FAILURE : EXIT_SUCCESS);
	}

	/* Wait for child to report fanotify initialization result */
	close(pipefd[1]);
	if (read(pipefd[0], &child_err, sizeof(child_err)) != sizeof(child_err))
		child_err = -EPIPE;
	close(pipefd[0]);

	if (child_err) {
		erofs_err("Child process failed: %s", erofs_strerror(child_err));
		err = child_err;
		goto kill_child;
	}

	err = mount(ctx.sparse_path, mountpoint, fstype, flags, options);
	if (err < 0)
		err = -errno;
	if (err)
		goto kill_child;

	if (asprintf(&state_path, "%s/%d.state",
		     EROFSMOUNT_FANOTIFY_STATE_DIR, pid) < 0) {
		err = -ENOMEM;
		goto out_umount;
	}

	err = erofsmount_write_fanotify_state(state_path, pid, state_mountpoint,
					      ctx.sparse_path);
	if (err)
		goto out_umount;
	erofs_dbg("Mounted %s at %s successfully", ctx.sparse_path, mountpoint);
	goto out;

out_umount:
	(void)umount(mountpoint);
kill_child:
	if (pid > 0) {
		(void)kill(pid, SIGTERM);
		(void)waitpid(pid, NULL, 0);
	}
out:
	free(state_path);
	free(state_mountpoint);
	erofsmount_fanotify_ctx_cleanup(&ctx);
	free(blob_digest);
	return err;
}
#endif

int erofsmount_umount(char *target)
{
	char *device = NULL, *mountpoint = NULL;
	int err, fd, nbdnum;
	struct stat st;
	FILE *mounts;
	size_t n;
	char *s;
	bool isblk;

	target = realpath(target, NULL);
	if (!target)
		return -errno;

	err = lstat(target, &st);
	if (err < 0) {
		err = -errno;
		goto err_out;
	}

	if (S_ISBLK(st.st_mode)) {
		isblk = true;
	} else if (S_ISDIR(st.st_mode)) {
		isblk = false;
	} else {
		err = -EINVAL;
		goto err_out;
	}

	mounts = fopen("/proc/mounts", "r");
	if (!mounts) {
		err = -ENOENT;
		goto err_out;
	}

	for (s = NULL; (getline(&s, &n, mounts)) > 0;) {
		bool hit = false;
		char *f1, *f2, *end;

		f1 = s;
		end = strchr(f1, ' ');
		if (end)
			*end = '\0';
		if (isblk && !strcmp(f1, target))
			hit = true;
		if (end) {
			f2 = end + 1;
			end = strchr(f2, ' ');
			if (end)
				*end = '\0';
			if (!isblk && !strcmp(f2, target))
				hit = true;
		}
		if (hit) {
			if (isblk) {
				err = -EBUSY;
				free(s);
				fclose(mounts);
				goto err_out;
			}
			free(device);
			device = strdup(f1);
			if (!mountpoint)
				mountpoint = strdup(f2);
		}
	}
	free(s);
	fclose(mounts);
	if (!isblk && !device) {
		err = -ENOENT;
		goto err_out;
	}

	if (isblk && !mountpoint &&
	    S_ISBLK(st.st_mode) && major(st.st_rdev) == EROFS_NBD_MAJOR) {
		nbdnum = erofs_nbd_get_index_from_minor(minor(st.st_rdev));
		err = erofs_nbd_nl_disconnect(nbdnum);
		if (err != -EOPNOTSUPP)
			return err;
	}

	/* Avoid TOCTOU issue with NBD_CFLAG_DISCONNECT_ON_CLOSE */
	fd = open(isblk ? target : device, O_RDWR);
	if (fd < 0) {
		err = -errno;
		goto err_out;
	}
	if (mountpoint) {
		err = umount(mountpoint);
		if (err) {
			err = -errno;
			close(fd);
			goto err_out;
		}
	}
#ifdef EROFS_FANOTIFY_ENABLED
	if (!isblk) {
		err = erofsmount_cleanup_fanotify_worker(target, device);
		if (err) {
			close(fd);
			goto err_out;
		}
	}
#endif
	err = fstat(fd, &st);
	if (err < 0)
		err = -errno;
	else if (S_ISBLK(st.st_mode) && major(st.st_rdev) == EROFS_NBD_MAJOR) {
		nbdnum = erofs_nbd_get_index_from_minor(minor(st.st_rdev));
		err = erofs_nbd_nl_disconnect(nbdnum);
		if (err == -EOPNOTSUPP)
			err = erofs_nbd_disconnect(fd);
	}
	close(fd);
err_out:
	free(device);
	free(mountpoint);
	free(target);
	return err < 0 ? err : 0;
}

static int erofsmount_disconnect(const char *target)
{
	int nbdnum, err, fd;
	struct stat st;

	err = lstat(target, &st);
	if (err < 0)
		return -errno;

	if (!S_ISBLK(st.st_mode) || major(st.st_rdev) != EROFS_NBD_MAJOR)
		return -ENOTBLK;

	nbdnum = erofs_nbd_get_index_from_minor(minor(st.st_rdev));
	err = erofs_nbd_nl_disconnect(nbdnum);
	if (err == -EOPNOTSUPP) {
		fd = open(target, O_RDWR);
		if (fd < 0) {
			err = -errno;
			goto err_out;
		}
		err = erofs_nbd_disconnect(fd);
		close(fd);
	}
err_out:
	return err < 0 ? err : 0;
}

int main(int argc, char *argv[])
{
	int err;

	erofs_init_configure();
	err = erofsmount_parse_options(argc, argv);
	if (err) {
		if (err == -EINVAL)
			fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (mountcfg.mountmode == EROFSMOUNT_MODE_UMOUNT) {
		err = erofsmount_umount(mountcfg.target);
		if (err < 0)
			fprintf(stderr, "Failed to unmount %s: %s\n",
				mountcfg.target, erofs_strerror(err));
		return err ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (mountcfg.mountmode == EROFSMOUNT_MODE_REATTACH) {
		err = erofsmount_reattach(mountcfg.target);
		if (err < 0)
			fprintf(stderr, "Failed to reattach %s: %s\n",
				mountcfg.target, erofs_strerror(err));
		return err ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (mountcfg.mountmode == EROFSMOUNT_MODE_DISCONNECT) {
		err = erofsmount_disconnect(mountcfg.target);
		if (err < 0)
			fprintf(stderr, "Failed to disconnect %s: %s\n",
				mountcfg.target, erofs_strerror(err));
		return err ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (mountcfg.backend == EROFSFUSE) {
		err = erofsmount_fuse(mountcfg.device, mountcfg.target,
				      mountcfg.fstype, mountcfg.full_options);
		goto exit;
	}

	if (mountcfg.backend == EROFSNBD) {
		if (mountsrc.type == EROFSMOUNT_SOURCE_OCI)
			mountsrc.ocicfg.image_ref = mountcfg.device;
		else
			mountsrc.device_path = mountcfg.device;
		err = erofsmount_nbd(&mountsrc, mountcfg.target,
				     mountcfg.fstype, mountcfg.flags, mountcfg.options);
		goto exit;
	}

#ifdef EROFS_FANOTIFY_ENABLED
	if (mountcfg.backend == EROFSFANOTIFY) {
		if (mountsrc.type != EROFSMOUNT_SOURCE_OCI) {
			erofs_err("Fanotify backend only supports OCI sources");
			err = -EINVAL;
			goto exit;
		}
		mountsrc.ocicfg.image_ref = mountcfg.device;
		err = erofsmount_fanotify(&mountsrc, mountcfg.target,
					  mountcfg.fstype, mountcfg.flags,
					  mountcfg.options);
		goto exit;
	}
#endif

	if (mountcfg.force_loopdev)
		goto loopmount;

	err = mount(mountcfg.device, mountcfg.target, mountcfg.fstype,
		    mountcfg.flags, mountcfg.options);
	if (err < 0)
		err = -errno;

	if ((err == -ENODEV || err == -EPERM) && mountcfg.backend == EROFSAUTO)
		err = erofsmount_fuse(mountcfg.device, mountcfg.target,
				      mountcfg.fstype, mountcfg.full_options);
	else if (err == -ENOTBLK)
loopmount:
		err = erofsmount_loopmount(mountcfg.device, mountcfg.target,
					   mountcfg.fstype, mountcfg.flags,
					   mountcfg.options);
exit:
	if (err < 0)
		fprintf(stderr, "Failed to mount %s: %s\n",
			mountcfg.fstype, erofs_strerror(err));
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
