#define _GNU_SOURCE
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>

#include "internal.h"

#ifdef DEBUG
#define dbgprint(...) printf(##__VA_ARGS__)
#else
#define dbgprint(...) ((void)0)
#endif

#define NAME_MAX 512
struct fd_path_link {
	int object_id;
	int fd;
	int size;
	char path[NAME_MAX];
} links[32];

unsigned int link_num = 0;
extern int imgdirfd;

static struct fd_path_link *find_fd_path_link(int object_id)
{
	struct fd_path_link *link;
	int i;

	for (i = 0; i < link_num; i++) {
		link = links + i;
		if (link->object_id == object_id)
			return link;
	}
	return NULL;
}

int process_open_req(int devfd, struct cachefiles_msg *msg)
{
	struct cachefiles_open *load;
	struct fd_path_link *link;
	char *volume_key, *cookie_key;
	struct stat stats;
	char cmd[32];
	int ret;
	unsigned long long size;

	load = (void *)msg->data;
	volume_key = load->data;
	cookie_key = load->data + load->volume_key_size;

	dbgprint("[OPEN] volume key %s (volume_key_size %lu), cookie key %s (cookie_key_size %lu), "
	       "object id %d, fd %d, flags %u\n",
		volume_key, load->volume_key_size, cookie_key, load->cookie_key_size,
		msg->object_id, load->fd, load->flags);

	ret = fstatat(imgdirfd, cookie_key, &stats, 0);
	if (ret) {
		fprintf(stderr, "stat %s failed, %d (%s)\n", cookie_key, errno, strerror(errno));
		return -1;
	}
	size = stats.st_size;

	snprintf(cmd, sizeof(cmd), "copen %u,%llu", msg->msg_id, size);
	dbgprint("Writing cmd: %s\n", cmd);

	ret = write(devfd, cmd, strlen(cmd));
	if (ret < 0) {
		fprintf(stderr, "write [copen] failed\n");
		return -1;
	}

	if (link_num >= 32)
		return -1;

	link = links + link_num;
	link_num ++;

	link->object_id = msg->object_id;
	link->fd = load->fd;
	link->size = size;
	strncpy(link->path, cookie_key, NAME_MAX);
	return 0;
}

/* error injection - return error directly */
int process_open_req_fail(int devfd, struct cachefiles_msg *msg)
{
	struct cachefiles_open *load;
	char *volume_key, *cookie_key;
	char cmd[32];
	int ret, size;

	load = (void *)msg->data;
	volume_key = load->data;
	cookie_key = load->data + load->volume_key_size;

	dbgprint("[OPEN] volume key %s (volume_key_size %lu), cookie key %s (cookie_key_size %lu), "
	       "object id %d, fd %d, flags %u\n",
		volume_key, load->volume_key_size, cookie_key, load->cookie_key_size,
		msg->object_id, load->fd, load->flags);

	snprintf(cmd, sizeof(cmd), "copen %u,-1", msg->msg_id);
	dbgprint("Writing cmd: %s\n", cmd);

	ret = write(devfd, cmd, strlen(cmd));
	if (ret < 0) {
		fprintf(stderr, "write [copen] failed\n");
		return -1;
	}
	return 0;
}

int process_close_req(int devfd, struct cachefiles_msg *msg)
{
	struct fd_path_link *link;

	link = find_fd_path_link(msg->object_id);
	if (!link) {
		fprintf(stderr, "invalid object id %d\n", msg->object_id);
		return -1;
	}

	dbgprint("[CLOSE] object_id %d, fd %d\n", msg->object_id, link->fd);
	close(link->fd);
	return 0;
}

/* error injection - don't close anon_fd */
int process_close_req_fail(int devfd, struct cachefiles_msg *msg)
{
	dbgprint("[CLOSE] object_id %d\n", msg->object_id);
	return 0;
}

/* 2MB buffer aligned with 512 (logical block size) for DIRECT IO  */
#define BUF_SIZE (2*1024*1024)
static char readbuf[BUF_SIZE] __attribute__((aligned(512)));

static int do_process_read_req(int devfd, struct cachefiles_msg *msg, int ra)
{
	struct cachefiles_read *read;
	struct fd_path_link *link;
	int i, ret, retval = -1;
	int dst_fd, src_fd;
	char *src_path = NULL;
	size_t len;
	unsigned long id;

	read = (void *)msg->data;

	link = find_fd_path_link(msg->object_id);
	if (!link) {
		fprintf(stderr, "invalid object id %d\n", msg->object_id);
		return -1;
	}
	src_path = link->path;
	dst_fd = link->fd;

	dbgprint("[READ] object_id %d, fd %d, src_path %s, off %llx, len %llx\n",
			msg->object_id, dst_fd, src_path, read->off, read->len);

	src_fd = openat(imgdirfd, src_path, O_RDONLY);
	if (src_fd < 0) {
		fprintf(stderr, "open src_path %s failed\n", src_path);
		return -1;
	}

	len = read->len;
	if (BUF_SIZE < len) {
		fprintf(stderr, "buffer overflow\n");
		close(src_fd);
		return -1;
	}

	if (ra && read->off + BUF_SIZE <= link->size)
		len = BUF_SIZE;

	ret = pread(src_fd, readbuf, len, read->off);
	if (ret != len) {
		fprintf(stderr, "read src image failed, ret %d, %d (%s)\n", ret, errno, strerror(errno));
		close(src_fd);
		return -1;
	}

	ret = pwrite(dst_fd, readbuf, len, read->off);
	if (ret != len) {
		fprintf(stderr, "write dst image failed, ret %d, %d (%s)\n", ret, errno, strerror(errno));
		close(src_fd);
		return -1;
	}

	id = msg->msg_id;
	ret = ioctl(dst_fd, CACHEFILES_IOC_CREAD, id);
	if (ret < 0) {
		fprintf(stderr, "send cread failed, %d (%s)\n", errno, strerror(errno));
		close(src_fd);
		return -1;
	}

	close(src_fd);
	return 0;
}

int process_read_req(int devfd, struct cachefiles_msg *msg)
{
	return do_process_read_req(devfd, msg, 0);
}

int process_read_req_ra(int devfd, struct cachefiles_msg *msg)
{
	return do_process_read_req(devfd, msg, 1);
}

/* error injection - return error directly */
int process_read_req_fail(int devfd, struct cachefiles_msg *msg)
{
	struct cachefiles_read *read;
	struct fd_path_link *link;
	int i, ret, retval = -1;
	int dst_fd, src_fd;
	char *src_path = NULL;
	size_t len;
	unsigned long id;

	read = (void *)msg->data;

	link = find_fd_path_link(msg->object_id);
	if (!link) {
		fprintf(stderr, "invalid object id %d\n", msg->object_id);
		return -1;
	}
	dst_fd = link->fd;
	id = msg->msg_id;

	ret = ioctl(dst_fd, CACHEFILES_IOC_CREAD, id);
	if (ret < 0) {
		fprintf(stderr, "send cread failed, %d (%s)\n", errno, strerror(errno));
		close(src_fd);
		return -1;
	}
	return 0;
}

int daemon_get_devfd(const char *fscachedir, const char *tag)
{
	char *cmd;
	char cmdbuf[128];
	int fd, ret;

	if (!fscachedir)
		return -1;

	fd = open("/dev/cachefiles", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open /dev/cachefiles failed\n");
		return -1;
	}

	snprintf(cmdbuf, sizeof(cmdbuf), "dir %s", fscachedir);
	ret = write(fd, cmdbuf, strlen(cmdbuf));
	if (ret < 0) {
		fprintf(stderr, "write dir failed, %d\n", errno);
		goto error;
	}

	if (tag) {
		snprintf(cmdbuf, sizeof(cmdbuf), "tag %s", tag);
		ret = write(fd, cmdbuf, strlen(cmdbuf));
		if (ret < 0) {
			fprintf(stderr, "write tag failed, %d\n", errno);
			goto error;
		}
	}

	cmd = "bind ondemand";
	ret = write(fd, cmd, strlen(cmd));
	if (ret < 0) {
		fprintf(stderr, "bind failed\n");
		goto error;
	}
	return fd;

error:
	close(fd);
	return -1;
}
