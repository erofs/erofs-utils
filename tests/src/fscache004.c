#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>

#include "internal.h"


static char *fscachedir;
int imgdirfd;
static char *tag;

static void parse_options(int argc, char *argv[])
{
	char *imgdir;

	if (argc != 3) {
		fprintf(stderr, "usage: fscache004 <fscachedir> <imgdir>\n");
		exit(-1);
	}

	fscachedir = argv[1];
	imgdir = argv[2];

	imgdirfd = open(imgdir, O_RDONLY);
	if (imgdirfd < 0) {
		fprintf(stderr, "open imgdir failed\n");
		exit(-1);
	}
}

/* error injection - write to premature anon_fd */
static int process_open_req_local(int devfd, struct cachefiles_msg *msg)
{
	struct cachefiles_open *load;
	char *volume_key, *cookie_key;
	char cmd[32];
	int ret;

	load = (void *)msg->data;
	volume_key = load->data;
	cookie_key = load->data + load->volume_key_size;

	/* write to premature anon_fd */
	ret = write(load->fd, cmd, sizeof(cmd));
	if (ret < 0)
		printf("write anon_fd, gets %d (%s)\n", errno, strerror(errno));

	snprintf(cmd, sizeof(cmd), "copen %u,-1", msg->msg_id);
	ret = write(devfd, cmd, strlen(cmd));
	if (ret < 0) {
		printf("write [copen] failed\n");
		return -1;
	}

	return 0;
}

static int process_one_req(int devfd)
{
	char buf[CACHEFILES_MSG_MAX_SIZE];
	struct cachefiles_msg *msg;
	size_t len;
	int ret;

	memset(buf, 0, sizeof(buf));

	ret = read(devfd, buf, sizeof(buf));
	if (ret < 0)
		printf("read devnode failed\n");
	if (ret <= 0)
		return -1;

	msg = (void *)buf;
	if (ret != msg->len) {
		printf("invalid message length %d (readed %d)\n", msg->len, ret);
		return -1;
	}

	printf("[HEADER] id %u, opcode %d\t", msg->msg_id, msg->opcode);

	switch (msg->opcode) {
	case CACHEFILES_OP_OPEN:
		return process_open_req_local(devfd, msg);
	default:
		printf("invalid opcode %d\n", msg->opcode);
		return -1;
	}
}

int main(int argc, char *argv[])
{
	struct pollfd pollfd;
	int fd, ret;

	parse_options(argc, argv);

	fd = daemon_get_devfd(fscachedir, tag);
	if (fd < 0)
		return -1;

	pollfd.fd = fd;
	pollfd.events = POLLIN;

	while (1) {
		ret = poll(&pollfd, 1, -1);
		if (ret < 0) {
			printf("poll failed\n");
			return -1;
		}

		if (ret == 0 || !(pollfd.revents & POLLIN)) {
			printf("poll returned %d (%x)\n", ret, pollfd.revents);
			continue;
		}

		/* process all pending read requests */
		while (!process_one_req(fd)) {}
	}

	return 0;
}
