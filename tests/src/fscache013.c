#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <stdint.h>
#include <errno.h>

#include "internal.h"

static char *fscachedir;
int imgdirfd;
static char *tag;
static int fd;

static char *cachedir;
static char *cachename;

static void parse_options(int argc, char *argv[])
{
	char *imgdir;

	if (argc != 5) {
		fprintf(stderr, "usage: fscache011 <fscachedir> <imgdir>\n");
		exit(-1);
	}

	fscachedir = argv[1];
	imgdir = argv[2];
	cachedir = argv[3];
	cachename = argv[4];

	imgdirfd = open(imgdir, O_RDONLY);
	if (imgdirfd < 0) {
		fprintf(stderr, "open imgdir failed\n");
		exit(-1);
	}
}

static int check_inuse_state(void)
{
	char cmdbuf[128];
	char cwd[128];
	int ret;

	/* wait for the file state switch */
	sleep(1);

	ret = chdir(cachedir);
	if (ret) {
		fprintf(stderr, "chdir failed %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	snprintf(cmdbuf, sizeof(cmdbuf), "inuse %s", cachename);
	ret = write(fd, cmdbuf, strlen(cmdbuf));
	if (ret < 0) {
		printf("backing file is inuse\n");
	} else {
		printf("backing file is not inuse\n");

		snprintf(cmdbuf, sizeof(cmdbuf), "cull %s", cachename);
		ret = write(fd, cmdbuf, strlen(cmdbuf));
		if (ret < 0)
			printf("failed to cull since it's inuse\n");
		else
			printf("backing file is culled\n");
	}

	fflush(stdout);
	return ret;
}

static int process_one_req(int devfd)
{
	char buf[CACHEFILES_MSG_MAX_SIZE];
	int ret;
	struct cachefiles_msg *msg;
	size_t len;

	memset(buf, 0, sizeof(buf));

	ret = read(devfd, buf, sizeof(buf));
	if (ret < 0)
		fprintf(stderr, "read devnode failed\n");
	if (ret <= 0)
		return -1;

	msg = (void *)buf;
	if (ret != msg->len) {
		fprintf(stderr, "invalid message length %d (readed %d)\n", msg->len, ret);
		return -1;
	}

	switch (msg->opcode) {
	case CACHEFILES_OP_OPEN:
		return process_open_req(devfd, msg);
	case CACHEFILES_OP_CLOSE:
		ret = process_close_req(devfd, msg);
		printf("[CLOSE]\n");
		check_inuse_state();
		return ret;
	case CACHEFILES_OP_READ:
		ret = process_read_req(devfd, msg);
		printf("[READ]\n");
		check_inuse_state();
		return ret;
	default:
		fprintf(stderr, "invalid opcode %d\n", msg->opcode);
		return -1;
	}
}

int main(int argc, char *argv[])
{
	struct pollfd pollfd;
	int ret;

	parse_options(argc, argv);

	fd = daemon_get_devfd(fscachedir, tag);
	if (fd < 0)
		return -1;

	pollfd.fd = fd;
	pollfd.events = POLLIN;

	while (1) {
		ret = poll(&pollfd, 1, -1);
		if (ret < 0) {
			fprintf(stderr, "poll failed\n");
			return -1;
		}

		if (ret == 0 || !(pollfd.revents & POLLIN)) {
			fprintf(stderr, "poll returned %d (%x)\n", ret, pollfd.revents);
			continue;
		}

		/* process all pending read requests */
		while (!process_one_req(fd)) {}
	}

	return 0;
}
