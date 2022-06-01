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

#include "internal.h"


static char *fscachedir;
int imgdirfd;
static char *tag;

/* Error injection policy */
#define POLICY_OPEN_INJECT	0x001
#define POLICY_OPEN_IGNORE	0x002
#define POLICY_CLOSE_INJECT	0x010
#define POLICY_CLOSE_IGNORE	0x020
#define POLICY_READ_INJECT	0x100
#define POLICY_READ_IGNORE	0x200
#define POLICY_READ_RA		0x400
#define POLICY_MASK		0xfff
static int policy;

static void usage(void)
{
	fprintf(stderr, "usage: cachefilesd2 <options> <fscachedir> <imgdir>\n");
	fprintf(stderr, "  options:\n");
	fprintf(stderr, "    -p           : error injection policy, no error injection by default\n");
	fprintf(stderr, "    -t           : tag of cachefiles cache, NULL by default\n");
	fprintf(stderr, "    -h           : this help\n\n");
	exit(-1);
}

static void parse_options(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	char *imgdir;
	int	c;
	const char *allopts = "hp:t:";

	while ((c = getopt(argc, argv, allopts)) != EOF) {
		switch(c) {
		case 'p':
			policy = strtol(optarg, NULL, 0);
			if (policy == LONG_MAX || policy == LONG_MIN || policy & (~POLICY_MASK)) {
				fprintf(stderr, "invalid eroor injection policy\n");
				usage();
			}
			break;
		case 't':
			tag = optarg;
			break;
		case 'h':
		case '?':
			usage();
		}
	}

	if (optind + 2 != argc) {
		fprintf(stderr, "missing fscachedir and imgdir\n");
		usage();
	}

	fscachedir = argv[optind];
	imgdir = argv[optind+1];
	imgdirfd = open(imgdir, O_RDONLY);
	if (imgdirfd < 0) {
		fprintf(stderr, "open imgdir failed\n");
		exit(-1);
	}
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
		if (policy & POLICY_OPEN_IGNORE)
			return 0;
		else if (policy & POLICY_OPEN_INJECT)
			return process_open_req_fail(devfd, msg);
		else
			return process_open_req(devfd, msg);
	case CACHEFILES_OP_CLOSE:
		if (policy & POLICY_CLOSE_IGNORE)
			return 0;
		else if (policy & POLICY_CLOSE_INJECT)
			return process_close_req_fail(devfd, msg);
		else
			return process_close_req(devfd, msg);
	case CACHEFILES_OP_READ:
		if (policy & POLICY_READ_IGNORE)
			return 0;
		else if (policy & POLICY_READ_INJECT)
			return process_read_req_fail(devfd, msg);
		else if (policy & POLICY_READ_RA)
			return process_read_req_ra(devfd, msg);
		else
			return process_read_req(devfd, msg);
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
