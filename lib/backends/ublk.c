// SPDX-License-Identifier: GPL-2.0+ OR MIT
/*
 * Copyright (C) 2026 Tencent, Inc.
 *             http://www.tencent.com/
 * Copyright (C) 2026 Alibaba Cloud
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "erofs/err.h"
#include "erofs/print.h"
#include "liberofs_ublk.h"

#ifdef HAVE_LIBURING
#include <liburing.h>
#endif

/* (Legacy) Admin commands, issued by ublk server, and handled by ublk driver */
#define UBLK_CMD_GET_QUEUE_AFFINITY	0x01
#define UBLK_CMD_GET_DEV_INFO		0x02
#define UBLK_CMD_ADD_DEV		0x04
#define UBLK_CMD_DEL_DEV		0x05
#define UBLK_CMD_START_DEV		0x06
#define UBLK_CMD_STOP_DEV		0x07
#define UBLK_CMD_SET_PARAMS		0x08
#define UBLK_CMD_GET_PARAMS		0x09
#define UBLK_CMD_START_USER_RECOVERY	0x10
#define UBLK_CMD_END_USER_RECOVERY	0x11

/* (Legacy) IO command definition */
#define UBLK_IO_FETCH_REQ		0x20
#define UBLK_IO_COMMIT_AND_FETCH_REQ	0x21

#define UBLK_U_CMD_GET_QUEUE_AFFINITY	\
	_IOR('u', UBLK_CMD_GET_QUEUE_AFFINITY, struct ublksrv_ctrl_cmd)
#define UBLK_U_CMD_GET_DEV_INFO		\
	_IOR('u', UBLK_CMD_GET_DEV_INFO, struct ublksrv_ctrl_cmd)
#define UBLK_U_CMD_ADD_DEV		\
	_IOWR('u', UBLK_CMD_ADD_DEV, struct ublksrv_ctrl_cmd)
#define UBLK_U_CMD_DEL_DEV		\
	_IOWR('u', UBLK_CMD_DEL_DEV, struct ublksrv_ctrl_cmd)
#define UBLK_U_CMD_START_DEV		\
	_IOWR('u', UBLK_CMD_START_DEV, struct ublksrv_ctrl_cmd)
#define UBLK_U_CMD_STOP_DEV		\
	_IOWR('u', UBLK_CMD_STOP_DEV, struct ublksrv_ctrl_cmd)
#define UBLK_U_CMD_SET_PARAMS		\
	_IOWR('u', UBLK_CMD_SET_PARAMS, struct ublksrv_ctrl_cmd)
#define UBLK_U_CMD_GET_PARAMS		\
	_IOR('u', UBLK_CMD_GET_PARAMS, struct ublksrv_ctrl_cmd)
#define UBLK_U_CMD_START_USER_RECOVERY	\
	_IOWR('u', UBLK_CMD_START_USER_RECOVERY, struct ublksrv_ctrl_cmd)
#define UBLK_U_CMD_END_USER_RECOVERY	\
	_IOWR('u', UBLK_CMD_END_USER_RECOVERY, struct ublksrv_ctrl_cmd)

#define UBLK_U_IO_FETCH_REQ		\
	_IOWR('u', UBLK_IO_FETCH_REQ, struct ublksrv_io_cmd)
#define UBLK_U_IO_COMMIT_AND_FETCH_REQ	\
	_IOWR('u', UBLK_IO_COMMIT_AND_FETCH_REQ, struct ublksrv_io_cmd)

#define UBLK_F_URING_CMD_COMP_IN_TASK	(1ULL << 1)
#define UBLK_F_USER_RECOVERY		(1ULL << 3)
#define UBLK_F_UNPRIVILEGED_DEV		(1ULL << 5)
#define UBLK_F_CMD_IOCTL_ENCODE		(1ULL << 6)

#define UBLK_S_DEV_QUIESCED	2
#define UBLK_S_DEV_FAIL_IO	3

#define UBLK_IO_RES_OK			0
#define UBLK_IO_RES_ABORT		(-ENODEV)

#define UBLKSRV_CMD_BUF_OFFSET		0
#define UBLK_MAX_QUEUE_DEPTH		4096

struct ublksrv_ctrl_cmd {
	__u32 dev_id;
	__u16 queue_id;
	__u16 len;
	__u64 addr;
	__u64 data[1];
	__u16 dev_path_len;
	__u16 pad;
	__u32 reserved;
};

struct ublksrv_ctrl_dev_info {
	__u16 nr_hw_queues;
	__u16 queue_depth;
	__u16 state;
	__u16 pad0;
	__u32 max_io_buf_bytes;
	__u32 dev_id;
	__s32 ublksrv_pid;
	__u32 pad1;
	__u64 flags;
	__u64 ublksrv_flags;
	__u32 owner_uid;
	__u32 owner_gid;
	__u64 reserved1;
	__u64 reserved2;
};

struct ublksrv_io_cmd {
	__u16 q_id;
	__u16 tag;
	__s32 result;
	__u64 addr;
};

struct ublksrv_io_desc {
	__u32 op_flags;
	__u32 nr_sectors;
	__u64 start_sector;
	__u64 addr;
};

#define UBLK_PARAM_TYPE_BASIC		(1 << 0)

struct ublk_param_basic {
#define UBLK_ATTR_READ_ONLY		(1 << 0)
	__u32 attrs;
	__u8 logical_bs_shift;
	__u8 physical_bs_shift;
	__u8 io_opt_shift;
	__u8 io_min_shift;
	__u32 max_sectors;
	__u32 chunk_sectors;
	__u64 dev_sectors;
	__u64 virt_boundary_mask;
};

struct ublk_params {
	__u32 len;
	__u32 types;
	struct ublk_param_basic basic;
};

#ifdef HAVE_LIBURING
#define UBLKSRV_IO_FREE			(1U << 0)
#define UBLKSRV_NEED_FETCH_RQ		(1U << 1)
#define UBLKSRV_NEED_COMMIT_RQ_COMP	(1U << 2)

#define UBLKSRV_QUEUE_STOPPING		(1U << 0)
#define UBLKSRV_QUEUE_IDLE		(1U << 1)

struct erofs_ublk_io {
	unsigned int flags;
	int result;
};

struct erofs_ublk_queue {
	int q_id;
	int q_depth;
	struct erofs_ublk_dev *dev;
	struct ublksrv_io_desc *io_cmd_buf;
	struct erofs_ublk_io *ios;
	void *io_buf;
	size_t io_buf_size;
	pthread_t thread;
	unsigned int state;
	cpu_set_t *cpuset;
	int idle_ticks;
	pthread_barrier_t *init_barrier;
	struct io_uring ring;
};

struct erofs_ublk_dev {
	int ctrl_fd;
	int cdev_fd;
	struct ublksrv_ctrl_dev_info dev_info;
	struct ublk_params params;
	struct erofs_ublk_queue *queues;
	erofsublk_io_handler_t handler;
	void *handler_ctx;
	int running;
	int stop_requested;
	int stop_efd;
	int recovering;
	struct io_uring ctrl_ring;
	int ctrl_ring_initialized;
};

#define UBLK_CTRL_DEV		"/dev/ublk-control"
#define UBLK_CDEV_FMT		"/dev/ublkc%d"

#define UBLK_IDLE_TIMEOUT_TICKS	200
#define UBLK_MAX_DEVS		128
static struct erofs_ublk_dev *ublk_devs[UBLK_MAX_DEVS];

static struct erofs_ublk_dev *ublk_get_dev(int dev_id)
{
	if (dev_id < 0 || dev_id >= UBLK_MAX_DEVS)
		return NULL;
	return ublk_devs[dev_id];
}

static volatile sig_atomic_t g_sig_dev_id = -1;

static inline __u8 ublksrv_get_op(const struct ublksrv_io_desc *iod)
{
	return iod->op_flags & 0xff;
}

static inline void *ublk_get_io_buf(struct erofs_ublk_queue *q, int tag)
{
	return (char *)q->io_buf + tag * q->dev->dev_info.max_io_buf_bytes;
}

static void ublk_set_io_flusher(void)
{
#ifndef PR_SET_IO_FLUSHER
#define PR_SET_IO_FLUSHER 49
#endif
	if (prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0) != 0)
		erofs_dbg("prctl(PR_SET_IO_FLUSHER) failed: %s",
			  strerror(errno));
}

static int ublk_ctrl_ring_init(struct io_uring *ring)
{
	struct io_uring_params p = {
		.flags = IORING_SETUP_SQE128,
	};
	return io_uring_queue_init_params(4, ring, &p);
}

static const unsigned int ctrl_cmd_op[] = {
	[UBLK_CMD_GET_QUEUE_AFFINITY]	= UBLK_U_CMD_GET_QUEUE_AFFINITY,
	[UBLK_CMD_GET_DEV_INFO]		= UBLK_U_CMD_GET_DEV_INFO,
	[UBLK_CMD_ADD_DEV]		= UBLK_U_CMD_ADD_DEV,
	[UBLK_CMD_DEL_DEV]		= UBLK_U_CMD_DEL_DEV,
	[UBLK_CMD_START_DEV]		= UBLK_U_CMD_START_DEV,
	[UBLK_CMD_STOP_DEV]		= UBLK_U_CMD_STOP_DEV,
	[UBLK_CMD_SET_PARAMS]		= UBLK_U_CMD_SET_PARAMS,
	[UBLK_CMD_GET_PARAMS]		= UBLK_U_CMD_GET_PARAMS,
	[UBLK_CMD_START_USER_RECOVERY]	= UBLK_U_CMD_START_USER_RECOVERY,
	[UBLK_CMD_END_USER_RECOVERY]	= UBLK_U_CMD_END_USER_RECOVERY,
};

static bool erofs_ublk_use_legacy_cmds;

static unsigned int erofsublk_formalize_cmd_op(unsigned int op)
{
	DBG_BUGON(_IOC_TYPE(op) != 0);
	DBG_BUGON(_IOC_DIR(op) != 0);
	DBG_BUGON(_IOC_SIZE(op) != 0);

	if (!erofs_ublk_use_legacy_cmds) {
		/* IO opcodes live above the ctrl table and need explicit encoding */
		if (op == UBLK_IO_FETCH_REQ)
			return UBLK_U_IO_FETCH_REQ;
		if (op == UBLK_IO_COMMIT_AND_FETCH_REQ)
			return UBLK_U_IO_COMMIT_AND_FETCH_REQ;
		if (op < ARRAY_SIZE(ctrl_cmd_op))
			return ctrl_cmd_op[op];
	}
	return op;
}

static int ublk_ctrl_cmd_ring(struct io_uring *ring, int ctrl_fd,
			      __u32 cmd_op,
			      const struct ublksrv_ctrl_cmd *cmd_data)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct ublksrv_ctrl_cmd *cmd;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -ENOMEM;

	io_uring_prep_rw(IORING_OP_URING_CMD, sqe, ctrl_fd, NULL, 0, 0);
	sqe->cmd_op = erofsublk_formalize_cmd_op(cmd_op);

	if (cmd_data) {
		cmd = (struct ublksrv_ctrl_cmd *)sqe->cmd;
		memcpy(cmd, cmd_data, sizeof(*cmd_data));
	}

	ret = io_uring_submit(ring);
	if (ret < 0) {
		erofs_err("io_uring_submit failed: %s", strerror(-ret));
		return ret;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		erofs_err("io_uring_wait_cqe failed: %s", strerror(-ret));
		return ret;
	}

	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

static int ublk_dev_ctrl_cmd(struct erofs_ublk_dev *dev, __u32 cmd_op,
			     const struct ublksrv_ctrl_cmd *cmd_data)
{
	return ublk_ctrl_cmd_ring(&dev->ctrl_ring, dev->ctrl_fd, cmd_op, cmd_data);
}

static int ublk_get_queue_affinity(struct erofs_ublk_dev *dev, int q_id,
				   cpu_set_t *cpuset)
{
	struct ublksrv_ctrl_cmd cmd = {0};
	int ret;

	cmd.dev_id = dev->dev_info.dev_id;
	cmd.queue_id = q_id;
	cmd.len = sizeof(cpu_set_t);
	cmd.addr = (__u64)(uintptr_t)cpuset;

	ret = ublk_dev_ctrl_cmd(dev, UBLK_CMD_GET_QUEUE_AFFINITY, &cmd);
	if (ret < 0)
		erofs_dbg("GET_QUEUE_AFFINITY failed for q%d: %s",
			  q_id, strerror(-ret));
	return ret;
}

int erofsublk_ctrl_add_dev(struct erofs_ublk_dev *dev)
{
	struct ublksrv_ctrl_dev_info *dev_info = &dev->dev_info;
	struct ublksrv_ctrl_cmd cmd = {0};
	int ret;

	cmd.dev_id = dev_info->dev_id;
	cmd.queue_id = (__u16)-1;
	cmd.len = sizeof(*dev_info);
	cmd.addr = (__u64)(uintptr_t)dev_info;

	ret = ublk_dev_ctrl_cmd(dev, UBLK_CMD_ADD_DEV, &cmd);
	if (ret < 0) {
		erofs_ublk_use_legacy_cmds = true;
		ret = ublk_dev_ctrl_cmd(dev, UBLK_CMD_ADD_DEV, &cmd);
		if (ret < 0)
			erofs_err("UBLK_CMD_ADD_DEV failed: %s",
				  erofs_strerror(ret));
	}
	return ret;
}

static int ublk_add_dev(struct erofs_ublk_dev *dev,
			const struct erofs_ublk_dev_info *info)
{
	struct ublksrv_ctrl_dev_info *dev_info = &dev->dev_info;
	int ret;

	*dev_info = (struct ublksrv_ctrl_dev_info) {
		.nr_hw_queues = info->nr_hw_queues,
		.queue_depth = info->queue_depth,
		.max_io_buf_bytes = info->max_io_buf_bytes,
		.dev_id = info->dev_id,
		.flags = UBLK_F_CMD_IOCTL_ENCODE |
			  UBLK_F_URING_CMD_COMP_IN_TASK |
			(info->flags & EROFS_UBLK_F_UNPRIVILEGED ?
				UBLK_F_UNPRIVILEGED_DEV : 0) |
			(info->flags & EROFS_UBLK_F_USER_RECOVERY ?
				UBLK_F_USER_RECOVERY : 0),
	};

	ret = erofsublk_ctrl_add_dev(dev);
	if (ret < 0)
		return ret;

	erofs_info("ublk device %d added (queues=%d, depth=%d, io_buf=%u)",
		   dev_info->dev_id, dev_info->nr_hw_queues,
		   dev_info->queue_depth, dev_info->max_io_buf_bytes);
	return 0;
}

static int ublk_del_dev(struct erofs_ublk_dev *dev)
{
	struct ublksrv_ctrl_cmd cmd = {
		.dev_id = dev->dev_info.dev_id,
		.queue_id = (u16)-1,
	};

	return ublk_dev_ctrl_cmd(dev, UBLK_CMD_DEL_DEV, &cmd);
}

static int ublk_set_params(struct erofs_ublk_dev *dev,
			   const struct erofs_ublk_dev_info *info)
{
	struct ublksrv_ctrl_cmd cmd = {0};
	struct ublk_params *params = &dev->params;
	int ret;

	memset(params, 0, sizeof(*params));
	params->len = sizeof(*params);
	params->types = UBLK_PARAM_TYPE_BASIC;

	params->basic.attrs = UBLK_ATTR_READ_ONLY;
	params->basic.logical_bs_shift = info->blkbits;
	params->basic.physical_bs_shift = info->blkbits;
	params->basic.io_opt_shift = info->blkbits;
	params->basic.io_min_shift = info->blkbits;
	params->basic.max_sectors = info->max_io_buf_bytes >> 9;
	params->basic.dev_sectors = info->dev_size >> 9;

	cmd.dev_id = dev->dev_info.dev_id;
	cmd.queue_id = (__u16)-1;
	cmd.len = sizeof(*params);
	cmd.addr = (__u64)(uintptr_t)params;

	ret = ublk_dev_ctrl_cmd(dev, UBLK_CMD_SET_PARAMS, &cmd);
	if (ret < 0)
		erofs_err("UBLK_CMD_SET_PARAMS failed: %s", strerror(-ret));

	return ret;
}

static int ublk_start_dev(struct erofs_ublk_dev *dev)
{
	struct ublksrv_ctrl_cmd cmd = {0};
	int ret;

	cmd.dev_id = dev->dev_info.dev_id;
	cmd.queue_id = (__u16)-1;
	dev->dev_info.ublksrv_pid = cmd.data[0] = getpid();

	ret = ublk_dev_ctrl_cmd(dev, UBLK_CMD_START_DEV, &cmd);
	if (ret < 0)
		erofs_err("UBLK_CMD_START_DEV failed: %s", strerror(-ret));
	else
		erofs_info("ublk device /dev/ublkb%d started",
			   dev->dev_info.dev_id);
	return ret;
}

static int ublk_stop_dev(struct erofs_ublk_dev *dev)
{
	struct ublksrv_ctrl_cmd cmd = {0};

	cmd.dev_id = dev->dev_info.dev_id;
	cmd.queue_id = (__u16)-1;

	return ublk_dev_ctrl_cmd(dev, UBLK_CMD_STOP_DEV, &cmd);
}

static int ublk_start_recovery(struct erofs_ublk_dev *dev)
{
	struct ublksrv_ctrl_cmd cmd = {0};
	int ret;

	cmd.dev_id = dev->dev_info.dev_id;
	cmd.queue_id = (__u16)-1;

	ret = ublk_dev_ctrl_cmd(dev, UBLK_CMD_START_USER_RECOVERY, &cmd);
	if (ret < 0)
		erofs_err("START_USER_RECOVERY failed: %s", strerror(-ret));
	else
		erofs_info("ublk device %d recovery started",
			   dev->dev_info.dev_id);

	return ret;
}

static int ublk_end_recovery(struct erofs_ublk_dev *dev)
{
	struct ublksrv_ctrl_cmd cmd = {0};
	int ret;

	cmd.dev_id = dev->dev_info.dev_id;
	cmd.queue_id = (__u16)-1;
	dev->dev_info.ublksrv_pid = cmd.data[0] = getpid();

	ret = ublk_dev_ctrl_cmd(dev, UBLK_CMD_END_USER_RECOVERY, &cmd);
	if (ret < 0)
		erofs_err("END_USER_RECOVERY failed: %s", strerror(-ret));
	else
		erofs_info("ublk device %d recovery completed",
			   dev->dev_info.dev_id);
	return ret;
}

static int ublk_get_dev_info(struct erofs_ublk_dev *dev, int dev_id)
{
	struct ublksrv_ctrl_cmd cmd = {
		.dev_id = dev_id,
		.queue_id = (u16)-1,
		.len = sizeof(dev->dev_info),
		.addr = (u64)(uintptr_t)&dev->dev_info,
	};
	int ret;

	ret = ublk_dev_ctrl_cmd(dev, UBLK_CMD_GET_DEV_INFO, &cmd);
	if ((ret == -ENODEV || ret == -EOPNOTSUPP) &&
	    !erofs_ublk_use_legacy_cmds) {
		erofs_ublk_use_legacy_cmds = true;
		ret = ublk_dev_ctrl_cmd(dev, UBLK_CMD_GET_DEV_INFO, &cmd);
		if (ret < 0)
			erofs_err("GET_DEV_INFO failed for device %d: %s",
				  dev_id, erofs_strerror(ret));
	}
	return ret;
}

static int ublk_get_params(struct erofs_ublk_dev *dev)
{
	struct ublksrv_ctrl_cmd cmd = {0};
	int ret;

	dev->params.len = sizeof(dev->params);

	cmd.dev_id = dev->dev_info.dev_id;
	cmd.queue_id = (__u16)-1;
	cmd.len = sizeof(dev->params);
	cmd.addr = (__u64)(uintptr_t)&dev->params;

	ret = ublk_dev_ctrl_cmd(dev, UBLK_CMD_GET_PARAMS, &cmd);
	if (ret < 0)
		erofs_err("GET_PARAMS failed: %s", strerror(-ret));
	return ret;
}

static inline u64 build_user_data(unsigned int tag, unsigned int op,
		unsigned int tgt_data, unsigned int is_target_io)
{
	assert(!(tag >> 16) && !(op >> 8) && !(tgt_data >> 16));

	return tag | (op << 16) | (tgt_data << 24) | (u64)is_target_io << 63;
}

static inline unsigned int user_data_to_tag(u64 user_data)
{
	return user_data & 0xffff;
}

static inline struct io_uring_sqe *erofsublk_alloc_sqe(struct io_uring *r)
{
	unsigned int left = io_uring_sq_space_left(r);

	if (left < 1)
		io_uring_submit(r);
	return io_uring_get_sqe(r);
}

static int ublk_queue_io_cmd(struct erofs_ublk_queue *q, int tag)
{
	struct io_uring_sqe *sqe;
	struct ublksrv_io_cmd *cmd;
	struct erofs_ublk_io *io = &q->ios[tag];
	__u32 cmd_op;

	/* only freed io can be issued */
	if (!(io->flags & UBLKSRV_IO_FREE))
		return 0;

	if (io->flags & UBLKSRV_NEED_COMMIT_RQ_COMP)
		cmd_op = UBLK_IO_COMMIT_AND_FETCH_REQ;
	else if (io->flags & UBLKSRV_NEED_FETCH_RQ)
		cmd_op = UBLK_IO_FETCH_REQ;
	else	/* we issue because we need either fetching or committing */
		return 0;

	sqe = erofsublk_alloc_sqe(&q->ring);
	if (!sqe)
		return -ENOMEM;

	memset(sqe, 0, sizeof(*sqe) * 2);
	cmd = (struct ublksrv_io_cmd *)sqe->cmd;
	if (cmd_op == UBLK_IO_COMMIT_AND_FETCH_REQ)
		cmd->result = io->result;
	else
		cmd->result = 0;

	sqe->opcode = IORING_OP_URING_CMD;
	sqe->fd = q->dev->cdev_fd;
	sqe->cmd_op = erofsublk_formalize_cmd_op(cmd_op);
	sqe->flags = 0;
	sqe->rw_flags = 0;
	cmd->tag = tag;
	cmd->addr = (__u64)(uintptr_t)ublk_get_io_buf(q, tag);
	cmd->q_id = q->q_id;
	io_uring_sqe_set_data64(sqe, build_user_data(tag, cmd_op, 0, 0));

	io->flags = 0;
	return 0;
}

static int ublk_submit_fetch_commands(struct erofs_ublk_queue *q)
{
	int i, ret;

	for (i = 0; i < q->q_depth; i++) {
		ret = ublk_queue_io_cmd(q, i);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int ublk_handle_io(struct erofs_ublk_queue *q, int tag)
{
	struct erofs_ublk_dev *dev = q->dev;
	const struct ublksrv_io_desc *iod = &q->io_cmd_buf[tag];
	struct erofs_ublk_io *io = &q->ios[tag];
	struct erofs_ublk_request req;
	int ret;

	req.op = ublksrv_get_op(iod);
	req.start_sector = iod->start_sector;
	req.nr_sectors = iod->nr_sectors;
	req.buf = ublk_get_io_buf(q, tag);
	req.result = 0;

	if (dev->handler) {
		ret = dev->handler(dev->handler_ctx, &req);

		if (ret < 0)
			io->result = ret;
		else
			io->result = req.nr_sectors << 9;
	} else {
		io->result = -EOPNOTSUPP;
	}
	return 0;
}

static int ublk_complete_io(struct erofs_ublk_queue *q, unsigned int tag)
{
	struct erofs_ublk_io *io = &q->ios[tag];

	io->flags |= (UBLKSRV_NEED_COMMIT_RQ_COMP | UBLKSRV_IO_FREE);
	return ublk_queue_io_cmd(q, tag);
}

static int ublk_handle_cqe(struct erofs_ublk_queue *q,
			   struct io_uring_cqe *cqe)
{
	int tag = user_data_to_tag(cqe->user_data);
	struct erofs_ublk_io *io = &q->ios[tag];
	int res = cqe->res;
	int fetch = (res != UBLK_IO_RES_ABORT) &&
		!(q->state & UBLKSRV_QUEUE_STOPPING);

	if (!fetch) {
		q->state |= UBLKSRV_QUEUE_STOPPING;
		io->flags &= ~UBLKSRV_NEED_FETCH_RQ;
	}

	if (res == UBLK_IO_RES_OK) {
		ublk_handle_io(q, tag);
		return ublk_complete_io(q, tag);
	}
	if (fetch)
		erofs_err("queue %d tag %d IO error: %s", q->q_id, tag, strerror(-res));
	io->flags = UBLKSRV_IO_FREE;
	return cqe->res;
}

static void ublk_queue_idle_enter(struct erofs_ublk_queue *q)
{
	if (q->state & UBLKSRV_QUEUE_IDLE)
		return;

	q->state |= UBLKSRV_QUEUE_IDLE;

	if (q->io_buf && q->io_buf_size > 0)
		madvise(q->io_buf, q->io_buf_size, MADV_DONTNEED);

	erofs_dbg("queue %d entered idle state", q->q_id);
}

static void ublk_queue_idle_exit(struct erofs_ublk_queue *q)
{
	if (!(q->state & UBLKSRV_QUEUE_IDLE))
		return;

	q->state &= ~UBLKSRV_QUEUE_IDLE;
	q->idle_ticks = 0;
	erofs_dbg("queue %d exited idle state", q->q_id);
}

static int ublk_reap_events_uring(struct erofs_ublk_queue *q, int *ret)
{
	struct io_uring_cqe *cqe;
	int reapped, ret2;
	unsigned int head;

	reapped = *ret = 0;
	io_uring_for_each_cqe(&q->ring, head, cqe) {
		ret2 = ublk_handle_cqe(q, cqe);
		if (ret2 && !*ret)
			*ret = ret2;
		++reapped;
	}
	if (reapped)
		io_uring_cq_advance(&q->ring, reapped);
	return reapped;
}

static void *ublk_queue_thread(void *arg)
{
	struct erofs_ublk_queue *q = arg;
	struct __kernel_timespec ts = {
		.tv_sec = 0,
		.tv_nsec = 100000000,
	};
	struct io_uring_cqe *cqe;
	int ret, ret2, reapped;

	if (q->cpuset)
		sched_setaffinity(0, sizeof(cpu_set_t), q->cpuset);

	setpriority(PRIO_PROCESS, 0, -20);

	ublk_set_io_flusher();

	ret = ublk_submit_fetch_commands(q);
	if (ret < 0) {
		erofs_err("Failed to submit fetch commands: %s",
			  strerror(-ret));
		if (q->init_barrier)
			pthread_barrier_wait(q->init_barrier);
		return NULL;
	}

	if (q->init_barrier)
		pthread_barrier_wait(q->init_barrier);

	erofs_info("queue %d thread started (tid=%d)", q->q_id, gettid());

	while (1) {
		ret = io_uring_submit_and_wait_timeout(&q->ring, &cqe, 1,
						       &ts, NULL);
		reapped = ublk_reap_events_uring(q, &ret2);
		if (q->state & UBLKSRV_QUEUE_STOPPING)
			break;

		if (ret == -ETIME && !reapped &&
		    ++q->idle_ticks >= UBLK_IDLE_TIMEOUT_TICKS)
			ublk_queue_idle_enter(q);
		else
			ublk_queue_idle_exit(q);
	}

	erofs_info("queue %d thread exiting", q->q_id);
	__atomic_store_n(&q->dev->stop_requested, 1, __ATOMIC_RELAXED);
	if (q->dev->stop_efd >= 0) {
		uint64_t val = 1;

		(void)write(q->dev->stop_efd, &val, sizeof(val));
	}
	return NULL;
}

static int __ublk_queue_cmd_buf_sz(unsigned int depth)
{
	int size = depth * sizeof(struct ublksrv_io_desc);
	unsigned int page_sz = getpagesize();

	return round_up(size, page_sz);
}

static int ublk_queue_max_cmd_buf_sz(void)
{
	return __ublk_queue_cmd_buf_sz(UBLK_MAX_QUEUE_DEPTH);
}

static int ublk_init_queue(struct erofs_ublk_dev *dev, int q_id)
{
	struct erofs_ublk_queue *q = &dev->queues[q_id];
	struct io_uring_params p;
	unsigned int cmd_buf_size;
	int i, ret;

	q->q_id = q_id;
	q->q_depth = dev->dev_info.queue_depth;
	q->dev = dev;
	q->state = 0;
	q->idle_ticks = 0;

	q->cpuset = malloc(sizeof(cpu_set_t));
	if (q->cpuset) {
		CPU_ZERO(q->cpuset);
		ret = ublk_get_queue_affinity(dev, q_id, q->cpuset);
		if (ret < 0) {
			free(q->cpuset);
			q->cpuset = NULL;
		}
	}

	cmd_buf_size = __ublk_queue_cmd_buf_sz(q->q_depth);
	q->io_cmd_buf = mmap(NULL, cmd_buf_size, PROT_READ,
			     MAP_SHARED | MAP_POPULATE, dev->cdev_fd,
			     UBLKSRV_CMD_BUF_OFFSET +
			     q_id * ublk_queue_max_cmd_buf_sz());
	if (q->io_cmd_buf == MAP_FAILED) {
		erofs_err("mmap io_cmd_buf failed: %s", strerror(errno));
		ret = -errno;
		goto err_free_cpuset;
	}

	q->ios = calloc(q->q_depth, sizeof(struct erofs_ublk_io));
	if (!q->ios) {
		ret = -ENOMEM;
		goto err_unmap_cmd;
	}

	q->io_buf_size = (size_t)q->q_depth * dev->dev_info.max_io_buf_bytes;
	q->io_buf = mmap(NULL, q->io_buf_size, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (q->io_buf == MAP_FAILED) {
		erofs_err("mmap io_buf failed: %s", strerror(errno));
		ret = -errno;
		goto err_free_ios;
	}

	for (i = 0; i < q->q_depth; ++i)
		q->ios[i].flags = UBLKSRV_NEED_FETCH_RQ | UBLKSRV_IO_FREE;

	p = (struct io_uring_params) { .flags = IORING_SETUP_SQE128 };

	ret = io_uring_queue_init_params(q->q_depth * 2, &q->ring, &p);
	if (ret < 0) {
		erofs_err("io_uring_queue_init failed: %s", strerror(-ret));
		goto err_unmap_buf;
	}

	return 0;

err_unmap_buf:
	munmap(q->io_buf, q->io_buf_size);
err_free_ios:
	free(q->ios);
err_unmap_cmd:
	munmap(q->io_cmd_buf, cmd_buf_size);
err_free_cpuset:
	free(q->cpuset);
	return ret;
}

static void ublk_cleanup_queue(struct erofs_ublk_dev *dev, int q_id)
{
	struct erofs_ublk_queue *q = &dev->queues[q_id];

	q->state |= UBLKSRV_QUEUE_STOPPING;

	if (q->thread) {
		pthread_join(q->thread, NULL);
		q->thread = 0;
	}

	io_uring_queue_exit(&q->ring);

	if (q->io_buf && q->io_buf != MAP_FAILED)
		munmap(q->io_buf, q->io_buf_size);

	free(q->ios);

	if (q->io_cmd_buf && q->io_cmd_buf != MAP_FAILED)
		munmap(q->io_cmd_buf, __ublk_queue_cmd_buf_sz(q->q_depth));

	free(q->cpuset);
}

static int erofs_ublk_stop(int dev_id)
{
	struct erofs_ublk_dev *dev = ublk_get_dev(dev_id);
	int i;

	if (!dev)
		return -EINVAL;

	__atomic_store_n(&dev->stop_requested, 1, __ATOMIC_RELAXED);

	if (dev->stop_efd >= 0) {
		uint64_t val = 1;

		if (write(dev->stop_efd, &val, sizeof(val)) != sizeof(val))
			erofs_dbg("stop_efd write failed");
	}

	for (i = 0; i < dev->dev_info.nr_hw_queues; i++)
		dev->queues[i].state |= UBLKSRV_QUEUE_STOPPING;

	if (__atomic_load_n(&dev->running, __ATOMIC_RELAXED))
		ublk_stop_dev(dev);

	__atomic_store_n(&dev->running, 0, __ATOMIC_RELAXED);
	return 0;
}

static void ublk_sig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT) {
		erofs_info("received signal %d, stopping ublk device",
			   sig);
		if (g_sig_dev_id >= 0)
			erofs_ublk_stop(g_sig_dev_id);
	}
}

static int ublk_install_sig_handler(int dev_id)
{
	struct sigaction sa;

	g_sig_dev_id = dev_id;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = ublk_sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		erofs_err("sigaction(SIGTERM) failed: %s",
			  strerror(errno));
		return -errno;
	}

	if (sigaction(SIGINT, &sa, NULL) < 0) {
		erofs_err("sigaction(SIGINT) failed: %s",
			  strerror(errno));
		return -errno;
	}
	return 0;
}

int erofs_ublk_init(void)
{
	if (access(UBLK_CTRL_DEV, F_OK) != 0)
		return -EOPNOTSUPP;
	return 0;
}

int erofs_ublk_create_dev(const struct erofs_ublk_dev_info *info,
			  erofsublk_io_handler_t handler,
			  void *handler_ctx)
{
	struct erofs_ublk_dev *dev;
	char cdev_path[64];
	int i, ret, dev_id;

	if (!info)
		return -EINVAL;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return -ENOMEM;

	dev->handler = handler;
	dev->handler_ctx = handler_ctx;
	dev->ctrl_fd = -1;
	dev->cdev_fd = -1;
	dev->stop_efd = -1;

	dev->ctrl_fd = open(UBLK_CTRL_DEV, O_RDWR);
	if (dev->ctrl_fd < 0) {
		ret = -errno;
		erofs_err("failed to open " UBLK_CTRL_DEV ": %s", strerror(errno));
		goto err_free;
	}

	ret = ublk_ctrl_ring_init(&dev->ctrl_ring);
	if (ret < 0) {
		erofs_err("ctrl ring init failed: %s", erofs_strerror(ret));
		goto err_close_ctrl;
	}
	dev->ctrl_ring_initialized = 1;

	dev->stop_efd = eventfd(0, EFD_CLOEXEC);
	if (dev->stop_efd < 0)
		erofs_dbg("stop eventfd creation failed: %s", strerror(errno));

	ret = ublk_add_dev(dev, info);
	if (ret < 0)
		goto err_close_ctrl;

	snprintf(cdev_path, sizeof(cdev_path), UBLK_CDEV_FMT,
		 dev->dev_info.dev_id);
	dev->cdev_fd = open(cdev_path, O_RDWR);
	if (dev->cdev_fd < 0) {
		ret = -errno;
		erofs_err("failed to open %s: %s", cdev_path, strerror(errno));
		goto err_del_dev;
	}

	ret = ublk_set_params(dev, info);
	if (ret < 0)
		goto err_close_cdev;

	dev->queues = calloc(dev->dev_info.nr_hw_queues,
			     sizeof(struct erofs_ublk_queue));
	if (!dev->queues) {
		ret = -ENOMEM;
		goto err_close_cdev;
	}

	for (i = 0; i < dev->dev_info.nr_hw_queues; i++) {
		ret = ublk_init_queue(dev, i);
		if (ret < 0)
			goto err_cleanup_queues;
	}

	dev_id = dev->dev_info.dev_id;
	if (dev_id < 0 || dev_id >= UBLK_MAX_DEVS) {
		erofs_err("kernel assigned dev_id %d out of range", dev_id);
		ret = -ERANGE;
		goto err_cleanup_queues;
	}
	ublk_devs[dev_id] = dev;
	return dev_id;

err_cleanup_queues:
	for (i = i - 1; i >= 0; i--)
		ublk_cleanup_queue(dev, i);
	free(dev->queues);
err_close_cdev:
	close(dev->cdev_fd);
err_del_dev:
	ublk_del_dev(dev);
err_close_ctrl:
	close(dev->ctrl_fd);
err_free:
	free(dev);
	return ret;
}

void erofs_ublk_destroy(int dev_id)
{
	struct erofs_ublk_dev *dev = ublk_get_dev(dev_id);
	int i;

	if (!dev)
		return;

	erofs_ublk_stop(dev_id);

	if (dev->queues) {
		for (i = 0; i < dev->dev_info.nr_hw_queues; i++)
			ublk_cleanup_queue(dev, i);
		free(dev->queues);
	}

	if (dev->cdev_fd >= 0)
		close(dev->cdev_fd);

	if (dev->ctrl_fd >= 0) {
		ublk_del_dev(dev);
		close(dev->ctrl_fd);
	}

	if (dev->ctrl_ring_initialized)
		io_uring_queue_exit(&dev->ctrl_ring);

	if (dev->stop_efd >= 0)
		close(dev->stop_efd);

	ublk_devs[dev_id] = NULL;
	free(dev);
}

int erofs_ublk_start(int dev_id, int ready_fd)
{
	struct erofs_ublk_dev *dev = ublk_get_dev(dev_id);
	pthread_barrier_t init_barrier;
	int i, ret;

	if (!dev)
		return -EINVAL;

	ublk_install_sig_handler(dev_id);

	ret = pthread_barrier_init(&init_barrier,
				   NULL, dev->dev_info.nr_hw_queues + 1);
	if (ret) {
		erofs_err("pthread_barrier_init failed: %s", strerror(ret));
		return -ret;
	}

	for (i = 0; i < dev->dev_info.nr_hw_queues; i++) {
		dev->queues[i].init_barrier = &init_barrier;
		ret = pthread_create(&dev->queues[i].thread, NULL,
				     ublk_queue_thread, &dev->queues[i]);
		if (ret) {
			erofs_err("pthread_create failed: %s", strerror(ret));
			goto err_stop_threads;
		}
	}

	pthread_barrier_wait(&init_barrier);
	pthread_barrier_destroy(&init_barrier);
	for (i = 0; i < dev->dev_info.nr_hw_queues; i++)
		dev->queues[i].init_barrier = NULL;

	if (dev->recovering)
		ret = ublk_end_recovery(dev);
	else
		ret = ublk_start_dev(dev);
	if (ret < 0)
		goto err_stop_threads;

	__atomic_store_n(&dev->running, 1, __ATOMIC_RELAXED);

	if (!dev->recovering && ready_fd >= 0) {
		char ready = 0;

		if (write(ready_fd, &ready, 1) != 1)
			erofs_dbg("ready_fd write failed");
		close(ready_fd);
	}
	erofs_info("ublk device %s successfully",
		   dev->recovering ? "recovery completed" : "started");

	if (dev->stop_efd >= 0) {
		uint64_t val;

		while (!__atomic_load_n(&dev->stop_requested, __ATOMIC_RELAXED)) {
			if (read(dev->stop_efd, &val, sizeof(val)) < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			break;
		}
	} else {
		while (!__atomic_load_n(&dev->stop_requested, __ATOMIC_RELAXED))
			usleep(100000);
	}

	return 0;

err_stop_threads:
	pthread_barrier_destroy(&init_barrier);
	for (i = 0; i < dev->dev_info.nr_hw_queues; i++) {
		dev->queues[i].init_barrier = NULL;
		if (dev->queues[i].thread) {
			dev->queues[i].state |= UBLKSRV_QUEUE_STOPPING;
			pthread_join(dev->queues[i].thread, NULL);
			dev->queues[i].thread = 0;
		}
	}
	return ret;
}

int erofs_ublk_recover_dev(int dev_id,
			   erofsublk_io_handler_t handler,
			   void *handler_ctx)
{
	struct erofs_ublk_dev *dev;
	char cdev_path[64];
	int i, ret;

	if (dev_id < 0)
		return -EINVAL;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return -ENOMEM;

	dev->handler = handler;
	dev->handler_ctx = handler_ctx;
	dev->ctrl_fd = -1;
	dev->cdev_fd = -1;
	dev->stop_efd = -1;

	dev->ctrl_fd = open(UBLK_CTRL_DEV, O_RDWR);
	if (dev->ctrl_fd < 0) {
		ret = -errno;
		erofs_err("failed to open %s: %s",
			  UBLK_CTRL_DEV, strerror(errno));
		goto err_free;
	}

	ret = ublk_ctrl_ring_init(&dev->ctrl_ring);
	if (ret < 0) {
		erofs_err("ctrl ring init failed: %s",
			  strerror(-ret));
		goto err_close_ctrl;
	}
	dev->ctrl_ring_initialized = 1;

	dev->stop_efd = eventfd(0, EFD_CLOEXEC);
	if (dev->stop_efd < 0)
		erofs_dbg("stop eventfd creation failed: %s",
			  strerror(errno));

	ret = ublk_get_dev_info(dev, dev_id);
	if (ret < 0)
		goto err_close_ctrl;

	if (!(dev->dev_info.flags & UBLK_F_USER_RECOVERY)) {
		erofs_err("Device %d does not support user recovery", dev_id);
		ret = -EOPNOTSUPP;
		goto err_close_ctrl;
	}

	if (dev->dev_info.state != UBLK_S_DEV_QUIESCED &&
	    dev->dev_info.state != UBLK_S_DEV_FAIL_IO) {
		erofs_err("Device %d is not in recoverable state (state=%d)",
			  dev_id, dev->dev_info.state);
		ret = -EBUSY;
		goto err_close_ctrl;
	}

	ret = ublk_get_params(dev);
	if (ret < 0)
		goto err_close_ctrl;

	ret = ublk_start_recovery(dev);
	if (ret < 0)
		goto err_close_ctrl;

	snprintf(cdev_path, sizeof(cdev_path), UBLK_CDEV_FMT, dev_id);
	dev->cdev_fd = open(cdev_path, O_RDWR);
	if (dev->cdev_fd < 0) {
		ret = -errno;
		erofs_err("Failed to open %s: %s", cdev_path, strerror(errno));
		goto err_close_ctrl;
	}

	dev->queues = calloc(dev->dev_info.nr_hw_queues,
			     sizeof(struct erofs_ublk_queue));
	if (!dev->queues) {
		ret = -ENOMEM;
		goto err_close_cdev;
	}

	for (i = 0; i < dev->dev_info.nr_hw_queues; i++) {
		ret = ublk_init_queue(dev, i);
		if (ret < 0)
			goto err_cleanup_queues;
	}

	dev->recovering = 1;
	ublk_devs[dev_id] = dev;
	return 0;

err_cleanup_queues:
	for (i = i - 1; i >= 0; i--)
		ublk_cleanup_queue(dev, i);
	free(dev->queues);
err_close_cdev:
	close(dev->cdev_fd);
err_close_ctrl:
	close(dev->ctrl_fd);
err_free:
	free(dev);
	return ret;
}

int erofs_ublk_is_recoverable(int dev_id)
{
	struct erofs_ublk_dev dev;
	int ctrl_fd, ret;

	ctrl_fd = open(UBLK_CTRL_DEV, O_RDWR);
	if (ctrl_fd < 0)
		return 0;

	memset(&dev, 0, sizeof(dev));
	dev.ctrl_fd = ctrl_fd;

	ret = ublk_ctrl_ring_init(&dev.ctrl_ring);
	if (ret < 0) {
		close(ctrl_fd);
		return 0;
	}

	ret = ublk_get_dev_info(&dev, dev_id);
	io_uring_queue_exit(&dev.ctrl_ring);
	close(ctrl_fd);

	if (ret < 0)
		return 0;

	if ((dev.dev_info.flags & UBLK_F_USER_RECOVERY) &&
	    dev.dev_info.state == UBLK_S_DEV_QUIESCED)
		return 1;

	return 0;
}

static int ublk_stop_io_daemon(const struct ublksrv_ctrl_dev_info *dev_info)
{
	int daemon_pid = dev_info->ublksrv_pid;
	int cnt = 0, ret;

	if (daemon_pid == -1)
		return 0;

	/* wait until daemon is exited, or timeout after 3 seconds */
	do {
		ret = kill(daemon_pid, 0);
		if (ret)
			break;
		usleep(500000);
		cnt++;
	} while (!ret && cnt < 6);
	return 0;
}

int erofs_ublk_del_dev_by_id(int dev_id)
{
	struct ublksrv_ctrl_dev_info dev_info;
	struct ublksrv_ctrl_cmd cmd = {};
	struct io_uring ring;
	int ctrl_fd, ret;

	ctrl_fd = open(UBLK_CTRL_DEV, O_RDWR);
	if (ctrl_fd < 0)
		return -errno;

	ret = ublk_ctrl_ring_init(&ring);
	if (ret < 0) {
		erofs_err("io_uring_queue_init failed: %s", strerror(-ret));
		return ret;
	}
	cmd.dev_id = dev_id;
	cmd.queue_id = (u16)-1;
	cmd.len = sizeof(dev_info);
	cmd.addr = (u64)(uintptr_t)&dev_info;
	ret = ublk_ctrl_cmd_ring(&ring, ctrl_fd, UBLK_CMD_GET_DEV_INFO, &cmd);
	if (ret < 0) {
		erofs_ublk_use_legacy_cmds = true;
		ret = ublk_ctrl_cmd_ring(&ring, ctrl_fd, UBLK_CMD_GET_DEV_INFO, &cmd);
		if (ret < 0) {
			erofs_err("GET_DEV_INFO failed for device %d: %s",
				  dev_id, strerror(-ret));
			return ret;
		}
	}
	cmd.len = 0;
	cmd.addr = 0;
	ret = ublk_ctrl_cmd_ring(&ring, ctrl_fd, UBLK_CMD_STOP_DEV, &cmd);
	if (ret < 0 && ret != -ENODEV)
		erofs_dbg("STOP_DEV %d: %s", dev_id, strerror(-ret));

	ret = ublk_stop_io_daemon(&dev_info);
	if (ret < 0)
		erofs_err("stop daemon %d failed\n", dev_id);
	(void)ublk_ctrl_cmd_ring(&ring, ctrl_fd, UBLK_CMD_DEL_DEV, &cmd);
	io_uring_queue_exit(&ring);
	close(ctrl_fd);
	return ret;
}

#endif
