// SPDX-License-Identifier: GPL-2.0
/*
 * Host tests of libxdev_ext session logic: option validation, the request
 * structures handed to io_uring_register(), call order, and the STOP /
 * close ownership rules.  io_uring_register() is replaced through the
 * library's test hook; its returns are injected values that exercise the
 * library's handling.  No test here asserts that a device run succeeds:
 * that is proven only by the guest test against the real kernel.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

#include "include/uapi/linux/io_uring.h"
#include "tools/xdev_ext_mech/lib/libxdev_ext.h"
#include "tools/xdev_ext_mech/lib/libxdev_ext_internal.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"

static unsigned int checks, failures, tests;
static unsigned int test_failures_before;

#define EXPECT_EQ(actual, expected) do { \
	long long a_ = (long long)(actual); \
	long long e_ = (long long)(expected); \
	checks++; \
	if (a_ != e_) { \
		fprintf(stderr, "# %s:%d: %s: got %lld, expected %lld\n", \
			__FILE__, __LINE__, #actual, a_, e_); \
		failures++; \
	} \
} while (0)
#define EXPECT_TRUE(v) EXPECT_EQ(!!(v), 1)

/* --- injected io_uring_register ---------------------------------------- */

#define MAX_CALLS 4096
struct call {
	unsigned int opcode, op;
	struct xdev_ext_mech_create create;
	struct xdev_ext_mech_start start;
	struct xdev_ext_mech_notify_arm arm;
	struct io_uring_xdev_ext_umem_reg umem;
	struct xdev_ext_mech_transport_stats_v3 tstats;
	__u32 user_frames[64];
	__u64 stop_id, stats_id;
};
static struct call calls[MAX_CALLS];
static unsigned int nr_calls, nr_sleeps;

/* Per mech op: return value queue (last entry repeats). */
static int ret_umem;
static int ret_op[8][8];
static unsigned int nr_ret_op[8], used_ret_op[8];
static __u64 create_session_id = 77;
static struct xdev_ext_mech_stats stats_reply;

static void reset(void)
{
	memset(calls, 0, sizeof(calls));
	nr_calls = nr_sleeps = 0;
	ret_umem = 0;
	memset(ret_op, 0, sizeof(ret_op));
	memset(nr_ret_op, 0, sizeof(nr_ret_op));
	memset(used_ret_op, 0, sizeof(used_ret_op));
	create_session_id = 77;
	memset(&stats_reply, 0, sizeof(stats_reply));
}

static void queue_ret(unsigned int op, int ret)
{
	ret_op[op][nr_ret_op[op]++] = ret;
}

static int next_ret(unsigned int op)
{
	unsigned int i = used_ret_op[op];

	if (!nr_ret_op[op])
		return 0;
	if (i >= nr_ret_op[op])
		i = nr_ret_op[op] - 1;
	else
		used_ret_op[op]++;
	return ret_op[op][i];
}

static int fake_register(int fd, unsigned int opcode, void *arg, unsigned int nr)
{
	struct call *c = &calls[nr_calls < MAX_CALLS ? nr_calls++ : MAX_CALLS - 1];
	int ret;

	(void)fd;
	if (nr != 1)
		return -EINVAL;
	c->opcode = opcode;
	if (opcode == IORING_REGISTER_XDEV_EXT_UMEM) {
		memcpy(&c->umem, arg, sizeof(c->umem));
		return ret_umem;
	}
	if (opcode != IORING_REGISTER_XDEV_EXT_MECH)
		return -EINVAL;
	{
		struct io_uring_xdev_ext_mech *req = arg;
		void *p = (void *)(uintptr_t)req->arg;

		c->op = req->op;
		if (req->rsvd || req->op >= 8)
			return -EINVAL;
		ret = next_ret(req->op);
		switch (req->op) {
		case XDEV_EXT_MECH_OP_CREATE:
			memcpy(&c->create, p, sizeof(c->create));
			if (!ret)
				((struct xdev_ext_mech_create *)p)->session_id =
					create_session_id;
			break;
		case XDEV_EXT_MECH_OP_START:
			memcpy(&c->start, p, sizeof(c->start));
			if (c->start.user_frames && c->start.nr_user_frames <= 64)
				memcpy(c->user_frames,
				       (void *)(uintptr_t)c->start.user_frames,
				       c->start.nr_user_frames * sizeof(__u32));
			break;
		case XDEV_EXT_MECH_OP_NOTIFY_ARM:
			memcpy(&c->arm, p, sizeof(c->arm));
			break;
		case XDEV_EXT_MECH_OP_STOP:
			c->stop_id = req->arg;
			break;
		case XDEV_EXT_MECH_OP_STATS:
			c->stats_id = *(__u64 *)p;
			if (!ret) {
				stats_reply.session_id = c->stats_id;
				memcpy(p, &stats_reply, sizeof(stats_reply));
			}
			break;
		case XDEV_EXT_MECH_OP_TRANSPORT_STATS:
			memcpy(&c->tstats, p, sizeof(c->tstats));
			break;
		}
	}
	return ret;
}

static void fake_usleep(unsigned int usec)
{
	(void)usec;
	nr_sleeps++;
}

static int fail_setup(unsigned int entries, struct io_uring_params *p)
{
	(void)entries;
	(void)p;
	return -ENOSYS;
}

static const struct xdev_ext_sys fake_sys = {
	.io_uring_register = fake_register,
	.usleep = fake_usleep,
};

static unsigned int count_ops(unsigned int op)
{
	unsigned int i, n = 0;

	for (i = 0; i < nr_calls; i++)
		n += calls[i].opcode == IORING_REGISTER_XDEV_EXT_MECH &&
		     calls[i].op == op;
	return n;
}

static const struct call *last_op(unsigned int op)
{
	unsigned int i;

	for (i = nr_calls; i--;)
		if (calls[i].opcode == IORING_REGISTER_XDEV_EXT_MECH &&
		    calls[i].op == op)
			return &calls[i];
	return NULL;
}

static int open_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	int n = 0;

	if (!d)
		return -1;
	while ((e = readdir(d)))
		n += e->d_name[0] != '.';
	closedir(d);
	return n - 1;	/* the directory stream itself */
}

static struct xdev_ext_session *open_iou(__u32 frames)
{
	struct xdev_ext_pool_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .nr_frames = frames);
	struct xdev_ext_session *s = NULL;

	EXPECT_EQ(xdev_ext_session_open(&o, &s), 0);
	return s;
}

static struct xdev_ext_create_opts nvme_nvme_create(void)
{
	struct xdev_ext_create_opts c = XDEV_EXT_OPTS_INIT(xdev_ext_create_opts,
		.group_bytes = 8192, .depth = 4, .nr_stages = 2);

	c.st[0] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 100,
		.arg0 = 8, .arg1 = 64 };
	c.st[1] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 101,
		.arg0 = 1024, .arg1 = 64 };
	return c;
}

static struct xdev_ext_session *created(__u32 frames)
{
	struct xdev_ext_create_opts c = nvme_nvme_create();
	struct xdev_ext_session *s = open_iou(frames);

	if (s)
		EXPECT_EQ(xdev_ext_session_create(s, &c), 0);
	return s;
}

/* --- tests ---------------------------------------------------------------- */

static void test_open_validation(void)
{
	struct xdev_ext_pool_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM);
	struct {
		struct xdev_ext_pool_opts o;
		__u64 tail;
	} big = { .o = o };
	struct xdev_ext_session *s = (void *)1;
	int fds = open_fds();

	EXPECT_EQ(xdev_ext_session_open(NULL, &s), -EINVAL);
	EXPECT_EQ(xdev_ext_session_open(&o, NULL), -EINVAL);
	o.sz = offsetof(struct xdev_ext_pool_opts, flags);
	EXPECT_EQ(xdev_ext_session_open(&o, &s), -EINVAL);
	o.sz = sizeof(o);
	o.flags = 1;
	EXPECT_EQ(xdev_ext_session_open(&o, &s), -EOPNOTSUPP);
	o.flags = 0;
	big.o.sz = sizeof(big);
	big.tail = 1;
	EXPECT_EQ(xdev_ext_session_open(&big.o, &s), -EOPNOTSUPP);
	o.pool_kind = 0;
	EXPECT_EQ(xdev_ext_session_open(&o, &s), -EINVAL);
	o.pool_kind = 99;
	EXPECT_EQ(xdev_ext_session_open(&o, &s), -EINVAL);
	o.pool_kind = XDEV_EXT_MECH_POOL_PEER;
	EXPECT_EQ(xdev_ext_session_open(&o, &s), -EOPNOTSUPP);
	o.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
	o.nr_frames = XDEV_EXT_MAX_FRAMES + 1;
	EXPECT_EQ(xdev_ext_session_open(&o, &s), -EINVAL);
	o.nr_frames = 0;
	o.pool_kind = XDEV_EXT_MECH_POOL_XSK;
	EXPECT_EQ(xdev_ext_session_open(&o, &s), -EINVAL);	/* no ifname */
	o.ifname = "xdevextnone0";
	o.xsk_mode = 2;
	EXPECT_EQ(xdev_ext_session_open(&o, &s), -EINVAL);
	o.xsk_mode = XDEV_EXT_XSK_COPY;
	EXPECT_EQ(xdev_ext_session_open(&o, &s), -ENODEV);
	EXPECT_EQ((uintptr_t)s, 1);	/* out untouched on failure */
	EXPECT_EQ(open_fds(), fds);
}

static void test_open_setup_failure(void)
{
	struct xdev_ext_sys sys = fake_sys;
	struct xdev_ext_pool_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM);
	struct xdev_ext_session *s = NULL;
	int fds = open_fds();

	sys.io_uring_setup = fail_setup;
	xdev_ext__set_sys(&sys);
	EXPECT_EQ(xdev_ext_session_open(&o, &s), -ENOSYS);
	EXPECT_EQ(open_fds(), fds);
	xdev_ext__set_sys(&fake_sys);
}

static void test_open_iou_umem(void)
{
	struct {
		struct xdev_ext_pool_opts o;
		__u64 tail;
	} big = { .o = XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .nr_frames = 16) };
	struct xdev_ext_session *s = NULL;
	int fds = open_fds();

	ret_umem = -EINVAL;
	EXPECT_EQ(xdev_ext_session_open(&big.o, &s), -EINVAL);
	EXPECT_EQ(open_fds(), fds);
	EXPECT_EQ(nr_calls, 1);
	EXPECT_EQ(calls[0].opcode, IORING_REGISTER_XDEV_EXT_UMEM);
	EXPECT_TRUE(calls[0].umem.addr);
	EXPECT_EQ(calls[0].umem.size, 16ULL * XDEV_EXT_FRAME_SIZE);
	EXPECT_EQ(calls[0].umem.frame_size, XDEV_EXT_FRAME_SIZE);
	EXPECT_EQ(calls[0].umem.flags, 0);
	EXPECT_EQ(calls[0].umem.shared_addr, 0);

	reset();
	big.o.sz = sizeof(big);	/* zero tail: accepted */
	EXPECT_EQ(xdev_ext_session_open(&big.o, &s), 0);
	EXPECT_TRUE(s);
	EXPECT_EQ(open_fds(), fds + 2);
	EXPECT_TRUE(xdev_ext_session_ring_fd(s) >= 0);
	EXPECT_TRUE(xdev_ext_session_eventfd(s) >= 0);
	EXPECT_EQ(xdev_ext_session_xsk_fd(s), -1);
	EXPECT_EQ(xdev_ext_session_id(s), 0);
	EXPECT_EQ(xdev_ext_session_retained(s), 0);
	EXPECT_EQ(xdev_ext_session_close(s), 0);
	EXPECT_EQ(nr_calls, 1);	/* no STOP for a session never created */
	EXPECT_EQ(open_fds(), fds);

	reset();
	big.o.nr_frames = 0;	/* default size */
	EXPECT_EQ(xdev_ext_session_open(&big.o, &s), 0);
	EXPECT_EQ(calls[0].umem.size, (__u64)XDEV_EXT_DEFAULT_FRAMES * XDEV_EXT_FRAME_SIZE);
	EXPECT_EQ(xdev_ext_session_close(s), 0);
}

static void test_order(void)
{
	struct xdev_ext_start_opts st = XDEV_EXT_OPTS_INIT(xdev_ext_start_opts,
		.nr_batches = 1);
	struct xdev_ext_mech_transport_stats_v3 t;
	struct xdev_ext_mech_stats out;
	struct xdev_ext_session *s = open_iou(16);

	EXPECT_EQ(xdev_ext_session_arm(s, 1, 0), -ENOTCONN);
	EXPECT_EQ(xdev_ext_session_start(s, &st), -ENOTCONN);
	EXPECT_EQ(xdev_ext_session_wait(s, 0, &out), -ENOTCONN);
	EXPECT_EQ(xdev_ext_session_stats(s, &out), -ENOTCONN);
	EXPECT_EQ(xdev_ext_session_nic_accounting(s, &t), -ENOTCONN);
	EXPECT_EQ(xdev_ext_session_stop(s), -ENOTCONN);
	EXPECT_EQ(nr_calls, 1);
	EXPECT_EQ(xdev_ext_session_close(s), 0);
	EXPECT_EQ(xdev_ext_session_close(NULL), -EINVAL);
	EXPECT_EQ(xdev_ext_session_stop(NULL), -EINVAL);
	EXPECT_EQ(xdev_ext_session_eventfd(NULL), -EINVAL);
	EXPECT_EQ(xdev_ext_session_id(NULL), 0);
}

static void test_create_validation(void)
{
	struct xdev_ext_create_opts c = nvme_nvme_create();
	struct {
		struct xdev_ext_create_opts c;
		__u32 tail;
	} big;
	struct xdev_ext_session *s = open_iou(16);

	EXPECT_EQ(xdev_ext_session_create(NULL, &c), -EINVAL);
	EXPECT_EQ(xdev_ext_session_create(s, NULL), -EINVAL);
	c.group_bytes = 0;
	EXPECT_EQ(xdev_ext_session_create(s, &c), -EINVAL);
	c = nvme_nvme_create();
	c.depth = 0;
	EXPECT_EQ(xdev_ext_session_create(s, &c), -EINVAL);
	c = nvme_nvme_create();
	c.nr_stages = 0;
	EXPECT_EQ(xdev_ext_session_create(s, &c), -EINVAL);
	c.nr_stages = XDEV_EXT_MECH_MAX_STAGES + 1;
	EXPECT_EQ(xdev_ext_session_create(s, &c), -EINVAL);
	c = nvme_nvme_create();
	c.flags = 1;
	EXPECT_EQ(xdev_ext_session_create(s, &c), -EOPNOTSUPP);
	c = nvme_nvme_create();
	c.sz = offsetof(struct xdev_ext_create_opts, flags);
	EXPECT_EQ(xdev_ext_session_create(s, &c), -EINVAL);
	big.c = nvme_nvme_create();
	big.c.sz = sizeof(big);
	big.tail = 9;
	EXPECT_EQ(xdev_ext_session_create(s, &big.c), -EOPNOTSUPP);
	EXPECT_EQ(nr_calls, 1);	/* only the UMEM registration */
	EXPECT_EQ(xdev_ext_session_close(s), 0);
}

static void test_create_request(void)
{
	struct xdev_ext_create_opts c = nvme_nvme_create();
	struct xdev_ext_mech_layout l;
	const struct call *k;
	struct xdev_ext_session *s = open_iou(16);

	c.peer.local_ip = 0x01020304;
	c.peer.peer_port = 0x3412;
	queue_ret(XDEV_EXT_MECH_OP_CREATE, -EXDEV);
	queue_ret(XDEV_EXT_MECH_OP_CREATE, 0);
	EXPECT_EQ(xdev_ext_session_create(s, &c), -EXDEV);
	EXPECT_EQ(xdev_ext_session_id(s), 0);
	EXPECT_EQ(xdev_ext_session_create(s, &c), 0);	/* a failed CREATE can be retried */
	EXPECT_EQ(xdev_ext_session_id(s), 77);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_CREATE), 2);
	k = last_op(XDEV_EXT_MECH_OP_CREATE);
	EXPECT_EQ(k->create.abi_version, XDEV_EXT_MECH_ABI_VERSION);
	EXPECT_EQ(k->create.nr_stages, 2);
	EXPECT_EQ(k->create.pool_kind, XDEV_EXT_MECH_POOL_IOU_UMEM);
	EXPECT_EQ(k->create.pool_fd, -1);
	EXPECT_EQ(k->create.eventfd, xdev_ext_session_eventfd(s));
	EXPECT_EQ(k->create.depth, 4);
	EXPECT_EQ(xdev_ext_mech_ctl_layout(1500, 8192, &l), 0);
	EXPECT_EQ(memcmp(&k->create.layout, &l, sizeof(l)), 0);
	EXPECT_EQ(memcmp(&k->create.peer, &c.peer, sizeof(c.peer)), 0);
	EXPECT_EQ(memcmp(k->create.st, c.st, sizeof(c.st)), 0);	/* fds passed through */
	EXPECT_EQ(k->create.session_id, 0);
	EXPECT_EQ(xdev_ext_session_create(s, &c), -EALREADY);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_CREATE), 2);
	queue_ret(XDEV_EXT_MECH_OP_STOP, 0);
	EXPECT_EQ(xdev_ext_session_close(s), 0);

	/* An explicit layout and MTU are passed through/used as given. */
	reset();
	s = open_iou(16);
	c = nvme_nvme_create();
	c.layout = (struct xdev_ext_mech_layout) { .frame_size = 4096,
		.hdr_room = 512, .seg_len = 3584, .group_bytes = 8192 };
	EXPECT_EQ(xdev_ext_session_create(s, &c), 0);
	k = last_op(XDEV_EXT_MECH_OP_CREATE);
	EXPECT_EQ(k->create.layout.hdr_room, 512);
	EXPECT_EQ(k->create.layout.seg_len, 3584);
	EXPECT_EQ(xdev_ext_session_close(s), 0);
	reset();
	s = open_iou(16);
	c = nvme_nvme_create();
	c.mtu = 9000;
	EXPECT_EQ(xdev_ext_session_create(s, &c), 0);
	EXPECT_EQ(xdev_ext_mech_ctl_layout(9000, 8192, &l), 0);
	k = last_op(XDEV_EXT_MECH_OP_CREATE);
	EXPECT_EQ(memcmp(&k->create.layout, &l, sizeof(l)), 0);
	EXPECT_EQ(xdev_ext_session_close(s), 0);
}

static void test_arm(void)
{
	struct xdev_ext_session *s = created(16);
	const struct call *k;

	EXPECT_EQ(xdev_ext_session_arm(NULL, 1, 0), -EINVAL);
	EXPECT_EQ(xdev_ext_session_arm(s, 0, 0), -EINVAL);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_NOTIFY_ARM), 0);
	queue_ret(XDEV_EXT_MECH_OP_NOTIFY_ARM, -ESHUTDOWN);
	EXPECT_EQ(xdev_ext_session_arm(s, 5, 7), -ESHUTDOWN);
	k = last_op(XDEV_EXT_MECH_OP_NOTIFY_ARM);
	EXPECT_EQ(k->arm.session_id, 77);
	EXPECT_EQ(k->arm.batches_target, 5);
	EXPECT_EQ(k->arm.published_target, 7);
	EXPECT_EQ(k->arm.flags, 0);
	EXPECT_EQ(k->arm.rsvd, 0);
	EXPECT_EQ(xdev_ext_session_close(s), 0);
}

static void test_start(void)
{
	struct xdev_ext_start_opts st = XDEV_EXT_OPTS_INIT(xdev_ext_start_opts,
		.nr_batches = 10);
	struct xdev_ext_session *s = created(16);	/* 8192 B at MTU 1500: 6 frames */
	const struct call *k;
	__u32 frames, i;
	struct xdev_ext_mech_layout l;

	EXPECT_EQ(xdev_ext_mech_ctl_layout(1500, 8192, &l), 0);
	frames = (__u32)xdev_ext_mech_layout_frames(&l);
	EXPECT_EQ(frames, 6);
	EXPECT_EQ(xdev_ext_session_start(s, NULL), -EINVAL);
	st.nr_batches = 0;
	EXPECT_EQ(xdev_ext_session_start(s, &st), -EINVAL);
	st.nr_batches = 10;
	st.flags = 1;
	EXPECT_EQ(xdev_ext_session_start(s, &st), -EOPNOTSUPP);
	st.flags = 0;
	/* depth 4 * 6 frames = 24 > 16 frames of pool: refused before START */
	EXPECT_EQ(xdev_ext_session_start(s, &st), -E2BIG);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_START), 0);
	EXPECT_EQ(xdev_ext_session_close(s), 0);

	reset();
	s = created(64);
	st.nr_batches = 2;	/* min(2, depth 4) = 2 groups lent */
	EXPECT_EQ(xdev_ext_session_start(s, &st), 0);
	k = last_op(XDEV_EXT_MECH_OP_START);
	EXPECT_EQ(k->start.session_id, 77);
	EXPECT_EQ(k->start.nr_batches, 2);
	EXPECT_EQ(k->start.first_seq, 1);
	EXPECT_EQ(k->start.flags, XDEV_EXT_MECH_START_F_USER_FRAMES |
				  XDEV_EXT_MECH_START_F_RECYCLE);
	EXPECT_EQ(k->start.nr_user_frames, 2 * frames);
	for (i = 0; i < 2 * frames; i++)
		EXPECT_EQ(k->user_frames[i], i);
	EXPECT_EQ(xdev_ext_session_start(s, &st), -EOPNOTSUPP);	/* append reserved */
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_START), 1);
	EXPECT_EQ(xdev_ext_session_close(s), 0);

	reset();
	s = created(64);
	st.nr_batches = 100;
	st.first_seq = 9;
	queue_ret(XDEV_EXT_MECH_OP_START, -EINVAL);
	EXPECT_EQ(xdev_ext_session_start(s, &st), -EINVAL);
	k = last_op(XDEV_EXT_MECH_OP_START);
	EXPECT_EQ(k->start.first_seq, 9);
	EXPECT_EQ(k->start.nr_user_frames, 4 * frames);
	EXPECT_EQ(xdev_ext_session_close(s), 0);
}

static void test_wait(void)
{
	struct xdev_ext_start_opts st = XDEV_EXT_OPTS_INIT(xdev_ext_start_opts,
		.nr_batches = 3);
	struct xdev_ext_mech_stats out;
	struct xdev_ext_session *s = created(64);
	__u64 one = 1;

	EXPECT_EQ(xdev_ext_session_arm(s, 3, 0), 0);
	EXPECT_EQ(xdev_ext_session_start(s, &st), 0);
	EXPECT_EQ(xdev_ext_session_wait(s, 0, NULL), -EINVAL);
	/* No notification: deadline, and still one final snapshot. */
	stats_reply.state = XDEV_EXT_MECH_SESSION_ACTIVE;
	stats_reply.inflight = 3;
	EXPECT_EQ(xdev_ext_session_wait(s, 20, &out), -ETIMEDOUT);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_STATS), 1);
	EXPECT_EQ(last_op(XDEV_EXT_MECH_OP_STATS)->stats_id, 77);
	EXPECT_EQ(out.inflight, 3);
	/* A notification with the armed target reached. */
	stats_reply.inflight = 0;
	stats_reply.batches_done = 3;
	stats_reply.submitted[0] = stats_reply.completed[0] = 3;
	EXPECT_EQ(write(xdev_ext_session_eventfd(s), &one, sizeof(one)), 8);
	EXPECT_EQ(xdev_ext_session_wait(s, 1000, &out), 0);
	EXPECT_EQ(out.batches_done, 3);
	/* Short of the target. */
	stats_reply.batches_done = 2;
	EXPECT_EQ(write(xdev_ext_session_eventfd(s), &one, sizeof(one)), 8);
	EXPECT_EQ(xdev_ext_session_wait(s, 1000, &out), -EIO);
	/* Aborted, sequestered. */
	stats_reply.batches_done = 3;
	stats_reply.batches_abort = 1;
	EXPECT_EQ(write(xdev_ext_session_eventfd(s), &one, sizeof(one)), 8);
	EXPECT_EQ(xdev_ext_session_wait(s, 1000, &out), -EIO);
	stats_reply.batches_abort = 0;
	stats_reply.sequestered = 1;
	EXPECT_EQ(write(xdev_ext_session_eventfd(s), &one, sizeof(one)), 8);
	EXPECT_EQ(xdev_ext_session_wait(s, 1000, &out), -EIO);
	stats_reply.sequestered = 0;
	/* Stopping, error. */
	stats_reply.state = XDEV_EXT_MECH_SESSION_STOPPING;
	EXPECT_EQ(write(xdev_ext_session_eventfd(s), &one, sizeof(one)), 8);
	EXPECT_EQ(xdev_ext_session_wait(s, 1000, &out), -ESHUTDOWN);
	stats_reply.last_err = -ENODATA;
	EXPECT_EQ(write(xdev_ext_session_eventfd(s), &one, sizeof(one)), 8);
	EXPECT_EQ(xdev_ext_session_wait(s, 1000, &out), -ENODATA);
	/* A failed final STATS is reported, with or without a notification. */
	queue_ret(XDEV_EXT_MECH_OP_STATS, -EFAULT);
	EXPECT_EQ(xdev_ext_session_wait(s, 10, &out), -EFAULT);
	EXPECT_EQ(xdev_ext_session_close(s), 0);
}

static void test_stats_and_accounting(void)
{
	struct xdev_ext_mech_transport_stats_v3 t;
	struct xdev_ext_mech_stats out;
	struct xdev_ext_session *s = created(16);
	const struct call *k;

	stats_reply.batches_done = 11;
	EXPECT_EQ(xdev_ext_session_stats(s, NULL), -EINVAL);
	EXPECT_EQ(xdev_ext_session_stats(s, &out), 0);
	EXPECT_EQ(out.session_id, 77);
	EXPECT_EQ(out.batches_done, 11);
	EXPECT_EQ(xdev_ext_session_nic_accounting(s, NULL), -EINVAL);
	queue_ret(XDEV_EXT_MECH_OP_TRANSPORT_STATS, -ENOENT);
	EXPECT_EQ(xdev_ext_session_nic_accounting(s, &t), -ENOENT);
	k = last_op(XDEV_EXT_MECH_OP_TRANSPORT_STATS);
	EXPECT_EQ(k->tstats.v2.v1.size, sizeof(struct xdev_ext_mech_transport_stats_v3));
	EXPECT_EQ(k->tstats.v2.v1.version, XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_3);
	EXPECT_EQ(k->tstats.v2.v1.session_id, 77);
	EXPECT_EQ(k->tstats.nic_zc_ops, 0);
	EXPECT_EQ(xdev_ext_session_close(s), 0);
}

static void test_stop_released(void)
{
	int fds = open_fds();
	struct xdev_ext_session *s = created(16);

	EXPECT_EQ(xdev_ext_session_stop(s), 0);
	EXPECT_EQ(last_op(XDEV_EXT_MECH_OP_STOP)->stop_id, 77);
	EXPECT_EQ(xdev_ext_session_retained(s), 0);
	EXPECT_EQ(xdev_ext_session_stop(s), 0);	/* idempotent: no second STOP */
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_STOP), 1);
	EXPECT_EQ(xdev_ext_session_close(s), 0);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_STOP), 1);
	EXPECT_EQ(open_fds(), fds);
}

static void test_stop_eagain(void)
{
	struct xdev_ext_session *s = created(16);
	unsigned int i;

	queue_ret(XDEV_EXT_MECH_OP_STOP, -EAGAIN);
	queue_ret(XDEV_EXT_MECH_OP_STOP, -EAGAIN);
	queue_ret(XDEV_EXT_MECH_OP_STOP, 0);
	EXPECT_EQ(xdev_ext_session_stop(s), 0);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_STOP), 3);
	EXPECT_EQ(nr_sleeps, 2);
	EXPECT_EQ(xdev_ext_session_close(s), 0);

	reset();
	s = created(16);
	queue_ret(XDEV_EXT_MECH_OP_STOP, -EAGAIN);	/* repeats */
	EXPECT_EQ(xdev_ext_session_stop(s), -EAGAIN);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_STOP), XDEV_EXT_STOP_RETRIES + 1);
	EXPECT_EQ(nr_sleeps, XDEV_EXT_STOP_RETRIES);
	EXPECT_EQ(xdev_ext_session_retained(s), 0);
	/* Still live: close tries STOP again, and keeps the handle on -EAGAIN. */
	EXPECT_EQ(xdev_ext_session_close(s), -EAGAIN);
	for (i = 0; i < 8; i++)
		ret_op[XDEV_EXT_MECH_OP_STOP][i] = 0;
	nr_ret_op[XDEV_EXT_MECH_OP_STOP] = 1;
	used_ret_op[XDEV_EXT_MECH_OP_STOP] = 0;
	EXPECT_EQ(xdev_ext_session_close(s), 0);
}

static void test_stop_retained(void)
{
	int fds = open_fds();
	struct xdev_ext_session *s = created(16);
	unsigned int stats_before;

	queue_ret(XDEV_EXT_MECH_OP_STOP, -EBUSY);
	EXPECT_EQ(xdev_ext_session_stop(s), -EBUSY);
	EXPECT_EQ(xdev_ext_session_retained(s), 1);
	EXPECT_EQ(xdev_ext_session_id(s), 77);
	/* Kernel still reports it: nothing is released. */
	stats_reply.state = XDEV_EXT_MECH_SESSION_ZOMBIE;
	stats_reply.inflight = 1;
	stats_before = count_ops(XDEV_EXT_MECH_OP_STATS);
	EXPECT_EQ(xdev_ext_session_close(s), -EBUSY);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_STATS), stats_before + 1);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_STOP), 1);	/* never re-STOPped */
	EXPECT_EQ(open_fds(), fds + 2);
	EXPECT_EQ(xdev_ext_session_stop(s), -EBUSY);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_STOP), 1);
	/* Another query error is not proof of release either. */
	queue_ret(XDEV_EXT_MECH_OP_STATS, -EFAULT);
	EXPECT_EQ(xdev_ext_session_close(s), -EBUSY);
	EXPECT_EQ(open_fds(), fds + 2);
	/* -ENOENT: the kernel released it; close frees everything. */
	ret_op[XDEV_EXT_MECH_OP_STATS][0] = -ENOENT;
	used_ret_op[XDEV_EXT_MECH_OP_STATS] = 0;
	EXPECT_EQ(xdev_ext_session_close(s), 0);
	EXPECT_EQ(open_fds(), fds);
}

static void test_close_stops_live(void)
{
	struct xdev_ext_session *s = created(16);

	EXPECT_EQ(xdev_ext_session_close(s), 0);
	EXPECT_EQ(count_ops(XDEV_EXT_MECH_OP_STOP), 1);
	EXPECT_EQ(calls[nr_calls - 1].op, XDEV_EXT_MECH_OP_STOP);

	reset();
	s = created(16);
	queue_ret(XDEV_EXT_MECH_OP_STOP, -EBUSY);
	stats_reply.state = XDEV_EXT_MECH_SESSION_STOPPING;
	EXPECT_EQ(xdev_ext_session_close(s), -EBUSY);
	EXPECT_EQ(xdev_ext_session_retained(s), 1);
	queue_ret(XDEV_EXT_MECH_OP_STATS, -ENOENT);
	EXPECT_EQ(xdev_ext_session_close(s), 0);
}

#define RUN(fn) do { \
	reset(); \
	xdev_ext__set_sys(&fake_sys); \
	test_failures_before = failures; \
	fn(); \
	xdev_ext__set_sys(NULL); \
	printf("%s %u - %s\n", failures == test_failures_before ? "ok" : "not ok", \
	       ++tests, #fn); \
} while (0)

int main(void)
{
	printf("TAP version 13\n1..14\n");
	RUN(test_open_validation);
	RUN(test_open_setup_failure);
	RUN(test_open_iou_umem);
	RUN(test_order);
	RUN(test_create_validation);
	RUN(test_create_request);
	RUN(test_arm);
	RUN(test_start);
	RUN(test_wait);
	RUN(test_stats_and_accounting);
	RUN(test_stop_released);
	RUN(test_stop_eagain);
	RUN(test_stop_retained);
	RUN(test_close_stops_live);
	printf("# checks=%u failures=%u\n", checks, failures);
	return failures ? 1 : 0;
}
