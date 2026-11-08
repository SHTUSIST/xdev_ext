// SPDX-License-Identifier: GPL-2.0
/* Host-frame endpoint contract (TP host-frame route for a GPU without
 * GPUDirect RDMA): send [CE FROM_DEVICE, XDOMAIN TO_DEVICE] and receive
 * [XDOMAIN FROM_DEVICE, CE TO_DEVICE + TARGET_RANGE] on the ring's UMEM,
 * one START per posted sequence. The real endpoint object is linked; the
 * session calls below record what it asks the kernel for and inject replies.
 * No io_uring, device, CE or XDOMAIN runs here.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include "libxdev_ext_frame_endpoint.h"

static unsigned checks, failures;
static int wait_fd = -1;
#define EQ(actual, expected) do { \
	long long a_ = (long long)(actual), e_ = (long long)(expected); checks++; \
	if (a_ != e_) { fprintf(stderr, "# line %d %s: got %lld expected %lld\n", \
		__LINE__, #actual, a_, e_); failures++; } \
} while (0)

/* ---- recorded session layer --------------------------------------------- */
struct xdev_ext_session { int id; bool created, stopped, closed; };
static struct xdev_ext_session sessions[16];
static unsigned opened, creates, starts, stops, closes, waits;
static struct xdev_ext_pool_opts seen_pool;
static struct xdev_ext_create_opts seen_create;
static int seen_fds[4]; static __u32 seen_nr;
static struct xdev_ext_start_frames_opts seen_start;
static __u32 seen_indices[64];
static int create_ret;
/* Scripted wait replies: return code and the stats the session reports. */
struct reply { int ret; struct xdev_ext_mech_stats st; };
static struct reply script[8]; static unsigned script_len, script_at;
static __u64 started_batches;

int xdev_ext_session_open(const struct xdev_ext_pool_opts *o, struct xdev_ext_session **out)
{
	seen_pool = *o;
	sessions[opened].id = (int)opened + 1;
	*out = &sessions[opened++];
	return 0;
}
int xdev_ext_session_create(struct xdev_ext_session *s, const struct xdev_ext_create_opts *o)
{
	creates++; seen_create = *o; seen_nr = 0;
	if (!create_ret) s->created = true;
	return create_ret;
}
int xdev_ext_session_create_programs(struct xdev_ext_session *s, const struct xdev_ext_create_opts *o,
	const int *fds, __u32 nr, struct xdev_ext_mech_create_report *report)
{
	(void)report;
	creates++; seen_create = *o; seen_nr = nr;
	for (__u32 i = 0; i < nr && i < 4; i++) seen_fds[i] = fds[i];
	if (!create_ret) s->created = true;
	return create_ret;
}
int xdev_ext_session_start_frames(struct xdev_ext_session *s, const struct xdev_ext_start_frames_opts *o)
{
	(void)s;
	starts++; seen_start = *o;
	for (__u32 i = 0; i < o->nr_indices && i < 64; i++) seen_indices[i] = o->indices[i];
	seen_start.indices = NULL;
	started_batches += o->nr_batches;
	return 0;
}
int xdev_ext_session_wait(struct xdev_ext_session *s, int timeout_ms, struct xdev_ext_mech_stats *out)
{
	(void)s; (void)timeout_ms;
	waits++;
	if (script_at >= script_len) return -ETIMEDOUT;
	*out = script[script_at].st;
	return script[script_at++].ret;
}
int xdev_ext_session_eventfd(const struct xdev_ext_session *s) { (void)s; return wait_fd; }
int xdev_ext_session_stop(struct xdev_ext_session *s) { stops++; s->stopped = true; return 0; }
int xdev_ext_session_close(struct xdev_ext_session *s) { closes++; s->closed = true; return 0; }
__u64 xdev_ext_session_id(const struct xdev_ext_session *s) { return (__u64)s->id; }
/* Same rule as the library's option-size check (xdev_ext_session.c). */
int xdev_ext__opts_check(const void *o, size_t sz, size_t known)
{
	if (sz < known) return -EINVAL;
	for (size_t i = known; i < sz; i++)
		if (((const unsigned char *)o)[i]) return -EOPNOTSUPP;
	return 0;
}
int xdev_ext_stage_xdomain(struct xdev_ext_mech_stage_uapi *out, int control_fd,
	__u64 link_token, __u32 direction, __u32 flags)
{
	*out = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_XDOMAIN,
		.direction = direction, .fd = control_fd, .flags = flags, .arg0 = link_token };
	return 0;
}

/* ---- helpers ----------------------------------------------------------- */
#define CONTROL 7
#define CE 9
#define TOKEN 0xabc123ULL
#define VA 0x7f0000200000ULL
#define GROUP (3U * 4096U + 64U)	/* 4 frames, the last one partial */

static struct xdev_ext_frame_endpoint_opts opts(__u32 direction, __u64 window)
{
	return (struct xdev_ext_frame_endpoint_opts){ .sz = sizeof(struct xdev_ext_frame_endpoint_opts),
		.control_fd = CONTROL, .ce_fd = CE, .link_token = TOKEN, .direction = direction,
		.depth = 1, .group_bytes = GROUP, .window_va = VA, .window_bytes = window };
}
static struct xdev_ext_mech_stats done_stats(__u64 done)
{
	return (struct xdev_ext_mech_stats){ .batches_done = done,
		.state = XDEV_EXT_MECH_SESSION_ACTIVE };
}
static void reset(void)
{
	if (wait_fd >= 0) close(wait_fd);
	wait_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	EQ(wait_fd >= 0, 1);
	memset(sessions, 0, sizeof(sessions));
	opened = creates = starts = stops = closes = waits = 0;
	script_len = script_at = 0; create_ret = 0; started_batches = 0;
	memset(&seen_create, 0, sizeof(seen_create));
	memset(&seen_start, 0, sizeof(seen_start));
}

/* Invalid options open nothing. */
static void test_open_refuses_bad_options(void)
{
	struct xdev_ext_frame_endpoint *e = (void *)1;
	struct xdev_ext_frame_endpoint_opts o;

	reset();
	EQ(xdev_ext_frame_endpoint_open(NULL, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP);
	EQ(xdev_ext_frame_endpoint_open(&o, NULL), -EINVAL);
	o.direction = 0; EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	EQ(e == NULL, 1);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP); o.control_fd = -1;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP); o.ce_fd = -1;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP); o.link_token = 0;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP); o.depth = 2;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EOPNOTSUPP);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP); o.depth = 0;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP); o.group_bytes = 0;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP); o.group_bytes = 4097;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, 33U * 4096U); o.group_bytes = 33U * 4096U;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP - 64);
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_FROM_DEVICE, GROUP - 64);
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP); o.window_va = 0;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP); o.window_va = UINT64_MAX - 4096;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EINVAL);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP); o.flags = 2;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), -EOPNOTSUPP);
	o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP); o.sz = 8;
	EQ(xdev_ext_frame_endpoint_open(&o, &e) < 0, 1);
	EQ(opened, 0);
}

/* Send: [CE FROM_DEVICE (slot), XDOMAIN TO_DEVICE] on UMEM frames. */
static void test_send_stages(void)
{
	struct xdev_ext_frame_endpoint_opts o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, 1U << 21);
	struct xdev_ext_frame_endpoint *e = NULL;
	__u64 off = 1; __u32 bytes = 0;

	reset();
	EQ(xdev_ext_frame_endpoint_open(&o, &e), 0);
	EQ(opened, 1);
	EQ(seen_pool.pool_kind, XDEV_EXT_MECH_POOL_IOU_UMEM);
	EQ(seen_pool.nr_frames, 4);
	EQ(xdev_ext_frame_endpoint_session(e) == &sessions[0], 1);
	EQ(xdev_ext_frame_endpoint_create(e), 0);
	EQ(seen_create.group_bytes, GROUP);
	EQ(seen_create.depth, 1);
	EQ(seen_create.nr_stages, 2);
	EQ(seen_create.layout.frame_size, 4096);
	EQ(seen_create.layout.hdr_room, 0);
	EQ(seen_create.layout.seg_len, 4096);
	EQ(seen_create.layout.group_bytes, GROUP);
	EQ(seen_create.st[0].class_id, XDEV_EXT_MECH_CLASS_CE);
	EQ(seen_create.st[0].direction, XDEV_EXT_MECH_DIR_FROM_DEVICE);
	EQ(seen_create.st[0].fd, CE);
	EQ(seen_create.st[0].flags, 0);
	EQ(seen_create.st[0].arg0, VA);
	EQ(seen_create.st[0].arg1, 1U << 21);
	EQ(seen_create.st[1].class_id, XDEV_EXT_MECH_CLASS_XDOMAIN);
	EQ(seen_create.st[1].direction, XDEV_EXT_MECH_DIR_TO_DEVICE);
	EQ(seen_create.st[1].fd, CONTROL);
	EQ(seen_create.st[1].arg0, TOKEN);
	EQ(seen_create.st[1].flags, 0);
	EQ(xdev_ext_frame_endpoint_place(e, 41, &off, &bytes), 0);
	EQ(off, 0); EQ(bytes, GROUP);
	EQ(xdev_ext_frame_endpoint_close(e), 0);
	EQ(stops, 1); EQ(closes, 1);
}

/* Receive: [XDOMAIN FROM_DEVICE, CE TO_DEVICE + TARGET_RANGE], early CTS,
 * explicit program selectors in stage order, keyed placement in a ring. */
static void test_receive_stages(void)
{
	struct xdev_ext_frame_endpoint_opts o = opts(XDEV_EXT_MECH_DIR_FROM_DEVICE, 3ULL * GROUP);
	struct xdev_ext_frame_endpoint *e = NULL;
	int fds[2] = { 11, -1 };
	__u64 off = 0; __u32 bytes = 0;

	reset();
	o.flags = XDEV_EXT_FRAME_ENDPOINT_F_EARLY;
	EQ(xdev_ext_frame_endpoint_open(&o, &e), 0);
	EQ(xdev_ext_frame_endpoint_create_programs(e, fds, 3, NULL), -EINVAL);
	EQ(creates, 0);
	EQ(xdev_ext_frame_endpoint_create_programs(e, fds, 2, NULL), 0);
	EQ(seen_nr, 2); EQ(seen_fds[0], 11); EQ(seen_fds[1], -1);
	EQ(seen_create.st[0].class_id, XDEV_EXT_MECH_CLASS_XDOMAIN);
	EQ(seen_create.st[0].direction, XDEV_EXT_MECH_DIR_FROM_DEVICE);
	EQ(seen_create.st[0].flags, XDEV_EXT_XDOMAIN_F_EARLY);
	EQ(seen_create.st[1].class_id, XDEV_EXT_MECH_CLASS_CE);
	EQ(seen_create.st[1].direction, XDEV_EXT_MECH_DIR_TO_DEVICE);
	EQ(seen_create.st[1].flags, XDEV_EXT_CE_STAGE_F_TARGET_RANGE);
	EQ(seen_create.st[1].arg0, VA);
	EQ(seen_create.st[1].arg1, 3ULL * GROUP);
	EQ(xdev_ext_frame_endpoint_place(e, 7, &off, &bytes), 0);
	EQ(off, GROUP); EQ(bytes, GROUP);
	EQ(xdev_ext_frame_endpoint_place(e, 9, &off, &bytes), 0);
	EQ(off, 0);
	EQ(xdev_ext_frame_endpoint_place(e, 0, &off, &bytes), -EINVAL);
	EQ(xdev_ext_frame_endpoint_close(e), 0);
}

/* One START per post, keyed by the sequence, recycled frames 0..n-1. */
static void test_post_and_wait(void)
{
	struct xdev_ext_frame_endpoint_opts o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP);
	struct xdev_ext_frame_endpoint *e = NULL;

	reset();
	EQ(xdev_ext_frame_endpoint_open(&o, &e), 0);
	EQ(xdev_ext_frame_endpoint_post(e, 5), -ENOTCONN);
	EQ(xdev_ext_frame_endpoint_create(e), 0);
	EQ(xdev_ext_frame_endpoint_post(e, 0), -EINVAL);
	EQ(starts, 0);
	EQ(xdev_ext_frame_endpoint_post(e, 5), 0);
	EQ(starts, 1);
	EQ(seen_start.nr_batches, 1);
	EQ(seen_start.first_seq, 5);
	EQ(seen_start.nr_indices, 4);
	EQ(seen_start.flags, XDEV_EXT_MECH_START_F_RECYCLE);
	EQ(seen_indices[0], 0); EQ(seen_indices[3], 3);
	EQ(xdev_ext_frame_endpoint_post(e, 6), -EBUSY);
	EQ(starts, 1);
	EQ(xdev_ext_frame_endpoint_wait(e, 6, 100), -EINVAL);
	/* A wake before the batch finished is not a failure. */
	script[0] = (struct reply){ -EIO, done_stats(0) };
	script[1] = (struct reply){ 0, done_stats(1) };
	script_len = 2;
	EQ(xdev_ext_frame_endpoint_wait(e, 5, 100), 0);
	EQ(waits, 2);
	EQ(xdev_ext_frame_endpoint_post(e, 6), 0);
	EQ(seen_start.first_seq, 6);
	/* A timeout keeps the batch posted; the same wait can finish it later. */
	script_len = script_at = 0;
	EQ(xdev_ext_frame_endpoint_wait(e, 6, 1), -ETIMEDOUT);
	EQ(xdev_ext_frame_endpoint_post(e, 7), -EBUSY);
	script[0] = (struct reply){ 0, done_stats(2) };
	script_len = 1; script_at = 0;
	EQ(xdev_ext_frame_endpoint_wait(e, 6, 100), 0);
	/* A failed batch is sticky: no further posts. */
	EQ(xdev_ext_frame_endpoint_post(e, 7), 0);
	script[0] = (struct reply){ -EPROTO, done_stats(2) };
	script[0].st.last_err = -EPROTO;
	script_len = 1; script_at = 0;
	EQ(xdev_ext_frame_endpoint_wait(e, 7, 100), -EPROTO);
	EQ(xdev_ext_frame_endpoint_post(e, 8), -EPROTO);
	EQ(xdev_ext_frame_endpoint_wait(e, 7, 100), -EPROTO);
	EQ(starts, 3);
	EQ(xdev_ext_frame_endpoint_close(e), 0);
	EQ(stops, 1); EQ(closes, 1);
}

/* An abort or a sequestered batch is a failure even when wait returned -EIO. */
static void test_wait_abort(void)
{
	struct xdev_ext_frame_endpoint_opts o = opts(XDEV_EXT_MECH_DIR_FROM_DEVICE, GROUP);
	struct xdev_ext_frame_endpoint *e = NULL;

	reset();
	EQ(xdev_ext_frame_endpoint_open(&o, &e), 0);
	EQ(xdev_ext_frame_endpoint_create(e), 0);
	EQ(xdev_ext_frame_endpoint_post(e, 3), 0);
	script[0] = (struct reply){ -EIO, done_stats(1) };
	script[0].st.batches_abort = 1;
	script_len = 1;
	EQ(xdev_ext_frame_endpoint_wait(e, 3, 100), -EIO);
	EQ(waits, 1);
	EQ(xdev_ext_frame_endpoint_post(e, 4), -EIO);
	EQ(xdev_ext_frame_endpoint_close(e), 0);
}

/* A failed CREATE never stops a session that was not created. */
static void test_create_failure(void)
{
	struct xdev_ext_frame_endpoint_opts o = opts(XDEV_EXT_MECH_DIR_TO_DEVICE, GROUP);
	struct xdev_ext_frame_endpoint *e = NULL;

	reset();
	EQ(xdev_ext_frame_endpoint_open(&o, &e), 0);
	create_ret = -EOPNOTSUPP;
	EQ(xdev_ext_frame_endpoint_create(e), -EOPNOTSUPP);
	EQ(xdev_ext_frame_endpoint_post(e, 1), -ENOTCONN);
	EQ(xdev_ext_frame_endpoint_close(e), 0);
	EQ(stops, 0); EQ(closes, 1);
}

/* A broken notification fd produces persistent POLLERR with an otherwise
 * pending final stats snapshot. Infinite wait must retain that error, rather
 * than retrying until the bounded fixture runs out of replies. */
static void test_wait_bad_notification_fd(void)
{
	struct xdev_ext_frame_endpoint_opts o = opts(XDEV_EXT_MECH_DIR_FROM_DEVICE, GROUP);
	struct xdev_ext_frame_endpoint *e = NULL;
	int p[2];

	reset();
	EQ(pipe(p), 0);
	EQ(close(p[0]), 0);
	EQ(close(wait_fd), 0);
	wait_fd = p[1]; /* write end without a reader: actual poll reports POLLERR */
	EQ(xdev_ext_frame_endpoint_open(&o, &e), 0);
	EQ(xdev_ext_frame_endpoint_create(e), 0);
	EQ(xdev_ext_frame_endpoint_post(e, 11), 0);
	for (unsigned i = 0; i < 4; i++)
		script[i] = (struct reply){ -EIO, done_stats(0) };
	script_len = 4;
	EQ(xdev_ext_frame_endpoint_wait(e, 11, -1), -EIO);
	EQ(waits, 1);
	EQ(xdev_ext_frame_endpoint_post(e, 12), -EIO);
	EQ(xdev_ext_frame_endpoint_wait(e, 11, -1), -EIO);
	EQ(waits, 1);
	EQ(xdev_ext_frame_endpoint_close(e), 0);
}

int main(void)
{
	test_open_refuses_bad_options();
	test_send_stages();
	test_receive_stages();
	test_post_and_wait();
	test_wait_abort();
	test_create_failure();
	test_wait_bad_notification_fd();
	if (wait_fd >= 0) close(wait_fd);
	printf("%s 1 - host-frame endpoint stages, START and wait (%u checks, %u failures)\n",
	       failures ? "not ok" : "ok", checks, failures);
	return failures != 0;
}
