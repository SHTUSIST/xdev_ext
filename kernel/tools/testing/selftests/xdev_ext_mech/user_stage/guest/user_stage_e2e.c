// SPDX-License-Identifier: GPL-2.0
/* GUEST TEST ONLY: the USER stage class (XDEV_EXT_MECH_CLASS_USER) on real
 * QEMU NVMe PCI controllers.  Correctness only; nothing here is timed.  The
 * user thread uses the libxdev_ext USER helpers.  Every session reads the
 * source disk and, when it has a write stage, writes the destination disk at
 * the same window offset; the host validator (user_validate.py) checks both
 * disks independently of this program, with its own CRC32C.
 *
 * Cases, in order (a CHECK failure ends the program with "not ok"):
 *   seal        NVMe READ -> USER (CRC32C of the first 4092 bytes of each
 *               frame written into its last 4, length kept) -> NVMe WRITE
 *   append      NVMe READ -> USER (CRC32C of each 2048-byte frame appended,
 *               +4) -> CPU CRC32C_CHECK: the kernel verifies every append
 *   append-bad  the same with one wrong CRC: that batch, and only it, fails
 *   deadline    one batch is never completed: cancelled at its 300 ms
 *               deadline, its late completion refused, the session goes on
 *   malformed   stale and garbage completion entries refused; a length past
 *               capacity, a length off the exact rule and a user errno each
 *               fail exactly their batch
 *   stop-held   STOP while the user thread holds every batch
 *   kill        SIGKILL of the process holding the batches (it alone holds
 *               the user stage fd): the session stops with -EPIPE, drains,
 *               returns every frame, STOP releases it
 *   kill-owner  SIGKILL of a process owning ring, session and user stage:
 *               ring exit frees the session (not quarantined)
 *   refuse      CREATE refusals (POLL, reused fd, small ring, foreign fd,
 *               no deadline, length change before NVMe), fd operation and
 *               register request refusals
 * Usage: user_stage_e2e SRC_BLOCK SRC_NG DST_BLOCK DST_NG BPF_DIR
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "linux/io_uring.h"
#include "linux/xdev_ext_mech.h"
#include "libxdev_ext.h"

#define LBA 512U
#define FRAME 4096U
#define GUARD 0x6b
#define WAIT_MS 60000

static unsigned int checks;
#define CHECK(c, msg) do { if (!(c)) { \
	fprintf(stderr, "not ok %u - %s (errno=%d %s)\n", ++checks, msg, errno, strerror(errno)); \
	printf("not ok %u - %s\n", checks, msg); exit(1); } printf("ok %u - %s\n", ++checks, msg); } while (0)

/* The plans are duplicated, not shared, with user_validate.py. */
struct plan {
	const char *name;
	__u32 seg, group, depth;
	__u64 groups, src_slba, dst_slba;	/* dst_slba 0: no write stage */
	__s64 delta;
	__u32 deadline_ms;
	bool cpu_check;
};
static const struct plan SEAL = { "seal", 4096, 8192, 4, 64, 2048, 2048, 0, 5000, false };
static const struct plan APPEND = { "append", 2048, 4096, 4, 32, 4096, 0, 4, 5000, true };
static const struct plan APPEND_BAD = { "append-bad", 2048, 4096, 4, 16, 4096, 0, 4, 5000, true };
static const struct plan DEADLINE = { "deadline", 4096, 4096, 2, 8, 8192, 8192, 0, 300, false };
static const struct plan MALFORMED = { "malformed", 4096, 4096, 1, 6, 9216, 9216, 0, 5000, false };
static const struct plan STOPHELD = { "stop-held", 4096, 4096, 4, 100, 10240, 10240, 0, 60000, false };
static const struct plan KILL = { "kill", 4096, 4096, 4, 100, 12288, 12288, 0, 60000, false };
static const struct plan KILL_OWNER = { "kill-owner", 4096, 4096, 4, 100, 14336, 14336, 0, 60000, false };
#define DEADLINE_HELD_ID 3
#define APPEND_BAD_ID 5

static __u64 window_nlb(const struct plan *p)
{
	return p->groups * p->group / LBA;
}

/* CRC32C (Castagnoli), bitwise; the validator has its own. */
static __u32 crc32c(const unsigned char *p, size_t n)
{
	__u32 crc = ~0U;
	size_t i;
	int k;

	for (i = 0; i < n; i++) {
		crc ^= p[i];
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0x82f63b78U & (0U - (crc & 1)));
	}
	return ~crc;
}

static void put_le32(unsigned char *p, __u32 v)
{
	p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

static int mech(int ring, __u32 op, __u64 arg)
{
	struct io_uring_xdev_ext_mech req = { .op = op, .arg = arg };
	int ret = syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_MECH, &req, 1);

	return ret < 0 ? -errno : ret;
}

static int open_ok(const char *path, int flags)
{
	int fd = open(path, flags | O_CLOEXEC);

	CHECK(fd >= 0, path);
	return fd;
}

struct ops_link { struct bpf_object *object; struct bpf_link *link; };
static void attach_ops(const char *dir, const char *name, struct ops_link *o)
{
	char path[PATH_MAX], what[96];
	struct bpf_map *map;

	snprintf(path, sizeof(path), "%s/%s.bpf.o", dir, name);
	snprintf(what, sizeof(what), "load and attach %s struct_ops", name);
	o->object = bpf_object__open_file(path, NULL);
	o->link = NULL;
	if (!libbpf_get_error(o->object) && !bpf_object__load(o->object))
		bpf_object__for_each_map(map, o->object) {
			if (bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS)
				continue;
			o->link = bpf_map__attach_struct_ops(map);
			break;
		}
	CHECK(o->link && !libbpf_get_error(o->link), what);
}

static void detach_ops(struct ops_link *o)
{
	bpf_link__destroy(o->link);
	bpf_object__close(o->object);
}

struct session {
	int ring;
	void *pool;
	size_t pool_bytes;
	__u32 nr_loan;
	__u32 frames[256];
	struct xdev_ext_mech_create c;
	struct xdev_ext_user_stage *u;
};

/* A ring with its UMEM and, when @entries, a user stage fd opened on it. */
static void ring_up(struct session *s, const struct plan *p, __u32 entries)
{
	struct io_uring_params params = {};
	struct io_uring_xdev_ext_umem_reg reg = { .frame_size = FRAME };
	__u32 per = p->group / p->seg, i;

	memset(s, 0, sizeof(*s));
	s->pool_bytes = (size_t)p->depth * per * FRAME * 2;
	s->pool = mmap(NULL, s->pool_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(s->pool != MAP_FAILED, "session pool memory");
	memset(s->pool, 0x97, s->pool_bytes);
	s->ring = syscall(__NR_io_uring_setup, 8, &params);
	CHECK(s->ring >= 0, "io_uring ring");
	reg.addr = (uintptr_t)s->pool;
	reg.size = s->pool_bytes;
	CHECK(!syscall(__NR_io_uring_register, s->ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg, 1),
	      "register the ring UMEM");
	s->nr_loan = p->depth * per;
	for (i = 0; i < s->nr_loan; i++)
		s->frames[i] = i;
	if (entries) {
		struct xdev_ext_user_stage_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_user_stage_opts,
			.ring_fd = s->ring, .umem = s->pool, .entries = entries);

		CHECK(!xdev_ext_user_stage_open(&o, &s->u), "open a user stage fd and map its rings");
	}
}

/* NVMe READ -> USER [-> NVMe WRITE | -> CPU CRC32C_CHECK]. */
static int create(struct session *s, const struct plan *p, int src_ng, int dst_ng,
		  int user_fd, __u32 user_flags)
{
	__u32 n = 0;

	s->c = (struct xdev_ext_mech_create){
		.abi_version = XDEV_EXT_MECH_ABI_VERSION, .pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM,
		.pool_fd = -1, .layout = { FRAME, 0, p->seg, p->group }, .depth = p->depth, .eventfd = -1,
	};
	s->c.st[n++] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = src_ng,
		.arg0 = p->src_slba, .arg1 = window_nlb(p) };
	s->c.st[n++] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_USER,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = user_fd, .flags = user_flags,
		.arg0 = p->deadline_ms, .arg1 = (__u64)p->delta };
	if (p->cpu_check)
		s->c.st[n++] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_CPU,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = -1,
			.arg0 = XDEV_EXT_CPU_XFORM_CRC32C_CHECK };
	else if (dst_ng >= 0)
		s->c.st[n++] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = dst_ng,
			.arg0 = p->dst_slba, .arg1 = window_nlb(p) };
	s->c.nr_stages = n;
	return mech(s->ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&s->c);
}

static void start(struct session *s, const struct plan *p)
{
	struct xdev_ext_mech_start st = { .session_id = s->c.session_id, .nr_batches = p->groups,
		.flags = XDEV_EXT_MECH_START_F_USER_FRAMES | XDEV_EXT_MECH_START_F_RECYCLE,
		.nr_user_frames = s->nr_loan, .user_frames = (uintptr_t)s->frames };

	CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&st), "exactly one START");
}

static int stats_of(int ring, __u64 id, struct xdev_ext_mech_stats *st)
{
	memset(st, 0, sizeof(*st));
	st->session_id = id;
	return mech(ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)st);
}

static void print_stats(const char *name, const struct xdev_ext_mech_stats *st)
{
	printf("# %s stats: done=%llu abort=%llu rejects=%llu protocol_err=%llu timeouts=%llu inflight=%llu "
	       "sequestered=%llu published=%llu submitted=%llu/%llu/%llu completed=%llu/%llu/%llu last_err=%d state=%u\n",
	       name, (unsigned long long)st->batches_done, (unsigned long long)st->batches_abort,
	       (unsigned long long)st->rejects, (unsigned long long)st->protocol_err,
	       (unsigned long long)st->timeouts, (unsigned long long)st->inflight,
	       (unsigned long long)st->sequestered, (unsigned long long)st->published,
	       (unsigned long long)st->submitted[0], (unsigned long long)st->submitted[1],
	       (unsigned long long)st->submitted[2], (unsigned long long)st->completed[0],
	       (unsigned long long)st->completed[1], (unsigned long long)st->completed[2],
	       st->last_err, st->state);
}

/* Polling loops: no TAP line per read; a failed read is still fatal. */
static void stats_quiet(struct session *s, struct xdev_ext_mech_stats *st)
{
	if (stats_of(s->ring, s->c.session_id, st))
		CHECK(0, "session STATS while waiting");
}

/* Poll STATS until done + abort reaches @n (and nothing is in flight when
 * @idle), or the wait bound. */
static struct xdev_ext_mech_stats wait_ended(struct session *s, __u64 n, bool idle)
{
	struct xdev_ext_mech_stats st;
	int i;

	for (i = 0; i < WAIT_MS / 5; i++) {
		stats_quiet(s, &st);
		if (st.batches_done + st.batches_abort >= n && (!idle || !st.inflight))
			break;
		usleep(5000);
	}
	return st;
}

static struct xdev_ext_mech_stats wait_finished(struct session *s, const struct plan *p, __u64 n)
{
	struct xdev_ext_mech_stats st = wait_ended(s, n, true);

	print_stats(p->name, &st);
	return st;
}

/* --- the user thread ---------------------------------------------------- */

enum action { SEAL_CRC, APPEND_CRC, IDENTITY, HOLD };
struct worker {
	struct session *s;
	const struct plan *p;
	enum action action;
	__u64 bad_id;			/* append-bad: wrong CRC for this batch */
	__u64 hold_id;			/* deadline: never complete this one in time */
	struct xdev_ext_user_batch held;
	bool have_held;
	volatile unsigned taken, completed;
	volatile int first_submitted_next;	/* seal: next stage submits seen at the first batch */
	volatile int exit_code;
	pthread_t thread;
};

static void *user_thread(void *arg)
{
	struct worker *w = arg;
	struct xdev_ext_user_batch b;
	__u32 i;
	int ret;

	for (;;) {
		ret = xdev_ext_user_stage_next(w->s->u, -1, &b);
		if (ret == -ESHUTDOWN) {
			w->exit_code = ret;
			return NULL;
		}
		if (ret) {
			w->exit_code = ret;
			return NULL;
		}
		if (!w->taken++ && w->action == SEAL_CRC) {
			struct xdev_ext_mech_stats st;

			/* The first batch is held: nothing can have reached the write stage. */
			if (!stats_of(w->s->ring, w->s->c.session_id, &st))
				w->first_submitted_next = (int)(st.submitted[2] + st.completed[1]);
		}
		if (w->action == HOLD || (w->hold_id && b.batch_id == w->hold_id)) {
			if (w->hold_id) {
				w->held = b;
				w->have_held = true;
			}
			continue;
		}
		for (i = 0; i < b.nr_frames; i++) {
			unsigned char *d = b.data[i];
			__u32 len = b.f[i].data_len;

			if (w->action == SEAL_CRC) {
				put_le32(d + len - 4, crc32c(d, len - 4));
			} else if (w->action == APPEND_CRC) {
				__u32 crc = crc32c(d, len);

				if (b.batch_id == w->bad_id && i == 0)
					crc ^= 1;
				put_le32(d + len, crc);
				b.f[i].out_len = len + 4;
			}
		}
		ret = xdev_ext_user_stage_complete(w->s->u, &b, 0);
		if (ret) {
			w->exit_code = ret;
			return NULL;
		}
		w->completed++;
	}
}

static void worker_start(struct worker *w, struct session *s, const struct plan *p, enum action a)
{
	memset(w, 0, sizeof(*w));
	w->s = s;
	w->p = p;
	w->action = a;
	w->first_submitted_next = -1;
	CHECK(!pthread_create(&w->thread, NULL, user_thread, w), "start the user thread");
}

/* After STOP: the thread must see the stopped stage and leave next(). */
static void worker_join(struct worker *w, const char *what)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 30;
	CHECK(!pthread_timedjoin_np(w->thread, NULL, &ts), what);
}

static void finish(struct session *s, int expect, const char *what)
{
	struct xdev_ext_mech_stats st;

	CHECK(mech(s->ring, XDEV_EXT_MECH_OP_STOP, s->c.session_id) == expect, what);
	CHECK(stats_of(s->ring, s->c.session_id, &st) == -ENOENT, "the released session is gone");
}

static void ring_down(struct session *s)
{
	if (s->u)
		xdev_ext_user_stage_close(s->u);
	s->u = NULL;
	CHECK(!close(s->ring), "close ring");
	munmap(s->pool, s->pool_bytes);
}

/* --- cases ------------------------------------------------------------- */

static void case_seal(int srcng, int dstng)
{
	struct xdev_ext_mech_stats st;
	struct session s;
	struct worker w;

	ring_up(&s, &SEAL, 4);
	CHECK(!create(&s, &SEAL, srcng, dstng, xdev_ext_user_stage_fd(s.u), 0),
	      "seal: CREATE NVMe READ -> USER -> NVMe WRITE");
	worker_start(&w, &s, &SEAL, SEAL_CRC);
	start(&s, &SEAL);
	st = wait_finished(&s, &SEAL, SEAL.groups);
	CHECK(st.batches_done == SEAL.groups && !st.batches_abort && !st.rejects && !st.protocol_err &&
	      !st.timeouts && !st.inflight && !st.sequestered && !st.last_err,
	      "seal: every batch done through the user thread");
	CHECK(st.submitted[1] == SEAL.groups && st.completed[1] == SEAL.groups &&
	      st.submitted[2] == SEAL.groups && st.completed[2] == SEAL.groups,
	      "seal: one USER hand-out and one NVMe WRITE per batch");
	CHECK(w.first_submitted_next == 0,
	      "seal: while the first batch was held no batch had reached the write stage");
	finish(&s, 0, "seal: STOP releases the session (0)");
	worker_join(&w, "seal: the user thread sees the stopped stage and returns");
	CHECK(w.exit_code == -ESHUTDOWN && w.completed == SEAL.groups, "seal: next() ends with -ESHUTDOWN");
	ring_down(&s);
	puts("XDEV_EXT_USER_CASE=PASS case=seal");
}

static void case_append(int srcng, const struct plan *p, bool bad)
{
	struct xdev_ext_mech_stats st;
	struct session s;
	struct worker w;

	ring_up(&s, p, 4);
	CHECK(!create(&s, p, srcng, -1, xdev_ext_user_stage_fd(s.u), 0),
	      "append: CREATE NVMe READ -> USER(+4) -> CPU CRC32C_CHECK");
	worker_start(&w, &s, p, APPEND_CRC);
	if (bad)
		w.bad_id = APPEND_BAD_ID;
	start(&s, p);
	st = wait_finished(&s, p, p->groups);
	if (!bad) {
		CHECK(st.batches_done == p->groups && !st.batches_abort && !st.rejects && !st.protocol_err &&
		      !st.last_err && st.completed[2] == p->groups,
		      "append: the kernel's CRC32C check accepts every appended CRC at the new length");
		finish(&s, 0, "append: STOP releases the session (0)");
	} else {
		CHECK(st.batches_done == p->groups - 1 && st.batches_abort == 1 && !st.protocol_err &&
		      st.last_err == -EBADMSG,
		      "append-bad: exactly the batch with the wrong CRC fails the kernel check (-EBADMSG)");
		finish(&s, -EBADMSG, "append-bad: STOP returns the first error");
	}
	worker_join(&w, "append: the user thread returns");
	ring_down(&s);
	printf("XDEV_EXT_USER_CASE=PASS case=%s\n", p->name);
}

static void case_deadline(int srcng, int dstng)
{
	struct xdev_ext_mech_stats st;
	struct session s;
	struct worker w;
	int i;

	ring_up(&s, &DEADLINE, 2);
	CHECK(!create(&s, &DEADLINE, srcng, dstng, xdev_ext_user_stage_fd(s.u), 0),
	      "deadline: CREATE with a 300 ms deadline");
	worker_start(&w, &s, &DEADLINE, IDENTITY);
	w.hold_id = DEADLINE_HELD_ID;
	start(&s, &DEADLINE);
	st = wait_finished(&s, &DEADLINE, DEADLINE.groups);
	CHECK(st.batches_done == DEADLINE.groups - 1 && st.batches_abort == 1 && st.timeouts == 1 &&
	      !st.inflight && st.last_err == -ETIMEDOUT && st.state == XDEV_EXT_MECH_SESSION_ACTIVE,
	      "deadline: the held batch is cancelled at its deadline; the session stays ACTIVE");
	CHECK(w.have_held && w.held.batch_id == DEADLINE_HELD_ID, "deadline: the user thread held batch 3");
	/* All other batches ended: the user thread waits in next(), one producer. */
	CHECK(!xdev_ext_user_stage_complete(s.u, &w.held, 0), "deadline: post the late completion (kick accepted)");
	for (i = 0; i < 2000; i++) {
		stats_quiet(&s, &st);
		if (st.rejects)
			break;
		usleep(1000);
	}
	print_stats("deadline after late completion", &st);
	CHECK(st.rejects == 1 && st.batches_done == DEADLINE.groups - 1 && st.batches_abort == 1,
	      "deadline: the late completion is refused and changes nothing");
	finish(&s, -ETIMEDOUT, "deadline: STOP returns the deadline error");
	worker_join(&w, "deadline: the user thread returns");
	ring_down(&s);
	puts("XDEV_EXT_USER_CASE=PASS case=deadline");
}

/* The user side done by hand: one batch at a time (depth 1). */
static void case_malformed(int srcng, int dstng)
{
	struct xdev_ext_user_batch b, bogus;
	struct xdev_ext_mech_stats st;
	struct session s;
	__u64 i;

	ring_up(&s, &MALFORMED, 4);
	CHECK(!create(&s, &MALFORMED, srcng, dstng, xdev_ext_user_stage_fd(s.u), 0),
	      "malformed: CREATE depth 1");
	start(&s, &MALFORMED);
	for (i = 1; i <= MALFORMED.groups; i++) {
		CHECK(!xdev_ext_user_stage_next(s.u, WAIT_MS, &b) && b.batch_id == i && b.nr_frames == 1,
		      "malformed: batches arrive one by one in id order");
		CHECK(b.f[0].data_len == FRAME && b.f[0].capacity == FRAME && b.f[0].out_len == FRAME,
		      "malformed: slot table describes the frame");
		switch (i) {
		case 1:
			bogus = b;
			bogus.slot = 3;		/* not below depth 1 */
			CHECK(!xdev_ext_user_stage_complete(s.u, &bogus, 0), "malformed: post an out-of-depth slot");
			bogus = b;
			bogus.ticket++;
			CHECK(!xdev_ext_user_stage_complete(s.u, &bogus, 0), "malformed: post a wrong ticket");
			break;
		case 2:
			b.f[0].out_len = FRAME + 1;
			break;
		case 4:
			b.f[0].out_len = FRAME - 1;
			break;
		}
		CHECK(!xdev_ext_user_stage_complete(s.u, &b, i == 3 ? -EIO : 0), "malformed: post the completion");
		st = wait_ended(&s, i, false);
		CHECK(st.batches_done + st.batches_abort == i, "malformed: that batch ended before the next");
	}
	st = wait_finished(&s, &MALFORMED, MALFORMED.groups);
	CHECK(st.batches_done == 3 && st.batches_abort == 3 && st.rejects == 2 && st.protocol_err == 2 &&
	      st.last_err == -EPROTO && st.submitted[2] == 3,
	      "malformed: two refused entries, three failed batches (past capacity, user errno, off the rule)");
	finish(&s, -EPROTO, "malformed: STOP returns the first error");
	ring_down(&s);
	puts("XDEV_EXT_USER_CASE=PASS case=malformed");
}

static void wait_held(struct session *s, struct worker *w, const struct plan *p, struct xdev_ext_mech_stats *st)
{
	int i;

	for (i = 0; i < WAIT_MS / 5; i++) {
		stats_quiet(s, st);
		if ((!w || w->taken == p->depth) && st->inflight == p->depth && st->submitted[1] == p->depth)
			break;
		usleep(5000);
	}
	print_stats(p->name, st);
}

static void case_stop_held(int srcng, int dstng)
{
	struct xdev_ext_mech_stats st;
	struct session s;
	struct worker w;

	ring_up(&s, &STOPHELD, 4);
	CHECK(!create(&s, &STOPHELD, srcng, dstng, xdev_ext_user_stage_fd(s.u), 0), "stop-held: CREATE");
	worker_start(&w, &s, &STOPHELD, HOLD);
	start(&s, &STOPHELD);
	wait_held(&s, &w, &STOPHELD, &st);
	CHECK(w.taken == STOPHELD.depth && st.inflight == STOPHELD.depth && !st.completed[1] &&
	      !st.submitted[2] && !st.batches_done && !st.batches_abort,
	      "stop-held: every batch held by the user thread, none past the USER stage");
	finish(&s, 0, "stop-held: STOP cancels the held batches, drains and releases (0)");
	worker_join(&w, "stop-held: the blocked user thread wakes and returns");
	CHECK(w.exit_code == -ESHUTDOWN, "stop-held: next() returns -ESHUTDOWN after STOP");
	ring_down(&s);
	puts("XDEV_EXT_USER_CASE=PASS case=stop-held");
}

static int pipe_read_timeout(int fd, void *buf, size_t n, int ms)
{
	struct pollfd p = { .fd = fd, .events = POLLIN };
	size_t got = 0;

	while (got < n) {
		ssize_t r;

		if (poll(&p, 1, ms) != 1)
			return -ETIMEDOUT;
		r = read(fd, (char *)buf + got, n - got);
		if (r <= 0)
			return -EIO;
		got += r;
	}
	return 0;
}

/* Child: the only holder of the user stage fd; holds every batch, then waits. */
static void hold_forever(struct xdev_ext_user_stage *u, int out, __u32 depth)
{
	struct xdev_ext_user_batch b;
	__u32 i;
	char c = 'h';

	for (i = 0; i < depth; i++) {
		if (xdev_ext_user_stage_next(u, WAIT_MS, &b))
			_exit(3);
		if (write(out, &c, 1) != 1)
			_exit(4);
	}
	for (;;)
		pause();
}

static void case_kill(int srcng, int dstng)
{
	struct xdev_ext_mech_stats st;
	struct session s;
	int fds[2], status, i;
	char held[8];
	pid_t pid;

	ring_up(&s, &KILL, 4);
	CHECK(!create(&s, &KILL, srcng, dstng, xdev_ext_user_stage_fd(s.u), 0), "kill: CREATE");
	CHECK(!pipe2(fds, O_CLOEXEC), "kill: pipe");
	pid = fork();
	CHECK(pid >= 0, "kill: fork the user process");
	if (!pid) {
		close(fds[0]);
		hold_forever(s.u, fds[1], KILL.depth);
	}
	close(fds[1]);
	/* The child alone keeps the user stage fd and mapping now. */
	xdev_ext_user_stage_close(s.u);
	s.u = NULL;
	start(&s, &KILL);
	CHECK(!pipe_read_timeout(fds[0], held, KILL.depth, WAIT_MS), "kill: the user process holds every batch");
	wait_held(&s, NULL, &KILL, &st);
	CHECK(st.inflight == KILL.depth && !st.submitted[2] && st.state == XDEV_EXT_MECH_SESSION_ACTIVE,
	      "kill: batches held by the user process, none past the USER stage");
	CHECK(!kill(pid, SIGKILL) && waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
	      WTERMSIG(status) == SIGKILL, "kill: SIGKILL the user process");
	for (i = 0; i < WAIT_MS / 5; i++) {
		stats_quiet(&s, &st);
		if (st.state == XDEV_EXT_MECH_SESSION_STOPPED)
			break;
		usleep(5000);
	}
	print_stats("kill after SIGKILL", &st);
	CHECK(st.state == XDEV_EXT_MECH_SESSION_STOPPED && st.last_err == -EPIPE && !st.inflight &&
	      !st.sequestered && st.batches_abort == KILL.depth && !st.batches_done && !st.submitted[2],
	      "kill: the release of the user stage file stops the session with -EPIPE and drains it");
	CHECK(st.published == s.nr_loan, "kill: every loaned frame went back to user space");
	finish(&s, -EPIPE, "kill: STOP releases the stopped session and returns -EPIPE");
	close(fds[0]);
	ring_down(&s);
	puts("XDEV_EXT_USER_CASE=PASS case=kill");
}

static void case_kill_owner(int srcng, int dstng)
{
	struct xdev_ext_mech_stats st;
	struct io_uring_params params = {};
	int fds[2], status, ring, i, ret = 0;
	__u64 id;
	pid_t pid;

	CHECK(!pipe2(fds, O_CLOEXEC), "kill-owner: pipe");
	pid = fork();
	CHECK(pid >= 0, "kill-owner: fork the owner");
	if (!pid) {
		/* The owner: ring, session, user stage fd and a user thread holding every batch. */
		struct session s;
		struct worker w;
		int i;

		close(fds[0]);
		ring_up(&s, &KILL_OWNER, 4);
		if (create(&s, &KILL_OWNER, srcng, dstng, xdev_ext_user_stage_fd(s.u), 0))
			_exit(5);
		worker_start(&w, &s, &KILL_OWNER, HOLD);
		start(&s, &KILL_OWNER);
		for (i = 0; i < WAIT_MS && w.taken < KILL_OWNER.depth; i++)
			usleep(1000);
		if (w.taken != KILL_OWNER.depth)
			_exit(6);
		id = s.c.session_id;
		if (write(fds[1], &id, sizeof(id)) != sizeof(id))
			_exit(7);
		for (;;)
			pause();
	}
	close(fds[1]);
	CHECK(!pipe_read_timeout(fds[0], &id, sizeof(id), WAIT_MS), "kill-owner: the owner holds every batch");
	ring = syscall(__NR_io_uring_setup, 4, &params);
	CHECK(ring >= 0, "kill-owner: an observer ring");
	CHECK(!stats_of(ring, id, &st) && st.state == XDEV_EXT_MECH_SESSION_ACTIVE &&
	      st.inflight == KILL_OWNER.depth && !st.submitted[2],
	      "kill-owner: STATS from another ring sees the held batches");
	CHECK(!kill(pid, SIGKILL) && waitpid(pid, &status, 0) == pid, "kill-owner: SIGKILL the owner");
	for (i = 0; i < WAIT_MS / 5; i++) {
		ret = stats_of(ring, id, &st);
		if (ret == -ENOENT)
			break;
		usleep(5000);
	}
	CHECK(ret == -ENOENT, "kill-owner: ring exit stops and frees the session (not quarantined)");
	close(ring);
	close(fds[0]);
	puts("XDEV_EXT_USER_CASE=PASS case=kill-owner");
}

static void case_refuse(int srcng, int dstng)
{
	struct xdev_ext_mech_user_stage r;
	struct session s, t;
	void *map;
	int efd, ret;

	/* POLL: the class has no ->poll. */
	ring_up(&s, &SEAL, 4);
	CHECK(create(&s, &SEAL, srcng, dstng, xdev_ext_user_stage_fd(s.u), XDEV_EXT_MECH_STAGE_F_POLL) == -EOPNOTSUPP,
	      "refuse: POLL on a USER stage is EOPNOTSUPP");
	/* The refused CREATE never bound the fd: it still serves one session. */
	CHECK(!create(&s, &SEAL, srcng, dstng, xdev_ext_user_stage_fd(s.u), 0), "refuse: the fd binds after a POLL refusal");
	finish(&s, 0, "refuse: STOP a never-started session (0)");
	CHECK(create(&s, &SEAL, srcng, dstng, xdev_ext_user_stage_fd(s.u), 0) == -EBUSY,
	      "refuse: a user stage fd serves one session only (EBUSY)");
	CHECK(ioctl(xdev_ext_user_stage_fd(s.u), XDEV_EXT_USER_IOC_KICK, 0) == -1 && errno == ENOTCONN,
	      "refuse: kick on an unbound fd is ENOTCONN");
	CHECK(ioctl(xdev_ext_user_stage_fd(s.u), XDEV_EXT_USER_IOC_KICK, 1) == -1 && errno == EINVAL,
	      "refuse: kick with an argument is EINVAL");
	map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, xdev_ext_user_stage_fd(s.u), 4096);
	CHECK(map == MAP_FAILED && errno == EINVAL, "refuse: a mapping at a nonzero offset is EINVAL");
	map = mmap(NULL, 1 << 20, PROT_READ, MAP_SHARED, xdev_ext_user_stage_fd(s.u), 0);
	CHECK(map == MAP_FAILED && errno == EINVAL, "refuse: a mapping past the region is EINVAL");
	ring_down(&s);

	/* Ring smaller than the depth. */
	ring_up(&s, &SEAL, 2);
	CHECK(create(&s, &SEAL, srcng, dstng, xdev_ext_user_stage_fd(s.u), 0) == -EINVAL,
	      "refuse: 2 ring entries for depth 4 is EINVAL");
	ring_down(&s);
	/* An fd that is not a user stage fd; no deadline; a length change before NVMe. */
	ring_up(&s, &SEAL, 0);
	efd = eventfd(0, EFD_CLOEXEC);
	CHECK(create(&s, &SEAL, srcng, dstng, efd, 0) == -EINVAL, "refuse: a foreign fd is EINVAL");
	close(efd);
	ring_up(&t, &SEAL, 4);
	{
		struct plan p = SEAL;

		p.deadline_ms = 0;
		CHECK(create(&t, &p, srcng, dstng, xdev_ext_user_stage_fd(t.u), 0) == -EINVAL,
		      "refuse: a USER stage without deadline is EINVAL");
		p.deadline_ms = 100;
		p.delta = 4;
		CHECK(create(&t, &p, srcng, dstng, xdev_ext_user_stage_fd(t.u), 0) == -EOPNOTSUPP,
		      "refuse: a length change before NVMe WRITE is EOPNOTSUPP");
	}
	ring_down(&t);
	/* Register request refusals. */
	memset(&r, 0, sizeof(r));
	r.size = sizeof(r);
	r.entries = 3;
	r.eventfd = -1;
	CHECK(mech(s.ring, XDEV_EXT_MECH_OP_USER_STAGE, (uintptr_t)&r) == -EINVAL, "refuse: 3 ring entries is EINVAL");
	r.entries = 4;
	r.size = sizeof(r) - 8;
	CHECK(mech(s.ring, XDEV_EXT_MECH_OP_USER_STAGE, (uintptr_t)&r) == -EINVAL, "refuse: wrong request size is EINVAL");
	r.size = sizeof(r);
	r.eventfd = s.ring;
	ret = mech(s.ring, XDEV_EXT_MECH_OP_USER_STAGE, (uintptr_t)&r);
	CHECK(ret == -EINVAL || ret == -EBADF, "refuse: a wakeup fd that is not an eventfd");
	ring_down(&s);
	puts("XDEV_EXT_USER_CASE=PASS case=refuse");
}

int main(int argc, char **argv)
{
	struct rlimit lim = { RLIM_INFINITY, RLIM_INFINITY };
	struct ops_link nvme, user, cpu;
	unsigned char *source, *dest, *dest_after, *source_after;
	__u64 source_bytes, dest_bytes, off, j;
	int src, srcng, dst, dstng;

	setbuf(stdout, NULL);
	setrlimit(RLIMIT_MEMLOCK, &lim);
	puts("TAP version 13\n# guest USER stage: QEMU NVMe PCI, correctness only, no timing");
	if (argc != 6) {
		fprintf(stderr, "usage: %s SRC_BLOCK SRC_NG DST_BLOCK DST_NG BPF_DIR\n", argv[0]);
		return 2;
	}
	CHECK(getenv("XDEV_EXT_USER_GUEST") && !strcmp(getenv("XDEV_EXT_USER_GUEST"), "1"), "guest-only opt-in");
	src = open_ok(argv[1], O_RDONLY); srcng = open_ok(argv[2], O_RDONLY);
	dst = open_ok(argv[3], O_RDWR); dstng = open_ok(argv[4], O_RDWR);
	CHECK(!ioctl(src, BLKGETSIZE64, &source_bytes) && !ioctl(dst, BLKGETSIZE64, &dest_bytes), "disk capacities");
	CHECK(source_bytes <= 64U << 20 && dest_bytes == source_bytes &&
	      dest_bytes >= (KILL_OWNER.dst_slba + window_nlb(&KILL_OWNER)) * LBA, "bounded whole-disk comparison");
	source = malloc(source_bytes); source_after = malloc(source_bytes);
	dest = malloc(dest_bytes); dest_after = malloc(dest_bytes);
	CHECK(source && source_after && dest && dest_after, "verification buffers");
	CHECK(pread(src, source, source_bytes, 0) == (ssize_t)source_bytes, "read the source disk");
	for (off = 1; off < source_bytes && source[off] == source[0]; off++)
		;
	CHECK(off < source_bytes, "source disk holds a nonuniform pattern");
	CHECK(pread(dst, dest, dest_bytes, 0) == (ssize_t)dest_bytes, "read the destination disk");
	for (off = 0; off < dest_bytes && dest[off] == GUARD; off++)
		;
	CHECK(off == dest_bytes, "destination disk starts as guard bytes");
	attach_ops(argv[5], "nvme_s0", &nvme);
	attach_ops(argv[5], "user_plan", &user);
	attach_ops(argv[5], "cpu_plan", &cpu);

	case_refuse(srcng, dstng);
	case_seal(srcng, dstng);
	case_append(srcng, &APPEND, false);
	case_append(srcng, &APPEND_BAD, true);
	case_deadline(srcng, dstng);
	case_malformed(srcng, dstng);
	case_stop_held(srcng, dstng);
	case_kill(srcng, dstng);
	case_kill_owner(srcng, dstng);

	detach_ops(&cpu);
	detach_ops(&user);
	detach_ops(&nvme);
	/* Whole-disk oracle in the guest; the host validator repeats it. */
	CHECK(!ioctl(src, BLKFLSBUF) && !ioctl(dst, BLKFLSBUF), "invalidate block caches before readback");
	CHECK(pread(src, source_after, source_bytes, 0) == (ssize_t)source_bytes &&
	      !memcmp(source, source_after, source_bytes), "whole source disk unchanged");
	CHECK(pread(dst, dest_after, dest_bytes, 0) == (ssize_t)dest_bytes, "read back the destination");
	for (j = 0; j < SEAL.groups * SEAL.group / FRAME; j++) {
		unsigned char *f = dest + SEAL.dst_slba * LBA + j * FRAME;

		memcpy(f, source + SEAL.src_slba * LBA + j * FRAME, FRAME);
		put_le32(f + FRAME - 4, crc32c(f, FRAME - 4));
	}
	for (j = 0; j < DEADLINE.groups; j++)
		if (j != DEADLINE_HELD_ID % DEADLINE.groups)
			memcpy(dest + DEADLINE.dst_slba * LBA + j * DEADLINE.group,
			       source + DEADLINE.src_slba * LBA + j * DEADLINE.group, DEADLINE.group);
	for (j = 0; j < MALFORMED.groups; j++)
		if (j != 2 && j != 3 && j != 4)
			memcpy(dest + MALFORMED.dst_slba * LBA + j * MALFORMED.group,
			       source + MALFORMED.src_slba * LBA + j * MALFORMED.group, MALFORMED.group);
	CHECK(!memcmp(dest, dest_after, dest_bytes),
	      "destination: sealed copy, deadline and malformed copies without their failed batches, guards elsewhere "
	      "(no held batch of stop-held, kill or kill-owner reached the disk)");
	close(src); close(srcng); close(dst); close(dstng);
	free(source); free(source_after); free(dest); free(dest_after);
	printf("1..%u\n", checks);
	puts("XDEV_EXT_USER_STAGE_E2E=PASS cases=refuse,seal,append,append-bad,deadline,malformed,stop-held,kill,kill-owner timing=none");
	return 0;
}
