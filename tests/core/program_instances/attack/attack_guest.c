// SPDX-License-Identifier: GPL-2.0
/*
 * GUEST TEST ONLY: attacker-brought program isolation on real QEMU NVMe PCI.
 * Correctness only; nothing here is timed. Two sessions share the same NVMe
 * namespaces at once: a VICTIM (NVMe READ source window -> NVMe WRITE victim
 * window) and an ATTACK session that loads its own PRIVATE mechanism program.
 * Both select programs through CREATE_PROGRAMS, so the two run different
 * programs over the same device at the same time.
 *
 * Each attack keeps a valid session topology but crosses one boundary the
 * kernel enforces. The test asserts the attack session ends with its declared
 * reason while the victim completes with zero aborts, and a whole-disk oracle
 * (repeated independently on the host by attack_validate.py) checks every
 * destination byte against an expected image.
 *
 *   case           what the attacker does                                reason
 *   reserved       in-window WRITE SQE with a nonzero reserved dword      -EPERM
 *   outside        WRITE SQE one window past its own = the victim's LBAs  -ERANGE
 *   outside-after  same, after the victim already wrote its window        -ERANGE
 *   frame          reads frame bytes past the frame (host-frame window)   -EPROTO
 *   verdict        returns an illegal build verdict                       -ECANCELED
 *   user-stall     its USER stage thread never completes a batch          -ETIMEDOUT
 *   detach         detaches its PRIVATE write link with a batch in flight -ECANCELED
 *
 * For attacks 1-5 the attack session stays ACTIVE with last_err latched after
 * every batch ended; the user STOP then returns that reason. The detach
 * retraction stops the session itself.
 *
 * Layout, in 64-LBA windows: case c owns destination windows 3c (attacker,
 * directly below the victim), 3c+1 (victim) and 3c+2 (spare); its victim
 * reads source window 2c and its attacker source window 2c+1. The source disk
 * is position-unique (see check_source), so a group copied from the wrong
 * place, in the wrong order or from the attacker cannot match.
 *
 * Usage: attack_guest SRC_BLOCK SRC_NG DST_BLOCK DST_NG BPF_DIR
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "linux/io_uring.h"
#include "linux/xdev_ext_mech.h"
#include "libxdev_ext.h"

#define LBA 512U
#define FRAME 4096U
#define GROUP 4096U		/* one frame per group */
#define GROUPS 8U
#define DEPTH 4U
#define WIN_NLB (GROUPS * GROUP / LBA)	/* 64 LBAs per window */
#define WIN_BYTES ((__u64)WIN_NLB * LBA)
#define FIRST_KEY 1ULL
#define GUARD 0x6bU
#define WAIT_MS 60000
#define USER_DEADLINE_MS 300U		/* user-stall: the held batch expires */
#define DETACH_DEADLINE_MS 60000U	/* detach: the hold outlives the retraction */
#define DETACH_DONE 2U			/* batches the detach attacker completes */
#define SPAN (4ULL << 20)		/* exact disk image size */

enum { C_RESERVED, C_OUTSIDE, C_OUTSIDE_AFTER, C_FRAME, C_VERDICT, C_USER, C_DETACH, NR_CASES };
static const char *const case_name[NR_CASES] = {
	"reserved", "outside", "outside-after", "frame", "verdict", "user-stall", "detach",
};

static __u64 atk_dst(unsigned c) { return 3ULL * c * WIN_NLB; }
static __u64 vic_dst(unsigned c) { return (3ULL * c + 1) * WIN_NLB; }
static __u64 vic_src(unsigned c) { return 2ULL * c * WIN_NLB; }
static __u64 atk_src(unsigned c) { return (2ULL * c + 1) * WIN_NLB; }

static unsigned int checks;
#define CHECK(c, msg) do { \
	if (!(c)) { fprintf(stderr, "not ok %u - %s (errno=%d %s)\n", ++checks, msg, errno, strerror(errno)); \
		printf("not ok %u - %s\n", checks, msg); exit(1); } \
	printf("ok %u - %s\n", ++checks, msg); } while (0)

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

/* ---- PRIVATE struct_ops links loaded from the test's BPF objects ---- */
struct object { struct bpf_object *obj; struct bpf_map *map; };

static void object_open(const char *dir, const char *name, struct object *o)
{
	char path[PATH_MAX];
	char what[128];
	struct bpf_map *map;

	snprintf(path, sizeof(path), "%s/%s.bpf.o", dir, name);
	snprintf(what, sizeof(what), "open and load %s", name);
	o->obj = bpf_object__open_file(path, NULL);
	o->map = NULL;
	if (!libbpf_get_error(o->obj) && !bpf_object__load(o->obj))
		bpf_object__for_each_map(map, o->obj) {
			if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS) {
				o->map = map;
				break;
			}
		}
	CHECK(o->map, what);
}

/* ---- one session (its own ring, UMEM and lent frames) ---- */
struct session {
	int ring;
	void *pool;
	size_t pool_bytes;
	__u32 nr_loan;
	__u32 frames[GROUPS];
	struct xdev_ext_mech_create_programs cp;
	__u64 id;
	struct xdev_ext_user_stage *u;	/* user-stall and detach only */
	struct bpf_link *links[XDEV_EXT_MECH_MAX_STAGES];
	unsigned nr_links;
};

/* A fresh PRIVATE link each call, owned by @s and destroyed at teardown. */
static int link_fd(struct session *s, struct object *o)
{
	struct bpf_link *l = bpf_map__attach_struct_ops(o->map);

	CHECK(l && !libbpf_get_error(l), "attach PRIVATE struct_ops link");
	s->links[s->nr_links++] = l;
	return bpf_link__fd(l);
}

static void ring_up(struct session *s)
{
	struct io_uring_params params = {};
	struct io_uring_xdev_ext_umem_reg reg = { .frame_size = FRAME };
	__u32 i;

	memset(s, 0, sizeof(*s));
	s->ring = -1;
	s->pool_bytes = (size_t)GROUPS * FRAME;
	s->pool = mmap(NULL, s->pool_bytes, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	CHECK(s->pool != MAP_FAILED, "session pool memory");
	memset(s->pool, 0x97, s->pool_bytes);
	s->ring = syscall(__NR_io_uring_setup, 8, &params);
	CHECK(s->ring >= 0, "io_uring ring");
	reg.addr = (uintptr_t)s->pool;
	reg.size = s->pool_bytes;
	CHECK(!syscall(__NR_io_uring_register, s->ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg, 1),
	      "register the ring UMEM");
	s->nr_loan = GROUPS;
	for (i = 0; i < s->nr_loan; i++)
		s->frames[i] = i;
}

static void user_open(struct session *s)
{
	struct xdev_ext_user_stage_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_user_stage_opts,
		.ring_fd = s->ring, .umem = s->pool, .entries = DEPTH);

	CHECK(!xdev_ext_user_stage_open(&o, &s->u), "attack: open a USER stage fd");
}

/* One stage of a CREATE_PROGRAMS request and the PRIVATE link that runs it. */
struct stage { __u32 class_id, direction; int fd; __u64 arg0, arg1; int link; };

static struct stage nvme_read(int ng, __u64 slba, int link)
{
	return (struct stage){ XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_FROM_DEVICE, ng, slba, WIN_NLB, link };
}

static struct stage nvme_write(int ng, __u64 slba, int link)
{
	return (struct stage){ XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_TO_DEVICE, ng, slba, WIN_NLB, link };
}

static struct stage user_stage(const struct session *s, __u32 deadline_ms, int link)
{
	return (struct stage){ XDEV_EXT_MECH_CLASS_USER, XDEV_EXT_MECH_DIR_TO_DEVICE,
			       xdev_ext_user_stage_fd(s->u), deadline_ms, 0, link };
}

static int create_programs(struct session *s, const struct stage *st, __u32 n)
{
	struct xdev_ext_mech_create *c = &s->cp.request.create;
	__u32 i;
	int ret;

	s->cp.size = sizeof(s->cp);
	s->cp.version = XDEV_EXT_MECH_CREATE_PROGRAMS_VERSION;
	for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++)
		s->cp.program_fds[i] = i < n ? st[i].link : -1;
	s->cp.request.size = sizeof(s->cp.request);
	s->cp.request.version = XDEV_EXT_MECH_CREATE_REPORT_VERSION;
	*c = (struct xdev_ext_mech_create){
		.abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .pool_fd = -1,
		.layout = { FRAME, 0, GROUP, GROUP }, .depth = DEPTH, .eventfd = -1,
	};
	for (i = 0; i < n; i++)
		c->st[i] = (struct xdev_ext_mech_stage_uapi){ .class_id = st[i].class_id,
			.direction = st[i].direction, .fd = st[i].fd,
			.arg0 = st[i].arg0, .arg1 = st[i].arg1 };
	c->nr_stages = n;
	ret = mech(s->ring, XDEV_EXT_MECH_OP_CREATE_PROGRAMS, (uintptr_t)&s->cp);
	if (ret)
		return ret;
	if (s->cp.request.report.size != sizeof(s->cp.request.report) ||
	    s->cp.request.report.version != XDEV_EXT_MECH_CREATE_REPORT_VERSION)
		return -EPROTO;
	if (s->cp.request.report.result)
		return s->cp.request.report.result;
	if (!c->session_id || c->session_id != s->cp.request.report.session_id)
		return -EPROTO;
	s->id = c->session_id;
	return 0;
}

static void start(struct session *s)
{
	struct xdev_ext_mech_start st = { .session_id = s->id, .nr_batches = GROUPS,
		.first_seq = FIRST_KEY, .flags = XDEV_EXT_MECH_START_F_USER_FRAMES,
		.nr_user_frames = s->nr_loan, .user_frames = (uintptr_t)s->frames };

	CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&st), "exactly one START");
}

static void stats(const struct session *s, struct xdev_ext_mech_stats *st)
{
	memset(st, 0, sizeof(*st));
	st->session_id = s->id;
	if (mech(s->ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)st))
		CHECK(0, "STATS");
}

static void print_stats(const char *name, const struct xdev_ext_mech_stats *st)
{
	printf("# %s: done=%llu abort=%llu rejects=%llu protocol_err=%llu timeouts=%llu "
	       "inflight=%llu sequestered=%llu last_err=%d state=%u submitted=%llu,%llu,%llu "
	       "completed=%llu,%llu,%llu\n", name,
	       (unsigned long long)st->batches_done, (unsigned long long)st->batches_abort,
	       (unsigned long long)st->rejects, (unsigned long long)st->protocol_err,
	       (unsigned long long)st->timeouts, (unsigned long long)st->inflight,
	       (unsigned long long)st->sequestered, st->last_err, st->state,
	       (unsigned long long)st->submitted[0], (unsigned long long)st->submitted[1],
	       (unsigned long long)st->submitted[2], (unsigned long long)st->completed[0],
	       (unsigned long long)st->completed[1], (unsigned long long)st->completed[2]);
}

static bool settled(const struct xdev_ext_mech_stats *st)
{
	return st->batches_done + st->batches_abort >= GROUPS && !st->inflight;
}

/* Poll one session until every batch ended, or the wait bound. */
static struct xdev_ext_mech_stats wait_settled(struct session *s)
{
	struct xdev_ext_mech_stats st;
	int i;

	for (i = 0; i < WAIT_MS / 5; i++) {
		stats(s, &st);
		if (settled(&st))
			break;
		usleep(5000);
	}
	return st;
}

/*
 * Poll both sessions until both settled. Records (does not assert, since it
 * is timing dependent) whether a refused attacker batch was seen while the
 * victim still had unfinished batches.
 */
static void wait_pair(struct session *v, struct session *a, const char *name,
		      struct xdev_ext_mech_stats *vs, struct xdev_ext_mech_stats *as)
{
	unsigned overlap = 0, polls;

	for (polls = 0; polls < WAIT_MS; polls++) {
		stats(v, vs);
		stats(a, as);
		if (as->batches_abort && vs->batches_done + vs->batches_abort < GROUPS)
			overlap++;
		if (settled(vs) && settled(as))
			break;
		usleep(1000);
	}
	printf("# overlap case=%s polls_with_attacker_refusal_while_victim_unfinished=%u of %u\n",
	       name, overlap, polls + 1);
}

static void stop_ok(struct session *s, int expect, const char *what)
{
	struct xdev_ext_mech_stats st;

	CHECK(mech(s->ring, XDEV_EXT_MECH_OP_STOP, s->id) == expect, what);
	memset(&st, 0, sizeof(st));
	st.session_id = s->id;
	CHECK(mech(s->ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&st) == -ENOENT,
	      "released session is gone");
}

static void links_destroy(struct session *s)
{
	unsigned i;

	for (i = 0; i < s->nr_links; i++)
		bpf_link__destroy(s->links[i]);
	s->nr_links = 0;
}

static void ring_down(struct session *s)
{
	if (s->u)
		xdev_ext_user_stage_close(s->u);
	s->u = NULL;
	if (s->ring >= 0)
		CHECK(!close(s->ring), "close ring");
	if (s->pool && s->pool != MAP_FAILED)
		munmap(s->pool, s->pool_bytes);
}

static void teardown(struct session *v, struct session *a)
{
	links_destroy(a);
	links_destroy(v);
	ring_down(a);
	ring_down(v);
}

/* The victim of case @c: correct PRIVATE programs on both NVMe stages. */
static void victim_create(struct session *v, unsigned c, int srcng, int dstng, struct object *correct)
{
	struct stage st[2];

	ring_up(v);
	st[0] = nvme_read(srcng, vic_src(c), link_fd(v, correct));
	st[1] = nvme_write(dstng, vic_dst(c), link_fd(v, correct));
	CHECK(!create_programs(v, st, 2), "victim: CREATE_PROGRAMS NVMe READ -> NVMe WRITE");
}

static void check_victim(const struct xdev_ext_mech_stats *vs, const char *what)
{
	CHECK(vs->batches_done == GROUPS && !vs->batches_abort && !vs->rejects &&
	      !vs->protocol_err && !vs->timeouts && !vs->sequestered && !vs->last_err &&
	      !vs->inflight && vs->state == XDEV_EXT_MECH_SESSION_ACTIVE &&
	      vs->submitted[1] == GROUPS && vs->completed[1] == GROUPS, what);
}

/* ---- the attacker's user thread: complete @complete_first, hold the rest ---- */
struct holder {
	struct xdev_ext_user_stage *u;
	unsigned complete_first;
	volatile unsigned taken, completed, held;
	volatile int exit_code;
	pthread_t thread;
};

static void *hold_thread(void *arg)
{
	struct holder *h = arg;
	struct xdev_ext_user_batch b;
	int ret;

	for (;;) {
		ret = xdev_ext_user_stage_next(h->u, -1, &b);
		if (ret) {
			h->exit_code = ret;
			return NULL;
		}
		h->taken++;
		if (h->completed < h->complete_first) {
			ret = xdev_ext_user_stage_complete(h->u, &b, 0);
			if (ret) {
				h->exit_code = ret;
				return NULL;
			}
			h->completed++;
			continue;
		}
		/* Never complete: the kernel cancels it at its deadline or a stop. */
		h->held++;
	}
}

static void holder_start(struct holder *h, struct session *a, unsigned complete_first)
{
	memset(h, 0, sizeof(*h));
	h->u = a->u;
	h->complete_first = complete_first;
	CHECK(!pthread_create(&h->thread, NULL, hold_thread, h), "attack: start the user thread");
}

static unsigned cases;
static __u64 detach_done;	/* the detach attacker's completed batches */

/*
 * Attacks 1-4: malicious program on the attacker's WRITE stage, read stage
 * correct. @victim_first: the victim completes its window before the attacker
 * STARTs, so an accepted attacker write would land after the victim's data.
 */
static void run_nvme_attack(unsigned c, int srcng, int dstng, struct object *correct,
			    struct object *malicious, int want_last_err, bool want_reject,
			    bool want_protocol, bool victim_first)
{
	const char *name = case_name[c];
	struct session v, a;
	struct xdev_ext_mech_stats vs, as, vs2;
	struct stage st[2];

	victim_create(&v, c, srcng, dstng, correct);
	ring_up(&a);
	st[0] = nvme_read(srcng, atk_src(c), link_fd(&a, correct));
	st[1] = nvme_write(dstng, atk_dst(c), link_fd(&a, malicious));
	CHECK(!create_programs(&a, st, 2), "attack: CREATE_PROGRAMS with its own PRIVATE write program");

	if (victim_first) {
		start(&v);
		vs = wait_settled(&v);
		print_stats("victim (before the attacker starts)", &vs);
		check_victim(&vs, "victim completes its window before the attacker starts");
		start(&a);
		as = wait_settled(&a);
		stats(&v, &vs2);
		print_stats("victim (after the attacker ran)", &vs2);
		print_stats(name, &as);
		CHECK(vs2.batches_done == vs.batches_done && vs2.batches_abort == vs.batches_abort &&
		      vs2.rejects == vs.rejects && vs2.protocol_err == vs.protocol_err &&
		      vs2.timeouts == vs.timeouts && vs2.sequestered == vs.sequestered &&
		      vs2.inflight == vs.inflight && vs2.last_err == vs.last_err &&
		      vs2.state == vs.state && vs2.submitted[1] == vs.submitted[1] &&
		      vs2.completed[1] == vs.completed[1],
		      "victim counters unchanged by the attacker's run");
	} else {
		start(&v);
		start(&a);
		wait_pair(&v, &a, name, &vs, &as);
		print_stats("victim", &vs);
		print_stats(name, &as);
		check_victim(&vs, "victim completes every batch with zero aborts while the attack runs");
	}
	CHECK(as.batches_abort == GROUPS && !as.batches_done && !as.sequestered && !as.inflight,
	      "attack: every batch is refused, none completes, nothing sequestered");
	CHECK(as.submitted[1] == 0 && as.completed[1] == 0,
	      "attack: no write command of the attacker reached the device");
	CHECK(as.last_err == want_last_err && as.state == XDEV_EXT_MECH_SESSION_ACTIVE,
	      "attack: last_err latches its declared reason (session ACTIVE)");
	if (want_reject)
		CHECK(as.rejects == GROUPS, "attack: each bad SQE counts a reject");
	if (want_protocol)
		CHECK(as.protocol_err >= 1, "attack: a protocol error is recorded");

	stop_ok(&a, want_last_err, "attack: STOP returns the declared reason");
	stop_ok(&v, 0, "victim: STOP releases the session (0)");
	teardown(&v, &a);
	printf("XDEV_EXT_ATTACK_CASE=PASS case=%s\n", name);
	cases++;
}

/* Attack 5: attacker NVMe READ -> USER; the user thread stalls the stage. */
static void run_user_stall(int srcng, int dstng, struct object *correct, struct object *userp)
{
	struct session v, a;
	struct xdev_ext_mech_stats vs, as;
	struct holder h;
	struct stage st[2];

	victim_create(&v, C_USER, srcng, dstng, correct);
	ring_up(&a);
	user_open(&a);
	st[0] = nvme_read(srcng, atk_src(C_USER), link_fd(&a, correct));
	st[1] = user_stage(&a, USER_DEADLINE_MS, link_fd(&a, userp));
	CHECK(!create_programs(&a, st, 2), "attack: CREATE_PROGRAMS NVMe READ -> USER (no write stage)");

	holder_start(&h, &a, 0);
	start(&v);
	start(&a);
	wait_pair(&v, &a, "user-stall", &vs, &as);
	print_stats("victim", &vs);
	print_stats("user-stall", &as);

	check_victim(&vs, "victim completes every batch while the attacker's USER stage stalls");
	CHECK(as.timeouts >= 1 && as.batches_abort == GROUPS && !as.batches_done &&
	      as.last_err == -ETIMEDOUT && !as.sequestered && as.state == XDEV_EXT_MECH_SESSION_ACTIVE,
	      "user-stall: held batches cancelled at their deadline (-ETIMEDOUT)");

	stop_ok(&a, -ETIMEDOUT, "user-stall: STOP returns the deadline error");
	/* STOP wakes next() with an error, so the holding thread returns. */
	pthread_join(h.thread, NULL);
	CHECK(h.exit_code != 0 && !h.completed, "user-stall: the user thread left next() after STOP");
	stop_ok(&v, 0, "victim: STOP releases the session (0)");
	teardown(&v, &a);
	puts("XDEV_EXT_ATTACK_CASE=PASS case=user-stall");
	cases++;
}

/*
 * Attack 6: NVMe READ -> USER -> NVMe WRITE, all PRIVATE. The user thread
 * completes DETACH_DONE batches and holds the next one, so the session is
 * mid-run with a batch in flight; then the victim STARTs and the attacker
 * detaches its write-stage link.
 */
static void run_detach(int srcng, int dstng, struct object *correct, struct object *userp)
{
	struct session v, a;
	struct xdev_ext_mech_stats vs, as;
	struct bpf_link *wlink;
	struct holder h;
	struct stage st[3];
	__u32 one = 0;
	int i;

	victim_create(&v, C_DETACH, srcng, dstng, correct);
	ring_up(&a);
	user_open(&a);
	/* The write-stage link is detached mid-run; keep it outside a.links. */
	wlink = bpf_map__attach_struct_ops(correct->map);
	CHECK(wlink && !libbpf_get_error(wlink), "attack: attach the write-stage PRIVATE link");
	st[0] = nvme_read(srcng, atk_src(C_DETACH), link_fd(&a, correct));
	st[1] = user_stage(&a, DETACH_DEADLINE_MS, link_fd(&a, userp));
	st[2] = nvme_write(dstng, atk_dst(C_DETACH), bpf_link__fd(wlink));
	CHECK(!create_programs(&a, st, 3),
	      "attack: CREATE_PROGRAMS NVMe READ -> USER -> NVMe WRITE, all PRIVATE");

	holder_start(&h, &a, DETACH_DONE);
	start(&a);
	for (i = 0; i < WAIT_MS / 5; i++) {
		stats(&a, &as);
		if (as.batches_done >= DETACH_DONE && h.held >= 1)
			break;
		usleep(5000);
	}
	print_stats("detach (before the detach)", &as);
	CHECK(as.state == XDEV_EXT_MECH_SESSION_ACTIVE && as.batches_done == DETACH_DONE &&
	      !as.batches_abort && as.inflight >= 1 && h.held >= 1 && as.completed[2] == DETACH_DONE,
	      "detach: attacker is mid-run (batches written, a batch held in flight)");

	start(&v);
	CHECK(!bpf_link__detach(wlink), "attack: detach the PRIVATE write link mid-run");
	vs = wait_settled(&v);
	for (i = 0; i < WAIT_MS / 5; i++) {
		stats(&a, &as);
		if (as.state != XDEV_EXT_MECH_SESSION_ACTIVE && !as.inflight)
			break;
		usleep(5000);
	}
	print_stats("victim", &vs);
	print_stats("detach", &as);

	check_victim(&vs, "victim completes every batch while the attacker detaches its link");
	CHECK(as.last_err == -ECANCELED && !as.timeouts &&
	      (as.state == XDEV_EXT_MECH_SESSION_STOPPING ||
	       as.state == XDEV_EXT_MECH_SESSION_STOPPED) && !as.inflight,
	      "detach: the retraction stops the session with -ECANCELED");
	CHECK(as.batches_done == DETACH_DONE && as.completed[2] == DETACH_DONE &&
	      as.batches_abort >= 1 && as.batches_done + as.batches_abort < GROUPS,
	      "detach: the in-flight batch is cancelled and the remaining batches are never admitted");
	detach_done = as.batches_done;
	printf("# detach: sequestered=%llu (attacker pool only)\n", (unsigned long long)as.sequestered);
	/* No further admission. An argument-invalid START fails its argument
	 * check first; a valid one must hit the closed admission. */
	{
		struct xdev_ext_mech_start bad = { .session_id = a.id, .nr_batches = 1,
			.first_seq = FIRST_KEY + GROUPS, .flags = XDEV_EXT_MECH_START_F_USER_FRAMES,
			.nr_user_frames = a.nr_loan, .user_frames = (uintptr_t)a.frames };
		struct xdev_ext_mech_start st2 = { .session_id = a.id, .nr_batches = 1,
			.first_seq = FIRST_KEY + GROUPS, .flags = XDEV_EXT_MECH_START_F_USER_FRAMES,
			.nr_user_frames = 1, .user_frames = (uintptr_t)&one };
		int r_bad = mech(a.ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&bad);
		int r = mech(a.ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&st2);

		printf("# detach: START nr_batches=1 nr_user_frames=%u -> %d; nr_user_frames=1 -> %d\n",
		       a.nr_loan, r_bad, r);
		CHECK(r_bad == -EINVAL, "detach: a START with mismatched frames is refused by its argument check (-EINVAL)");
		CHECK(r == -ESHUTDOWN, "detach: a valid new START is refused by the closed admission (-ESHUTDOWN)");
	}

	stop_ok(&a, -ECANCELED, "detach: STOP returns -ECANCELED");
	pthread_join(h.thread, NULL);
	printf("# detach: user thread taken=%u completed=%u held=%u exit=%d\n",
	       h.taken, h.completed, h.held, h.exit_code);
	CHECK(h.exit_code != 0 && h.completed == DETACH_DONE,
	      "detach: the user thread left next() after the stop");
	stop_ok(&v, 0, "victim: STOP releases the session (0)");
	bpf_link__destroy(wlink);
	teardown(&v, &a);
	puts("XDEV_EXT_ATTACK_CASE=PASS case=detach");
	cases++;
}

/*
 * The source disk is position-unique: the 8-byte word at byte offset o holds
 * low32 = ((o / 512) << 7) | (((o % 512) / 8) << 1) | 1 and high32 = the seed
 * (the high word of word 0). attack_kvm.sh writes it; attack_validate.py
 * regenerates it.
 */
static void check_source(const unsigned char *src, __u64 bytes)
{
	__u32 seed, low, high;
	__u64 o;

	memcpy(&seed, src + 4, sizeof(seed));
	for (o = 0; o < bytes; o += 8) {
		memcpy(&low, src + o, sizeof(low));
		memcpy(&high, src + o + 4, sizeof(high));
		if (high != seed || low != (__u32)(((o / LBA) << 7) | (((o % LBA) / 8) << 1) | 1))
			break;
	}
	printf("# source seed=0x%08x\n", seed);
	CHECK(o == bytes, "source disk holds the position-unique pattern");
}

/*
 * Whole-disk oracle: every victim window is an exact copy of its victim's
 * source window; the detach attacker window holds exactly detach_done groups,
 * each its own source group at the same slot, guard elsewhere; every other
 * byte is guard.
 */
static void check_destination(const unsigned char *source, const unsigned char *dest, __u64 bytes)
{
	unsigned char *expect = malloc(bytes);
	const unsigned char *own, *got;
	__u64 lo, g, b, copied = 0;
	unsigned c;

	CHECK(expect, "oracle buffer");
	memset(expect, GUARD, bytes);
	for (c = 0; c < NR_CASES; c++)
		memcpy(expect + vic_dst(c) * LBA, source + vic_src(c) * LBA, WIN_BYTES);
	lo = atk_dst(C_DETACH) * LBA;
	for (g = 0; g < GROUPS; g++) {
		got = dest + lo + g * GROUP;
		own = source + atk_src(C_DETACH) * LBA + g * GROUP;
		if (!memcmp(got, own, GROUP)) {
			memcpy(expect + lo + g * GROUP, own, GROUP);
			copied++;
		} else {
			for (b = 0; b < GROUP && got[b] == GUARD; b++)
				;
			CHECK(b == GROUP, "detach attacker group is guard or its own source group at its slot");
		}
	}
	printf("# oracle: detach attacker groups written=%llu\n", (unsigned long long)copied);
	CHECK(copied == detach_done && copied == DETACH_DONE,
	      "detach attacker window holds exactly its completed groups");
	for (b = 0; b < bytes && dest[b] == expect[b]; b++)
		;
	if (b < bytes) {
		__u64 w = b / WIN_BYTES;

		printf("# oracle: first mismatch byte=%llu lba=%llu window=%llu (case %s, %s)\n",
		       (unsigned long long)b, (unsigned long long)(b / LBA), (unsigned long long)w,
		       w / 3 < NR_CASES ? case_name[w / 3] : "none",
		       w / 3 < NR_CASES ? (const char *[]){ "attacker", "victim", "spare" }[w % 3] : "unused");
	}
	CHECK(b == bytes, "whole-disk oracle: victim windows exact, no attacker byte anywhere else");
	free(expect);
}

int main(int argc, char **argv)
{
	struct rlimit lim = { RLIM_INFINITY, RLIM_INFINITY };
	struct object correct, reserved, outside, frame, verdict, userp;
	unsigned char *source, *dest, *dest_after;
	__u64 src_bytes, dst_bytes, off;
	int src, srcng, dst, dstng;

	setbuf(stdout, NULL);
	setrlimit(RLIMIT_MEMLOCK, &lim);
	puts("TAP version 13\n# attacker-brought program isolation: QEMU NVMe, correctness only, no timing");
	if (argc != 6) {
		fprintf(stderr, "usage: %s SRC_BLOCK SRC_NG DST_BLOCK DST_NG BPF_DIR\n", argv[0]);
		return 2;
	}
	CHECK(getenv("XDEV_EXT_ATTACK_GUEST") && !strcmp(getenv("XDEV_EXT_ATTACK_GUEST"), "1"),
	      "guest-only opt-in");
	src = open_ok(argv[1], O_RDONLY); srcng = open_ok(argv[2], O_RDONLY);
	dst = open_ok(argv[3], O_RDWR); dstng = open_ok(argv[4], O_RDWR);
	CHECK(!ioctl(src, BLKGETSIZE64, &src_bytes) && !ioctl(dst, BLKGETSIZE64, &dst_bytes),
	      "disk capacities");
	CHECK(src_bytes == SPAN && dst_bytes == SPAN, "whole-disk comparison over the exact image size");
	source = malloc(src_bytes); dest = malloc(dst_bytes); dest_after = malloc(dst_bytes);
	CHECK(source && dest && dest_after, "verification buffers");
	CHECK(pread(src, source, src_bytes, 0) == (ssize_t)src_bytes, "read the source disk");
	check_source(source, src_bytes);
	CHECK(pread(dst, dest, dst_bytes, 0) == (ssize_t)dst_bytes, "read the destination disk");
	for (off = 0; off < dst_bytes && dest[off] == GUARD; off++)
		;
	CHECK(off == dst_bytes, "destination disk starts as guard bytes");

	object_open(argv[5], "attack_correct", &correct);
	object_open(argv[5], "attack_reserved", &reserved);
	object_open(argv[5], "attack_outside", &outside);
	object_open(argv[5], "attack_frame", &frame);
	object_open(argv[5], "attack_verdict", &verdict);
	object_open(argv[5], "attack_user", &userp);

	run_nvme_attack(C_RESERVED, srcng, dstng, &correct, &reserved, -EPERM, true, false, false);
	run_nvme_attack(C_OUTSIDE, srcng, dstng, &correct, &outside, -ERANGE, true, false, false);
	run_nvme_attack(C_OUTSIDE_AFTER, srcng, dstng, &correct, &outside, -ERANGE, true, false, true);
	run_nvme_attack(C_FRAME, srcng, dstng, &correct, &frame, -EPROTO, false, true, false);
	run_nvme_attack(C_VERDICT, srcng, dstng, &correct, &verdict, -ECANCELED, false, true, false);
	run_user_stall(srcng, dstng, &correct, &userp);
	run_detach(srcng, dstng, &correct, &userp);

	bpf_object__close(correct.obj); bpf_object__close(reserved.obj);
	bpf_object__close(outside.obj); bpf_object__close(frame.obj);
	bpf_object__close(verdict.obj); bpf_object__close(userp.obj);

	CHECK(!ioctl(dst, BLKFLSBUF), "invalidate the block cache before readback");
	CHECK(pread(dst, dest_after, dst_bytes, 0) == (ssize_t)dst_bytes, "read back the destination");
	check_destination(source, dest_after, dst_bytes);

	close(src); close(srcng); close(dst); close(dstng);
	free(source); free(dest); free(dest_after);
	printf("1..%u\n", checks);
	printf("XDEV_EXT_ATTACK_ISOLATION=PASS cases=%u order=reserved,outside,outside-after,frame,verdict,user-stall,detach timing=none\n", cases);
	return 0;
}
