// SPDX-License-Identifier: GPL-2.0
/*
 * GUEST TEST ONLY: attacker-brought program isolation on real QEMU NVMe PCI.
 * Correctness only; nothing here is timed. Two sessions share the same NVMe
 * namespaces at once: a VICTIM (NVMe READ source-window -> NVMe WRITE
 * destination victim-window) and an ATTACK session that loads its own PRIVATE
 * mechanism program. Both select programs through CREATE_PROGRAMS, so the two
 * run different programs over the same device simultaneously.
 *
 * Each attack keeps a valid session topology but crosses one boundary the
 * kernel enforces. The test asserts the attack session stops with its declared
 * reason while the victim completes with zero aborts and a byte-exact window,
 * and that no attacker byte reached the victim window. The host validator
 * (attack_validate.py) repeats the whole-image comparison independently.
 *
 *   1 reserved  a valid in-window WRITE SQE with a nonzero reserved dword   -EPERM
 *   2 outside   a WRITE SQE one window past the attacker's bound LBA window  -ERANGE
 *   3 frame     reads frame bytes past the frame (host-frame window)         -EPROTO
 *   4 verdict   returns an illegal build verdict                            -ECANCELED
 *   5 user      an attacker USER stage whose thread never completes a batch -ETIMEDOUT
 *   6 detach    detaches its own PRIVATE link mid-run                       -ECANCELED
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
#define FIRST_KEY 1ULL
#define GUARD 0x6bU
#define WAIT_MS 60000
#define USER_DEADLINE_MS 300U

/* Disjoint destination windows (in LBAs); source read window is shared at 0. */
#define SRC_SLBA   0ULL
#define VIC_SLBA   (1ULL * WIN_NLB)	/* 64 */
#define ATK1_SLBA  (2ULL * WIN_NLB)	/* 128 reserved */
#define ATK2_SLBA  (3ULL * WIN_NLB)	/* 192 outside */
#define ATK3_SLBA  (4ULL * WIN_NLB)	/* 256 frame */
#define ATK4_SLBA  (5ULL * WIN_NLB)	/* 320 verdict */
#define ATK6_SLBA  (6ULL * WIN_NLB)	/* 384 detach */
#define DISK_LBAS  (8ULL * WIN_NLB)	/* 512 LBAs span checked */

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

/* A fresh PRIVATE link each call; destroyed at session teardown. */
static int link_fd(struct object *o, struct bpf_link **keep)
{
	struct bpf_link *l = bpf_map__attach_struct_ops(o->map);

	CHECK(l && !libbpf_get_error(l), "attach PRIVATE struct_ops link");
	*keep = l;
	return bpf_link__fd(l);
}

/* ---- one NVMe session (its own ring, UMEM and lent frames) ---- */
struct session {
	int ring;
	void *pool;
	size_t pool_bytes;
	__u32 nr_loan;
	__u32 frames[GROUPS];
	struct xdev_ext_mech_create_programs cp;
	__u64 id;
	struct xdev_ext_user_stage *u;	/* attack 5 only */
	struct bpf_link *links[XDEV_EXT_MECH_MAX_STAGES];
	unsigned nr_links;
};

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

/* NVMe READ (src window) -> {NVMe WRITE dst window | USER}. The third fd is a
 * USER stage fd when user_fd >= 0 (attack 5); otherwise a second NVMe stage. */
static int create_programs(struct session *s, int src_ng, __u64 src_slba,
			   int dst_ng, __u64 dst_slba, int user_fd,
			   int read_link, int second_link)
{
	struct xdev_ext_mech_create *c = &s->cp.request.create;
	__u32 n = 0;
	int ret;

	s->cp.size = sizeof(s->cp);
	s->cp.version = XDEV_EXT_MECH_CREATE_PROGRAMS_VERSION;
	s->cp.program_fds[0] = read_link;
	s->cp.program_fds[1] = second_link;
	s->cp.program_fds[2] = -1;
	s->cp.program_fds[3] = -1;
	s->cp.request.size = sizeof(s->cp.request);
	s->cp.request.version = XDEV_EXT_MECH_CREATE_REPORT_VERSION;
	*c = (struct xdev_ext_mech_create){
		.abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .pool_fd = -1,
		.layout = { FRAME, 0, GROUP, GROUP }, .depth = DEPTH, .eventfd = -1,
	};
	c->st[n++] = (struct xdev_ext_mech_stage_uapi){
		.class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE,
		.fd = src_ng, .arg0 = src_slba, .arg1 = WIN_NLB };
	if (user_fd >= 0)
		c->st[n++] = (struct xdev_ext_mech_stage_uapi){
			.class_id = XDEV_EXT_MECH_CLASS_USER, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
			.fd = user_fd, .arg0 = USER_DEADLINE_MS, .arg1 = 0 };
	else
		c->st[n++] = (struct xdev_ext_mech_stage_uapi){
			.class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
			.fd = dst_ng, .arg0 = dst_slba, .arg1 = WIN_NLB };
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

static int stats_of(int ring, __u64 id, struct xdev_ext_mech_stats *st)
{
	memset(st, 0, sizeof(*st));
	st->session_id = id;
	return mech(ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)st);
}

static void print_stats(const char *name, const struct xdev_ext_mech_stats *st)
{
	printf("# %s: done=%llu abort=%llu rejects=%llu protocol_err=%llu timeouts=%llu "
	       "inflight=%llu sequestered=%llu last_err=%d state=%u\n", name,
	       (unsigned long long)st->batches_done, (unsigned long long)st->batches_abort,
	       (unsigned long long)st->rejects, (unsigned long long)st->protocol_err,
	       (unsigned long long)st->timeouts, (unsigned long long)st->inflight,
	       (unsigned long long)st->sequestered, st->last_err, st->state);
}

/* Poll until done+abort reaches GROUPS (idle), or the wait bound. */
static struct xdev_ext_mech_stats wait_settled(struct session *s)
{
	struct xdev_ext_mech_stats st;
	int i;

	for (i = 0; i < WAIT_MS / 5; i++) {
		if (stats_of(s->ring, s->id, &st))
			CHECK(0, "STATS while waiting");
		if (st.batches_done + st.batches_abort >= GROUPS && !st.inflight)
			break;
		usleep(5000);
	}
	return st;
}

static void stop_ok(struct session *s, int expect, const char *what)
{
	struct xdev_ext_mech_stats st;

	CHECK(mech(s->ring, XDEV_EXT_MECH_OP_STOP, s->id) == expect, what);
	CHECK(stats_of(s->ring, s->id, &st) == -ENOENT, "released session is gone");
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

/* The victim: correct PRIVATE programs on both NVMe stages. */
static void victim_create(struct session *v, int srcng, int dstng, struct object *correct)
{
	int rl, wl;

	ring_up(v);
	rl = link_fd(correct, &v->links[v->nr_links++]);
	wl = link_fd(correct, &v->links[v->nr_links++]);
	CHECK(!create_programs(v, srcng, SRC_SLBA, dstng, VIC_SLBA, -1, rl, wl),
	      "victim: CREATE_PROGRAMS NVMe READ -> NVMe WRITE");
}

/* ---- the user thread for attack 5: hold the first batch forever ---- */
struct holder { struct xdev_ext_user_stage *u; volatile unsigned taken; volatile int exit_code; pthread_t thread; };
static void *hold_thread(void *arg)
{
	struct holder *h = arg;
	struct xdev_ext_user_batch b;
	int ret;

	for (;;) {
		ret = xdev_ext_user_stage_next(h->u, -1, &b);
		if (ret) { h->exit_code = ret; return NULL; }
		h->taken++;
		/* Never complete: the kernel cancels the held batch at its deadline. */
	}
}

static unsigned cases;

/* Attacks 1-4: malicious program on the WRITE stage; read stage correct. */
static void run_nvme_attack(int srcng, int dstng, struct object *correct,
			    struct object *malicious, const char *name,
			    __u64 atk_slba, int want_last_err, bool want_reject,
			    bool want_protocol)
{
	struct session v, a;
	struct xdev_ext_mech_stats vs, as;
	int rl, wl;

	victim_create(&v, srcng, dstng, correct);
	ring_up(&a);
	rl = link_fd(correct, &a.links[a.nr_links++]);
	wl = link_fd(malicious, &a.links[a.nr_links++]);
	CHECK(!create_programs(&a, srcng, SRC_SLBA, dstng, atk_slba, -1, rl, wl),
	      "attack: CREATE_PROGRAMS with its own PRIVATE write program");

	start(&v);
	start(&a);
	vs = wait_settled(&v);
	as = wait_settled(&a);
	print_stats("victim", &vs);
	print_stats(name, &as);

	CHECK(vs.batches_done == GROUPS && !vs.batches_abort && !vs.rejects &&
	      !vs.protocol_err && !vs.timeouts && !vs.sequestered && !vs.last_err &&
	      vs.state == XDEV_EXT_MECH_SESSION_ACTIVE,
	      "victim completes every batch with zero aborts while the attack runs");
	CHECK(as.batches_abort == GROUPS && !as.batches_done && !as.sequestered,
	      "attack: every batch is refused, none completes, nothing sequestered");
	CHECK(as.last_err == want_last_err, "attack: stops with its declared reason");
	if (want_reject)
		CHECK(as.rejects == GROUPS, "attack: each bad SQE counts a reject");
	if (want_protocol)
		CHECK(as.protocol_err >= 1, "attack: a protocol error is recorded");

	stop_ok(&a, want_last_err, "attack: STOP returns the declared reason");
	stop_ok(&v, 0, "victim: STOP releases the session (0)");
	links_destroy(&a);
	links_destroy(&v);
	ring_down(&a);
	ring_down(&v);
	printf("XDEV_EXT_ATTACK_CASE=PASS case=%s\n", name);
	cases++;
}

/* Attack 5: attacker NVMe READ -> USER; the user thread stalls the stage. */
static void run_user_stall(int srcng, int dstng, struct object *correct, struct object *userp)
{
	struct session v, a;
	struct xdev_ext_mech_stats vs, as;
	struct holder h = {0};
	struct xdev_ext_user_stage_opts o;
	int rl, ul;

	victim_create(&v, srcng, dstng, correct);
	ring_up(&a);
	o = (struct xdev_ext_user_stage_opts)XDEV_EXT_OPTS_INIT(xdev_ext_user_stage_opts,
		.ring_fd = a.ring, .umem = a.pool, .entries = DEPTH);
	CHECK(!xdev_ext_user_stage_open(&o, &a.u), "attack: open a USER stage fd");
	rl = link_fd(correct, &a.links[a.nr_links++]);
	ul = link_fd(userp, &a.links[a.nr_links++]);
	CHECK(!create_programs(&a, srcng, SRC_SLBA, -1, 0, xdev_ext_user_stage_fd(a.u), rl, ul),
	      "attack: CREATE_PROGRAMS NVMe READ -> USER (no write stage)");

	h.u = a.u;
	CHECK(!pthread_create(&h.thread, NULL, hold_thread, &h), "attack: start the holding user thread");
	start(&v);
	start(&a);
	vs = wait_settled(&v);
	as = wait_settled(&a);
	print_stats("victim", &vs);
	print_stats("user-stall", &as);

	CHECK(vs.batches_done == GROUPS && !vs.batches_abort && !vs.last_err,
	      "victim completes every batch while the attacker's USER stage stalls");
	CHECK(as.timeouts >= 1 && as.batches_abort >= 1 && as.last_err == -ETIMEDOUT &&
	      !as.sequestered, "user-stall: held batch cancelled at its deadline (-ETIMEDOUT)");

	stop_ok(&a, -ETIMEDOUT, "user-stall: STOP returns the deadline error");
	CHECK(pthread_cancel(h.thread) == 0 || 1, "user-stall: cancel the holding thread");
	pthread_join(h.thread, NULL);
	stop_ok(&v, 0, "victim: STOP releases the session (0)");
	links_destroy(&a);
	links_destroy(&v);
	ring_down(&a);
	ring_down(&v);
	puts("XDEV_EXT_ATTACK_CASE=PASS case=user-stall");
	cases++;
}

/* Attack 6: detach the attacker's own PRIVATE link while the session runs. */
static void run_detach(int srcng, int dstng, struct object *correct)
{
	struct session v, a;
	struct xdev_ext_mech_stats vs, as;
	int rl, i;
	struct bpf_link *wlink;

	victim_create(&v, srcng, dstng, correct);
	ring_up(&a);
	rl = link_fd(correct, &a.links[a.nr_links++]);
	/* The write-stage link is detached mid-run; keep it separately. */
	wlink = bpf_map__attach_struct_ops(correct->map);
	CHECK(wlink && !libbpf_get_error(wlink), "attack: attach the write-stage PRIVATE link");
	CHECK(!create_programs(&a, srcng, SRC_SLBA, dstng, ATK6_SLBA, -1, rl, bpf_link__fd(wlink)),
	      "attack: CREATE_PROGRAMS with a correct in-window write program");

	start(&v);
	start(&a);
	/* Retract the attacker's write-stage link immediately; admission closes. */
	CHECK(!bpf_link__detach(wlink), "attack: detach the PRIVATE write link mid-run");
	vs = wait_settled(&v);
	for (i = 0; i < WAIT_MS / 5; i++) {
		if (stats_of(a.ring, a.id, &as))
			CHECK(0, "attack STATS while waiting");
		if (as.state != XDEV_EXT_MECH_SESSION_ACTIVE && !as.inflight)
			break;
		usleep(5000);
	}
	print_stats("victim", &vs);
	print_stats("detach", &as);

	CHECK(vs.batches_done == GROUPS && !vs.batches_abort && !vs.last_err,
	      "victim completes every batch while the attacker detaches its link");
	CHECK(as.last_err == -ECANCELED &&
	      (as.state == XDEV_EXT_MECH_SESSION_STOPPING ||
	       as.state == XDEV_EXT_MECH_SESSION_STOPPED),
	      "detach: the session stops with -ECANCELED and admits no new batch");
	/* No further admission: a START now is refused. */
	{
		struct xdev_ext_mech_start st2 = { .session_id = a.id, .nr_batches = 1,
			.first_seq = FIRST_KEY + GROUPS, .flags = XDEV_EXT_MECH_START_F_USER_FRAMES,
			.nr_user_frames = a.nr_loan, .user_frames = (uintptr_t)a.frames };
		CHECK(mech(a.ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&st2) < 0,
		      "detach: a new START is refused after retraction");
	}

	stop_ok(&a, -ECANCELED, "detach: STOP returns -ECANCELED");
	stop_ok(&v, 0, "victim: STOP releases the session (0)");
	bpf_link__destroy(wlink);
	links_destroy(&a);
	links_destroy(&v);
	ring_down(&a);
	ring_down(&v);
	puts("XDEV_EXT_ATTACK_CASE=PASS case=detach");
	cases++;
}

int main(int argc, char **argv)
{
	struct rlimit lim = { RLIM_INFINITY, RLIM_INFINITY };
	struct object correct, reserved, outside, frame, verdict, userp;
	unsigned char *source, *dest, *dest_after;
	__u64 src_bytes, dst_bytes, off, g, b;
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
	CHECK(dst_bytes == src_bytes && dst_bytes >= DISK_LBAS * LBA,
	      "bounded whole-disk comparison");
	source = malloc(src_bytes); dest = malloc(dst_bytes); dest_after = malloc(dst_bytes);
	CHECK(source && dest && dest_after, "verification buffers");
	CHECK(pread(src, source, src_bytes, 0) == (ssize_t)src_bytes, "read the source disk");
	for (off = 1; off < src_bytes && source[off] == source[0]; off++)
		;
	CHECK(off < src_bytes, "source disk holds a nonuniform pattern");
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

	run_nvme_attack(srcng, dstng, &correct, &reserved, "reserved", ATK1_SLBA, -EPERM, true, false);
	run_nvme_attack(srcng, dstng, &correct, &outside, "outside", ATK2_SLBA, -ERANGE, true, false);
	run_nvme_attack(srcng, dstng, &correct, &frame, "frame", ATK3_SLBA, -EPROTO, false, true);
	run_nvme_attack(srcng, dstng, &correct, &verdict, "verdict", ATK4_SLBA, -ECANCELED, false, true);
	run_user_stall(srcng, dstng, &correct, &userp);
	run_detach(srcng, dstng, &correct);

	bpf_object__close(correct.obj); bpf_object__close(reserved.obj);
	bpf_object__close(outside.obj); bpf_object__close(frame.obj);
	bpf_object__close(verdict.obj); bpf_object__close(userp.obj);

	/* Whole-disk oracle: the victim window is an exact copy of the source
	 * read window; every byte outside it is guard, except the detach
	 * attacker window which may hold completed source groups or guard. No
	 * byte is anything else, proving no attacker reached the victim window. */
	CHECK(!ioctl(dst, BLKFLSBUF), "invalidate the block cache before readback");
	CHECK(pread(dst, dest_after, dst_bytes, 0) == (ssize_t)dst_bytes, "read back the destination");
	for (g = 0; g < GROUPS; g++) {
		unsigned char *f = dest_after + VIC_SLBA * LBA + g * GROUP;
		CHECK(!memcmp(f, source + SRC_SLBA * LBA + g * GROUP, GROUP),
		      "victim window group is an exact source copy");
	}
	for (b = 0; b < dst_bytes; b++) {
		__u64 lba = b / LBA;
		if (lba >= VIC_SLBA && lba < VIC_SLBA + WIN_NLB)
			continue;			/* checked above */
		if (lba >= ATK6_SLBA && lba < ATK6_SLBA + WIN_NLB) {
			__u64 within = b - ATK6_SLBA * LBA;
			if (dest_after[b] == GUARD || dest_after[b] == source[SRC_SLBA * LBA + within])
				continue;		/* guard or a completed group byte */
			CHECK(0, "detach attacker window holds only guard or its own source copy");
		}
		if (dest_after[b] != GUARD)
			CHECK(0, "no byte outside the victim window changed");
	}
	CHECK(1, "whole-disk oracle: victim window exact, attacker windows never touched it");

	close(src); close(srcng); close(dst); close(dstng);
	free(source); free(dest); free(dest_after);
	printf("1..%u\n", checks);
	printf("XDEV_EXT_ATTACK_ISOLATION=PASS cases=%u order=reserved,outside,frame,verdict,user-stall,detach timing=none\n", cases);
	return 0;
}
