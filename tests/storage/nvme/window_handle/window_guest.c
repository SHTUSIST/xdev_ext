// SPDX-License-Identifier: GPL-2.0
/*
 * GUEST TEST ONLY (prototype for ASK.69): NVMe LBA window handles on real QEMU
 * NVMe PCI. Correctness only; nothing is timed.
 *
 * Requirement under test: a holder of a namespace issues a window handle
 * (NVME_IOCTL_XDEV_EXT_WINDOW on /dev/ngXnY) naming one LBA range and its
 * access; a session that presents the handle as its NVMe stage fd binds only
 * inside that range and only in a granted direction; handles of one namespace
 * that share an LBA are refused unless both are read-only; a handle's range
 * stays reserved until its last reference goes, and a session holds its stage
 * file until it is released, so closing the fd under a running session keeps
 * the session's window and keeps the range reserved until the session ends.
 *
 * Layout, in 64-LBA windows W(i) of the destination namespace:
 *   W0 tenant (writes source W0), W1 victim (writes source W1), W2 spare,
 *   W3 read-only handle, W4 write-only handle, W5 raw-fd session (source W5).
 * The source disk is position-unique (see check_source), so a group copied
 * from the wrong window or slot cannot match. The victim writes first; the
 * tenant then tries the victim's window and must be refused; the victim's
 * bytes are compared again afterwards.
 *
 * The tenant is a child that sets up its ring and PRIVATE links as root,
 * receives its handles over SCM_RIGHTS, drops to uid/gid 65534 and cannot
 * open either namespace node; everything it does afterwards uses handles.
 *
 * Usage: window_guest SRC_BLOCK SRC_NG DST_BLOCK DST_NG BPF_DIR
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "linux/io_uring.h"
#include "linux/xdev_ext_mech.h"
#include "linux/nvme_ioctl.h"

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
#define SPAN (4ULL << 20)
#define SPAN_LBAS (SPAN / LBA)
#define NOBODY 65534

#define RD NVME_XDEV_EXT_WINDOW_F_READ
#define WR NVME_XDEV_EXT_WINDOW_F_WRITE
#define RDWR (NVME_XDEV_EXT_WINDOW_F_READ | NVME_XDEV_EXT_WINDOW_F_WRITE)

enum { W_TENANT, W_VICTIM, W_SPARE, W_RO, W_WO, W_RAW };
static __u64 win(unsigned i) { return (__u64)i * WIN_NLB; }

static const char *who = "holder";
static unsigned int checks;
#define CHECK(c, msg) do { \
	if (!(c)) { int e_ = errno; \
		fprintf(stderr, "not ok %u - %s: %s (errno=%d %s)\n", ++checks, who, msg, e_, strerror(e_)); \
		printf("not ok %u - %s: %s\n", checks, who, msg); exit(1); } \
	printf("ok %u - %s: %s\n", ++checks, who, msg); } while (0)
#define CHECK_EQ(got, want, msg) do { long long g_ = (got), w_ = (want); \
	if (g_ != w_) printf("# %s: %s: got %lld want %lld\n", who, msg, g_, w_); \
	CHECK(g_ == w_, msg); } while (0)

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

/* The handle under test: a new fd, or -errno. */
static int issue(int ng, __u64 slba, __u64 nlb, __u32 flags, __u32 rsvd)
{
	struct nvme_xdev_ext_window w = { .slba = slba, .nlb = nlb, .flags = flags, .rsvd = rsvd };
	int fd = ioctl(ng, NVME_IOCTL_XDEV_EXT_WINDOW, &w);

	return fd < 0 ? -errno : fd;
}

static int issue_ok(int ng, __u64 slba, __u64 nlb, __u32 flags, const char *what)
{
	int fd = issue(ng, slba, nlb, flags, 0);

	if (fd < 0)
		printf("# %s: %s: issue returned %d\n", who, what, fd);
	CHECK(fd >= 0, what);
	return fd;
}

/* ---- PRIVATE struct_ops link ---- */
struct object { struct bpf_object *obj; struct bpf_map *map; };

static void object_open(const char *dir, struct object *o)
{
	char path[PATH_MAX];
	struct bpf_map *map;

	snprintf(path, sizeof(path), "%s/window_nvme.bpf.o", dir);
	o->obj = bpf_object__open_file(path, NULL);
	o->map = NULL;
	if (!libbpf_get_error(o->obj) && !bpf_object__load(o->obj))
		bpf_object__for_each_map(map, o->obj) {
			if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS) {
				o->map = map;
				break;
			}
		}
	CHECK(o->map, "open and load window_nvme");
}

/* ---- one session ring: UMEM, lent frames and two PRIVATE links ---- */
struct session {
	int ring;
	void *pool;
	size_t pool_bytes;
	__u32 frames[GROUPS];
	struct bpf_link *links[2];
	struct xdev_ext_mech_create_programs cp;
	__u64 id;
};

static void ring_up(struct session *s, struct object *o)
{
	struct io_uring_params params = {};
	struct io_uring_xdev_ext_umem_reg reg = { .frame_size = FRAME };
	__u32 i;

	memset(s, 0, sizeof(*s));
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
	for (i = 0; i < GROUPS; i++)
		s->frames[i] = i;
	for (i = 0; i < 2; i++) {
		s->links[i] = bpf_map__attach_struct_ops(o->map);
		CHECK(s->links[i] && !libbpf_get_error(s->links[i]), "attach a PRIVATE struct_ops link");
	}
}

struct stage { int fd; __u64 slba, nlb; };

/* NVMe READ (@src) -> NVMe WRITE (@dst); 0 or the CREATE result. */
static int create(struct session *s, struct stage src, struct stage dst)
{
	struct xdev_ext_mech_create *c = &s->cp.request.create;
	int ret;

	memset(&s->cp, 0, sizeof(s->cp));
	s->id = 0;
	s->cp.size = sizeof(s->cp);
	s->cp.version = XDEV_EXT_MECH_CREATE_PROGRAMS_VERSION;
	s->cp.program_fds[0] = bpf_link__fd(s->links[0]);
	s->cp.program_fds[1] = bpf_link__fd(s->links[1]);
	for (ret = 2; ret < XDEV_EXT_MECH_MAX_STAGES; ret++)
		s->cp.program_fds[ret] = -1;
	s->cp.request.size = sizeof(s->cp.request);
	s->cp.request.version = XDEV_EXT_MECH_CREATE_REPORT_VERSION;
	*c = (struct xdev_ext_mech_create){
		.abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 2,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .pool_fd = -1,
		.layout = { FRAME, 0, GROUP, GROUP }, .depth = DEPTH, .eventfd = -1,
	};
	c->st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = src.fd,
		.arg0 = src.slba, .arg1 = src.nlb };
	c->st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = dst.fd,
		.arg0 = dst.slba, .arg1 = dst.nlb };
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

/* A refused CREATE: its result, from the class bind of the expected stage. */
static void create_refused(struct session *s, struct stage src, struct stage dst,
			   int want, __u32 stage, const char *what)
{
	int ret = create(s, src, dst);
	const struct xdev_ext_mech_create_report *r = &s->cp.request.report;

	printf("# %s: %s: result=%d phase=%u failed_stage=%u\n", who, what, ret, r->phase,
	       r->failed_stage);
	CHECK_EQ(ret, want, what);
	CHECK_EQ(r->phase, XDEV_EXT_MECH_CREATE_CLASS_BIND, "refused in the stage class bind");
	CHECK_EQ(r->failed_stage, stage, "refused at the stage that presented the window");
	CHECK(!s->id, "no session id for a refused CREATE");
}

static void start(struct session *s)
{
	struct xdev_ext_mech_start st = { .session_id = s->id, .nr_batches = GROUPS,
		.first_seq = FIRST_KEY, .flags = XDEV_EXT_MECH_START_F_USER_FRAMES,
		.nr_user_frames = GROUPS, .user_frames = (uintptr_t)s->frames };

	CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&st), "exactly one START");
}

static bool settled(const struct xdev_ext_mech_stats *st)
{
	return st->batches_done + st->batches_abort >= GROUPS && !st->inflight;
}

static void quiet_stats(const struct session *s, struct xdev_ext_mech_stats *st)
{
	memset(st, 0, sizeof(*st));
	st->session_id = s->id;
	if (mech(s->ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)st))
		CHECK(0, "STATS");
}

static struct xdev_ext_mech_stats wait_settled(const struct session *s)
{
	struct xdev_ext_mech_stats st;
	int i;

	for (i = 0; i < WAIT_MS / 5; i++) {
		quiet_stats(s, &st);
		if (settled(&st))
			break;
		usleep(5000);
	}
	printf("# %s: done=%llu abort=%llu rejects=%llu protocol_err=%llu inflight=%llu "
	       "sequestered=%llu last_err=%d state=%u submitted=%llu,%llu completed=%llu,%llu\n", who,
	       (unsigned long long)st.batches_done, (unsigned long long)st.batches_abort,
	       (unsigned long long)st.rejects, (unsigned long long)st.protocol_err,
	       (unsigned long long)st.inflight, (unsigned long long)st.sequestered, st.last_err,
	       st.state, (unsigned long long)st.submitted[0], (unsigned long long)st.submitted[1],
	       (unsigned long long)st.completed[0], (unsigned long long)st.completed[1]);
	return st;
}

static void check_exact_run(const struct xdev_ext_mech_stats *st, const char *what)
{
	CHECK(st->batches_done == GROUPS && !st->batches_abort && !st->rejects &&
	      !st->protocol_err && !st->timeouts && !st->sequestered && !st->last_err &&
	      !st->inflight && st->state == XDEV_EXT_MECH_SESSION_ACTIVE &&
	      st->submitted[1] == GROUPS && st->completed[1] == GROUPS, what);
}

static void stop_ok(struct session *s, const char *what)
{
	struct xdev_ext_mech_stats st;

	CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_STOP, s->id), what);
	memset(&st, 0, sizeof(st));
	st.session_id = s->id;
	CHECK(mech(s->ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&st) == -ENOENT,
	      "the stopped session is released");
}

static void ring_down(struct session *s)
{
	bpf_link__destroy(s->links[0]);
	bpf_link__destroy(s->links[1]);
	CHECK(!close(s->ring), "close the ring");
	munmap(s->pool, s->pool_bytes);
}

/* ---- SCM_RIGHTS ---- */
#define NR_PASSED 4
/* The message carries the TAP counter, so numbering continues across processes. */
static void send_fds(int sock, const int *fds)
{
	unsigned int count = checks + 1;	/* this send is check count */
	struct iovec iov = { &count, sizeof(count) };
	union { char buf[CMSG_SPACE(sizeof(int) * NR_PASSED)]; struct cmsghdr align; } u;
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
			      .msg_control = u.buf, .msg_controllen = sizeof(u.buf) };
	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);

	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(int) * NR_PASSED);
	memcpy(CMSG_DATA(c), fds, sizeof(int) * NR_PASSED);
	CHECK(sendmsg(sock, &msg, 0) == (ssize_t)sizeof(count), "pass the tenant's handles over SCM_RIGHTS");
}

static bool recv_fds(int sock, int *fds)
{
	unsigned int count;
	struct iovec iov = { &count, sizeof(count) };
	union { char buf[CMSG_SPACE(sizeof(int) * NR_PASSED)]; struct cmsghdr align; } u;
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
			      .msg_control = u.buf, .msg_controllen = sizeof(u.buf) };
	struct cmsghdr *c;

	if (recvmsg(sock, &msg, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(count))
		return false;
	c = CMSG_FIRSTHDR(&msg);
	if (!c || c->cmsg_type != SCM_RIGHTS || c->cmsg_len != CMSG_LEN(sizeof(int) * NR_PASSED))
		return false;
	memcpy(fds, CMSG_DATA(c), sizeof(int) * NR_PASSED);
	checks = count;
	return true;
}

/* ---- the tenant: handles only, no namespace node ---- */
enum { T_DST_RW_W0, T_SRC_R_W0, T_DST_R_W3, T_DST_W_W4 };

static int tenant(int sock, const char *src_ng, const char *dst_ng, const char *bpf_dir)
{
	struct xdev_ext_mech_stats st;
	struct session s;
	struct object o;
	int h[NR_PASSED];

	who = "tenant";
	/* Nothing is printed before the handles arrive: the holder is blocked
	 * in waitpid from then on, so the two TAP streams never interleave. */
	if (!recv_fds(sock, h)) {
		printf("# tenant: no handles received\n");
		return 3;
	}
	CHECK(1, "received four window handles");
	object_open(bpf_dir, &o);
	ring_up(&s, &o);
	CHECK(!setgroups(0, NULL) && !setgid(NOBODY) && !setuid(NOBODY), "drop to uid/gid 65534");
	CHECK(getuid() == NOBODY && geteuid() == NOBODY && getegid() == NOBODY, "running unprivileged");
	errno = 0;
	CHECK(open(dst_ng, O_RDWR) < 0 && errno == EACCES, "cannot open the destination namespace");
	errno = 0;
	CHECK(open(src_ng, O_RDONLY) < 0 && errno == EACCES, "cannot open the source namespace");

	/* Outside the destination handle [W0]: the victim's window, a straddle, one LBA more. */
	create_refused(&s, (struct stage){ h[T_SRC_R_W0], win(W_TENANT), WIN_NLB },
		       (struct stage){ h[T_DST_RW_W0], win(W_VICTIM), WIN_NLB }, -EACCES, 1,
		       "CREATE at the victim's window [N,2N) with a handle for [0,N) is refused");
	create_refused(&s, (struct stage){ h[T_SRC_R_W0], win(W_TENANT), WIN_NLB },
		       (struct stage){ h[T_DST_RW_W0], win(W_TENANT) + WIN_NLB / 2, WIN_NLB }, -EACCES, 1,
		       "CREATE straddling into the victim's window is refused");
	create_refused(&s, (struct stage){ h[T_SRC_R_W0], win(W_TENANT), WIN_NLB },
		       (struct stage){ h[T_DST_RW_W0], win(W_TENANT), WIN_NLB + 1 }, -EACCES, 1,
		       "CREATE one LBA longer than the handle is refused");
	/* The read direction is bounded the same way. */
	create_refused(&s, (struct stage){ h[T_SRC_R_W0], win(W_VICTIM), WIN_NLB },
		       (struct stage){ h[T_DST_RW_W0], win(W_TENANT), WIN_NLB }, -EACCES, 0,
		       "READ stage outside its read handle is refused");
	/* Ungranted directions. */
	create_refused(&s, (struct stage){ h[T_SRC_R_W0], win(W_TENANT), WIN_NLB },
		       (struct stage){ h[T_DST_R_W3], win(W_RO), WIN_NLB }, -EBADF, 1,
		       "WRITE stage on a read-only handle is refused");
	create_refused(&s, (struct stage){ h[T_DST_W_W4], win(W_WO), WIN_NLB },
		       (struct stage){ h[T_DST_RW_W0], win(W_TENANT), WIN_NLB }, -EBADF, 0,
		       "READ stage on a write-only handle is refused");

	/* Inside its handles the tenant's session runs exactly. */
	CHECK_EQ(create(&s, (struct stage){ h[T_SRC_R_W0], win(W_TENANT), WIN_NLB },
			(struct stage){ h[T_DST_RW_W0], win(W_TENANT), WIN_NLB }), 0,
		 "CREATE inside both handles succeeds");
	start(&s);
	st = wait_settled(&s);
	check_exact_run(&st, "tenant session completed every batch exactly");
	stop_ok(&s, "STOP the tenant session");
	ring_down(&s);
	bpf_object__close(o.obj);
	for (int i = 0; i < NR_PASSED; i++)
		CHECK(!close(h[i]), "close a tenant handle");
	printf("# tenant: done\n");
	fflush(stdout);
	/* Hand the counter back. */
	return write(sock, &checks, sizeof(checks)) == (ssize_t)sizeof(checks) ? 0 : 4;
}

/* ---- disks ---- */
/*
 * The source disk is position-unique: the 8-byte word at byte offset o holds
 * low32 = ((o / 512) << 7) | (((o % 512) / 8) << 1) | 1 and high32 = the seed
 * (the high word of word 0). window_kvm.sh writes it; window_validate.py
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

static void read_disk(int blk, unsigned char *buf, __u64 bytes, const char *what)
{
	CHECK(!ioctl(blk, BLKFLSBUF), "invalidate the block cache before reading");
	CHECK(pread(blk, buf, bytes, 0) == (ssize_t)bytes, what);
}

static bool window_is(const unsigned char *dest, const unsigned char *source, unsigned w)
{
	return !memcmp(dest + win(w) * LBA, source + win(w) * LBA, WIN_BYTES);
}

/* Whole-disk oracle: W0, W1, W5 hold their own source windows, every other byte guard. */
static void check_destination(const unsigned char *source, const unsigned char *dest, __u64 bytes)
{
	unsigned char *expect = malloc(bytes);
	static const unsigned written[] = { W_TENANT, W_VICTIM, W_RAW };
	__u64 b;
	unsigned i;

	CHECK(expect, "oracle buffer");
	memset(expect, GUARD, bytes);
	for (i = 0; i < sizeof(written) / sizeof(written[0]); i++)
		memcpy(expect + win(written[i]) * LBA, source + win(written[i]) * LBA, WIN_BYTES);
	for (b = 0; b < bytes && dest[b] == expect[b]; b++)
		;
	if (b < bytes)
		printf("# oracle: first mismatch byte=%llu lba=%llu window=%llu\n",
		       (unsigned long long)b, (unsigned long long)(b / LBA),
		       (unsigned long long)(b / WIN_BYTES));
	CHECK(b == bytes, "whole-disk oracle: W0, W1, W5 exact; every other byte guard");
	free(expect);
}

int main(int argc, char **argv)
{
	struct rlimit lim = { RLIM_INFINITY, RLIM_INFINITY };
	struct xdev_ext_mech_stats st;
	unsigned char *source, *dest;
	__u64 src_bytes, dst_bytes, off;
	int src, srcng, dst, dstng, dstng_ro, sv[2], status = 0, fd, x, y;
	int ha, hv, ra, rv, hro, hwo;
	struct session v, r;
	struct object o;
	pid_t child;

	setvbuf(stdout, NULL, _IOLBF, 0);
	setrlimit(RLIMIT_MEMLOCK, &lim);
	puts("TAP version 13\n# NVMe LBA window handles (prototype for ASK.69): QEMU NVMe, correctness only, no timing");
	if (argc != 6) {
		fprintf(stderr, "usage: %s SRC_BLOCK SRC_NG DST_BLOCK DST_NG BPF_DIR\n", argv[0]);
		return 2;
	}
	CHECK(getenv("XDEV_EXT_WINDOW_GUEST") && !strcmp(getenv("XDEV_EXT_WINDOW_GUEST"), "1"),
	      "guest-only opt-in");
	/* The tenant is forked before any namespace node is opened. */
	CHECK(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv), "tenant socket pair");
	fflush(stdout);
	child = fork();
	if (!child) {
		close(sv[0]);
		exit(tenant(sv[1], argv[2], argv[4], argv[5]));
	}
	CHECK(child > 0, "fork the tenant");
	close(sv[1]);

	src = open_ok(argv[1], O_RDONLY); srcng = open_ok(argv[2], O_RDONLY);
	dst = open_ok(argv[3], O_RDWR); dstng = open_ok(argv[4], O_RDWR);
	dstng_ro = open_ok(argv[4], O_RDONLY);
	CHECK(!ioctl(src, BLKGETSIZE64, &src_bytes) && !ioctl(dst, BLKGETSIZE64, &dst_bytes),
	      "disk capacities");
	CHECK(src_bytes == SPAN && dst_bytes == SPAN, "whole-disk comparison over the exact image size");
	source = malloc(src_bytes); dest = malloc(dst_bytes);
	CHECK(source && dest, "verification buffers");
	read_disk(src, source, src_bytes, "read the source disk");
	check_source(source, src_bytes);
	read_disk(dst, dest, dst_bytes, "read the destination disk");
	for (off = 0; off < dst_bytes && dest[off] == GUARD; off++)
		;
	CHECK(off == dst_bytes, "destination disk starts as guard bytes");
	object_open(argv[5], &o);

	/* Issue errors. */
	CHECK_EQ(issue(dstng, 0, WIN_NLB, 0, 0), -EINVAL, "issue without an access bit is refused");
	CHECK_EQ(issue(dstng, 0, WIN_NLB, 4, 0), -EINVAL, "issue with an unknown access bit is refused");
	CHECK_EQ(issue(dstng, 0, WIN_NLB, RDWR, 1), -EINVAL, "issue with a nonzero reserved word is refused");
	CHECK_EQ(issue(dstng, 0, 0, RDWR, 0), -EINVAL, "issue of an empty window is refused");
	CHECK_EQ(issue(dstng, SPAN_LBAS - WIN_NLB / 2, WIN_NLB, RDWR, 0), -ERANGE,
		 "issue past the namespace capacity is refused");
	CHECK_EQ(issue(dstng_ro, win(W_SPARE), WIN_NLB, WR, 0), -EBADF,
		 "a holder whose fd is read-only cannot issue a writable handle");
	CHECK_EQ(issue(srcng, win(W_SPARE), WIN_NLB, RDWR, 0), -EBADF,
		 "a read-only source fd cannot issue a writable handle");

	/* Handles. */
	ha = issue_ok(dstng, win(W_TENANT), WIN_NLB, RDWR, "issue the tenant's destination handle [0,N)");
	hv = issue_ok(dstng, win(W_VICTIM), WIN_NLB, RDWR, "issue the victim's adjacent destination handle [N,2N)");
	ra = issue_ok(srcng, win(W_TENANT), WIN_NLB, RD, "issue the tenant's read-only source handle");
	rv = issue_ok(srcng, win(W_VICTIM), WIN_NLB, RD,
		      "a read-only source handle over the same LBAs of another namespace is independent");
	fd = issue_ok(srcng, win(W_TENANT), WIN_NLB, RD, "read-only handles may overlap");
	CHECK(!close(fd), "close the overlapping read-only handle");
	hro = issue_ok(dstng, win(W_RO), WIN_NLB, RD, "issue a read-only destination handle");
	hwo = issue_ok(dstng, win(W_WO), WIN_NLB, WR, "issue a write-only destination handle");

	/* Overlap with a live handle where either side may write. */
	CHECK_EQ(issue(dstng, win(W_TENANT) + WIN_NLB / 2, WIN_NLB, RDWR, 0), -EBUSY,
		 "a writable handle overlapping two writable handles is refused");
	CHECK_EQ(issue(dstng, win(W_VICTIM), WIN_NLB, RD, 0), -EBUSY,
		 "a read-only handle over a writable handle is refused");
	CHECK_EQ(issue(dstng, win(W_VICTIM) + WIN_NLB - 1, 1, WR, 0), -EBUSY,
		 "a write-only handle sharing one LBA is refused");
	CHECK_EQ(issue(dstng, 0, 2 * WIN_NLB, RDWR, 0), -EBUSY, "a covering writable handle is refused");
	CHECK_EQ(issue(dstng, win(W_RO) + WIN_NLB - 4, 8, WR, 0), -EBUSY,
		 "a writable handle over a read-only handle is refused");
	fd = issue_ok(dstng, win(W_RO) - 2, 4, RD, "a read-only handle partly over a read-only handle is allowed");
	CHECK(!close(fd), "close it");
	x = issue_ok(dstng, win(W_SPARE), WIN_NLB, RDWR, "issue a spare writable handle");
	CHECK(!close(x), "close the spare handle without using it");
	y = issue_ok(dstng, win(W_SPARE), WIN_NLB, RDWR, "the closed range can be issued again");
	CHECK(!close(y), "close it again");

	/* Victim: CREATE with handles, then close its only handle fds mid-session. */
	who = "victim";
	ring_up(&v, &o);
	CHECK_EQ(create(&v, (struct stage){ rv, win(W_VICTIM), WIN_NLB },
			(struct stage){ hv, win(W_VICTIM), WIN_NLB }), 0,
		 "CREATE inside the victim's handles succeeds");
	CHECK(!close(hv) && !close(rv), "close the victim's only handle fds");
	CHECK_EQ(issue(dstng, win(W_VICTIM), WIN_NLB, RDWR, 0), -EBUSY,
		 "after close, the live session still reserves its range");
	start(&v);
	quiet_stats(&v, &st);
	printf("# victim: at mid-run issue: done=%llu inflight=%llu\n",
	       (unsigned long long)st.batches_done, (unsigned long long)st.inflight);
	CHECK_EQ(issue(dstng, win(W_VICTIM) + WIN_NLB / 4, WIN_NLB / 4, WR, 0), -EBUSY,
		 "after START the range is still reserved");
	st = wait_settled(&v);
	check_exact_run(&st, "the session kept its admitted window and completed exactly");
	CHECK_EQ(issue(dstng, win(W_VICTIM), WIN_NLB, RDWR, 0), -EBUSY,
		 "a settled but unreleased session still reserves its range");
	stop_ok(&v, "STOP the victim session");
	ring_down(&v);
	fd = issue_ok(dstng, win(W_VICTIM), WIN_NLB, RDWR, "the range is free once the session is released");
	CHECK(!close(fd), "close the re-issued handle");
	read_disk(dst, dest, dst_bytes, "read the destination after the victim");
	CHECK(window_is(dest, source, W_VICTIM), "the victim's window holds its own source window");

	/* Tenant: unprivileged, handles only. */
	who = "holder";
	{
		int pass[NR_PASSED] = { ha, ra, hro, hwo };

		send_fds(sv[0], pass);
	}
	/* Silent until the tenant hands the counter back: no interleaving. */
	x = !close(ha) && !close(ra) && !close(hro) && !close(hwo);
	y = waitpid(child, &status, 0) == child;
	fd = y && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
	     read(sv[0], &checks, sizeof(checks)) == (ssize_t)sizeof(checks);
	printf("# tenant exit status=0x%x\n", status);
	CHECK(x, "the holder dropped its copies of the tenant's handles");
	CHECK(y, "wait for the tenant");
	CHECK(fd, "the tenant passed every check");
	read_disk(dst, dest, dst_bytes, "read the destination after the tenant");
	CHECK(window_is(dest, source, W_VICTIM), "the victim's bytes are unchanged after the tenant");
	CHECK(window_is(dest, source, W_TENANT), "the tenant's window holds its own source window");
	fd = issue_ok(dstng, win(W_TENANT), WIN_NLB, RDWR,
		      "the tenant's range is free once its handles and session are gone");
	CHECK(!close(fd), "close it");

	/* Backward compatibility: the namespace fds themselves still bind any window. */
	who = "raw";
	ring_up(&r, &o);
	CHECK_EQ(create(&r, (struct stage){ srcng, win(W_RAW), WIN_NLB },
			(struct stage){ dstng, win(W_RAW), WIN_NLB }), 0,
		 "CREATE with the namespace fds themselves succeeds as before");
	start(&r);
	st = wait_settled(&r);
	check_exact_run(&st, "the raw-fd session completed exactly");
	stop_ok(&r, "STOP the raw-fd session");
	ring_down(&r);

	who = "holder";
	bpf_object__close(o.obj);
	read_disk(dst, dest, dst_bytes, "read back the destination");
	check_destination(source, dest, dst_bytes);
	close(src); close(srcng); close(dst); close(dstng); close(dstng_ro);
	free(source); free(dest);
	printf("1..%u\n", checks);
	printf("XDEV_EXT_WINDOW_HANDLE=PASS timing=none\n");
	return 0;
}
