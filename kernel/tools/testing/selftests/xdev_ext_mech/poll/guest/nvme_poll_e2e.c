// SPDX-License-Identifier: GPL-2.0
/* GUEST TEST ONLY: NVMe stage polling (XDEV_EXT_MECH_STAGE_F_POLL) on real
 * QEMU NVMe PCI controllers booted with nvme.poll_queues=2.  Correctness
 * only; nothing here is timed.
 *
 * Cases, each its own session on the ring's UMEM (NVMe READ -> NVMe WRITE):
 *   polled-copy   both stages polled; the I/O-queue interrupt counters of both
 *                 controllers must not move while every command completes
 *   plain-copy    the same chain without the bit: interrupts must move, so
 *                 the interrupt oracle can see interrupt completions
 *   polled-stop   STOP while polled commands are in flight must drain and
 *                 release (STOP 0, not -EBUSY from a deferred release)
 * and, in mode reset (run last: resetting a controller to fewer poll queues
 * makes the upstream IRQ affinity code warn about more queues than CPUs):
 *   lost-queues   a polled session whose controller is reset to zero poll
 *                 queues after CREATE refuses its submit with -EOPNOTSUPP;
 *                 a RECYCLE START then stops at that first refusal
 *   refuse        CREATE with the bit on that controller now fails
 *                 -EOPNOTSUPP; without the bit it still reads
 * Usage: nvme_poll_e2e SRC_BLOCK SRC_NG DST_BLOCK DST_NG SPARE_BLOCK SPARE_NG BPF_DIR main|reset
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "linux/io_uring.h"
#include "linux/xdev_ext_mech.h"

#define LBA 512U
#define FRAME 4096U
#define GUARD 0x6b
#define WAIT_MS 120000
#define POLL XDEV_EXT_MECH_STAGE_F_POLL

static unsigned int checks;
#define CHECK(c, msg) do { if (!(c)) { \
	fprintf(stderr, "not ok %u - %s (errno=%d %s)\n", ++checks, msg, errno, strerror(errno)); \
	printf("not ok %u - %s\n", checks, msg); exit(1); } printf("ok %u - %s\n", ++checks, msg); } while (0)

struct plan {
	const char *name;
	__u32 group, depth;
	__u64 groups, src_slba, dst_slba, window_nlb;
};
/* Disjoint destination ranges; the STOP case's range holds no oracle data. */
static const struct plan POLLED = { "polled-copy", 4096, 8, 256, 2048, 4096, 2048 };
static const struct plan PLAIN = { "plain-copy", 4096, 8, 256, 2048, 8192, 2048 };
static const struct plan STOP = { "polled-stop", 65536, 64, 100000, 16384, 16384, 8192 };
static const struct plan LOST = { "lost-queues", 4096, 1, 4, 0, 0, 256 };

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

static void read_all(int fd, void *buf, size_t n, off_t off)
{
	CHECK(pread(fd, buf, n, off) == (ssize_t)n, "complete pread");
}

/* Sum of the I/O-queue interrupt counts (nvmeNq1..) of controller @ctrl. */
static unsigned long long io_irqs(const char *ctrl)
{
	char line[4096], want[32];
	unsigned long long sum = 0;
	FILE *f = fopen("/proc/interrupts", "r");

	CHECK(f, "read /proc/interrupts");
	snprintf(want, sizeof(want), "%sq", ctrl);
	while (fgets(line, sizeof(line), f)) {
		char *name = strrchr(line, ' '), *p;
		size_t n;

		if (!name)
			continue;
		name++;
		n = strcspn(name, "\n");
		name[n] = 0;
		if (strncmp(name, want, strlen(want)) || !strcmp(name + strlen(want), "0"))
			continue;
		p = strchr(line, ':');
		if (!p)
			continue;
		for (p++;;) {
			char *end;
			unsigned long long v;

			while (*p == ' ')
				p++;
			if (!isdigit((unsigned char)*p))
				break;
			v = strtoull(p, &end, 10);
			if (*end != ' ' && *end != '\n')
				break;
			sum += v;
			p = end;
		}
	}
	fclose(f);
	return sum;
}

static bool sysfs_text(const char *path, char *out, size_t n)
{
	FILE *f = fopen(path, "r");
	bool ok = f && fgets(out, (int)n, f);

	if (f)
		fclose(f);
	if (ok)
		out[strcspn(out, "\n")] = 0;
	return ok;
}

static int io_poll(const char *block)
{
	char path[256], text[16];

	snprintf(path, sizeof(path), "/sys/block/%s/queue/io_poll", block);
	return sysfs_text(path, text, sizeof(text)) ? atoi(text) : -1;
}

static void write_text(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);

	CHECK(fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text), path);
	close(fd);
}

struct ops_link { struct bpf_object *object; struct bpf_link *link; };
static void attach_nvme_ops(const char *directory, struct ops_link *o)
{
	char path[PATH_MAX];
	struct bpf_map *map;

	CHECK(snprintf(path, sizeof(path), "%s/nvme_s0.bpf.o", directory) < (int)sizeof(path), "BPF path");
	o->object = bpf_object__open_file(path, NULL);
	CHECK(!libbpf_get_error(o->object), "open nvme_s0 BPF object");
	CHECK(!bpf_object__load(o->object), "load nvme_s0 BPF object");
	o->link = NULL;
	bpf_object__for_each_map(map, o->object) {
		if (bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS)
			continue;
		o->link = bpf_map__attach_struct_ops(map);
		break;
	}
	CHECK(o->link && !libbpf_get_error(o->link), "attach nvme_s0 struct_ops");
}

struct session {
	int ring, notify;
	void *pool;
	size_t pool_bytes;
	__u32 frames[1024];
	struct xdev_ext_mech_create c;
};

/* A NVMe READ (and, when @dst_ng >= 0, NVMe WRITE) session; @flags on every stage. */
static int create(struct session *s, const struct plan *p, int src_ng, int dst_ng, __u32 flags)
{
	struct io_uring_params params = {};
	__u32 per = p->group / FRAME, i;
	struct io_uring_xdev_ext_umem_reg reg = { .frame_size = FRAME };

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
	for (i = 0; i < p->depth * per; i++)
		s->frames[i] = i;
	s->notify = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	CHECK(s->notify >= 0, "session eventfd");
	s->c = (struct xdev_ext_mech_create){
		.abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = dst_ng >= 0 ? 2 : 1,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .pool_fd = -1,
		.layout = { FRAME, 0, FRAME, p->group }, .depth = p->depth, .eventfd = s->notify,
	};
	s->c.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = src_ng, .flags = flags,
		.arg0 = p->src_slba, .arg1 = p->window_nlb };
	if (dst_ng >= 0)
		s->c.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = dst_ng, .flags = flags,
			.arg0 = p->dst_slba, .arg1 = p->window_nlb };
	return mech(s->ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&s->c);
}

static void start(struct session *s, const struct plan *p, bool arm)
{
	struct xdev_ext_mech_notify_arm a = { .session_id = s->c.session_id, .batches_target = p->groups };
	struct xdev_ext_mech_start st = { .session_id = s->c.session_id, .nr_batches = p->groups,
		.flags = XDEV_EXT_MECH_START_F_USER_FRAMES | XDEV_EXT_MECH_START_F_RECYCLE,
		.nr_user_frames = p->depth * (p->group / FRAME), .user_frames = (uintptr_t)s->frames };

	if (arm)
		CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&a), "NOTIFY_ARM once for the run");
	CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&st), "exactly one START");
}

static struct xdev_ext_mech_stats stats(struct session *s)
{
	struct xdev_ext_mech_stats st = { .session_id = s->c.session_id };

	CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&st), "session STATS");
	return st;
}

/* Polling loops: no TAP line per read; a failed read is still fatal. */
static struct xdev_ext_mech_stats stats_quiet(struct session *s)
{
	struct xdev_ext_mech_stats st = { .session_id = s->c.session_id };

	if (mech(s->ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&st))
		CHECK(0, "session STATS while waiting");
	return st;
}

static void print_stats(const char *name, const struct xdev_ext_mech_stats *st)
{
	printf("# %s stats: done=%llu abort=%llu rejects=%llu inflight=%llu sequestered=%llu timeouts=%llu submitted=%llu/%llu completed=%llu/%llu last_err=%d state=%u\n",
	       name, (unsigned long long)st->batches_done, (unsigned long long)st->batches_abort,
	       (unsigned long long)st->rejects, (unsigned long long)st->inflight,
	       (unsigned long long)st->sequestered, (unsigned long long)st->timeouts,
	       (unsigned long long)st->submitted[0], (unsigned long long)st->submitted[1],
	       (unsigned long long)st->completed[0], (unsigned long long)st->completed[1],
	       st->last_err, st->state);
}

static struct xdev_ext_mech_stats wait_terminal(struct session *s, const struct plan *p)
{
	struct pollfd w = { .fd = s->notify, .events = POLLIN };
	struct xdev_ext_mech_stats st;
	int ret;

	do {
		ret = poll(&w, 1, WAIT_MS);
	} while (ret < 0 && errno == EINTR);
	CHECK(ret == 1, "terminal eventfd notification without user continuation");
	st = stats(s);
	print_stats(p->name, &st);
	return st;
}

static void finish(struct session *s, int expect)
{
	CHECK(mech(s->ring, XDEV_EXT_MECH_OP_STOP, s->c.session_id) == expect,
	      "STOP releases the session and returns its last error");
	CHECK(!close(s->ring) && !close(s->notify), "close ring and eventfd");
	munmap(s->pool, s->pool_bytes);
}

static void exact_copy(const struct plan *p, const struct xdev_ext_mech_stats *st)
{
	CHECK(st->batches_done == p->groups && !st->batches_abort && !st->rejects && !st->inflight &&
	      !st->sequestered && !st->timeouts && !st->last_err, "every batch done, none aborted or stuck");
	CHECK(st->submitted[0] == p->groups && st->completed[0] == p->groups &&
	      st->submitted[1] == p->groups && st->completed[1] == p->groups,
	      "one native NVMe READ and one native NVMe WRITE per batch");
}

static const char *base(const char *path)
{
	const char *b = strrchr(path, '/');

	return b ? b + 1 : path;
}

int main(int argc, char **argv)
{
	char src_ctrl[16], dst_ctrl[16], spare_ctrl[32], path[256], text[32];
	unsigned long long before_src, before_dst, after_src, after_dst;
	unsigned char *source, *source_after, *dest, *dest_after;
	__u64 source_bytes, dest_bytes;
	struct xdev_ext_mech_stats st;
	struct ops_link ops = {};
	struct session s, t;
	struct rlimit lim = { RLIM_INFINITY, RLIM_INFINITY };
	int src, srcng, dst, dstng, spare, spareng, i, ret;
	bool reset;
	__u64 off;

	setbuf(stdout, NULL);
	setrlimit(RLIMIT_MEMLOCK, &lim);
	puts("TAP version 13\n# guest NVMe stage polling: QEMU NVMe PCI, nvme.poll_queues=2, correctness only, no timing");
	if (argc != 9 || (strcmp(argv[8], "main") && strcmp(argv[8], "reset"))) {
		fprintf(stderr, "usage: %s SRC_BLOCK SRC_NG DST_BLOCK DST_NG SPARE_BLOCK SPARE_NG BPF_DIR main|reset\n", argv[0]);
		return 2;
	}
	reset = !strcmp(argv[8], "reset");
	CHECK(getenv("XDEV_EXT_POLL_GUEST") && !strcmp(getenv("XDEV_EXT_POLL_GUEST"), "1"), "guest-only opt-in");
	snprintf(src_ctrl, sizeof(src_ctrl), "%.*s", (int)(strchr(base(argv[1]) + 4, 'n') - base(argv[1])), base(argv[1]));
	snprintf(dst_ctrl, sizeof(dst_ctrl), "%.*s", (int)(strchr(base(argv[3]) + 4, 'n') - base(argv[3])), base(argv[3]));
	snprintf(spare_ctrl, sizeof(spare_ctrl), "%.*s", (int)(strchr(base(argv[5]) + 4, 'n') - base(argv[5])), base(argv[5]));
	printf("# controllers source=%s destination=%s spare=%s\n", src_ctrl, dst_ctrl, spare_ctrl);
	CHECK(io_poll(base(argv[1])) == 1 && io_poll(base(argv[3])) == 1 && io_poll(base(argv[5])) == 1,
	      "every namespace starts with poll queues (io_poll=1)");
	if (reset) {
		spareng = open_ok(argv[6], O_RDONLY);
		attach_nvme_ops(argv[7], &ops);
		goto reset_cases;
	}
	src = open_ok(argv[1], O_RDONLY); srcng = open_ok(argv[2], O_RDONLY);
	dst = open_ok(argv[3], O_RDWR); dstng = open_ok(argv[4], O_RDWR);
	spare = open_ok(argv[5], O_RDONLY); spareng = open_ok(argv[6], O_RDONLY);
	CHECK(!ioctl(src, BLKGETSIZE64, &source_bytes) && !ioctl(dst, BLKGETSIZE64, &dest_bytes), "disk capacities");
	CHECK(source_bytes <= 64U << 20 && dest_bytes <= 64U << 20 && dest_bytes >= (STOP.dst_slba + STOP.window_nlb) * LBA,
	      "bounded whole-disk comparison");
	source = malloc(source_bytes); source_after = malloc(source_bytes);
	dest = malloc(dest_bytes); dest_after = malloc(dest_bytes);
	CHECK(source && source_after && dest && dest_after, "verification buffers");
	read_all(src, source, source_bytes, 0);
	for (off = 1; off < source_bytes && source[off] == source[0]; off++)
		;
	CHECK(off < source_bytes, "source disk holds a nonuniform pattern");
	memset(dest, GUARD, dest_bytes);
	CHECK(pwrite(dst, dest, dest_bytes, 0) == (ssize_t)dest_bytes && !fsync(dst), "initialize destination guards");
	CHECK(!ioctl(dst, BLKFLSBUF), "drop destination block cache");
	attach_nvme_ops(argv[7], &ops);

	/* polled-copy: completions without any I/O-queue interrupt. */
	ret = create(&s, &POLLED, srcng, dstng, POLL);
	CHECK(!ret, "polled-copy: CREATE with POLL on NVMe READ and WRITE");
	before_src = io_irqs(src_ctrl);
	before_dst = io_irqs(dst_ctrl);
	start(&s, &POLLED, true);
	st = wait_terminal(&s, &POLLED);
	after_src = io_irqs(src_ctrl);
	after_dst = io_irqs(dst_ctrl);
	printf("# polled-copy io_irq_delta source=%llu destination=%llu\n", after_src - before_src, after_dst - before_dst);
	exact_copy(&POLLED, &st);
	CHECK(after_src == before_src && after_dst == before_dst,
	      "polled-copy: no I/O-queue interrupt on either controller (completions were polled)");
	finish(&s, 0);

	/* plain-copy: the same chain on interrupts; the oracle sees them. */
	ret = create(&s, &PLAIN, srcng, dstng, 0);
	CHECK(!ret, "plain-copy: CREATE without POLL");
	before_src = io_irqs(src_ctrl);
	before_dst = io_irqs(dst_ctrl);
	start(&s, &PLAIN, true);
	st = wait_terminal(&s, &PLAIN);
	after_src = io_irqs(src_ctrl);
	after_dst = io_irqs(dst_ctrl);
	printf("# plain-copy io_irq_delta source=%llu destination=%llu\n", after_src - before_src, after_dst - before_dst);
	exact_copy(&PLAIN, &st);
	CHECK(after_src > before_src && after_dst > before_dst,
	      "plain-copy: interrupt completions are visible to the same oracle");
	finish(&s, 0);

	/* polled-stop: STOP with accepted polled commands outstanding. */
	ret = create(&s, &STOP, srcng, dstng, POLL);
	CHECK(!ret, "polled-stop: CREATE with POLL, depth 64");
	start(&s, &STOP, false);
	for (i = 0; i < 200000; i++) {
		st = stats_quiet(&s);
		if (st.inflight >= 8 && st.submitted[0] > STOP.depth)
			break;
	}
	print_stats("polled-stop before STOP", &st);
	CHECK(st.inflight >= 8 && !st.last_err, "polled-stop: polled batches in flight at STOP");
	CHECK(mech(s.ring, XDEV_EXT_MECH_OP_STOP, s.c.session_id) == 0,
	      "polled-stop: STOP drains every accepted polled command and releases (not -EBUSY)");
	CHECK(!close(s.ring) && !close(s.notify), "polled-stop: close ring and eventfd");
	munmap(s.pool, s.pool_bytes);
	bpf_link__destroy(ops.link);
	bpf_object__close(ops.object);
	/* Whole destination oracle: both copies, guards everywhere but the STOP range. */
	CHECK(!ioctl(src, BLKFLSBUF) && !ioctl(dst, BLKFLSBUF), "invalidate block caches before readback");
	read_all(src, source_after, source_bytes, 0);
	CHECK(!memcmp(source, source_after, source_bytes), "whole source disk unchanged");
	read_all(dst, dest_after, dest_bytes, 0);
	memcpy(dest + POLLED.dst_slba * LBA, source + POLLED.src_slba * LBA, POLLED.groups * POLLED.group);
	memcpy(dest + PLAIN.dst_slba * LBA, source + PLAIN.src_slba * LBA, PLAIN.groups * PLAIN.group);
	memcpy(dest + STOP.dst_slba * LBA, dest_after + STOP.dst_slba * LBA, STOP.window_nlb * LBA);
	CHECK(!memcmp(dest, dest_after, dest_bytes),
	      "destination equals both copies and every guard byte outside the STOP window");
	close(src); close(srcng); close(dst); close(dstng); close(spare); close(spareng);
	free(source); free(source_after); free(dest); free(dest_after);
	printf("1..%u\n", checks);
	printf("XDEV_EXT_NVME_POLL=PASS cases=polled-copy,plain-copy,polled-stop timing=none\n");
	return 0;

reset_cases:
	/* lost-queues: CREATE while the spare controller can poll, then reset it to none. */
	ret = create(&t, &LOST, spareng, -1, POLL);
	CHECK(!ret, "lost-queues: CREATE with POLL while the controller has poll queues");
	write_text("/sys/module/nvme/parameters/poll_queues", "0");
	snprintf(path, sizeof(path), "/sys/class/nvme/%s/reset_controller", spare_ctrl);
	write_text(path, "1");
	for (i = 0; i < 1000; i++) {
		snprintf(path, sizeof(path), "/sys/class/nvme/%s/state", spare_ctrl);
		if (io_poll(base(argv[5])) == 0 && sysfs_text(path, text, sizeof(text)) && !strcmp(text, "live"))
			break;
		usleep(10000);
	}
	CHECK(io_poll(base(argv[5])) == 0, "lost-queues: reset left the controller without poll queues");
	write_text("/sys/module/nvme/parameters/poll_queues", "2");
	start(&t, &LOST, true);
	st = wait_terminal(&t, &LOST);
	CHECK(!st.batches_done && st.batches_abort >= 1 && st.last_err == -EOPNOTSUPP &&
	      !st.submitted[0] && !st.completed[0] && !st.inflight,
	      "lost-queues: the submit is refused before the device, never on an interrupt queue");
	finish(&t, -EOPNOTSUPP);

	/* refuse: the bit cannot be honoured now; without it the device still works. */
	ret = create(&t, &LOST, spareng, -1, POLL);
	CHECK(ret == -EOPNOTSUPP, "refuse: CREATE with POLL on a namespace without poll queues is EOPNOTSUPP");
	CHECK(!close(t.ring) && !close(t.notify), "refuse: discard refused ring");
	munmap(t.pool, t.pool_bytes);
	ret = create(&t, &LOST, spareng, -1, 0);
	CHECK(!ret, "refuse: the same namespace without POLL");
	start(&t, &LOST, true);
	st = wait_terminal(&t, &LOST);
	CHECK(st.batches_done == LOST.groups && !st.batches_abort && !st.last_err, "refuse: interrupt-driven reads complete");
	finish(&t, 0);
	bpf_link__destroy(ops.link);
	bpf_object__close(ops.object);
	close(spareng);
	printf("1..%u\n", checks);
	printf("XDEV_EXT_NVME_POLL_RESET=PASS cases=lost-queues,refuse timing=none\n");
	return 0;
}
