// SPDX-License-Identifier: GPL-2.0
/* GUEST TEST ONLY: one-START POOL_PEER mechanism sessions (NVMe read ->
 * authoritative device-memory frame pool -> NVMe write) over the guest-only
 * host-RAM provider fixture xdev_ext_peer_sw.  Real QEMU NVMe PCI DMA and
 * the real provider registry; host RAM stands in for device memory, so this
 * is never a VRAM, GPU or performance result.  No timing is measured.
 *
 * Cases, all on one guest boot, each its own session on the same pool kind:
 *   reject-map  provider refuses the DMA map: no completion, no DMA, errno kept
 *   cli         the product controller xdev_ext_peer_chain --allocation-fd,
 *               frame 64 KiB, depth 1 (its fixed geometry)
 *   depth4      4 KiB frames, 2 frames per batch, depth 4 (8 of 16 frames
 *               in flight); a second CREATE on the claimed allocation is EBUSY
 *   fd-release  32 KiB frames, depth 2; ring and allocation fds are closed
 *               without STOP, and every provider pin/map must still drain
 * The plan below is duplicated, not shared, by the host validator.
 */
#define _GNU_SOURCE
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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "linux/io_uring.h"
#include "linux/xdev_ext_peer.h"
#include "linux/xdev_ext_mech.h"
#include "sw_provider_uapi.h"

#define LBA 512U
#define DEST_GUARD 0x6b
#define WAIT_MS 120000

struct plan {
	const char *name;
	uint32_t frame, seg, group, depth;
	uint64_t groups, src_slba, dst_slba;
	bool copies;
};
/* Sector ranges never overlap on either disk; source != destination offset. */
static const struct plan REJECT = {"reject-map", 4096, 4096, 4096, 1, 4, 2048, 16384, false};
static const struct plan CLI = {"cli", 65536, 16384, 16384, 1, 64, 2048, 4096, true};
static const struct plan DEEP = {"depth4", 4096, 4096, 8192, 4, 96, 8192, 10240, true};
static const struct plan FDREL = {"fd-release", 32768, 32768, 32768, 2, 8, 12288, 14336, true};
static const struct plan *const PLANS[] = {&REJECT, &CLI, &DEEP, &FDREL};

static unsigned int checks;
#define CHECK(c, msg) do { if (!(c)) { \
	fprintf(stderr, "not ok %u - %s (errno=%d %s)\n", ++checks, msg, errno, strerror(errno)); \
	printf("not ok %u - %s\n", checks, msg); exit(1); } printf("ok %u - %s\n", ++checks, msg); } while (0)

static uint64_t nlb(const struct plan *p) { return p->groups * (p->group / LBA); }
static uint64_t bytes(const struct plan *p) { return p->groups * p->group; }

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
static void write_all(int fd, const void *buf, size_t n, off_t off)
{
	CHECK(pwrite(fd, buf, n, off) == (ssize_t)n, "complete pwrite");
}
static struct peer_sw_stats stats(int fd)
{
	struct peer_sw_stats s = {};
	CHECK(!ioctl(fd, PEER_SW_STATS, &s), "provider lifetime counters");
	return s;
}
static void print_stats(const char *when, const struct peer_sw_stats *s)
{
	printf("# provider %s: opens=%llu closes=%llu pins=%llu unpins=%llu maps=%llu unmaps=%llu live_pins=%llu live_maps=%llu\n",
	       when, (unsigned long long)s->opens, (unsigned long long)s->closes,
	       (unsigned long long)s->pins, (unsigned long long)s->unpins,
	       (unsigned long long)s->maps, (unsigned long long)s->unmaps,
	       (unsigned long long)s->live_pins, (unsigned long long)s->live_maps);
}
static int registration(int ctl, int provider, uint64_t *generation)
{
	struct xdev_ext_peer_register r = {
		.gpu_fd = provider, .gpu_va = PEER_SW_VA, .len = PEER_SW_BYTES,
	};
	int fd = ioctl(ctl, XDEV_EXT_PEER_REGISTER, &r);
	CHECK(fd >= 0 && r.generation, "REGISTER returns allocation fd and nonzero generation");
	CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC, "allocation fd is CLOEXEC");
	*generation = r.generation;
	return fd;
}

/* Same struct_ops loading as the product controller xdev_ext_peer_chain. */
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
		if (bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS) continue;
		o->link = bpf_map__attach_struct_ops(map);
		break;
	}
	CHECK(o->link && !libbpf_get_error(o->link), "attach nvme_s0 struct_ops");
}
static void detach_nvme_ops(struct ops_link *o)
{
	bpf_link__destroy(o->link); bpf_object__close(o->object);
	o->link = NULL; o->object = NULL;
}

static int mech(int ring, __u32 op, uint64_t argument)
{
	struct io_uring_xdev_ext_mech req = {.op = op, .arg = argument};
	int ret = syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_MECH, &req, 1);
	return ret < 0 ? -errno : ret;
}
struct session { int ring, notify; struct xdev_ext_mech_create c; };
static int create(struct session *s, const struct plan *p, int pool_fd, int src_ng, int dst_ng)
{
	struct io_uring_params params = {};
	s->c = (struct xdev_ext_mech_create){
		.abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 2,
		.pool_kind = XDEV_EXT_MECH_POOL_PEER, .pool_fd = pool_fd,
		.layout = {p->frame, 0, p->seg, p->group}, .depth = p->depth,
	};
	s->c.st[0] = (struct xdev_ext_mech_stage_uapi){.class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = src_ng, .arg0 = p->src_slba, .arg1 = nlb(p)};
	s->c.st[1] = (struct xdev_ext_mech_stage_uapi){.class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = dst_ng, .arg0 = p->dst_slba, .arg1 = nlb(p)};
	s->notify = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	CHECK(s->notify >= 0, "session eventfd");
	s->c.eventfd = s->notify;
	s->ring = syscall(__NR_io_uring_setup, 8, &params);
	CHECK(s->ring >= 0, "io_uring ring");
	return mech(s->ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&s->c);
}
static struct xdev_ext_mech_stats start_and_wait(struct session *s, const struct plan *p)
{
	struct xdev_ext_mech_notify_arm arm = {.session_id = s->c.session_id, .batches_target = p->groups};
	struct xdev_ext_mech_start start = {.session_id = s->c.session_id, .nr_batches = p->groups};
	struct xdev_ext_mech_stats st = {.session_id = s->c.session_id};
	struct pollfd w = {.fd = s->notify, .events = POLLIN};
	int ret;
	CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm), "NOTIFY_ARM once for the whole run");
	CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&start), "exactly one START for every batch");
	do { ret = poll(&w, 1, WAIT_MS); } while (ret < 0 && errno == EINTR);
	CHECK(ret == 1, "terminal eventfd notification without user continuation");
	CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&st), "session STATS");
	printf("# %s stats: done=%llu abort=%llu rejects=%llu inflight=%llu sequestered=%llu timeouts=%llu submitted=%llu/%llu completed=%llu/%llu last_err=%d state=%u\n",
	       p->name, (unsigned long long)st.batches_done, (unsigned long long)st.batches_abort,
	       (unsigned long long)st.rejects, (unsigned long long)st.inflight,
	       (unsigned long long)st.sequestered, (unsigned long long)st.timeouts,
	       (unsigned long long)st.submitted[0], (unsigned long long)st.submitted[1],
	       (unsigned long long)st.completed[0], (unsigned long long)st.completed[1],
	       st.last_err, st.state);
	return st;
}
static void exact_success(const struct plan *p, const struct xdev_ext_mech_stats *st)
{
	CHECK(st->batches_done == p->groups && !st->batches_abort && !st->rejects &&
	      !st->inflight && !st->sequestered && !st->timeouts && !st->last_err,
	      "every batch done, none aborted, rejected, in flight, sequestered or timed out");
	CHECK(st->submitted[0] == p->groups && st->completed[0] == p->groups &&
	      st->submitted[1] == p->groups && st->completed[1] == p->groups,
	      "one native NVMe read and one native NVMe write per batch");
}
/* STOP releases the session and returns its recorded last error (see
 * xdev_ext_mech_session_release()); 0 only for a run without error. */
static void finish(struct session *s, bool stop, int expect)
{
	if (stop) CHECK(mech(s->ring, XDEV_EXT_MECH_OP_STOP, s->c.session_id) == expect,
			"STOP with full session identity returns the session's last error");
	CHECK(!close(s->ring), "close io_uring ring");
	CHECK(!close(s->notify), "close session eventfd");
}
/* Teardown may finish on the ring's exit work; wait only for the provider's
 * own counters to drain, never for a fixed time.  Not a timing result. */
static struct peer_sw_stats drained(int observer, uint64_t want_pins)
{
	struct peer_sw_stats s;
	unsigned int tries;
	for (tries = 0; tries < 6000; tries++) {
		s = stats(observer);
		if (s.live_pins == want_pins && !s.live_maps) return s;
		usleep(10000);
	}
	print_stats("not drained", &s);
	CHECK(0, "provider pins and maps drained after session teardown");
	return s;
}

static void run_cli(const char *tool, const char *bpf_dir, int alloc,
		    const char *src_ng, const char *dst_ng)
{
	char out[4096], expect[160], fdtext[16], groups[24], len[16], srcslba[24], dstslba[24];
	int pipefd[2], status;
	ssize_t got, n = 0;
	pid_t child;
	CHECK(!pipe2(pipefd, O_CLOEXEC), "controller output pipe");
	child = fork();
	CHECK(child >= 0, "fork product controller");
	if (!child) {
		int fd = fcntl(alloc, F_DUPFD, 100);	/* inherited across exec */
		if (fd < 0 || dup2(pipefd[1], 1) < 0) _exit(126);
		snprintf(fdtext, sizeof(fdtext), "%d", fd);
		snprintf(groups, sizeof(groups), "%llu", (unsigned long long)CLI.groups);
		snprintf(len, sizeof(len), "%u", CLI.group);
		snprintf(srcslba, sizeof(srcslba), "%llu", (unsigned long long)CLI.src_slba);
		snprintf(dstslba, sizeof(dstslba), "%llu", (unsigned long long)CLI.dst_slba);
		execl(tool, tool, "--allocation-fd", fdtext, src_ng, dst_ng, groups, len, "9",
		      srcslba, dstslba, bpf_dir, (char *)NULL);
		_exit(127);
	}
	close(pipefd[1]);
	while (n < (ssize_t)sizeof(out) - 1 && (got = read(pipefd[0], out + n, sizeof(out) - 1 - n)) > 0) n += got;
	out[n] = 0; close(pipefd[0]);
	CHECK(waitpid(child, &status, 0) == child, "reap product controller");
	printf("# controller output: %s", out);
	CHECK(WIFEXITED(status) && !WEXITSTATUS(status), "product controller exits 0");
	snprintf(expect, sizeof(expect), "peer chain: done=%llu abort=0 inflight=0 sequestered=0 status=0\n",
		 (unsigned long long)CLI.groups);
	CHECK(!strcmp(out, expect), "product controller reports exact completion and nothing else");
}

int main(int argc, char **argv)
{
	unsigned char *source, *source_after, *dest, *dest_after;
	uint64_t source_bytes, dest_bytes, gen1, gen2;
	struct peer_sw_stats before, mid, after;
	struct xdev_ext_mech_stats st;
	struct session s, busy;
	struct ops_link ops = {};
	struct stat ss, ds;
	int src, srcng, dst, dstng, ctl, observer, provider1, provider2, alloc1, alloc2, lb, ret;
	unsigned int i;
	setbuf(stdout, NULL);
	puts("TAP version 13\n# guest POOL_PEER session: host RAM/CPU stand-in for device memory, real QEMU NVMe PCI DMA, correctness only");
	if (argc != 7) {
		fprintf(stderr, "usage: %s SOURCE_BLOCK SOURCE_NG DEST_BLOCK DEST_NG BPF_DIR PEER_CHAIN\n", argv[0]);
		return 2;
	}
	CHECK(getenv("XDEV_EXT_PEER_GUEST") && !strcmp(getenv("XDEV_EXT_PEER_GUEST"), "1"), "guest-only opt-in");
	for (i = 0; i < sizeof(PLANS) / sizeof(PLANS[0]); i++)
		printf("PLAN case=%s frame=%u seg=%u group=%u depth=%u groups=%llu src_slba=%llu dst_slba=%llu copies=%d\n",
		       PLANS[i]->name, PLANS[i]->frame, PLANS[i]->seg, PLANS[i]->group, PLANS[i]->depth,
		       (unsigned long long)PLANS[i]->groups, (unsigned long long)PLANS[i]->src_slba,
		       (unsigned long long)PLANS[i]->dst_slba, PLANS[i]->copies);
	observer = open_ok("/dev/xdev_ext_peer_sw", O_RDWR);
	before = stats(observer);
	print_stats("before", &before);
	CHECK(!before.live_pins && !before.live_maps, "isolated provider starts without pins or maps");
	ctl = open_ok("/dev/xdev_ext_peer", O_RDWR);
	src = open_ok(argv[1], O_RDONLY); srcng = open_ok(argv[2], O_RDONLY);
	dst = open_ok(argv[3], O_RDWR); dstng = open_ok(argv[4], O_RDWR);
	CHECK(!fstat(src, &ss) && !fstat(dst, &ds) && S_ISBLK(ss.st_mode) && S_ISBLK(ds.st_mode) &&
	      ss.st_rdev != ds.st_rdev, "distinct source and private destination block devices");
	CHECK(!ioctl(src, BLKGETSIZE64, &source_bytes) && !ioctl(dst, BLKGETSIZE64, &dest_bytes), "disk capacities");
	CHECK(!ioctl(src, BLKSSZGET, &lb) && lb == LBA && !ioctl(dst, BLKSSZGET, &lb) && lb == LBA,
	      "fixture requires 512-byte logical sectors");
	CHECK(source_bytes <= 64U << 20 && dest_bytes <= 64U << 20, "bounded whole-disk comparison");
	for (i = 0; i < sizeof(PLANS) / sizeof(PLANS[0]); i++)
		CHECK((PLANS[i]->src_slba + nlb(PLANS[i])) * LBA <= source_bytes &&
		      (PLANS[i]->dst_slba + nlb(PLANS[i])) * LBA <= dest_bytes &&
		      PLANS[i]->depth * (PLANS[i]->group / PLANS[i]->seg) * PLANS[i]->frame <= PEER_SW_BYTES,
		      "plan fits both disks and the provider allocation");
	source = malloc(source_bytes); source_after = malloc(source_bytes);
	dest = malloc(dest_bytes); dest_after = malloc(dest_bytes);
	CHECK(source && source_after && dest && dest_after, "whole-disk verification buffers");
	read_all(src, source, source_bytes, 0);
	for (i = 1; i < source_bytes && source[i] == source[0]; i++) ;
	CHECK(i < source_bytes, "source disk holds a nonuniform pattern");
	memset(dest, DEST_GUARD, dest_bytes); write_all(dst, dest, dest_bytes, 0);
	CHECK(!fsync(dst), "initialize private destination guards");

	provider1 = open_ok("/dev/xdev_ext_peer_sw", O_RDWR);
	alloc1 = registration(ctl, provider1, &gen1);
	provider2 = open_ok("/dev/xdev_ext_peer_sw", O_RDWR);
	CHECK(!ioctl(provider2, PEER_SW_REJECT_MAP), "configure unsupported mapping on a second allocation");
	alloc2 = registration(ctl, provider2, &gen2);
	CHECK(gen1 != gen2, "allocation generations are distinct");
	attach_nvme_ops(argv[5], &ops);

	/* reject-map: the provider refuses before any DMA mapping exists. */
	CHECK(!create(&s, &REJECT, alloc2, srcng, dstng), "reject-map: CREATE claims the allocation");
	st = start_and_wait(&s, &REJECT);
	CHECK(!st.batches_done && !st.completed[0] && !st.completed[1] && !st.submitted[1],
	      "reject-map: no native command completes and no write is issued");
	CHECK(st.last_err == -EOPNOTSUPP, "reject-map: provider EOPNOTSUPP is reported, no fallback");
	finish(&s, true, -EOPNOTSUPP);
	CHECK(!close(alloc2) && !close(provider2), "reject-map: close allocation and provider fds");
	mid = drained(observer, 1);
	print_stats("after reject-map", &mid);
	CHECK(mid.maps == before.maps && mid.unmaps == before.unmaps, "reject-map: no DMA mapping was ever created");
	detach_nvme_ops(&ops);

	/* cli: the shipped one-registration/one-START controller, inherited fd. */
	run_cli(argv[6], argv[5], alloc1, argv[2], argv[4]);
	mid = stats(observer);
	print_stats("after cli", &mid);
	CHECK(mid.live_pins == 1 && mid.live_maps == 2 && mid.maps - before.maps == 2,
	      "cli: one live allocation, one cached DMA mapping per NVMe PCI function");

	/* depth4: STOP of the controller released the claim; a second claim fails. */
	attach_nvme_ops(argv[5], &ops);
	CHECK(!create(&s, &DEEP, alloc1, srcng, dstng), "depth4: CREATE reclaims the allocation after cli STOP");
	ret = create(&busy, &DEEP, alloc1, srcng, dstng);
	CHECK(ret == -EBUSY, "depth4: a second session cannot claim the same allocation");
	CHECK(!close(busy.ring) && !close(busy.notify), "depth4: discard refused session ring");
	st = start_and_wait(&s, &DEEP);
	exact_success(&DEEP, &st);
	finish(&s, true, 0);
	mid = stats(observer);
	print_stats("after depth4", &mid);
	CHECK(mid.live_pins == 1 && mid.live_maps == 2 && mid.maps - before.maps == 2,
	      "depth4: mappings stay cached per PCI function, never remapped per batch");

	/* fd-release: no STOP; closing every fd must still drain everything. */
	CHECK(!create(&s, &FDREL, alloc1, srcng, dstng), "fd-release: CREATE reclaims the allocation after STOP");
	st = start_and_wait(&s, &FDREL);
	exact_success(&FDREL, &st);
	finish(&s, false, 0);
	CHECK(!close(alloc1) && !close(provider1), "fd-release: close last allocation and provider fds");
	detach_nvme_ops(&ops);
	after = drained(observer, 0);
	print_stats("after", &after);
	CHECK(after.maps - before.maps == after.unmaps - before.unmaps &&
	      after.pins - before.pins == after.unpins - before.unpins && after.pins - before.pins == 2,
	      "every successful pin and map released exactly once");
	CHECK(after.opens - before.opens == after.closes - before.closes, "provider file refs released");

	/* Whole-disk data oracle, independent of session statistics. */
	for (i = 0; i < sizeof(PLANS) / sizeof(PLANS[0]); i++)
		if (PLANS[i]->copies)
			memcpy(dest + PLANS[i]->dst_slba * LBA, source + PLANS[i]->src_slba * LBA, bytes(PLANS[i]));
	CHECK(!ioctl(src, BLKFLSBUF) && !ioctl(dst, BLKFLSBUF), "invalidate block cache before readback");
	read_all(src, source_after, source_bytes, 0); read_all(dst, dest_after, dest_bytes, 0);
	CHECK(!memcmp(source, source_after, source_bytes), "whole source disk unchanged");
	CHECK(!memcmp(dest, dest_after, dest_bytes), "whole destination disk equals copies plus every guard byte");
	close(observer); close(ctl); close(src); close(srcng); close(dst); close(dstng);
	free(source); free(source_after); free(dest); free(dest_after);
	printf("1..%u\n", checks);
	printf("XDEV_EXT_PEER_SESSION=PASS cases=reject-map,cli,depth4,fd-release batches=%llu pool=POOL_PEER stages=nvme-read,nvme-write memory=host-RAM-standin gpu=none net=none timing=none\n",
	       (unsigned long long)(CLI.groups + DEEP.groups + FDREL.groups));
	return 0;
}
