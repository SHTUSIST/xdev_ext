// SPDX-License-Identifier: GPL-2.0
/* GUEST TEST ONLY: QEMU NVMe PCI DMA into and out of a system-heap dma-buf
 * imported through /dev/xdev_ext_peer (XDEV_EXT_PEER_REGISTER_F_DMABUF).
 * The exporter is the kernel's own system heap; no provider fixture, no
 * device stand-in and no GPU is involved. Correctness only, no timing.
 *
 * Cases, one guest boot, two NVMe controllers (source, private destination):
 *   batch-read     16 x 4 KiB NVMe READ (XDEV_EXT_PEER_NVME_BATCH) into the
 *                  dma-buf, pages in reverse LBA order; the CPU view of the
 *                  dma-buf (mmap + DMA_BUF_IOCTL_SYNC) is hashed for the host
 *   batch-write    CPU fills the dma-buf; 16 x 4 KiB NVMe WRITE from it
 *   chain          POOL_PEER session on a second dma-buf: NVMe read ->
 *                  NVMe write, one START, all groups exact
 *   exporter-close POOL_PEER session; the dma-buf fd handed out by the
 *                  exporter is closed while native commands are in flight;
 *                  every group must still complete exactly (the importer
 *                  holds its own buffer reference until its last fd closes)
 *   kill           a child imports and runs a session, and is SIGKILLed with
 *                  native commands in flight; the session is released, its
 *                  MEMLOCK charge is returned and the buffer is freed; each
 *                  destination group is its source group or untouched guard
 * Accounting: VmPin rises by exactly the export while registered and returns
 * after the last allocation fd closes; dma-buf debugfs lists both NVMe PCI
 * functions as attached while registered and drops the buffer after close.
 * The plan below is duplicated, not shared, by the host validator.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/fs.h>
#include <poll.h>
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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "linux/io_uring.h"
#include "linux/xdev_ext_peer.h"
#include "linux/xdev_ext_mech.h"

#define LBA 512U
#define PAGE 4096U
#define EXPORT 65536U
#define PAGES (EXPORT / PAGE)
#define IMAGE (32U << 20)
#define DEST_GUARD 0x6b
#define WAIT_MS 240000
#define BATCH_READ_SLBA 2048ULL
#define BATCH_WRITE_SLBA 2048ULL
#define BUFINFO "/sys/kernel/debug/dma_buf/bufinfo"

struct plan {
	const char *name;
	uint32_t frame, seg, group, depth;
	uint64_t groups, src_slba, dst_slba;
	const char *copies;
};
static const struct plan CHAIN = {"chain", 4096, 4096, 8192, 4, 96, 4096, 4096, "ALL"};
static const struct plan CLOSE = {"exporter-close", 4096, 4096, 8192, 4, 1024, 8192, 8192, "ALL"};
static const struct plan KILL = {"kill", 4096, 4096, 8192, 4, 512, 32768, 32768, "PART"};

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
static uint64_t vmpin(void)
{
	FILE *f = fopen("/proc/self/status", "re");
	char line[256];
	unsigned long long kb = ULLONG_MAX;
	CHECK(f, "open /proc/self/status");
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "VmPin: %llu kB", &kb) == 1) break;
	fclose(f);
	CHECK(kb != ULLONG_MAX, "VmPin is reported");
	return kb * 1024;
}
static uint64_t fnv64(const unsigned char *p, size_t n)
{
	uint64_t h = 0xcbf29ce484222325ULL;
	while (n--) { h ^= *p++; h *= 0x100000001b3ULL; }
	return h;
}
static int heap_alloc(int heap, unsigned long *ino)
{
	struct dma_heap_allocation_data a = {.len = EXPORT, .fd_flags = O_RDWR | O_CLOEXEC};
	struct stat st;
	CHECK(!ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &a), "system heap allocates one 64 KiB dma-buf");
	CHECK(!fstat((int)a.fd, &st), "dma-buf inode");
	*ino = st.st_ino;
	return (int)a.fd;
}
/* No TAP output: also used by the forked importer process. */
static int raw_heap_alloc(int heap, unsigned long *ino)
{
	struct dma_heap_allocation_data a = {.len = EXPORT, .fd_flags = O_RDWR | O_CLOEXEC};
	struct stat st;
	if (ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &a) || fstat((int)a.fd, &st)) return -errno;
	*ino = st.st_ino;
	return (int)a.fd;
}
static void cpu_access(int buf, unsigned char *data, bool write)
{
	struct dma_buf_sync sync = {.flags = DMA_BUF_SYNC_START | (write ? DMA_BUF_SYNC_WRITE : DMA_BUF_SYNC_READ)};
	unsigned char *map = mmap(NULL, EXPORT, PROT_READ | PROT_WRITE, MAP_SHARED, buf, 0);
	CHECK(map != MAP_FAILED, "CPU mapping of the dma-buf");
	CHECK(!ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync), "DMA_BUF_IOCTL_SYNC start");
	if (write) memcpy(map, data, EXPORT); else memcpy(data, map, EXPORT);
	sync.flags = DMA_BUF_SYNC_END | (write ? DMA_BUF_SYNC_WRITE : DMA_BUF_SYNC_READ);
	CHECK(!ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync), "DMA_BUF_IOCTL_SYNC end");
	CHECK(!munmap(map, EXPORT), "drop CPU mapping before device work");
}
static int reg(int ctl, int buf, uint64_t *generation)
{
	struct xdev_ext_peer_register r = {.gpu_fd = buf, .flags = XDEV_EXT_PEER_REGISTER_F_DMABUF, .len = EXPORT};
	int fd = ioctl(ctl, XDEV_EXT_PEER_REGISTER, &r);
	if (fd < 0) return -errno;
	*generation = r.generation;
	return fd;
}
static int register_ok(int ctl, int buf, uint64_t *generation, const char *name)
{
	int fd = reg(ctl, buf, generation);
	errno = fd < 0 ? -fd : 0;
	CHECK(fd >= 0 && *generation, name);
	CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC, "allocation fd is CLOEXEC");
	return fd;
}
/* Attached device names of the buffer with inode ino; returns false if absent. */
static bool bufinfo(unsigned long ino, char *attached, size_t size)
{
	static char text[1 << 16];
	char key[32], *line, *save = NULL, *field, *fsave;
	bool found = false, in_attached = false;
	ssize_t n, got = 0;
	int fd = open(BUFINFO, O_RDONLY | O_CLOEXEC);
	CHECK(fd >= 0, "open dma-buf debugfs bufinfo");
	while (got < (ssize_t)sizeof(text) - 1 && (n = read(fd, text + got, sizeof(text) - 1 - got)) > 0) got += n;
	CHECK(n >= 0 && got < (ssize_t)sizeof(text) - 1, "read complete bufinfo");
	close(fd);
	text[got] = 0;
	attached[0] = 0;
	snprintf(key, sizeof(key), "%08lu", ino);
	for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (!found) {
			/* size, flags, mode, count, exp_name, ino, name: match the ino field only. */
			unsigned int column = 0;
			char copy[512];
			if (line[0] == '\t') continue;
			snprintf(copy, sizeof(copy), "%s", line);
			for (field = strtok_r(copy, "\t", &fsave); field; field = strtok_r(NULL, "\t", &fsave))
				if (column++ == 5) { found = !strcmp(field, key); break; }
			continue;
		}
		if (!strcmp(line, "\tAttached Devices:")) { in_attached = true; continue; }
		if (!strncmp(line, "Total ", 6)) break;
		if (in_attached && line[0] == '\t') {
			if (attached[0]) strncat(attached, ",", size - strlen(attached) - 1);
			strncat(attached, line + 1, size - strlen(attached) - 1);
		}
	}
	return found;
}
static void expect_absent(const char *name, unsigned long ino, const char *key)
{
	char attached[256];
	unsigned int tries;
	bool present = true;
	/* Release can finish on deferred work; wait only for the buffer itself. */
	for (tries = 0; tries < 6000 && (present = bufinfo(ino, attached, sizeof(attached))); tries++)
		usleep(10000);
	printf("OBSERVE case=%s %s=%s\n", name, key, present ? "present" : "absent");
	CHECK(!present, "dma-buf freed after its last reference closed");
}

static int nvme_batch(int ng, int alloc, uint64_t generation, bool write, uint64_t slba0, bool reverse)
{
	struct xdev_ext_peer_nvme_batch b = {.allocation_fd = alloc, .generation = generation,
		.flags = write ? XDEV_EXT_PEER_NVME_F_WRITE : 0, .nr = PAGES};
	unsigned int i;
	for (i = 0; i < PAGES; i++)
		b.desc[i] = (struct xdev_ext_peer_nvme_desc){.offset = (uint64_t)i * PAGE,
			.slba = slba0 + (uint64_t)(reverse ? PAGES - 1 - i : i) * (PAGE / LBA), .bytes = PAGE};
	if (ioctl(ng, XDEV_EXT_PEER_NVME_BATCH, &b)) return -errno;
	return b.completed == PAGES && !b.status ? 0 : -EIO;
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
		if (bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS) continue;
		o->link = bpf_map__attach_struct_ops(map);
		break;
	}
	CHECK(o->link && !libbpf_get_error(o->link), "attach nvme_s0 struct_ops");
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
	s->c.eventfd = s->notify;
	s->ring = syscall(__NR_io_uring_setup, 8, &params);
	if (s->notify < 0 || s->ring < 0) return -errno;
	return mech(s->ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&s->c);
}
static int session_stats(int ring, uint64_t id, struct xdev_ext_mech_stats *st)
{
	*st = (struct xdev_ext_mech_stats){.session_id = id};
	return mech(ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)st);
}
static void print_run(const char *name, const char *when, const struct xdev_ext_mech_stats *st)
{
	printf("# %s %s: done=%llu abort=%llu rejects=%llu inflight=%llu sequestered=%llu timeouts=%llu "
	       "submitted=%llu/%llu completed=%llu/%llu last_err=%d state=%u\n",
	       name, when, (unsigned long long)st->batches_done, (unsigned long long)st->batches_abort,
	       (unsigned long long)st->rejects, (unsigned long long)st->inflight,
	       (unsigned long long)st->sequestered, (unsigned long long)st->timeouts,
	       (unsigned long long)st->submitted[0], (unsigned long long)st->submitted[1],
	       (unsigned long long)st->completed[0], (unsigned long long)st->completed[1],
	       st->last_err, st->state);
}
static void arm_and_start(struct session *s, const struct plan *p)
{
	struct xdev_ext_mech_notify_arm arm = {.session_id = s->c.session_id, .batches_target = p->groups};
	struct xdev_ext_mech_start start = {.session_id = s->c.session_id, .nr_batches = p->groups};
	CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm), "NOTIFY_ARM once for the whole run");
	CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&start), "exactly one START for every batch");
}
static struct xdev_ext_mech_stats wait_done(struct session *s, const struct plan *p)
{
	struct pollfd w = {.fd = s->notify, .events = POLLIN};
	struct xdev_ext_mech_stats st;
	int ret;
	do { ret = poll(&w, 1, WAIT_MS); } while (ret < 0 && errno == EINTR);
	CHECK(ret == 1, "terminal eventfd notification without user continuation");
	CHECK(!session_stats(s->ring, s->c.session_id, &st), "session STATS");
	print_run(p->name, "end", &st);
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
/* START only queues work: observe native commands submitted but incomplete.
 * Sampling and the following action are not atomic; see the README. */
static int wait_native_inflight(int ring, uint64_t id, const struct plan *p, struct xdev_ext_mech_stats *st)
{
	unsigned int tries;
	int ret;
	for (tries = 0; tries < 6000; tries++) {
		ret = session_stats(ring, id, st);
		if (ret) return ret;
		if (st->state != XDEV_EXT_MECH_SESSION_ACTIVE || st->last_err || st->sequestered ||
		    st->batches_done >= p->groups)
			return -ENODATA;
		if (st->inflight && st->inflight <= p->depth &&
		    (st->submitted[0] > st->completed[0] || st->submitted[1] > st->completed[1]))
			return 0;
		usleep(1000);
	}
	return -ETIMEDOUT;
}
static void stage_caps(struct session *s, const struct plan *p)
{
	unsigned int i;
	for (i = 0; i < 2; i++) {
		struct xdev_ext_mech_stage_caps c = {.size = sizeof(c), .version = XDEV_EXT_MECH_STAGE_CAPS_VERSION,
			.session_id = s->c.session_id, .stage = i};
		CHECK(!mech(s->ring, XDEV_EXT_MECH_OP_STAGE_CAPS, (uintptr_t)&c), "STAGE_CAPS for a dma-buf pool stage");
		printf("OBSERVE case=%s stage=%u family=%u reachability=%u requester_mapping=%u backing=0x%x refused=0x%x\n",
		       p->name, i, c.family, c.reachability, c.requester_mapping, c.backing, c.refused);
		CHECK(c.family == XDEV_EXT_FAMILY_STORAGE && c.reachability == XDEV_EXT_CAP_HOST_DMA_MAPPED &&
		      c.requester_mapping == XDEV_EXT_CAP_ESTABLISHED && !c.refused &&
		      c.backing == (XDEV_EXT_PEER_BACKING_HOST_SYSTEM | XDEV_EXT_PEER_BACKING_STRUCT_PAGE),
		      "NVMe requester admitted host-system dma-buf memory and mapped it at CREATE");
	}
}
static void finish(struct session *s, int expect)
{
	CHECK(mech(s->ring, XDEV_EXT_MECH_OP_STOP, s->c.session_id) == expect,
	      "STOP with full session identity returns the session's last error");
	CHECK(!close(s->ring) && !close(s->notify), "close io_uring ring and session eventfd");
}
static void attached_both(const char *name, unsigned long ino, const char *nvme_a, const char *nvme_b)
{
	char attached[256], want1[64], want2[64];
	CHECK(bufinfo(ino, attached, sizeof(attached)), "registered dma-buf is listed in bufinfo");
	printf("OBSERVE case=%s bufinfo attached=%s\n", name, attached);
	snprintf(want1, sizeof(want1), "%s,%s", nvme_a, nvme_b);
	snprintf(want2, sizeof(want2), "%s,%s", nvme_b, nvme_a);
	CHECK(!strcmp(attached, want1) || !strcmp(attached, want2),
	      "importer attached the dma-buf to exactly the two NVMe requesters");
}

int main(int argc, char **argv)
{
	static unsigned char view[EXPORT], pattern[EXPORT];
	unsigned char *source, *source_after, *dest, *dest_after;
	struct xdev_ext_mech_stats st;
	struct ops_link ops = {};
	struct session s;
	struct stat ss, ds;
	struct rlimit original, quota;
	unsigned long ino;
	uint64_t gen, base, value;
	int heap, ctl, src, srcng, dst, dstng, buf, alloc, ret, lb;
	uint64_t source_bytes, dest_bytes, kill_copied = 0, g;
	unsigned int i;

	setbuf(stdout, NULL);
	puts("TAP version 13\n# guest dma-buf device DMA: system heap exporter, xdev_ext_peer importer, QEMU NVMe PCI DMA, correctness only");
	if (argc != 8) {
		fprintf(stderr, "usage: %s SOURCE_BLOCK SOURCE_NG DEST_BLOCK DEST_NG SOURCE_PCI DEST_PCI BPF_DIR\n", argv[0]);
		return 2;
	}
	CHECK(getenv("XDEV_EXT_DMABUF_GUEST") && !strcmp(getenv("XDEV_EXT_DMABUF_GUEST"), "1"), "guest-only opt-in");
	printf("PLAN case=batch-read src_slba=%llu pages=%u order=reverse\n", BATCH_READ_SLBA, PAGES);
	printf("PLAN case=batch-write dst_slba=%llu pages=%u pattern=xor5a\n", BATCH_WRITE_SLBA, PAGES);
	for (i = 0; i < 3; i++) {
		const struct plan *p = i == 0 ? &CHAIN : i == 1 ? &CLOSE : &KILL;
		printf("PLAN case=%s frame=%u seg=%u group=%u depth=%u groups=%llu src_slba=%llu dst_slba=%llu copies=%s\n",
		       p->name, p->frame, p->seg, p->group, p->depth, (unsigned long long)p->groups,
		       (unsigned long long)p->src_slba, (unsigned long long)p->dst_slba, p->copies);
	}
	heap = open_ok("/dev/dma_heap/system", O_RDONLY);
	ctl = open_ok("/dev/xdev_ext_peer", O_RDWR);
	src = open_ok(argv[1], O_RDONLY); srcng = open_ok(argv[2], O_RDONLY);
	dst = open_ok(argv[3], O_RDWR); dstng = open_ok(argv[4], O_RDWR);
	CHECK(!fstat(src, &ss) && !fstat(dst, &ds) && S_ISBLK(ss.st_mode) && S_ISBLK(ds.st_mode) &&
	      ss.st_rdev != ds.st_rdev, "distinct source and private destination block devices");
	CHECK(!ioctl(src, BLKGETSIZE64, &source_bytes) && !ioctl(dst, BLKGETSIZE64, &dest_bytes) &&
	      source_bytes == IMAGE && dest_bytes == IMAGE, "both disks have the planned 32 MiB capacity");
	CHECK(!ioctl(src, BLKSSZGET, &lb) && lb == LBA && !ioctl(dst, BLKSSZGET, &lb) && lb == LBA,
	      "512-byte logical sectors");
	source = malloc(IMAGE); source_after = malloc(IMAGE); dest = malloc(IMAGE); dest_after = malloc(IMAGE);
	CHECK(source && source_after && dest && dest_after, "whole-disk verification buffers");
	read_all(src, source, IMAGE, 0);
	for (i = 1; i < IMAGE && source[i] == source[0]; i++) ;
	CHECK(i < IMAGE, "source disk holds a nonuniform pattern");
	memset(dest, DEST_GUARD, IMAGE); write_all(dst, dest, IMAGE, 0);
	CHECK(!fsync(dst), "initialize private destination guards");
	CHECK(!ioctl(dst, BLKFLSBUF), "drop destination block cache before device writes");

	/* batch-read / batch-write: one registration, both NVMe requesters. */
	base = vmpin();
	buf = heap_alloc(heap, &ino);
	memset(pattern, 0xa5, EXPORT);
	cpu_access(buf, pattern, true);
	alloc = register_ok(ctl, buf, &gen, "REGISTER imports the whole system-heap dma-buf");
	value = vmpin();
	ret = nvme_batch(srcng, alloc, gen, false, BATCH_READ_SLBA, true);
	errno = ret < 0 ? -ret : 0;
	CHECK(!ret, "batch-read: 16 NVMe READ commands complete into the dma-buf");
	cpu_access(buf, view, false);
	for (i = 0; i < PAGES; i++)
		if (memcmp(view + i * PAGE, source + (BATCH_READ_SLBA + (PAGES - 1 - i) * (PAGE / LBA)) * LBA, PAGE)) break;
	CHECK(i == PAGES, "batch-read: CPU view of every dma-buf page equals its source LBA range");
	printf("OBSERVE case=batch-read fnv64=%016llx\n", (unsigned long long)fnv64(view, EXPORT));
	for (i = 0; i < EXPORT; i++) pattern[i] = (unsigned char)(((i * 131U) + 7U) ^ 0x5aU);
	cpu_access(buf, pattern, true);
	ret = nvme_batch(dstng, alloc, gen, true, BATCH_WRITE_SLBA, false);
	errno = ret < 0 ? -ret : 0;
	CHECK(!ret, "batch-write: 16 NVMe WRITE commands complete from the dma-buf");
	attached_both("batch", ino, argv[5], argv[6]);
	CHECK(!close(buf), "close exporter dma-buf fd (importer keeps its reference)");
	CHECK(!close(alloc), "close the last allocation fd");
	expect_absent("batch", ino, "bufinfo_after_close");
	printf("OBSERVE case=batch vmpin_baseline=%llu vmpin_registered=%llu vmpin_closed=%llu\n",
	       (unsigned long long)base, (unsigned long long)value, (unsigned long long)vmpin());

	attach_nvme_ops(argv[7], &ops);

	/* chain: dma-buf as a POOL_PEER frame pool, NVMe read -> NVMe write. */
	base = vmpin();
	buf = heap_alloc(heap, &ino);
	alloc = register_ok(ctl, buf, &gen, "chain: REGISTER");
	value = vmpin();
	ret = create(&s, &CHAIN, alloc, srcng, dstng);
	errno = ret < 0 ? -ret : 0;
	CHECK(!ret, "chain: CREATE a POOL_PEER session on the imported dma-buf");
	stage_caps(&s, &CHAIN);
	attached_both("chain", ino, argv[5], argv[6]);
	arm_and_start(&s, &CHAIN);
	st = wait_done(&s, &CHAIN);
	exact_success(&CHAIN, &st);
	finish(&s, 0);
	CHECK(!close(buf) && !close(alloc), "chain: close dma-buf and allocation fds");
	expect_absent("chain", ino, "bufinfo_after_close");
	printf("OBSERVE case=chain vmpin_baseline=%llu vmpin_registered=%llu vmpin_closed=%llu\n",
	       (unsigned long long)base, (unsigned long long)value, (unsigned long long)vmpin());

	/* exporter-close: the exporter's fd goes away with native work in flight. */
	base = vmpin();
	buf = heap_alloc(heap, &ino);
	alloc = register_ok(ctl, buf, &gen, "exporter-close: REGISTER");
	value = vmpin();
	ret = create(&s, &CLOSE, alloc, srcng, dstng);
	errno = ret < 0 ? -ret : 0;
	CHECK(!ret, "exporter-close: CREATE");
	attached_both("exporter-close", ino, argv[5], argv[6]);
	arm_and_start(&s, &CLOSE);
	ret = wait_native_inflight(s.ring, s.c.session_id, &CLOSE, &st);
	if (ret) print_run(CLOSE.name, "native observation failed", &st);
	CHECK(!ret, "exporter-close: STATS observed native incomplete work before the close");
	print_run(CLOSE.name, "before exporter close", &st);
	CHECK(!close(buf), "exporter-close: close the exporter dma-buf fd mid-run");
	CHECK(!session_stats(s.ring, s.c.session_id, &st), "exporter-close: STATS right after the close");
	print_run(CLOSE.name, "after exporter close", &st);
	printf("OBSERVE case=exporter-close exporter_fd_closed_inflight=1 done_at_close=%llu groups=%llu\n",
	       (unsigned long long)st.batches_done, (unsigned long long)CLOSE.groups);
	st = wait_done(&s, &CLOSE);
	exact_success(&CLOSE, &st);
	finish(&s, 0);
	CHECK(vmpin() == value, "exporter-close: charge retained while the allocation fd lives");
	CHECK(!close(alloc), "exporter-close: close the last allocation fd");
	expect_absent("exporter-close", ino, "bufinfo_after_close");
	printf("OBSERVE case=exporter-close vmpin_baseline=%llu vmpin_registered=%llu vmpin_closed=%llu\n",
	       (unsigned long long)base, (unsigned long long)value, (unsigned long long)vmpin());

	/* kill: the importing process dies with native work in flight. */
	CHECK(!getrlimit(RLIMIT_MEMLOCK, &original), "read MEMLOCK limit");
	quota = original;
	quota.rlim_cur = EXPORT;
	CHECK(original.rlim_max == RLIM_INFINITY || original.rlim_max >= EXPORT, "MEMLOCK hard limit allows one export");
	CHECK(!setrlimit(RLIMIT_MEMLOCK, &quota), "kill: soft MEMLOCK limit of exactly one export");
	{
		unsigned long probe_ino, child_ino = 0;
		uint64_t id = 0, probe_gen;
		int idpipe[2], status, probe_buf, probe_alloc, observer;
		unsigned int tries;
		pid_t child;

		probe_buf = heap_alloc(heap, &probe_ino);
		CHECK(!pipe2(idpipe, O_CLOEXEC), "kill: session id pipe");
		child = fork();
		/* TAP is reported by the parent only, never after fork in the child. */
		if (child < 0) CHECK(0, "kill: fork importer process");
		if (!child) {	/* never report TAP from the child */
			struct session c;
			uint64_t cgen;
			int cbuf, calloc_fd;
			cbuf = raw_heap_alloc(heap, &child_ino);
			calloc_fd = cbuf < 0 ? cbuf : reg(ctl, cbuf, &cgen);
			if (calloc_fd < 0 || create(&c, &KILL, calloc_fd, srcng, dstng)) _exit(1);
			{
				struct xdev_ext_mech_notify_arm arm = {.session_id = c.c.session_id, .batches_target = KILL.groups};
				struct xdev_ext_mech_start start = {.session_id = c.c.session_id, .nr_batches = KILL.groups};
				if (mech(c.ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm) ||
				    mech(c.ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&start)) _exit(2);
			}
			if (write(idpipe[1], &c.c.session_id, sizeof(c.c.session_id)) != sizeof(c.c.session_id) ||
			    write(idpipe[1], &child_ino, sizeof(child_ino)) != sizeof(child_ino)) _exit(3);
			for (;;) pause();
		}
		close(idpipe[1]);
		CHECK(read(idpipe[0], &id, sizeof(id)) == sizeof(id) && id &&
		      read(idpipe[0], &child_ino, sizeof(child_ino)) == sizeof(child_ino),
		      "kill: child imported a dma-buf and started its session");
		close(idpipe[0]);
		observer = syscall(__NR_io_uring_setup, 8, &(struct io_uring_params){});
		CHECK(observer >= 0, "kill: observer ring");
		ret = wait_native_inflight(observer, id, &KILL, &st);
		if (ret) {
			print_run(KILL.name, "native observation failed", &st);
			kill(child, SIGKILL);
			waitpid(child, &status, 0);
		}
		CHECK(!ret, "kill: STATS observed native incomplete work before SIGKILL");
		print_run(KILL.name, "before SIGKILL", &st);
		ret = reg(ctl, probe_buf, &probe_gen);
		if (ret >= 0) close(ret);
		printf("# kill quota probe while owner alive returned %d\n", ret);
		CHECK(ret == -ENOMEM, "kill: live owner's charge fills the one-export MEMLOCK quota");
		CHECK(!kill(child, SIGKILL) && waitpid(child, &status, 0) == child &&
		      WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "kill: importer died of SIGKILL");
		for (tries = 0; tries < 6000 && session_stats(observer, id, &st) != -ENOENT; tries++) usleep(10000);
		CHECK(session_stats(observer, id, &st) == -ENOENT, "kill: ring exit released the session");
		CHECK(!close(observer), "kill: close observer ring");
		/* All accepted commands complete on QEMU NVMe, so release must follow. */
		for (tries = 0; tries < 6000 && (probe_alloc = reg(ctl, probe_buf, &probe_gen)) == -ENOMEM; tries++)
			usleep(10000);
		printf("# kill quota probe after owner exit returned %d after %u polls\n", probe_alloc, tries);
		errno = probe_alloc < 0 ? -probe_alloc : 0;
		CHECK(probe_alloc >= 0, "kill: dead owner's charge returned; the same quota admits a new import");
		CHECK(!close(probe_alloc) && !close(probe_buf), "kill: close quota probe");
		expect_absent("kill", child_ino, "bufinfo_after_owner_exit");
	}
	CHECK(!setrlimit(RLIMIT_MEMLOCK, &original), "restore MEMLOCK limit");

	/* Whole-disk data oracle, independent of session statistics. */
	bpf_link__destroy(ops.link); bpf_object__close(ops.object);
	CHECK(!ioctl(src, BLKFLSBUF) && !ioctl(dst, BLKFLSBUF), "invalidate block cache before readback");
	read_all(src, source_after, IMAGE, 0); read_all(dst, dest_after, IMAGE, 0);
	memcpy(dest + BATCH_WRITE_SLBA * LBA, pattern, EXPORT);
	memcpy(dest + CHAIN.dst_slba * LBA, source + CHAIN.src_slba * LBA, bytes(&CHAIN));
	memcpy(dest + CLOSE.dst_slba * LBA, source + CLOSE.src_slba * LBA, bytes(&CLOSE));
	for (g = 0; g < KILL.groups; g++) {
		const unsigned char *from = source + KILL.src_slba * LBA + g * KILL.group;
		if (!memcmp(dest_after + KILL.dst_slba * LBA + g * KILL.group, from, KILL.group)) {
			memcpy(dest + KILL.dst_slba * LBA + g * KILL.group, from, KILL.group);
			kill_copied++;
		}
	}
	/* Both quota results were CHECKed above; a failure would have exited. */
	printf("OBSERVE case=kill quota_while_owner_alive=ENOMEM quota_after_owner_exit=ok copied_groups=%llu\n",
	       (unsigned long long)kill_copied);
	printf("# kill destination groups copied=%llu of %llu\n", (unsigned long long)kill_copied,
	       (unsigned long long)KILL.groups);
	CHECK(!memcmp(source, source_after, IMAGE), "whole source disk unchanged");
	CHECK(!memcmp(dest, dest_after, IMAGE), "whole destination disk equals copies plus every guard byte");
	close(heap); close(ctl); close(src); close(srcng); close(dst); close(dstng);
	printf("1..%u\n", checks);
	printf("XDEV_EXT_DMABUF_DMA=PASS cases=batch-read,batch-write,chain,exporter-close,kill "
	       "exporter=system-heap requesters=2 timing=none\n");
	return 0;
}
