// SPDX-License-Identifier: GPL-2.0
/*
 * Guest only: an UNKNOWN native peer DMA outcome on the mechanism-session
 * path (POOL_PEER pool, stage 0 NVMe read on the source controller, stage 1
 * NVMe write on the other controller) and its release by a proven NVMe
 * Controller Reset of the source controller only.  The UNKNOWN outcome is the
 * kernel's own nvme fault_inject status; QEMU NVMe performs the DMA into the
 * host-RAM provider fixture.  Correctness only: nothing here measures time
 * or models a real GPU.  Companion of peer_reset_e2e (the fd path).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "linux/io_uring.h"
#include "linux/xdev_ext_peer.h"
#include "linux/xdev_ext_mech.h"
#include "sw_provider_uapi.h"

static const char *case_name;
static unsigned int checks;
#define CHECK(c, msg) do { if (!(c)) { \
	printf("not ok %u - %s: %s (errno=%d %s)\n", ++checks, case_name, msg, errno, strerror(errno)); \
	printf("XDEV_EXT_PEER_RESET_CASE=%s FAIL\n", case_name); exit(1); } \
	printf("ok %u - %s: %s\n", ++checks, case_name, msg); } while (0)

struct env { const char *ng, *ctrl, *other, *disk, *bpf_dir; char other_ng[64]; int ctl; };

static int observer = -1;
static struct peer_sw_stats stats(void)
{
	struct peer_sw_stats s = {};

	if (ioctl(observer, PEER_SW_STATS, &s)) {
		printf("not ok - %s: provider counters unavailable\n", case_name);
		exit(1);
	}
	return s;
}
static void put(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n = fd < 0 ? -1 : write(fd, value, strlen(value));

	if (n != (ssize_t)strlen(value)) {
		printf("not ok - %s: write %s to %s (errno=%d)\n", case_name, value, path, errno);
		exit(1);
	}
	close(fd);
}
static void putf(const char *value, const char *fmt, const char *name)
{
	char path[256];

	snprintf(path, sizeof(path), fmt, name);
	put(path, value);
}
static void sleep_ms(long ms)
{
	struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };

	while (nanosleep(&t, &t) && errno == EINTR) { }
}
static void reset_controller(const char *ctrl) { putf("1", "/sys/class/nvme/%s/reset_controller", ctrl); }
static bool live(const char *ctrl)
{
	char path[256], state[32] = "";
	FILE *f;

	snprintf(path, sizeof(path), "/sys/class/nvme/%s/state", ctrl);
	f = fopen(path, "re");
	if (!f)
		return false;
	if (!fgets(state, sizeof(state), f))
		state[0] = 0;
	fclose(f);
	return !strncmp(state, "live", 4);
}
static void wait_live(const char *ctrl)
{
	long ms;

	for (ms = 0; ms < 20000 && !live(ctrl); ms += 100)
		sleep_ms(100);
	CHECK(live(ctrl), "the controller is live");
}
static void inject_status_once(struct env *e)
{
	putf("100", "/sys/kernel/debug/%s/fault_inject/probability", e->disk);
	putf("1", "/sys/kernel/debug/%s/fault_inject/interval", e->disk);
	putf("1", "/sys/kernel/debug/%s/fault_inject/times", e->disk);
}
/* Same live pins and maps as right after CREATE: nothing was given back. */
static bool held(struct peer_sw_stats now, struct peer_sw_stats created)
{
	return now.live_pins == created.live_pins && now.live_maps == created.live_maps &&
	       now.unpins == created.unpins && now.unmaps == created.unmaps &&
	       now.closes == created.closes;
}
/* Everything the case pinned and mapped is gone, the provider file closed once. */
static bool released(struct peer_sw_stats now, struct peer_sw_stats before,
		     struct peer_sw_stats created)
{
	return now.live_pins == before.live_pins && now.live_maps == before.live_maps &&
	       now.unpins == created.unpins + 1 &&
	       now.unmaps == created.unmaps + (created.live_maps - before.live_maps) &&
	       now.closes == created.closes + 1;
}

static int mech(int ring, __u32 op, uint64_t argument)
{
	struct io_uring_xdev_ext_mech req = { .op = op, .arg = argument };
	int ret = syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_MECH, &req, 1);

	return ret < 0 ? -errno : ret;
}
static int ring_new(void)
{
	struct io_uring_params params = {};

	return syscall(__NR_io_uring_setup, 8, &params);
}
/* STATS through a ring that does not own the session: 0, or -ENOENT once freed. */
static int foreign_stats(uint64_t id, struct xdev_ext_mech_stats *st)
{
	int ring = ring_new(), ret;

	if (ring < 0)
		return -errno;
	*st = (struct xdev_ext_mech_stats){ .session_id = id };
	ret = mech(ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)st);
	close(ring);
	return ret;
}
static bool parked(uint64_t id)
{
	struct xdev_ext_mech_stats st;

	return !foreign_stats(id, &st) && st.state == XDEV_EXT_MECH_SESSION_ZOMBIE &&
	       st.sequestered >= 1 && !st.inflight;
}
/* Bounded: recovery is deferred work after the reset returns. */
static bool released_within(uint64_t id, struct peer_sw_stats before,
			    struct peer_sw_stats created, long ms)
{
	struct xdev_ext_mech_stats st;

	for (; ms > 0; ms -= 100) {
		if (released(stats(), before, created) && foreign_stats(id, &st) == -ENOENT)
			return true;
		sleep_ms(100);
	}
	return released(stats(), before, created) && foreign_stats(id, &st) == -ENOENT;
}

/* nvme_s0 struct_ops, as the product controller xdev_ext_peer_chain loads it. */
static struct bpf_link *attach_nvme_ops(const char *dir, struct bpf_object **object)
{
	char path[PATH_MAX];
	struct bpf_link *link = NULL;
	struct bpf_map *map;

	snprintf(path, sizeof(path), "%s/nvme_s0.bpf.o", dir);
	*object = bpf_object__open_file(path, NULL);
	CHECK(!libbpf_get_error(*object), "open nvme_s0 BPF object");
	CHECK(!bpf_object__load(*object), "load nvme_s0 BPF object");
	bpf_object__for_each_map(map, *object) {
		if (bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS)
			continue;
		link = bpf_map__attach_struct_ops(map);
		break;
	}
	CHECK(link && !libbpf_get_error(link), "attach nvme_s0 struct_ops");
	return link;
}

/*
 * The source read completes with an injected NVMe error status (UNKNOWN):
 * the batch is sequestered and STOP quarantines the session.  It stays
 * parked, with the allocation pinned and mapped, through owner close, time
 * and a completed reset of the other controller (stage 1's device); the
 * source controller's completed reset releases the session and every
 * provider reference exactly once.
 */
static void case_session_error_status(struct env *e)
{
	struct peer_sw_stats before = stats(), created;
	struct xdev_ext_peer_register r = { .gpu_va = PEER_SW_VA, .len = PEER_SW_BYTES };
	struct xdev_ext_mech_create c = {
		.abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 2,
		.pool_kind = XDEV_EXT_MECH_POOL_PEER, .layout = { 4096, 0, 4096, 4096 }, .depth = 1,
	};
	struct xdev_ext_mech_notify_arm arm = { .batches_target = 1 };
	struct xdev_ext_mech_start start = { .nr_batches = 1 };
	struct xdev_ext_mech_stats st;
	struct bpf_object *object;
	struct bpf_link *link;
	struct pollfd w;
	int provider, alloc, src, dst, notify, ring, ret;

	link = attach_nvme_ops(e->bpf_dir, &object);
	provider = open("/dev/xdev_ext_peer_sw", O_RDWR | O_CLOEXEC);
	CHECK(provider >= 0, "open a fresh provider allocation");
	r.gpu_fd = provider;
	alloc = ioctl(e->ctl, XDEV_EXT_PEER_REGISTER, &r);
	CHECK(alloc >= 0 && r.generation, "REGISTER returns an allocation fd and generation");
	src = open(e->ng, O_RDONLY | O_CLOEXEC);
	dst = open(e->other_ng, O_RDWR | O_CLOEXEC);
	CHECK(src >= 0 && dst >= 0, "source and other generic namespaces");
	notify = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	ring = ring_new();
	CHECK(notify >= 0 && ring >= 0, "session eventfd and io_uring ring");
	c.pool_fd = alloc;
	c.eventfd = notify;
	c.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = src, .arg0 = 0, .arg1 = 8 };
	c.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = dst, .arg0 = 0, .arg1 = 8 };
	CHECK(!mech(ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&c), "CREATE a POOL_PEER read-to-write session");
	created = stats();
	CHECK(created.live_pins == before.live_pins + 1 && created.live_maps > before.live_maps,
	      "the session claims the allocation and maps it for its NVMe requesters");
	arm.session_id = start.session_id = c.session_id;
	CHECK(!mech(ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm), "NOTIFY_ARM for the one batch");
	inject_status_once(e);
	CHECK(!mech(ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&start), "START one batch");
	w = (struct pollfd){ .fd = notify, .events = POLLIN };
	do { ret = poll(&w, 1, 20000); } while (ret < 0 && errno == EINTR);
	CHECK(ret == 1, "terminal notification");
	for (ret = 0; ret < 2000; ret++) {
		st = (struct xdev_ext_mech_stats){ .session_id = c.session_id };
		if (mech(ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&st) || !st.inflight)
			break;
		sleep_ms(10);
	}
	printf("# session stats: done=%llu abort=%llu inflight=%llu sequestered=%llu submitted=%llu/%llu completed=%llu/%llu last_err=%d state=%u\n",
	       (unsigned long long)st.batches_done, (unsigned long long)st.batches_abort,
	       (unsigned long long)st.inflight, (unsigned long long)st.sequestered,
	       (unsigned long long)st.submitted[0], (unsigned long long)st.submitted[1],
	       (unsigned long long)st.completed[0], (unsigned long long)st.completed[1],
	       st.last_err, st.state);
	CHECK(st.last_err && st.sequestered >= 1 && !st.inflight && st.submitted[0] == 1 &&
	      st.completed[0] == 1 && !st.submitted[1],
	      "the injected NVMe status sequesters the read batch; no write is issued");
	CHECK(mech(ring, XDEV_EXT_MECH_OP_STOP, c.session_id) == -EBUSY,
	      "STOP quarantines the session (UNKNOWN DMA)");
	CHECK(parked(c.session_id), "another ring still finds the parked ZOMBIE session");
	close(ring); close(notify); close(src); close(dst); close(alloc); close(provider);
	bpf_link__destroy(link); bpf_object__close(object);
	CHECK(held(stats(), created), "closing ring, files and program releases nothing");
	close(observer); /* an open observer would hold the module itself */
	CHECK(syscall(SYS_delete_module, "xdev_ext_peer_sw", O_NONBLOCK) == -1 && errno == EWOULDBLOCK,
	      "the parked session keeps the provider module loaded");
	observer = open("/dev/xdev_ext_peer_sw", O_RDWR | O_CLOEXEC);
	CHECK(observer >= 0, "reopen the provider counters");
	before.closes++; created.closes++; /* the observer's own close */
	reset_controller(e->other);
	sleep_ms(1500);
	CHECK(held(stats(), created) && parked(c.session_id),
	      "a completed reset of the other controller (stage 1's device) is not evidence");
	sleep_ms(1500);
	CHECK(held(stats(), created) && parked(c.session_id), "time alone is not evidence");
	reset_controller(e->ctrl);
	CHECK(released_within(c.session_id, before, created, 10000),
	      "the source controller's completed reset releases the session and the allocation exactly once");
}

int main(int argc, char **argv)
{
	const char *n;
	struct env e;

	setbuf(stdout, NULL);
	if (argc != 7) {
		fprintf(stderr, "usage: %s CASE SOURCE_NG SOURCE_CTRL OTHER_CTRL SOURCE_DISK BPF_DIR\n", argv[0]);
		return 2;
	}
	case_name = argv[1];
	e = (struct env){ .ng = argv[2], .ctrl = argv[3], .other = argv[4], .disk = argv[5],
			  .bpf_dir = argv[6] };
	CHECK(getenv("XDEV_EXT_PEER_GUEST") && !strcmp(getenv("XDEV_EXT_PEER_GUEST"), "1"), "guest-only opt-in");
	n = !strncmp(e.other, "nvme", 4) ? e.other + 4 : "";
	snprintf(e.other_ng, sizeof(e.other_ng), "/dev/ng%sn1", n);
	e.ctl = open("/dev/xdev_ext_peer", O_RDWR | O_CLOEXEC);
	CHECK(e.ctl >= 0 && *n, "peer control and the other controller's generic namespace name");
	observer = open("/dev/xdev_ext_peer_sw", O_RDWR | O_CLOEXEC);
	CHECK(observer >= 0, "provider counters");
	wait_live(e.ctrl); wait_live(e.other);
	if (!strcmp(case_name, "session-error-status")) case_session_error_status(&e);
	else { printf("not ok - unknown case %s\n", case_name); return 2; }
	close(e.ctl); close(observer);
	printf("XDEV_EXT_PEER_RESET_CASE=%s PASS checks=%u\n", case_name, checks);
	return 0;
}
