// SPDX-License-Identifier: GPL-2.0
/* KVM guest only: the generic stage-polling bit (XDEV_EXT_MECH_STAGE_F_POLL)
 * driving the dynamically registered CPU-memcpy DMA provider through the
 * production io_uring + BPF + provider ABI.  A DMA FROM_DEVICE stage reads the
 * provider's input window into the shared pool, a DMA TO_DEVICE stage writes
 * the output window.  CPU simulation only: no physical DMA, no timing.
 *
 *   dma_poll_runtime OBJECT poll|plain GROUPS DEPTH
 *   dma_poll_runtime OBJECT stop GROUPS DEPTH      polled requests in flight at STOP
 *   dma_poll_runtime OBJECT refuse-provider        provider refuses a polled region
 *   dma_poll_runtime OBJECT refuse-class           CE (no class poll) with the bit
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "include/uapi/linux/io_uring.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "dma_provider_fixture.h"
#include "dma_campaign.h"

#define FRAME 4096U
#define POOL_BYTES (32U * FRAME)
#define STRIDE FRAME
#define MAX_DEPTH 8U
#define HEAD 256U
#define SEG 1024U
#define PAYLOAD (2U * SEG)
#define POLL XDEV_EXT_MECH_STAGE_F_POLL

static int bad;
#define REQUIRE(v) do { if (!(v)) { fprintf(stderr, "FAIL line %d: %s (errno=%d)\n", \
	__LINE__, #v, errno); bad = 1; goto out; } } while (0)

static int mech(int ring, __u32 op, __u64 arg)
{
	struct io_uring_xdev_ext_mech req = { .op = op, .arg = arg };
	int ret = syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_MECH, &req, 1);

	return ret < 0 ? -errno : ret;
}

static __u64 now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (__u64)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int module_refs(void)
{
	FILE *f = fopen("/sys/module/xdev_ext_dma_provider_sim/refcnt", "r");
	int refs = -1;

	if (f) {
		if (fscanf(f, "%d", &refs) != 1)
			refs = -1;
		fclose(f);
	}
	return refs;
}

static int param(const char *name, const char *value)
{
	char path[160];
	int fd, ret;

	snprintf(path, sizeof(path), "/sys/module/xdev_ext_dma_provider_sim/parameters/%s", name);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ret = write(fd, value, strlen(value)) == (ssize_t)strlen(value) ? 0 : -1;
	close(fd);
	return ret;
}

static void stage(struct xdev_ext_mech_stage_uapi *u, __u32 cls, __u32 dir, int fd, __u64 off, __u32 flags)
{
	*u = (struct xdev_ext_mech_stage_uapi){ .class_id = cls, .direction = dir, .fd = fd,
		.arg0 = off, .arg1 = DMA_FIXTURE_WINDOW_BYTES, .flags = flags };
}

int main(int argc, char **argv)
{
	const char *objfile = argc > 1 ? argv[1] : "dma_provider_pair.bpf.o";
	const char *mode = argc > 2 ? argv[2] : "poll";
	unsigned int groups = argc > 3 ? (unsigned int)strtoul(argv[3], NULL, 10) : 257;
	unsigned int depth = argc > 4 ? (unsigned int)strtoul(argv[4], NULL, 10) : 8;
	int polled = !strcmp(mode, "poll") || !strcmp(mode, "stop") || !strcmp(mode, "refuse-provider");
	int stopping = !strcmp(mode, "stop");
	int refuse = !strncmp(mode, "refuse-", 7);
	struct bpf_object *object = NULL;
	struct bpf_link *link = NULL;
	struct bpf_map *map;
	struct io_uring_params params = { 0 };
	struct io_uring_xdev_ext_umem_reg reg = { .size = POOL_BYTES, .frame_size = FRAME };
	struct xdev_ext_mech_create c = { .abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 2,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .pool_fd = -1, .eventfd = -1,
		.layout = { .frame_size = FRAME, .hdr_room = HEAD, .seg_len = SEG, .group_bytes = PAYLOAD } };
	__u32 frame_index[2 * MAX_DEPTH];
	struct xdev_ext_mech_start start = { .flags = XDEV_EXT_MECH_START_F_USER_FRAMES |
		XDEV_EXT_MECH_START_F_RECYCLE, .user_frames = (uintptr_t)frame_index };
	struct xdev_ext_mech_stats stats = { 0 };
	struct dma_fixture_stats device = { 0 }, before_stats = { 0 };
	unsigned char *window = MAP_FAILED, *pool = MAP_FAILED, *before = NULL;
	struct rlimit lim = { RLIM_INFINITY, RLIM_INFINITY };
	int dma = -1, ring = -1, refs = -1, created = 0, stopped = 0, ret;
	unsigned int i, g;
	__u64 deadline;

	if ((!polled && strcmp(mode, "plain") && strcmp(mode, "refuse-class")) || !groups || !depth ||
	    depth > MAX_DEPTH || groups < depth ||
	    !campaign_offset(groups - 1, STRIDE, PAYLOAD, DMA_FIXTURE_WINDOW_BYTES, &(uint64_t){ 0 })) {
		fprintf(stderr, "FAIL usage: OBJECT {poll|plain|stop} GROUPS DEPTH, or {refuse-provider|refuse-class}\n");
		return 1;
	}
	setrlimit(RLIMIT_MEMLOCK, &lim);
	c.depth = depth;
	start.nr_batches = groups;
	start.nr_user_frames = 2 * depth;
	for (i = 0; i < 2 * depth; i++)
		frame_index[i] = 2 * i + 1;
	REQUIRE(!param("fail_mode", "0") && !param("stale_replays", "0"));
	REQUIRE(!param("delay_us", stopping ? "500000" : "0"));
	REQUIRE(!param("poll_refuse", !strcmp(mode, "refuse-provider") ? "1" : "0"));
	dma = open("/dev/xdev_ext_dma_provider_sim", O_RDWR | O_CLOEXEC);
	REQUIRE(dma >= 0);
	window = mmap(NULL, DMA_FIXTURE_MAP_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, dma, 0);
	REQUIRE(window != MAP_FAILED);
	memset(window, 0xa6, DMA_FIXTURE_MAP_BYTES);
	for (g = 0; g < groups; g++)
		for (i = 0; i < PAYLOAD; i++)
			window[DMA_FIXTURE_INPUT_OFF + g * STRIDE + i] = campaign_pattern(g, i);
	before = malloc(DMA_FIXTURE_MAP_BYTES);
	REQUIRE(before);
	memcpy(before, window, DMA_FIXTURE_MAP_BYTES);
	refs = module_refs();
	REQUIRE(refs >= 1);
	REQUIRE(!ioctl(dma, DMA_FIXTURE_STATS, &before_stats));
	object = bpf_object__open_file(objfile, NULL);
	REQUIRE(object && !libbpf_get_error(object));
	REQUIRE(!bpf_object__load(object));
	map = bpf_object__find_map_by_name(object, "dma_pair");
	REQUIRE(map);
	link = bpf_map__attach_struct_ops(map);
	REQUIRE(!libbpf_get_error(link));
	ring = syscall(__NR_io_uring_setup, 8, &params);
	REQUIRE(ring >= 0);
	pool = mmap(NULL, POOL_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	REQUIRE(pool != MAP_FAILED);
	memset(pool, 0x97, POOL_BYTES);
	reg.addr = (uintptr_t)pool;
	REQUIRE(!syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg, 1));
	stage(&c.st[0], XDEV_EXT_MECH_CLASS_DMA, XDEV_EXT_MECH_DIR_FROM_DEVICE, dma,
	      DMA_FIXTURE_INPUT_OFF, polled ? POLL : 0);
	if (!strcmp(mode, "refuse-class"))
		/* CE has no class poll; any fd suffices, CREATE refuses before binding. */
		stage(&c.st[1], XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_TO_DEVICE, dma, 0, POLL);
	else
		stage(&c.st[1], XDEV_EXT_MECH_CLASS_DMA, XDEV_EXT_MECH_DIR_TO_DEVICE, dma,
		      DMA_FIXTURE_OUTPUT_OFF, polled ? POLL : 0);

	ret = mech(ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&c);
	if (refuse) {
		REQUIRE(ret == -EOPNOTSUPP);
		REQUIRE(!ioctl(dma, DMA_FIXTURE_STATS, &device));
		REQUIRE(device.region_binds == before_stats.region_binds &&
			device.host_binds == before_stats.host_binds && !device.accepted);
		REQUIRE(module_refs() == refs);
		printf("PASS poll case=%s create=-EOPNOTSUPP region_binds=0 host_binds=0 accepted=0 owner_refs_released=1\n",
		       mode);
		goto out;
	}
	REQUIRE(ret == 0);
	created = 1;
	REQUIRE(module_refs() >= refs + 2);
	start.session_id = c.session_id;
	REQUIRE(!mech(ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&start));
	deadline = now_ms() + 20000;
	do {
		memset(&stats, 0, sizeof(stats));
		stats.session_id = c.session_id;
		REQUIRE(!mech(ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&stats));
		REQUIRE(!ioctl(dma, DMA_FIXTURE_STATS, &device));
		if (stopping ? device.pending > 0 :
		    stats.batches_done == groups || stats.batches_abort || stats.sequestered)
			break;
		usleep(1000);
	} while (now_ms() < deadline);
	if (stopping) {
		/* Polled requests are accepted and outstanding: nothing but a poll
		 * pass completes them, so STOP returns 0 only if the worker kept
		 * polling through STOPPING and the bounded drain. */
		REQUIRE(device.pending > 0 && !device.region_unbinds && !device.host_unbinds);
		REQUIRE(device.polled_completed == device.completed);
		printf("# stop: pending_at_stop=%llu accepted=%llu completed=%llu inflight=%llu\n",
		       (unsigned long long)device.pending, (unsigned long long)device.accepted,
		       (unsigned long long)device.completed, (unsigned long long)stats.inflight);
		ret = mech(ring, XDEV_EXT_MECH_OP_STOP, c.session_id);
		stopped = 1;
		REQUIRE(ret == 0);
		REQUIRE(!ioctl(dma, DMA_FIXTURE_STATS, &device));
		REQUIRE(device.accepted && device.accepted == device.completed && !device.pending);
		REQUIRE(device.polled_completed == device.completed);
		REQUIRE(device.region_unbinds == 2 && device.host_unbinds == 2 && module_refs() == refs);
		printf("PASS poll case=stop stop=0 accepted=%llu completed=%llu polled_completed=%llu pending=0 unbinds=2 owner_refs_released=1\n",
		       (unsigned long long)device.accepted, (unsigned long long)device.completed,
		       (unsigned long long)device.polled_completed);
		goto out;
	}
	REQUIRE(stats.batches_done == groups && !stats.batches_abort && !stats.rejects &&
		!stats.sequestered && !stats.protocol_err && !stats.inflight && !stats.last_err);
	for (i = 0; i < 2; i++)
		REQUIRE(stats.submitted[i] == groups && stats.completed[i] == groups);
	REQUIRE(!campaign_verify(window, before, DMA_FIXTURE_MAP_BYTES, DMA_FIXTURE_OUTPUT_OFF, groups, STRIDE, PAYLOAD));
	REQUIRE(!ioctl(dma, DMA_FIXTURE_STATS, &device));
	REQUIRE(device.accepted == 2ULL * groups && device.completed == 2ULL * groups && !device.pending &&
		device.from_device == groups && device.to_device == groups &&
		device.bytes == 2ULL * groups * PAYLOAD);
	if (polled)
		REQUIRE(device.polled_completed == device.completed && device.polls > 0);
	else
		REQUIRE(!device.polled_completed && !device.polls);
	REQUIRE(!mech(ring, XDEV_EXT_MECH_OP_STOP, c.session_id));
	stopped = 1;
	REQUIRE(!ioctl(dma, DMA_FIXTURE_STATS, &device));
	REQUIRE(device.region_unbinds == 2 && device.host_unbinds == 2 && module_refs() == refs);
	printf("PASS poll case=%s groups=%u depth=%u full_output=1 accepted=%llu completed=%llu polled_completed=%llu polls_nonzero=%d owner_refs_released=1 CPU_simulation=1\n",
	       mode, groups, depth, (unsigned long long)device.accepted, (unsigned long long)device.completed,
	       (unsigned long long)device.polled_completed, device.polls > 0);
out:
	if (created && !stopped && ring >= 0)
		mech(ring, XDEV_EXT_MECH_OP_STOP, c.session_id);
	if (ring >= 0)
		close(ring);
	if (pool != MAP_FAILED)
		munmap(pool, POOL_BYTES);
	if (link && !libbpf_get_error(link))
		bpf_link__destroy(link);
	if (object && !libbpf_get_error(object))
		bpf_object__close(object);
	if (window != MAP_FAILED)
		munmap(window, DMA_FIXTURE_MAP_BYTES);
	if (dma >= 0)
		close(dma);
	param("delay_us", "0");
	param("poll_refuse", "0");
	free(before);
	return bad ? 1 : 0;
}
