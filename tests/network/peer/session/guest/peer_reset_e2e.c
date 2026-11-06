// SPDX-License-Identifier: GPL-2.0
/*
 * Guest only: UNKNOWN native peer DMA outcomes and their release by a proven
 * NVMe Controller Reset, through the synchronous XDEV_EXT_PEER_NVME_RW ioctl.
 * The UNKNOWN outcomes are produced by the kernel's own fault injection
 * (nvme fault_inject status, fail_io_timeout); QEMU NVMe really performs the
 * READ DMA into the host-RAM provider fixture. One case per process so that
 * a failing case cannot hide the next one. Reads only; disks stay unchanged.
 * Correctness only: nothing here measures time or models a real GPU.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "linux/xdev_ext_peer.h"
#include "sw_provider_uapi.h"

static const char *case_name;
static unsigned int checks;
#define CHECK(c, msg) do { if (!(c)) { \
	printf("not ok %u - %s: %s (errno=%d %s)\n", ++checks, case_name, msg, errno, strerror(errno)); \
	printf("XDEV_EXT_PEER_RESET_CASE=%s FAIL\n", case_name); exit(1); } \
	printf("ok %u - %s: %s\n", ++checks, case_name, msg); } while (0)

struct env { const char *ng, *ctrl, *other, *disk; int ctl, ngfd; };

/* One observer for the whole case: its own open/close would move the counters. */
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
/* Synchronous: returns after the reset work has finished. */
static void reset_controller(const char *ctrl) { putf("1", "/sys/class/nvme/%s/reset_controller", ctrl); }
/* A reset scheduled by the timeout handler finishes asynchronously. */
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
static int allocation(struct env *e, int *provider, uint64_t *generation)
{
	struct xdev_ext_peer_register r = { .gpu_va = PEER_SW_VA, .len = PEER_SW_BYTES };
	int fd;

	*provider = open("/dev/xdev_ext_peer_sw", O_RDWR | O_CLOEXEC);
	CHECK(*provider >= 0, "open a fresh provider allocation");
	r.gpu_fd = *provider;
	fd = ioctl(e->ctl, XDEV_EXT_PEER_REGISTER, &r);
	CHECK(fd >= 0 && r.generation, "REGISTER returns an allocation fd and generation");
	*generation = r.generation;
	return fd;
}
static int peer_read(struct env *e, int alloc, uint64_t generation)
{
	struct xdev_ext_peer_nvme_rw u = {
		.allocation_fd = alloc, .generation = generation, .slba = 0, .bytes = 4096,
	};

	errno = 0;
	return ioctl(e->ngfd, XDEV_EXT_PEER_NVME_RW, &u);
}
static bool held(struct peer_sw_stats now, struct peer_sw_stats before)
{
	return now.live_pins == before.live_pins + 1 && now.live_maps == before.live_maps + 1 &&
	       now.unpins == before.unpins && now.unmaps == before.unmaps &&
	       now.closes == before.closes;
}
static bool released(struct peer_sw_stats now, struct peer_sw_stats before)
{
	return now.live_pins == before.live_pins && now.live_maps == before.live_maps &&
	       now.unpins == before.unpins + 1 && now.unmaps == before.unmaps + 1 &&
	       now.closes == before.closes + 1;
}
/* Bounded: recovery is deferred work after the reset returns. */
static bool released_within(struct peer_sw_stats before, long ms)
{
	for (; ms > 0; ms -= 100) {
		if (released(stats(), before))
			return true;
		sleep_ms(100);
	}
	return released(stats(), before);
}
static void inject_status_once(struct env *e)
{
	putf("100", "/sys/kernel/debug/%s/fault_inject/probability", e->disk);
	putf("1", "/sys/kernel/debug/%s/fault_inject/interval", e->disk);
	putf("1", "/sys/kernel/debug/%s/fault_inject/times", e->disk);
}

/* A completed read releases at owner close; nothing waits for a reset. */
static void case_control(struct env *e)
{
	struct peer_sw_stats before = stats();
	uint64_t gen; int provider, alloc = allocation(e, &provider, &gen);

	CHECK(peer_read(e, alloc, gen) == 0, "native peer read completes");
	CHECK(held(stats(), before), "the allocation and its NVMe mapping are live while the owner holds them");
	close(alloc); close(provider);
	CHECK(released(stats(), before), "owner close unmaps, unpins and drops the provider file at once");
}

/* An error status (UNKNOWN): held through close and an unrelated reset, released by its own reset. */
static void case_error_status(struct env *e)
{
	struct peer_sw_stats before = stats();
	uint64_t gen; int provider, alloc = allocation(e, &provider, &gen), ret;

	inject_status_once(e);
	ret = peer_read(e, alloc, gen);
	CHECK(ret > 0, "the injected NVMe error status reaches the caller");
	CHECK(held(stats(), before), "UNKNOWN keeps the allocation pinned and mapped");
	close(alloc); close(provider);
	CHECK(held(stats(), before), "closing the owner releases nothing");
	close(observer); /* an open observer would hold the module itself */
	CHECK(syscall(SYS_delete_module, "xdev_ext_peer_sw", O_NONBLOCK) == -1 && errno == EWOULDBLOCK,
	      "the held region keeps the provider module loaded");
	observer = open("/dev/xdev_ext_peer_sw", O_RDWR | O_CLOEXEC);
	CHECK(observer >= 0, "reopen the provider counters");
	before.closes++; /* the observer's own close */
	reset_controller(e->other);
	sleep_ms(1500);
	CHECK(held(stats(), before), "a completed reset of another controller is not evidence");
	sleep_ms(1500);
	CHECK(held(stats(), before), "time alone is not evidence");
	reset_controller(e->ctrl);
	CHECK(released_within(before, 10000),
	      "the source controller's completed reset releases the region exactly once");
}

/* Fake timeout: abort, second timeout, reset; the cancellation completes after the proof. */
static void case_timeout_cancel(struct env *e)
{
	struct peer_sw_stats before = stats();
	uint64_t gen; int provider, alloc = allocation(e, &provider, &gen), ret;

	put("/sys/module/nvme_core/parameters/io_timeout", "2");
	putf("1", "/sys/block/%s/io-timeout-fail", e->disk);
	put("/sys/kernel/debug/fail_io_timeout/probability", "100");
	put("/sys/kernel/debug/fail_io_timeout/interval", "1");
	put("/sys/kernel/debug/fail_io_timeout/times", "1");
	ret = peer_read(e, alloc, gen);
	CHECK(ret == -1 && errno == EINTR, "the timed out command is cancelled by the controller reset");
	putf("0", "/sys/block/%s/io-timeout-fail", e->disk);
	put("/sys/module/nvme_core/parameters/io_timeout", "30");
	wait_live(e->ctrl);
	CHECK(held(stats(), before), "the owner still holds its allocation");
	close(alloc); close(provider);
	CHECK(released(stats(), before),
	      "a command cancelled inside a proven reset releases at owner close without another reset");
}

/* Recovery while the owner still holds the fd: the region stays invalid until close. */
static void case_owner_open(struct env *e)
{
	struct peer_sw_stats before = stats();
	uint64_t gen; int provider, alloc = allocation(e, &provider, &gen);

	inject_status_once(e);
	CHECK(peer_read(e, alloc, gen) > 0, "the injected NVMe error status reaches the caller");
	reset_controller(e->ctrl);
	sleep_ms(1000);
	CHECK(held(stats(), before), "a recovered region stays with its live owner");
	CHECK(peer_read(e, alloc, gen) == -1 && errno == ESTALE, "a recovered region admits no new command");
	close(alloc); close(provider);
	CHECK(released(stats(), before), "the owner close then releases it at once");
}

int main(int argc, char **argv)
{
	struct env e;

	setbuf(stdout, NULL);
	if (argc != 6) {
		fprintf(stderr, "usage: %s CASE SOURCE_NG SOURCE_CTRL OTHER_CTRL SOURCE_DISK\n", argv[0]);
		return 2;
	}
	case_name = argv[1];
	e = (struct env){ .ng = argv[2], .ctrl = argv[3], .other = argv[4], .disk = argv[5] };
	CHECK(getenv("XDEV_EXT_PEER_GUEST") && !strcmp(getenv("XDEV_EXT_PEER_GUEST"), "1"), "guest-only opt-in");
	e.ctl = open("/dev/xdev_ext_peer", O_RDWR | O_CLOEXEC);
	e.ngfd = open(e.ng, O_RDONLY | O_CLOEXEC);
	CHECK(e.ctl >= 0 && e.ngfd >= 0, "peer control and source generic namespace");
	observer = open("/dev/xdev_ext_peer_sw", O_RDWR | O_CLOEXEC);
	CHECK(observer >= 0, "provider counters");
	wait_live(e.ctrl); wait_live(e.other);
	if (!strcmp(case_name, "control")) case_control(&e);
	else if (!strcmp(case_name, "error-status")) case_error_status(&e);
	else if (!strcmp(case_name, "timeout-cancel")) case_timeout_cancel(&e);
	else if (!strcmp(case_name, "owner-open")) case_owner_open(&e);
	else { printf("not ok - unknown case %s\n", case_name); return 2; }
	close(e.ngfd); close(e.ctl); close(observer);
	printf("XDEV_EXT_PEER_RESET_CASE=%s PASS checks=%u\n", case_name, checks);
	return 0;
}
