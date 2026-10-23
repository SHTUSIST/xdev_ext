// SPDX-License-Identifier: GPL-2.0
/*
 * Test-only userspace model of the XDEV_EXT_MECH control API, so that a stock
 * host can drive the preload front end's opt-in socket mechanism path
 * (XDEV_EXT_PRELOAD_SOCKET_MECH=1).  Load it after the front end:
 *
 *   LD_PRELOAD=libio_uring_unified.so:libxdev_ext_preload_mech_model.so
 *
 * It interposes syscall(3) and handles only io_uring_register with
 * IORING_REGISTER_XDEV_EXT_UMEM, IORING_UNREGISTER_XDEV_EXT_UMEM (accepted and
 * recorded per ring descriptor) and IORING_REGISTER_XDEV_EXT_MECH.  CREATE
 * keeps a duplicate of the last (socket) stage's descriptor, START sends the
 * span's bytes from the ring's registered frame on that duplicate with
 * sendto(2) and signals the session eventfd, STATS returns the session's
 * counters, and STOP drops the duplicate.  Rings, eventfds, frames and the
 * datagrams themselves are real; only the unavailable kernel API is modelled.
 * Everything else reaches the host kernel unchanged.
 *
 *   XDEV_EXT_MECH_MODEL_STOP_FAIL=<n>
 *	The n-th STOP (1-based, per process) fails with EBUSY and leaves its
 *	session active, as a STOP whose DMA barrier could not be proven.
 *   XDEV_EXT_MECH_MODEL_SUMMARY=1
 *	Print one XDEV_EXT_MECH_MODEL_SUMMARY line per process at exit.
 *
 * xdev_ext_mech_model_counts() reports, for syscall accounting, the control
 * operations it modelled and the real syscalls the model itself issued.
 *
 * It is not evidence that the mechanism, its socket stage or any device works;
 * the KVM harness provides that.
 */
#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../../../include/uapi/linux/io_uring.h"
#include "../../../../include/uapi/linux/xdev_ext_mech.h"

#define MECH_MODEL_MAX_FDS 1024

typedef long (*mech_model_syscall_fn)(long, ...);

struct mech_model_ring {
	uint64_t umem;
	uint64_t umem_size;
	uint64_t session;
	int sink;
	int eventfd;
	unsigned int nr_stages;
	struct xdev_ext_mech_stats stats;
};

struct xdev_ext_mech_model_counts {
	uint64_t creates;
	uint64_t starts;
	uint64_t stops;
	uint64_t stop_failures;
	/* io_uring_register calls answered here instead of by a kernel. */
	uint64_t modelled_ops;
	/* Real syscalls the model issued on its own behalf. */
	uint64_t own_syscalls;
};

static mech_model_syscall_fn real_syscall;
static pthread_once_t mech_model_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t mech_model_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mech_model_ring mech_model_rings[MECH_MODEL_MAX_FDS];
static struct xdev_ext_mech_model_counts mech_model_counts;
static uint64_t mech_model_next_session = 1;
static uint64_t mech_model_stop_fail;
static bool mech_model_summary;

static void mech_model_init(void)
{
	const char *value;

	*(void **)&real_syscall = dlsym(RTLD_NEXT, "syscall");
	value = getenv("XDEV_EXT_MECH_MODEL_STOP_FAIL");
	if (value && *value)
		mech_model_stop_fail = strtoull(value, NULL, 10);
	value = getenv("XDEV_EXT_MECH_MODEL_SUMMARY");
	mech_model_summary = value && !strcmp(value, "1");
}

/* Kept out of line so that a stack trace names the model as the issuer. */
__attribute__((noinline)) static long
mech_model_own(long number, long a0, long a1, long a2, long a3, long a4,
	       long a5)
{
	mech_model_counts.own_syscalls++;
	return real_syscall(number, a0, a1, a2, a3, a4, a5);
}

static long mech_model_fail(int error)
{
	errno = error;
	return -1;
}

static long mech_model_control(struct mech_model_ring *ring,
			       const struct io_uring_xdev_ext_mech *request)
{
	void *argument = (void *)(uintptr_t)request->arg;
	uint64_t one = 1;

	mech_model_counts.modelled_ops++;
	switch (request->op) {
	case XDEV_EXT_MECH_OP_CREATE: {
		struct xdev_ext_mech_create *create = argument;
		int stage_fd;

		if (ring->session || !ring->umem || !create->nr_stages ||
		    create->nr_stages > XDEV_EXT_MECH_MAX_STAGES ||
		    create->depth != 1 ||
		    create->layout.group_bytes > ring->umem_size)
			return mech_model_fail(EINVAL);
		stage_fd = create->st[create->nr_stages - 1].fd;
		ring->sink = (int)mech_model_own(SYS_fcntl, stage_fd,
						 F_DUPFD_CLOEXEC, 0, 0, 0, 0);
		if (ring->sink < 0)
			return -1;
		ring->eventfd = create->eventfd;
		ring->nr_stages = create->nr_stages;
		ring->session = mech_model_next_session++;
		memset(&ring->stats, 0, sizeof(ring->stats));
		ring->stats.session_id = ring->session;
		ring->stats.state = XDEV_EXT_MECH_SESSION_ACTIVE;
		create->session_id = ring->session;
		mech_model_counts.creates++;
		return 0;
	}
	case XDEV_EXT_MECH_OP_NOTIFY_ARM: {
		struct xdev_ext_mech_notify_arm *arm = argument;

		if (!ring->session || arm->session_id != ring->session ||
		    arm->batches_target != ring->stats.batches_done + 1 ||
		    arm->published_target != ring->stats.published + 1)
			return mech_model_fail(EINVAL);
		return 0;
	}
	case XDEV_EXT_MECH_OP_START: {
		struct xdev_ext_mech_start *start = argument;
		const struct xdev_ext_mech_user_span *span =
			(const void *)(uintptr_t)start->user_frames;
		unsigned int i;
		long sent;

		if (!ring->session || start->session_id != ring->session ||
		    start->nr_batches != 1 || start->nr_user_frames != 1 ||
		    !span || span->index || !span->len ||
		    span->len > ring->umem_size)
			return mech_model_fail(EINVAL);
		sent = mech_model_own(SYS_sendto, ring->sink, (long)ring->umem,
				      span->len, MSG_NOSIGNAL, 0, 0);
		mech_model_counts.starts++;
		ring->stats.batches_done++;
		ring->stats.published++;
		for (i = 0; i < ring->nr_stages; i++) {
			ring->stats.submitted[i]++;
			ring->stats.completed[i]++;
		}
		if (sent != (long)span->len)
			ring->stats.last_err = -EIO;
		(void)mech_model_own(SYS_write, ring->eventfd, (long)&one,
				     sizeof(one), 0, 0, 0);
		return 0;
	}
	case XDEV_EXT_MECH_OP_STATS: {
		struct xdev_ext_mech_stats *stats = argument;

		if (!ring->session || stats->session_id != ring->session)
			return mech_model_fail(EINVAL);
		*stats = ring->stats;
		return 0;
	}
	case XDEV_EXT_MECH_OP_STOP:
		if (!ring->session || request->arg != ring->session)
			return mech_model_fail(EINVAL);
		mech_model_counts.stops++;
		if (mech_model_stop_fail &&
		    mech_model_counts.stops == mech_model_stop_fail) {
			mech_model_counts.stop_failures++;
			return mech_model_fail(EBUSY);
		}
		(void)mech_model_own(SYS_close, ring->sink, 0, 0, 0, 0, 0);
		ring->sink = -1;
		ring->session = 0;
		return 0;
	default:
		return mech_model_fail(EINVAL);
	}
}

static long mech_model_register(long fd, long opcode, long argument, long count)
{
	struct mech_model_ring *ring;
	long ret = 0;

	if ((opcode != IORING_REGISTER_XDEV_EXT_UMEM &&
	     opcode != IORING_UNREGISTER_XDEV_EXT_UMEM &&
	     opcode != IORING_REGISTER_XDEV_EXT_MECH) ||
	    fd < 0 || fd >= MECH_MODEL_MAX_FDS)
		return real_syscall(SYS_io_uring_register, fd, opcode, argument,
				    count);
	pthread_mutex_lock(&mech_model_lock);
	ring = &mech_model_rings[fd];
	if (opcode != IORING_REGISTER_XDEV_EXT_MECH)
		mech_model_counts.modelled_ops++;
	if (opcode == IORING_REGISTER_XDEV_EXT_UMEM) {
		const struct io_uring_xdev_ext_umem_reg *reg =
			(const void *)(uintptr_t)argument;

		if (!reg || count != 1 || !reg->addr || !reg->size) {
			ret = mech_model_fail(EINVAL);
		} else {
			/* A ring descriptor number is reused after close. */
			memset(ring, 0, sizeof(*ring));
			ring->umem = reg->addr;
			ring->umem_size = reg->size;
			ring->sink = -1;
		}
	} else if (opcode == IORING_UNREGISTER_XDEV_EXT_UMEM) {
		ring->umem = 0;
		ring->umem_size = 0;
	} else if (!argument || count != 1) {
		ret = mech_model_fail(EINVAL);
	} else {
		ret = mech_model_control(ring, (const void *)(uintptr_t)argument);
	}
	pthread_mutex_unlock(&mech_model_lock);
	return ret;
}

long syscall(long number, ...)
{
	va_list args;
	long a[6];
	int i;

	pthread_once(&mech_model_once, mech_model_init);
	va_start(args, number);
	for (i = 0; i < 6; i++)
		a[i] = va_arg(args, long);
	va_end(args);
	if (number == SYS_io_uring_register)
		return mech_model_register(a[0], a[1], a[2], a[3]);
	return real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}

void xdev_ext_mech_model_counts(struct xdev_ext_mech_model_counts *out)
{
	pthread_mutex_lock(&mech_model_lock);
	*out = mech_model_counts;
	pthread_mutex_unlock(&mech_model_lock);
}

__attribute__((destructor)) static void mech_model_fini(void)
{
	char line[256];
	int length;

	pthread_once(&mech_model_once, mech_model_init);
	if (!mech_model_summary)
		return;
	length = snprintf(line, sizeof(line),
			  "XDEV_EXT_MECH_MODEL_SUMMARY pid=%ld creates=%llu "
			  "starts=%llu stops=%llu stop_failures=%llu\n",
			  (long)getpid(),
			  (unsigned long long)mech_model_counts.creates,
			  (unsigned long long)mech_model_counts.starts,
			  (unsigned long long)mech_model_counts.stops,
			  (unsigned long long)mech_model_counts.stop_failures);
	if (length > 0 && (size_t)length < sizeof(line))
		(void)real_syscall(SYS_write, STDERR_FILENO, (long)line,
				   (long)length, 0, 0, 0);
}
