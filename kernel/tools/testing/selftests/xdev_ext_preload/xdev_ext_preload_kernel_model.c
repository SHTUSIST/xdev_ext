// SPDX-License-Identifier: GPL-2.0
/*
 * Test-only userspace model of a matching kernel for the transparent preload
 * front end, so that a stock host can execute the front end's takeover path.
 * Load it after the front end:
 *
 *   LD_PRELOAD=libio_uring_unified.so:libxdev_ext_preload_kernel_model.so
 *
 * It interposes syscall(3), which the front end uses for statx,
 * io_uring_register and io_uring_enter.  Every behaviour is opt-in:
 *
 *   XDEV_EXT_MODEL_DIOALIGN=<mem>:<offset>
 *	Report STATX_DIOALIGN for regular files when the host kernel does not,
 *	and replace the values the host kernel reports when the model's are at
 *	least as strict (each a multiple of the host's non-zero value), so a
 *	test can run at a stricter alignment than the host's device needs.
 *   XDEV_EXT_MODEL_UMEM=1
 *	Accept IORING_REGISTER_XDEV_EXT_UMEM/IORING_UNREGISTER_XDEV_EXT_UMEM on a real
 *	io_uring and complete each published READ_COMPAT/WRITE_COMPAT SQE with
 *	pread64/pwrite64 on the SQE's descriptor, offset and registered bytes,
 *	updating io_uring_unified_shared as the kernel does.  A published
 *	connected-socket SEND (no IOSQE_XDEV_EXT_UMEM) is completed with send(2) on
 *	the SQE's descriptor, user buffer, length and flags.  Without it the
 *	host kernel answers the registration (a stock kernel rejects it, a
 *	matching kernel accepts it).
 *   XDEV_EXT_MODEL_REJECT_UMEM=1
 *	Fail every IORING_REGISTER_XDEV_EXT_UMEM with EINVAL, as a stock kernel
 *	does, without passing it to the host kernel, so a test of the rejected
 *	path does not depend on the host.  A held registration is held first.
 *	It takes precedence over XDEV_EXT_MODEL_UMEM=1.
 *   XDEV_EXT_MODEL_EINTR=1
 *	Accept each request, then fail that io_uring_enter with EINTR; the CQE
 *	is posted by the next io_uring_enter.
 *   XDEV_EXT_MODEL_SQ_BUSY=1
 *	With XDEV_EXT_MODEL_UMEM=1, leave one unconsumed entry in the SQ of each
 *	ring right after its XDEV_EXT_UMEM registration, so the front end finds the
 *	SQ busy and refuses every publication on that ring (pre-publication
 *	fallback).  The entry is never submitted.
 *   XDEV_EXT_MODEL_SUMMARY=1
 *	Print one XDEV_EXT_MODEL_SUMMARY line per process at exit.
 *   XDEV_EXT_MODEL_IO_URING_SETUP_ERRNO=<errno>
 *	Fail every io_uring_setup with that errno, as a kernel built without
 *	io_uring (ENOSYS), kernel.io_uring_disabled=2 or a seccomp filter
 *	(EPERM) does.
 *   XDEV_EXT_MODEL_RING128=fd-only|ring-fds|reject (unset = fd-only)
 *	The host (5.15) has no 128-byte SQEs, IORING_SETUP_NO_MMAP or
 *	registered ring descriptors, so every io_uring_setup that asks for
 *	SQE128, CQE32, NO_MMAP or REGISTERED_FD_ONLY is simulated in full,
 *	with the Linux 6.16 ring layout (struct io_rings and rings_size()).
 *	fd-only behaves as 6.5+: rings in the caller's pages, a registered-ring
 *	index instead of a descriptor.  ring-fds behaves as 5.19-6.4: NO_MMAP
 *	and REGISTERED_FD_ONLY fail with EINVAL, a plain setup returns a memfd
 *	(rings at offset 0, SQEs at IORING_OFF_SQES; IORING_OFF_CQ_RING is not
 *	aliased, so callers must rely on IORING_FEAT_SINGLE_MMAP).  reject
 *	behaves as a kernel without SQE128.  On simulated rings the model
 *	implements IORING_REGISTER_RING_FDS, IORING_UNREGISTER_RING_FDS (a
 *	per-thread table, empty in a fork child and dropped when the thread
 *	exits, as current->io_uring),
 *	IORING_REGISTER_FILES with -1 slots, IORING_UNREGISTER_FILES and
 *	IORING_REGISTER_FILES_UPDATE (each slot keeps a model-private dup),
 *	IORING_REGISTER_USE_REGISTERED_RING, IORING_ENTER_REGISTERED_RING, and
 *	executes IORING_OP_NOP, IORING_OP_WRITE and IORING_OP_URING_CMD (which
 *	fails with EOPNOTSUPP, as on a file without ->uring_cmd).
 *	XDEV_EXT_MODEL_EINTR=1 applies to these rings too.  Setups that ask for
 *	none of the four flags still reach the host unchanged.
 *
 * It also interposes fcntl, fstat, readlink and close only to count, per
 * thread, the descriptor calls made between xdev_ext_model_count_calls_begin() and
 * xdev_ext_model_count_calls_end().  Those calls always run unchanged.  It also
 * counts close() calls that fail with EBADF, the sign of a descriptor closed
 * twice (xdev_ext_model_ebadf_closes()), and on request holds the next close() of
 * any thread before it reaches libc (xdev_ext_model_block_next_close()).  A
 * close() of a simulated ring's memfd also drops the model's reference.
 *
 * The model never decides whether a call is admitted; the front end does.  It
 * is not evidence that the custom opcode works; the KVM harness provides that.
 */
#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "../../../../include/uapi/linux/io_uring.h"
#define statx_timestamp xdev_ext_kernel_statx_timestamp
#define statx xdev_ext_kernel_statx
#include "../../../../include/uapi/linux/stat.h"
#undef statx
#undef statx_timestamp

#define MODEL_MAX_RINGS 1024
#define MODEL_BLOCK_TIMEOUT_NS (10ULL * 1000 * 1000 * 1000)

struct model_ring {
	pid_t owner;
	bool registered;
	struct io_uring_params params;
	unsigned char *sq_ring;
	size_t sq_size;
	unsigned char *cq_ring;
	size_t cq_size;
	struct io_uring_sqe *sqes;
	size_t sqes_size;
	unsigned char *umem;
	uint64_t umem_size;
	struct io_uring_unified_shared *shared;
	bool pending;
	uint64_t pending_user_data;
	int32_t pending_result;
};

struct model_counters {
	pid_t owner;
	uint64_t read_sqes;
	uint64_t write_sqes;
	uint64_t send_sqes;
	uint64_t other_sqes;
	uint64_t eintr_returned;
	uint64_t ring128_setups;
	uint64_t ring128_sqes;
};

/*
 * struct io_rings of include/linux/io_uring_types.h on x86-64: cqes[] is
 * ____cacheline_aligned_in_smp, so the header is one 64-byte line.
 */
struct model_io_rings {
	struct {
		uint32_t head;
		uint32_t tail;
	} sq, cq;
	uint32_t sq_ring_mask, cq_ring_mask;
	uint32_t sq_ring_entries, cq_ring_entries;
	uint32_t sq_dropped;
	uint32_t sq_flags;
	uint32_t cq_flags;
	uint32_t cq_overflow;
	unsigned char cqes[] __attribute__((aligned(64)));
};

_Static_assert(sizeof(struct model_io_rings) == 64, "struct io_rings header");
_Static_assert(offsetof(struct model_io_rings, cqes) == 64, "io_rings cqes");

/* IO_RINGFD_REG_MAX, IORING_MAX_ENTRIES, IORING_MAX_CQ_ENTRIES */
#define MODEL_R128_TASK_SLOTS 16U
#define MODEL_R128_MAX_ENTRIES 32768U
#define MODEL_R128_MAX_CQ_ENTRIES (2U * MODEL_R128_MAX_ENTRIES)
#define MODEL_R128_MAX_RINGS 64
#define MODEL_R128_MAX_FILES 64U
/* A setup asking for any of these cannot be served by the 5.15 host. */
#define MODEL_R128_SIMULATED_FLAGS (IORING_SETUP_SQE128 | IORING_SETUP_CQE32 | \
				    IORING_SETUP_NO_MMAP | \
				    IORING_SETUP_REGISTERED_FD_ONLY)
/* io_uring_setup() in io_uring/io_uring.c accepts exactly these. */
#define MODEL_R128_KERNEL_FLAGS (IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL | \
				 IORING_SETUP_SQ_AFF | IORING_SETUP_CQSIZE | \
				 IORING_SETUP_CLAMP | IORING_SETUP_ATTACH_WQ | \
				 IORING_SETUP_R_DISABLED | \
				 IORING_SETUP_SUBMIT_ALL | \
				 IORING_SETUP_COOP_TASKRUN | \
				 IORING_SETUP_TASKRUN_FLAG | \
				 IORING_SETUP_SQE128 | IORING_SETUP_CQE32 | \
				 IORING_SETUP_SINGLE_ISSUER | \
				 IORING_SETUP_DEFER_TASKRUN | \
				 IORING_SETUP_NO_MMAP | \
				 IORING_SETUP_REGISTERED_FD_ONLY | \
				 IORING_SETUP_NO_SQARRAY | \
				 IORING_SETUP_HYBRID_IOPOLL)
/* The subset whose behaviour the model reproduces. */
#define MODEL_R128_SUPPORTED_FLAGS (MODEL_R128_SIMULATED_FLAGS | \
				    IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP | \
				    IORING_SETUP_SUBMIT_ALL | \
				    IORING_SETUP_COOP_TASKRUN | \
				    IORING_SETUP_SINGLE_ISSUER)
/* io_uring_enter() in io_uring/io_uring.c accepts exactly these. */
#define MODEL_R128_ENTER_FLAGS (IORING_ENTER_GETEVENTS | \
				IORING_ENTER_SQ_WAKEUP | IORING_ENTER_SQ_WAIT | \
				IORING_ENTER_EXT_ARG | \
				IORING_ENTER_REGISTERED_RING | \
				IORING_ENTER_ABS_TIMER | \
				IORING_ENTER_EXT_ARG_REG | \
				IORING_ENTER_NO_IOWAIT)

enum model_r128_mode {
	MODEL_R128_FD_ONLY,
	MODEL_R128_RING_FDS,
	MODEL_R128_REJECT,
};

struct model_r128_file {
	int fd;			/* model-private dup, -1 = empty slot */
};

struct model_r128 {
	bool used;
	pid_t owner;
	unsigned int flags;
	unsigned int sq_entries;
	unsigned int cq_entries;
	unsigned int sqe_size;
	unsigned int cqe_size;
	struct io_uring_params params;
	unsigned char *rings;	/* the caller's pages, or the model's view */
	size_t rings_len;
	unsigned char *sqes;
	size_t sqes_len;
	bool own_views;		/* rings/sqes are the model's memfd mappings */
	int fd;			/* caller-visible memfd, -1 once closed */
	dev_t fd_dev;
	ino_t fd_ino;
	unsigned int nregs;	/* registered-ring slots naming this ring */
	uint32_t sq_head;	/* the kernel's cached SQ head and CQ tail */
	uint32_t cq_tail;
	unsigned int nr_files;	/* 0 = no fixed-file table */
	struct model_r128_file files[MODEL_R128_MAX_FILES];
	bool pending;
	uint64_t pending_user_data;
	int32_t pending_result;
};

/* current->io_uring: one per thread, none in a fork child. */
struct model_r128_task {
	pid_t owner;
	struct model_r128 *slots[MODEL_R128_TASK_SLOTS];
};

typedef long (*model_syscall_fn)(long, ...);

static model_syscall_fn real_syscall;
static int (*real_fcntl)(int, int, ...);
static int (*real_fstat)(int, struct stat *);
static ssize_t (*real_readlink)(const char *, char *, size_t);
static int (*real_close)(int);
static __thread bool model_counting;
static __thread uint64_t model_counted_calls;
static uint64_t model_ebadf_closes;
static pthread_once_t model_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t model_lock = PTHREAD_MUTEX_INITIALIZER;
static struct model_ring model_rings[MODEL_MAX_RINGS];
static struct model_counters model_counts;
static bool model_umem;
static bool model_reject_umem;
static bool model_eintr;
static bool model_sq_busy;
static bool model_summary;
static uint32_t model_dio_mem;
static uint32_t model_dio_offset;
static int model_setup_errno;
static enum model_r128_mode model_r128_mode;
static struct model_r128 model_r128_rings[MODEL_R128_MAX_RINGS];
static unsigned int model_r128_fd_rings;	/* rings with a memfd number */
static __thread struct model_r128_task model_r128_task;
static pthread_once_t model_r128_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t model_r128_key;
static int model_r128_key_error;

static long model_r128_result(long ret);
static long model_r128_setup(long entries, long params);
static struct model_r128 *model_r128_by_fd(long fd);
static long model_r128_registered(long index, struct model_r128 **ring);
static long model_r128_register(struct model_r128 *ring, unsigned int opcode,
				long argument, long count);
static bool block_armed;
static bool block_register_armed;
static bool block_close_armed;
static bool block_reached;
static bool block_released;

static bool model_env_is_one(const char *name)
{
	const char *value = getenv(name);

	return value && !strcmp(value, "1");
}

static void model_init(void)
{
	const char *alignment = getenv("XDEV_EXT_MODEL_DIOALIGN");
	const char *setup_errno = getenv("XDEV_EXT_MODEL_IO_URING_SETUP_ERRNO");
	const char *ring128 = getenv("XDEV_EXT_MODEL_RING128");

	*(void **)&real_syscall = dlsym(RTLD_NEXT, "syscall");
	*(void **)&real_fcntl = dlsym(RTLD_NEXT, "fcntl");
	*(void **)&real_fstat = dlsym(RTLD_NEXT, "fstat");
	*(void **)&real_readlink = dlsym(RTLD_NEXT, "readlink");
	*(void **)&real_close = dlsym(RTLD_NEXT, "close");
	model_umem = model_env_is_one("XDEV_EXT_MODEL_UMEM");
	model_reject_umem = model_env_is_one("XDEV_EXT_MODEL_REJECT_UMEM");
	model_eintr = model_env_is_one("XDEV_EXT_MODEL_EINTR");
	model_sq_busy = model_env_is_one("XDEV_EXT_MODEL_SQ_BUSY");
	model_summary = model_env_is_one("XDEV_EXT_MODEL_SUMMARY");
	if (alignment &&
	    sscanf(alignment, "%" SCNu32 ":%" SCNu32, &model_dio_mem,
		   &model_dio_offset) != 2) {
		model_dio_mem = 0;
		model_dio_offset = 0;
	}
	if (setup_errno)
		model_setup_errno = atoi(setup_errno);
	if (!ring128 || !strcmp(ring128, "fd-only")) {
		model_r128_mode = MODEL_R128_FD_ONLY;
	} else if (!strcmp(ring128, "ring-fds")) {
		model_r128_mode = MODEL_R128_RING_FDS;
	} else if (!strcmp(ring128, "reject")) {
		model_r128_mode = MODEL_R128_REJECT;
	} else {
		fprintf(stderr, "XDEV_EXT_MODEL_RING128=%s is not fd-only, ring-fds "
			"or reject\n", ring128);
		abort();
	}
}

/* Counters and ring views belong to one process; a fork child starts empty. */
static struct model_counters *model_counters_locked(void)
{
	if (model_counts.owner != getpid()) {
		memset(&model_counts, 0, sizeof(model_counts));
		model_counts.owner = getpid();
	}
	return &model_counts;
}

enum model_counter {
	MODEL_READ_SQE,
	MODEL_WRITE_SQE,
	MODEL_SEND_SQE,
	MODEL_OTHER_SQE,
	MODEL_EINTR_RETURNED,
	MODEL_R128_SETUP,
	MODEL_R128_SQE,
};

static void model_count(enum model_counter which)
{
	struct model_counters *counts;

	pthread_mutex_lock(&model_lock);
	counts = model_counters_locked();
	switch (which) {
	case MODEL_READ_SQE:
		counts->read_sqes++;
		break;
	case MODEL_WRITE_SQE:
		counts->write_sqes++;
		break;
	case MODEL_SEND_SQE:
		counts->send_sqes++;
		break;
	case MODEL_OTHER_SQE:
		counts->other_sqes++;
		break;
	case MODEL_EINTR_RETURNED:
		counts->eintr_returned++;
		break;
	case MODEL_R128_SETUP:
		counts->ring128_setups++;
		break;
	case MODEL_R128_SQE:
		counts->ring128_sqes++;
		break;
	}
	pthread_mutex_unlock(&model_lock);
}

__attribute__((destructor)) static void model_report(void)
{
	struct model_counters snapshot;

	if (!model_summary)
		return;
	pthread_mutex_lock(&model_lock);
	snapshot = *model_counters_locked();
	pthread_mutex_unlock(&model_lock);
	fprintf(stderr,
		"XDEV_EXT_MODEL_SUMMARY pid=%ld read_sqes=%" PRIu64
		" write_sqes=%" PRIu64 " other_sqes=%" PRIu64
		" eintr_returned=%" PRIu64 " send_sqes=%" PRIu64,
		(long)getpid(), snapshot.read_sqes, snapshot.write_sqes,
		snapshot.other_sqes, snapshot.eintr_returned,
		snapshot.send_sqes);
	/* Only processes that asked for a 128-byte SQE ring get these. */
	if (snapshot.ring128_setups)
		fprintf(stderr, " ring128_setups=%" PRIu64
			" ring128_sqes=%" PRIu64, snapshot.ring128_setups,
			snapshot.ring128_sqes);
	fputc('\n', stderr);
}

static void model_unmap_locked(struct model_ring *ring)
{
	if (ring->owner == getpid()) {
		if (ring->sq_ring)
			munmap(ring->sq_ring, ring->sq_size);
		if (ring->cq_ring)
			munmap(ring->cq_ring, ring->cq_size);
		if (ring->sqes)
			munmap(ring->sqes, ring->sqes_size);
	}
	memset(ring, 0, sizeof(*ring));
}

static struct model_ring *model_registered_ring(long fd)
{
	struct model_ring *ring = NULL;

	if (fd < 0 || fd >= MODEL_MAX_RINGS)
		return NULL;
	pthread_mutex_lock(&model_lock);
	if (model_rings[fd].owner == getpid() && model_rings[fd].registered)
		ring = &model_rings[fd];
	pthread_mutex_unlock(&model_lock);
	return ring;
}

/*
 * Linux 6.1 and later report STATX_DIOALIGN themselves.  Replacing their
 * values only with ones at least as strict keeps every request the model
 * admits valid on the host's device; 0 (no direct I/O) is kept.
 */
static bool model_dioalign_applies(const struct xdev_ext_kernel_statx *stx)
{
	if (!(stx->stx_mask & STATX_DIOALIGN))
		return true;
	return stx->stx_dio_mem_align && stx->stx_dio_offset_align &&
	       !(model_dio_mem % stx->stx_dio_mem_align) &&
	       !(model_dio_offset % stx->stx_dio_offset_align);
}

static long model_statx(long dirfd, long path, long flags, long mask,
			long buffer)
{
	struct xdev_ext_kernel_statx *stx = (struct xdev_ext_kernel_statx *)buffer;
	long ret;

	ret = real_syscall(SYS_statx, dirfd, path, flags, mask, buffer);
	if (ret || !stx || !model_dio_mem || !model_dio_offset ||
	    !((unsigned long)mask & STATX_DIOALIGN) ||
	    !(stx->stx_mask & STATX_TYPE) || !S_ISREG(stx->stx_mode) ||
	    !model_dioalign_applies(stx))
		return ret;
	stx->stx_mask |= STATX_DIOALIGN;
	stx->stx_dio_mem_align = model_dio_mem;
	stx->stx_dio_offset_align = model_dio_offset;
	return ret;
}

static long model_setup(long entries, long params)
{
	long fd;

	if (model_setup_errno > 0) {
		errno = model_setup_errno;
		return -1;
	}
	if (params && (((struct io_uring_params *)params)->flags &
		       MODEL_R128_SIMULATED_FLAGS))
		return model_r128_result(model_r128_setup(entries, params));
	fd = real_syscall(SYS_io_uring_setup, entries, params);

	if (fd >= 0 && fd < MODEL_MAX_RINGS && params) {
		pthread_mutex_lock(&model_lock);
		model_unmap_locked(&model_rings[fd]);
		model_rings[fd].owner = getpid();
		model_rings[fd].params = *(struct io_uring_params *)params;
		pthread_mutex_unlock(&model_lock);
	}
	return fd;
}

static void *model_map(long fd, size_t size, off_t offset)
{
	void *view = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
			  (int)fd, offset);

	return view == MAP_FAILED ? NULL : view;
}

static uint64_t model_now_ns(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

/*
 * Hold one accepted request "in flight", one XDEV_EXT_UMEM registration, or one
 * close(), until the test releases it.  The wait deliberately uses no
 * cancellation point: a real io_uring_enter or io_uring_register is not one
 * either, and a held close() acts on a pending request only when it reaches
 * libc's close(), as an unheld one does at its entry.
 */
static bool model_block_if_armed(bool *armed_flag)
{
	uint64_t deadline;
	bool armed;

	pthread_mutex_lock(&model_lock);
	armed = __atomic_load_n(armed_flag, __ATOMIC_RELAXED);
	if (armed) {
		__atomic_store_n(armed_flag, false, __ATOMIC_RELAXED);
		block_reached = true;
	}
	pthread_mutex_unlock(&model_lock);
	if (!armed)
		return true;
	deadline = model_now_ns() + MODEL_BLOCK_TIMEOUT_NS;
	while (!__atomic_load_n(&block_released, __ATOMIC_ACQUIRE)) {
		if (model_now_ns() > deadline)
			return false;
		sched_yield();
	}
	return true;
}

/* XDEV_EXT_MODEL_SQ_BUSY: one entry that is never submitted stays in the SQ. */
static void model_leave_sq_entry(struct model_ring *ring)
{
	unsigned int *tail = (unsigned int *)(ring->sq_ring +
					      ring->params.sq_off.tail);

	__atomic_store_n(tail, __atomic_load_n(tail, __ATOMIC_RELAXED) + 1,
			 __ATOMIC_RELEASE);
}

static long model_register(long fd, long opcode, long argument, long count)
{
	const struct io_uring_xdev_ext_umem_reg *reg = (const void *)argument;
	unsigned int op = (unsigned int)opcode;
	struct model_r128 *ring128 = NULL;
	struct model_ring *ring;
	long ret = 0;

	/* Registered ring indices exist only on simulated rings. */
	if (op & IORING_REGISTER_USE_REGISTERED_RING) {
		ret = model_r128_registered(fd, &ring128);
		if (ret)
			return model_r128_result(ret);
	} else {
		ring128 = model_r128_by_fd(fd);
	}
	if (ring128)
		return model_r128_result(model_r128_register(
			ring128, op & ~(unsigned int)IORING_REGISTER_USE_REGISTERED_RING,
			argument, count));
	/* Also held when the host kernel or XDEV_EXT_MODEL_REJECT_UMEM answers. */
	if (opcode == IORING_REGISTER_XDEV_EXT_UMEM &&
	    !model_block_if_armed(&block_register_armed)) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (model_reject_umem && opcode == IORING_REGISTER_XDEV_EXT_UMEM) {
		errno = EINVAL;
		return -1;
	}
	if (!model_umem || fd < 0 || fd >= MODEL_MAX_RINGS ||
	    (opcode != IORING_REGISTER_XDEV_EXT_UMEM &&
	     opcode != IORING_UNREGISTER_XDEV_EXT_UMEM))
		return real_syscall(SYS_io_uring_register, fd, opcode, argument,
				    count);
	pthread_mutex_lock(&model_lock);
	ring = &model_rings[fd];
	if (ring->owner != getpid()) {
		ret = -EBADF;
	} else if (opcode == IORING_UNREGISTER_XDEV_EXT_UMEM) {
		if (!ring->registered)
			ret = -ENXIO;
		ring->registered = false;
	} else if (ring->registered) {
		ret = -EBUSY;
	} else if (count != 1 || !reg || !reg->addr || !reg->size ||
		   !reg->shared_addr || reg->flags || !reg->frame_size ||
		   (reg->frame_size & (reg->frame_size - 1))) {
		ret = -EINVAL;
	} else {
		struct io_uring_params *p = &ring->params;

		ring->sq_size = p->sq_off.array + p->sq_entries * sizeof(__u32);
		ring->cq_size = p->cq_off.cqes +
				p->cq_entries * sizeof(struct io_uring_cqe);
		ring->sqes_size = p->sq_entries * sizeof(struct io_uring_sqe);
		ring->sq_ring = model_map(fd, ring->sq_size, IORING_OFF_SQ_RING);
		ring->cq_ring = model_map(fd, ring->cq_size, IORING_OFF_CQ_RING);
		ring->sqes = model_map(fd, ring->sqes_size, IORING_OFF_SQES);
		if (!ring->sq_ring || !ring->cq_ring || !ring->sqes) {
			pid_t owner = ring->owner;
			struct io_uring_params saved = ring->params;

			model_unmap_locked(ring);
			ring->owner = owner;
			ring->params = saved;
			ret = -ENOMEM;
		} else {
			ring->umem = (unsigned char *)(uintptr_t)reg->addr;
			ring->umem_size = reg->size;
			ring->shared = (void *)(uintptr_t)reg->shared_addr;
			ring->registered = true;
			if (model_sq_busy)
				model_leave_sq_entry(ring);
		}
	}
	pthread_mutex_unlock(&model_lock);
	if (ret < 0) {
		errno = (int)-ret;
		return -1;
	}
	return 0;
}

/* The kernel's user-visible statistics protocol: 0/1 lock, then fields. */
static void model_update_stats(struct io_uring_unified_shared *shared,
			       bool write, int32_t result)
{
	uint32_t expected = 0;

	if (!__atomic_compare_exchange_n(&shared->lock, &expected, 1, false,
					 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		return;
	if (result < 0) {
		if (write)
			shared->send_errors++;
		else
			shared->read_errors++;
	} else if (write) {
		shared->send_count++;
		shared->send_bytes += (uint64_t)result;
	} else {
		shared->read_count++;
		shared->read_bytes += (uint64_t)result;
	}
	__atomic_store_n(&shared->lock, 0, __ATOMIC_RELEASE);
}

/*
 * The front end's connected-socket SEND: user buffer in addr, length in
 * rw_flags, send flags in off and the statistics page in addr3.
 */
static int32_t model_send(const struct io_uring_sqe *sqe)
{
	long ret;

	model_count(MODEL_SEND_SQE);
	ret = real_syscall(SYS_sendto, (long)sqe->fd, (long)sqe->addr,
			   (long)sqe->rw_flags, (long)sqe->off, 0L, 0L);
	if (ret < 0)
		ret = -errno;
	if (sqe->addr3)
		model_update_stats((void *)(uintptr_t)sqe->addr3, true,
				   (int32_t)ret);
	return (int32_t)ret;
}

static int32_t model_execute(struct model_ring *ring,
			     const struct io_uring_sqe *sqe)
{
	bool write = sqe->len == IO_UNIFIED_OP_WRITE_COMPAT;
	uint32_t count = sqe->rw_flags;
	long ret;

	if (sqe->opcode == IORING_OP_UNIFIED_OPS &&
	    sqe->len == IO_UNIFIED_OP_SEND && !(sqe->flags & IOSQE_XDEV_EXT_UMEM))
		return model_send(sqe);
	if (sqe->opcode != IORING_OP_UNIFIED_OPS ||
	    !(sqe->flags & IOSQE_XDEV_EXT_UMEM) ||
	    (sqe->len != IO_UNIFIED_OP_READ_COMPAT && !write)) {
		model_count(MODEL_OTHER_SQE);
		return -EINVAL;
	}
	model_count(write ? MODEL_WRITE_SQE : MODEL_READ_SQE);
	if (sqe->addr > ring->umem_size || count > ring->umem_size - sqe->addr)
		return -EINVAL;
	ret = real_syscall(write ? SYS_pwrite64 : SYS_pread64, (long)sqe->fd,
			   (long)(uintptr_t)(ring->umem + sqe->addr), (long)count,
			   (long)sqe->off);
	if (ret < 0)
		ret = -errno;
	model_update_stats(ring->shared, write, (int32_t)ret);
	return (int32_t)ret;
}

static void model_post(struct model_ring *ring, uint64_t user_data,
		       int32_t result)
{
	struct io_uring_params *p = &ring->params;
	unsigned int *tail = (unsigned int *)(ring->cq_ring + p->cq_off.tail);
	unsigned int *mask = (unsigned int *)(ring->cq_ring +
					      p->cq_off.ring_mask);
	struct io_uring_cqe *cqes =
		(struct io_uring_cqe *)(ring->cq_ring + p->cq_off.cqes);
	unsigned int now = __atomic_load_n(tail, __ATOMIC_RELAXED);
	struct io_uring_cqe *cqe = &cqes[now & *mask];

	cqe->user_data = user_data;
	cqe->res = result;
	cqe->flags = 0;
	__atomic_store_n(tail, now + 1, __ATOMIC_RELEASE);
}

static long model_enter(struct model_ring *ring, long to_submit)
{
	struct io_uring_params *p = &ring->params;
	unsigned int *head = (unsigned int *)(ring->sq_ring + p->sq_off.head);
	unsigned int *tail = (unsigned int *)(ring->sq_ring + p->sq_off.tail);
	unsigned int *mask = (unsigned int *)(ring->sq_ring +
					      p->sq_off.ring_mask);
	unsigned int *array = (unsigned int *)(ring->sq_ring + p->sq_off.array);
	unsigned int now;
	long submitted = 0;

	if (ring->pending) {
		ring->pending = false;
		model_post(ring, ring->pending_user_data, ring->pending_result);
		return 0;
	}
	now = __atomic_load_n(head, __ATOMIC_RELAXED);
	while (submitted < to_submit &&
	       now != __atomic_load_n(tail, __ATOMIC_ACQUIRE)) {
		struct io_uring_sqe sqe = ring->sqes[array[now & *mask] & *mask];
		int32_t result;

		/* The kernel consumes the entry before it executes it. */
		__atomic_store_n(head, ++now, __ATOMIC_RELEASE);
		submitted++;
		if (!model_block_if_armed(&block_armed)) {
			errno = ETIMEDOUT;
			return -1;
		}
		result = model_execute(ring, &sqe);
		if (model_eintr) {
			ring->pending = true;
			ring->pending_user_data = sqe.user_data;
			ring->pending_result = result;
			model_count(MODEL_EINTR_RETURNED);
			errno = EINTR;
			return -1;
		}
		model_post(ring, sqe.user_data, result);
	}
	return submitted;
}

/*
 * XDEV_EXT_MODEL_RING128: a Linux 6.16 io_uring with 128-byte SQEs, simulated.
 * Locking: model_lock covers the ring table, reference counts and fixed-file
 * slots; ring memory and the per-thread task table belong to one thread, as
 * a registered ring index does in the kernel.
 */
static long model_r128_result(long ret)
{
	if (ret < 0) {
		errno = (int)-ret;
		return -1;
	}
	return ret;
}

static void model_r128_put_locked(struct model_r128 *ring);

/* Task exit drops the registered rings (io_uring_unreg_ringfd()). */
static void model_r128_task_exit(void *opaque)
{
	struct model_r128_task *task = opaque;
	unsigned int i;

	if (task->owner != getpid())
		return;
	pthread_mutex_lock(&model_lock);
	for (i = 0; i < MODEL_R128_TASK_SLOTS; i++) {
		struct model_r128 *ring = task->slots[i];

		task->slots[i] = NULL;
		if (ring && ring->used && ring->owner == getpid()) {
			ring->nregs--;
			model_r128_put_locked(ring);
		}
	}
	pthread_mutex_unlock(&model_lock);
}

static void model_r128_make_key(void)
{
	model_r128_key_error = pthread_key_create(&model_r128_key,
						  model_r128_task_exit);
}

static struct model_r128_task *model_r128_tctx(bool create)
{
	if (model_r128_task.owner != getpid()) {
		if (!create)
			return NULL;
		memset(&model_r128_task, 0, sizeof(model_r128_task));
		model_r128_task.owner = getpid();
		pthread_once(&model_r128_key_once, model_r128_make_key);
		if (!model_r128_key_error)
			pthread_setspecific(model_r128_key, &model_r128_task);
	}
	return &model_r128_task;
}

static size_t model_page_align(size_t length)
{
	size_t page = (size_t)sysconf(_SC_PAGESIZE);

	return (length + page - 1) & ~(page - 1);
}

static uint32_t model_roundup_pow2(uint32_t value)
{
	uint32_t result = 1;

	while (result < value)
		result <<= 1;
	return result;
}

static struct model_io_rings *model_r128_header(const struct model_r128 *ring)
{
	return (struct model_io_rings *)ring->rings;
}

/* A ring with a caller-visible memfd, identified by number and inode. */
static struct model_r128 *model_r128_by_fd(long fd)
{
	struct model_r128 *found = NULL;
	struct stat st;
	int i;

	if (fd < 0 || !__atomic_load_n(&model_r128_fd_rings, __ATOMIC_RELAXED) ||
	    real_fstat((int)fd, &st))
		return NULL;
	pthread_mutex_lock(&model_lock);
	for (i = 0; i < MODEL_R128_MAX_RINGS; i++) {
		struct model_r128 *ring = &model_r128_rings[i];

		if (ring->used && ring->owner == getpid() && ring->fd == fd &&
		    ring->fd_dev == st.st_dev && ring->fd_ino == st.st_ino) {
			found = ring;
			break;
		}
	}
	pthread_mutex_unlock(&model_lock);
	return found;
}

/* io_uring_register_get_file() and io_uring_enter() for a registered index. */
static long model_r128_registered(long index, struct model_r128 **ring)
{
	struct model_r128_task *task = model_r128_tctx(false);

	if (!task || index < 0 || index >= (long)MODEL_R128_TASK_SLOTS)
		return -EINVAL;
	*ring = task->slots[index];
	return *ring ? 0 : -EBADF;
}

static void model_r128_clear_files_locked(struct model_r128 *ring)
{
	unsigned int i;

	for (i = 0; i < ring->nr_files; i++)
		if (ring->files[i].fd >= 0)
			real_close(ring->files[i].fd);
	ring->nr_files = 0;
}

static void model_r128_free_locked(struct model_r128 *ring)
{
	if (ring->owner == getpid()) {
		if (ring->own_views) {
			munmap(ring->rings, ring->rings_len);
			munmap(ring->sqes, ring->sqes_len);
		}
		model_r128_clear_files_locked(ring);
		if (ring->fd >= 0)
			__atomic_sub_fetch(&model_r128_fd_rings, 1,
					   __ATOMIC_RELAXED);
	}
	memset(ring, 0, sizeof(*ring));
}

/* The ring dies with its last descriptor and its last registration. */
static void model_r128_put_locked(struct model_r128 *ring)
{
	if (ring->fd < 0 && !ring->nregs)
		model_r128_free_locked(ring);
}

static struct model_r128 *model_r128_alloc(void)
{
	struct model_r128 *ring = NULL;
	int i;

	pthread_mutex_lock(&model_lock);
	for (i = 0; i < MODEL_R128_MAX_RINGS; i++) {
		/* Entries a fork child inherited are reused without unmapping. */
		if (!model_r128_rings[i].used ||
		    model_r128_rings[i].owner != getpid()) {
			ring = &model_r128_rings[i];
			memset(ring, 0, sizeof(*ring));
			ring->used = true;
			ring->owner = getpid();
			ring->fd = -1;
			break;
		}
	}
	pthread_mutex_unlock(&model_lock);
	return ring;
}

/* io_create_region() with IORING_MEM_REGION_TYPE_USER: checks and "pin". */
static long model_r128_user_region(uint64_t user_addr, size_t size)
{
	size_t page = (size_t)sysconf(_SC_PAGESIZE);
	unsigned char present;
	size_t done;

	if (!user_addr)
		return -EFAULT;
	if ((user_addr | size) & (page - 1))
		return -EINVAL;
	for (done = 0; done < size; done += page)
		if (mincore((void *)(uintptr_t)(user_addr + done), page,
			    &present))
			return -EFAULT;
	return 0;
}

/* io_uring_fill_params() */
static long model_r128_fill_params(long entries, struct io_uring_params *p)
{
	if (entries <= 0)
		return -EINVAL;
	if (entries > (long)MODEL_R128_MAX_ENTRIES) {
		if (!(p->flags & IORING_SETUP_CLAMP))
			return -EINVAL;
		entries = MODEL_R128_MAX_ENTRIES;
	}
	p->sq_entries = model_roundup_pow2((uint32_t)entries);
	if (p->flags & IORING_SETUP_CQSIZE) {
		if (!p->cq_entries)
			return -EINVAL;
		if (p->cq_entries > MODEL_R128_MAX_CQ_ENTRIES) {
			if (!(p->flags & IORING_SETUP_CLAMP))
				return -EINVAL;
			p->cq_entries = MODEL_R128_MAX_CQ_ENTRIES;
		}
		p->cq_entries = model_roundup_pow2(p->cq_entries);
		if (p->cq_entries < p->sq_entries)
			return -EINVAL;
	} else {
		p->cq_entries = 2 * p->sq_entries;
	}
	p->sq_off.head = offsetof(struct model_io_rings, sq.head);
	p->sq_off.tail = offsetof(struct model_io_rings, sq.tail);
	p->sq_off.ring_mask = offsetof(struct model_io_rings, sq_ring_mask);
	p->sq_off.ring_entries = offsetof(struct model_io_rings,
					  sq_ring_entries);
	p->sq_off.flags = offsetof(struct model_io_rings, sq_flags);
	p->sq_off.dropped = offsetof(struct model_io_rings, sq_dropped);
	p->sq_off.resv1 = 0;
	if (!(p->flags & IORING_SETUP_NO_MMAP))
		p->sq_off.user_addr = 0;
	p->cq_off.head = offsetof(struct model_io_rings, cq.head);
	p->cq_off.tail = offsetof(struct model_io_rings, cq.tail);
	p->cq_off.ring_mask = offsetof(struct model_io_rings, cq_ring_mask);
	p->cq_off.ring_entries = offsetof(struct model_io_rings,
					  cq_ring_entries);
	p->cq_off.overflow = offsetof(struct model_io_rings, cq_overflow);
	p->cq_off.cqes = offsetof(struct model_io_rings, cqes);
	p->cq_off.flags = offsetof(struct model_io_rings, cq_flags);
	p->cq_off.resv1 = 0;
	if (!(p->flags & IORING_SETUP_NO_MMAP))
		p->cq_off.user_addr = 0;
	return 0;
}

/* rings_size(): the header and CQEs, all doubled for CQE32, then the array. */
static size_t model_r128_rings_size(unsigned int flags, unsigned int sq,
				    unsigned int cq, size_t *sq_array)
{
	size_t off = sizeof(struct model_io_rings) +
		     (size_t)cq * sizeof(struct io_uring_cqe);

	if (flags & IORING_SETUP_CQE32)
		off <<= 1;
	off = (off + 63) & ~(size_t)63;
	*sq_array = off;
	return off + (size_t)sq * sizeof(uint32_t);
}

static long model_r128_map_memfd(struct model_r128 *ring)
{
	int fd = memfd_create("[io_uring]", MFD_CLOEXEC);
	void *rings, *sqes;
	struct stat st;

	if (fd < 0)
		return -errno;
	if (ftruncate(fd, (off_t)(IORING_OFF_SQES + ring->sqes_len)) ||
	    real_fstat(fd, &st)) {
		long ret = -errno;

		real_close(fd);
		return ret;
	}
	rings = mmap(NULL, ring->rings_len, PROT_READ | PROT_WRITE, MAP_SHARED,
		     fd, (off_t)IORING_OFF_SQ_RING);
	sqes = mmap(NULL, ring->sqes_len, PROT_READ | PROT_WRITE, MAP_SHARED,
		    fd, (off_t)IORING_OFF_SQES);
	if (rings == MAP_FAILED || sqes == MAP_FAILED) {
		if (rings != MAP_FAILED)
			munmap(rings, ring->rings_len);
		if (sqes != MAP_FAILED)
			munmap(sqes, ring->sqes_len);
		real_close(fd);
		return -ENOMEM;
	}
	ring->rings = rings;
	ring->sqes = sqes;
	ring->own_views = true;
	ring->fd = fd;
	ring->fd_dev = st.st_dev;
	ring->fd_ino = st.st_ino;
	return 0;
}

/* io_uring_setup() -> io_uring_create(), for the flags the host lacks. */
static long model_r128_setup(long entries, long params)
{
	struct io_uring_params p;
	struct model_r128_task *task;
	struct model_r128 *ring;
	struct model_io_rings *header;
	size_t sq_array, rings_size;
	unsigned int i;
	long ret;

	model_count(MODEL_R128_SETUP);
	if (!params)
		return -EFAULT;
	memcpy(&p, (void *)params, sizeof(p));
	for (i = 0; i < sizeof(p.resv) / sizeof(p.resv[0]); i++)
		if (p.resv[i])
			return -EINVAL;
	if (p.flags & ~MODEL_R128_KERNEL_FLAGS)
		return -EINVAL;
	/* Older kernels do not know these flags at all. */
	if (model_r128_mode == MODEL_R128_REJECT ||
	    (model_r128_mode == MODEL_R128_RING_FDS &&
	     (p.flags & (IORING_SETUP_NO_MMAP |
			 IORING_SETUP_REGISTERED_FD_ONLY))))
		return -EINVAL;
	if (p.flags & ~MODEL_R128_SUPPORTED_FLAGS) {
		fprintf(stderr, "XDEV_EXT_MODEL_RING128: setup flags 0x%x are not "
			"simulated\n", p.flags & ~MODEL_R128_SUPPORTED_FLAGS);
		return -EINVAL;
	}
	/* io_uring_sanitise_params(): no way to mmap rings without an fd. */
	if ((p.flags & IORING_SETUP_REGISTERED_FD_ONLY) &&
	    !(p.flags & IORING_SETUP_NO_MMAP))
		return -EINVAL;
	ret = model_r128_fill_params(entries, &p);
	if (ret)
		return ret;
	ring = model_r128_alloc();
	if (!ring)
		return -ENOMEM;
	ring->flags = p.flags;
	ring->sq_entries = p.sq_entries;
	ring->cq_entries = p.cq_entries;
	ring->sqe_size = (p.flags & IORING_SETUP_SQE128) ? 128 : 64;
	ring->cqe_size = (p.flags & IORING_SETUP_CQE32) ? 32 : 16;
	rings_size = model_r128_rings_size(p.flags, p.sq_entries,
					   p.cq_entries, &sq_array);
	ring->rings_len = model_page_align(rings_size);
	ring->sqes_len = model_page_align((size_t)p.sq_entries *
					  ring->sqe_size);
	/* io_allocate_scq_urings(): the rings region, then the SQE region. */
	if (p.flags & IORING_SETUP_NO_MMAP) {
		ret = model_r128_user_region(p.cq_off.user_addr,
					     ring->rings_len);
		if (!ret)
			ret = model_r128_user_region(p.sq_off.user_addr,
						     ring->sqes_len);
		ring->rings = (unsigned char *)(uintptr_t)p.cq_off.user_addr;
		ring->sqes = (unsigned char *)(uintptr_t)p.sq_off.user_addr;
	} else {
		ret = model_r128_map_memfd(ring);
	}
	if (ret)
		goto fail;
	/* The kernel does not clear user-provided pages. */
	header = model_r128_header(ring);
	header->sq_ring_mask = p.sq_entries - 1;
	header->cq_ring_mask = p.cq_entries - 1;
	header->sq_ring_entries = p.sq_entries;
	header->cq_ring_entries = p.cq_entries;
	p.sq_off.array = (uint32_t)sq_array;
	p.features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP |
		     IORING_FEAT_SUBMIT_STABLE | IORING_FEAT_RW_CUR_POS |
		     IORING_FEAT_CUR_PERSONALITY | IORING_FEAT_FAST_POLL |
		     IORING_FEAT_POLL_32BITS | IORING_FEAT_SQPOLL_NONFIXED |
		     IORING_FEAT_EXT_ARG | IORING_FEAT_NATIVE_WORKERS |
		     IORING_FEAT_RSRC_TAGS | IORING_FEAT_CQE_SKIP |
		     IORING_FEAT_LINKED_FILE | IORING_FEAT_REG_REG_RING |
		     IORING_FEAT_RECVSEND_BUNDLE | IORING_FEAT_MIN_TIMEOUT |
		     IORING_FEAT_RW_ATTR | IORING_FEAT_NO_IOWAIT;
	ring->params = p;
	memcpy((void *)params, &p, sizeof(p));
	task = model_r128_tctx(true);
	if (p.flags & IORING_SETUP_REGISTERED_FD_ONLY) {
		/* io_ring_add_registered_file(tctx, file, 0, IO_RINGFD_REG_MAX) */
		for (i = 0; i < MODEL_R128_TASK_SLOTS; i++)
			if (!task->slots[i])
				break;
		if (i == MODEL_R128_TASK_SLOTS) {
			ret = -EBUSY;
			goto fail;
		}
		pthread_mutex_lock(&model_lock);
		task->slots[i] = ring;
		ring->nregs = 1;
		pthread_mutex_unlock(&model_lock);
		return i;
	}
	if (ring->fd < 0) {
		/* NO_MMAP without REGISTERED_FD_ONLY still installs an fd. */
		struct stat st;
		int fd = memfd_create("[io_uring]", MFD_CLOEXEC);

		if (fd < 0 || real_fstat(fd, &st)) {
			ret = -errno;
			if (fd >= 0)
				real_close(fd);
			goto fail;
		}
		ring->fd = fd;
		ring->fd_dev = st.st_dev;
		ring->fd_ino = st.st_ino;
	}
	__atomic_add_fetch(&model_r128_fd_rings, 1, __ATOMIC_RELAXED);
	return ring->fd;
fail:
	pthread_mutex_lock(&model_lock);
	if (ring->own_views) {
		munmap(ring->rings, ring->rings_len);
		munmap(ring->sqes, ring->sqes_len);
	}
	if (ring->fd >= 0)
		real_close(ring->fd);
	memset(ring, 0, sizeof(*ring));
	pthread_mutex_unlock(&model_lock);
	return ret;
}

/* A file the model may hold: not a simulated ring (io_is_uring_fops()). */
static long model_r128_dup_file(int fd, int *dup_fd)
{
	int copy;

	if (fd < 0 || real_fcntl(fd, F_GETFD) < 0)
		return -EBADF;
	if (model_r128_by_fd(fd))
		return -EBADF;
	copy = real_fcntl(fd, F_DUPFD_CLOEXEC, 512);
	if (copy < 0 && errno == EINVAL)
		copy = real_fcntl(fd, F_DUPFD_CLOEXEC, 3);
	if (copy < 0)
		return -errno;
	*dup_fd = copy;
	return 0;
}

/* io_sqe_files_register(); the dups are made before model_lock is taken. */
static long model_r128_files_register(struct model_r128 *ring, const void *arg,
				      unsigned long nr)
{
	int copies[MODEL_R128_MAX_FILES];
	const int32_t *fds = arg;
	unsigned int i;
	long ret = 0;

	if (!arg)
		return -EFAULT;
	if (!nr)
		return -EINVAL;
	if (nr > MODEL_R128_MAX_FILES)
		return -EMFILE;
	for (i = 0; i < nr; i++)
		copies[i] = -1;
	for (i = 0; i < nr && !ret; i++)
		if (fds[i] != -1)
			ret = model_r128_dup_file(fds[i], &copies[i]);
	pthread_mutex_lock(&model_lock);
	if (!ret && ring->nr_files)
		ret = -EBUSY;
	if (!ret) {
		for (i = 0; i < nr; i++)
			ring->files[i].fd = copies[i];
		ring->nr_files = (unsigned int)nr;
	}
	pthread_mutex_unlock(&model_lock);
	if (ret)
		for (i = 0; i < nr; i++)
			if (copies[i] >= 0)
				real_close(copies[i]);
	return ret;
}

/* __io_sqe_files_update(); stops at the first descriptor it cannot hold. */
static long model_r128_files_update(struct model_r128 *ring, const void *arg,
				    unsigned long nr)
{
	struct io_uring_rsrc_update update;
	const int32_t *fds;
	unsigned int done;
	long err = 0;

	if (!nr)
		return -EINVAL;
	if (!arg)
		return -EFAULT;
	memcpy(&update, arg, sizeof(update));
	if (update.resv)
		return -EINVAL;
	fds = (const int32_t *)(uintptr_t)update.data;
	pthread_mutex_lock(&model_lock);
	if (!ring->nr_files)
		err = -ENXIO;
	else if ((uint64_t)update.offset + nr > ring->nr_files)
		err = -EINVAL;
	pthread_mutex_unlock(&model_lock);
	if (err)
		return err;
	for (done = 0; done < nr; done++) {
		struct model_r128_file *slot = &ring->files[update.offset + done];
		int copy = -1, old;

		if (fds[done] == IORING_REGISTER_FILES_SKIP)
			continue;
		if (fds[done] != -1) {
			err = model_r128_dup_file(fds[done], &copy);
			if (err)
				break;
		}
		pthread_mutex_lock(&model_lock);
		old = slot->fd;
		slot->fd = copy;
		pthread_mutex_unlock(&model_lock);
		if (old >= 0)
			real_close(old);
	}
	return done ? (long)done : err;
}

/* io_ringfd_register(): the task table, whatever ring the call names. */
static long model_r128_ringfd_register(void *arg, unsigned long nr)
{
	struct io_uring_rsrc_update *updates = arg;
	struct model_r128_task *task;
	unsigned long i;
	long ret = 0;

	if (!nr || nr > MODEL_R128_TASK_SLOTS)
		return -EINVAL;
	task = model_r128_tctx(true);
	for (i = 0; i < nr; i++) {
		struct io_uring_rsrc_update update;
		struct model_r128 *target;
		unsigned int start, end, slot;

		memcpy(&update, &updates[i], sizeof(update));
		if (update.resv) {
			ret = -EINVAL;
			break;
		}
		if (update.offset == ~0U) {
			start = 0;
			end = MODEL_R128_TASK_SLOTS;
		} else if (update.offset >= MODEL_R128_TASK_SLOTS) {
			ret = -EINVAL;
			break;
		} else {
			start = update.offset;
			end = start + 1;
		}
		target = model_r128_by_fd((long)(int)update.data);
		if (!target) {
			struct stat st;

			ret = real_fstat((int)update.data, &st) ? -EBADF :
								  -EOPNOTSUPP;
			break;
		}
		for (slot = start; slot < end; slot++)
			if (!task->slots[slot])
				break;
		if (slot == end) {
			ret = -EBUSY;
			break;
		}
		pthread_mutex_lock(&model_lock);
		task->slots[slot] = target;
		target->nregs++;
		pthread_mutex_unlock(&model_lock);
		updates[i].offset = slot;
	}
	return i ? (long)i : ret;
}

/* io_ringfd_unregister() */
static long model_r128_ringfd_unregister(const void *arg, unsigned long nr)
{
	const struct io_uring_rsrc_update *updates = arg;
	struct model_r128_task *task = model_r128_tctx(false);
	unsigned long i;
	long ret = 0;

	if (!nr || nr > MODEL_R128_TASK_SLOTS)
		return -EINVAL;
	if (!task)
		return 0;
	for (i = 0; i < nr; i++) {
		struct io_uring_rsrc_update update;
		struct model_r128 *ring;

		memcpy(&update, &updates[i], sizeof(update));
		if (update.resv || update.data ||
		    update.offset >= MODEL_R128_TASK_SLOTS) {
			ret = -EINVAL;
			break;
		}
		ring = task->slots[update.offset];
		if (!ring)
			continue;
		pthread_mutex_lock(&model_lock);
		task->slots[update.offset] = NULL;
		ring->nregs--;
		model_r128_put_locked(ring);
		pthread_mutex_unlock(&model_lock);
	}
	return i ? (long)i : ret;
}

static long model_r128_register(struct model_r128 *ring, unsigned int opcode,
				long argument, long count)
{
	void *arg = (void *)argument;
	unsigned long nr = (unsigned int)count;

	switch (opcode) {
	case IORING_REGISTER_FILES:
		return model_r128_files_register(ring, arg, nr);
	case IORING_UNREGISTER_FILES:
		if (arg || nr)
			return -EINVAL;
		pthread_mutex_lock(&model_lock);
		if (!ring->nr_files) {
			pthread_mutex_unlock(&model_lock);
			return -ENXIO;
		}
		model_r128_clear_files_locked(ring);
		pthread_mutex_unlock(&model_lock);
		return 0;
	case IORING_REGISTER_FILES_UPDATE:
		return model_r128_files_update(ring, arg, nr);
	case IORING_REGISTER_RING_FDS:
		return model_r128_ringfd_register(arg, nr);
	case IORING_UNREGISTER_RING_FDS:
		return model_r128_ringfd_unregister(arg, nr);
	default:
		fprintf(stderr, "XDEV_EXT_MODEL_RING128: register opcode %u is not "
			"simulated\n", opcode);
		return -EINVAL;
	}
}

static int model_r128_file(struct model_r128 *ring,
			   const struct io_uring_sqe *sqe)
{
	int fd = -1;

	if (!(sqe->flags & IOSQE_FIXED_FILE))
		return sqe->fd;
	pthread_mutex_lock(&model_lock);
	if (sqe->fd >= 0 && (unsigned int)sqe->fd < ring->nr_files)
		fd = ring->files[sqe->fd].fd;
	pthread_mutex_unlock(&model_lock);
	return fd;
}

static int32_t model_r128_execute(struct model_r128 *ring,
				  const unsigned char *bytes)
{
	struct io_uring_sqe sqe;
	long ret;
	int fd;

	memcpy(&sqe, bytes, sizeof(sqe));
	if (sqe.flags & ~IOSQE_FIXED_FILE)
		return -EINVAL;
	switch (sqe.opcode) {
	case IORING_OP_NOP:
		return sqe.rw_flags ? -EINVAL : 0;
	case IORING_OP_WRITE:
	case IORING_OP_URING_CMD:
		fd = model_r128_file(ring, &sqe);
		if (fd < 0)
			return -EBADF;
		if (sqe.opcode == IORING_OP_URING_CMD) {
			struct stat st;

			if (real_fstat(fd, &st))
				return -EBADF;
			/* No simulated file has ->uring_cmd. */
			return -EOPNOTSUPP;
		}
		ret = real_syscall(SYS_pwrite64, (long)fd, (long)sqe.addr,
				   (long)sqe.len, (long)sqe.off);
		return ret < 0 ? -errno : (int32_t)ret;
	default:
		return -EINVAL;
	}
}

static void model_r128_post(struct model_r128 *ring, uint64_t user_data,
			    int32_t result)
{
	struct model_io_rings *header = model_r128_header(ring);
	struct io_uring_cqe *cqe;

	if (ring->cq_tail - __atomic_load_n(&header->cq.head, __ATOMIC_ACQUIRE) >=
	    ring->cq_entries) {
		fprintf(stderr, "XDEV_EXT_MODEL_RING128: CQ overflow is not "
			"simulated\n");
		abort();
	}
	cqe = (struct io_uring_cqe *)(header->cqes +
				      (size_t)(ring->cq_tail &
					       (ring->cq_entries - 1)) *
				      ring->cqe_size);
	cqe->user_data = user_data;
	cqe->res = result;
	cqe->flags = 0;
	if (ring->cqe_size == 32)
		memset((unsigned char *)cqe + 16, 0, 16);
	ring->cq_tail++;
	__atomic_store_n(&header->cq.tail, ring->cq_tail, __ATOMIC_RELEASE);
}

/* io_uring_enter() without SQPOLL or IOPOLL: execute, then complete. */
static long model_r128_enter(struct model_r128 *ring, long to_submit,
			     long min_complete, long flags)
{
	struct model_io_rings *header = model_r128_header(ring);
	unsigned char sqe[128];
	long submitted = 0;

	if ((unsigned long)flags & ~(unsigned long)MODEL_R128_ENTER_FLAGS)
		return -EINVAL;
	if ((unsigned long)flags & ~(unsigned long)(IORING_ENTER_GETEVENTS |
						    IORING_ENTER_REGISTERED_RING)) {
		fprintf(stderr, "XDEV_EXT_MODEL_RING128: enter flags 0x%lx are not "
			"simulated\n", (unsigned long)flags);
		return -EINVAL;
	}
	if (ring->pending) {
		ring->pending = false;
		model_r128_post(ring, ring->pending_user_data,
				ring->pending_result);
		return 0;
	}
	if ((unsigned int)to_submit) {
		uint32_t tail = __atomic_load_n(&header->sq.tail,
						__ATOMIC_ACQUIRE);
		uint32_t entries = tail - ring->sq_head;
		uint32_t *array = (uint32_t *)(ring->rings +
					       ring->params.sq_off.array);

		(void)model_r128_tctx(true);
		if (entries > ring->sq_entries)
			entries = ring->sq_entries;
		while (submitted < (long)(unsigned int)to_submit &&
		       submitted < (long)entries) {
			uint32_t index = array[ring->sq_head &
					       (ring->sq_entries - 1)];
			int32_t result;
			uint64_t user_data;

			ring->sq_head++;
			if (index >= ring->sq_entries) {
				header->sq_dropped++;
				__atomic_store_n(&header->sq.head, ring->sq_head,
						 __ATOMIC_RELEASE);
				break;
			}
			/* The kernel consumes the entry before it executes it. */
			memcpy(sqe, ring->sqes + (size_t)index * ring->sqe_size,
			       ring->sqe_size);
			__atomic_store_n(&header->sq.head, ring->sq_head,
					 __ATOMIC_RELEASE);
			submitted++;
			model_count(MODEL_R128_SQE);
			if (!model_block_if_armed(&block_armed))
				return -ETIMEDOUT;
			result = model_r128_execute(ring, sqe);
			memcpy(&user_data, sqe + offsetof(struct io_uring_sqe,
							  user_data),
			       sizeof(user_data));
			if (model_eintr) {
				ring->pending = true;
				ring->pending_user_data = user_data;
				ring->pending_result = result;
				model_count(MODEL_EINTR_RETURNED);
				return -EINTR;
			}
			model_r128_post(ring, user_data, result);
		}
	}
	if (((unsigned long)flags & IORING_ENTER_GETEVENTS) &&
	    (uint32_t)(ring->cq_tail -
		       __atomic_load_n(&header->cq.head, __ATOMIC_ACQUIRE)) <
	    (uint32_t)min_complete) {
		/* The kernel would sleep here forever. */
		fprintf(stderr, "XDEV_EXT_MODEL_RING128: io_uring_enter waits for "
			"%ld completions that can never arrive\n", min_complete);
		abort();
	}
	return submitted;
}

static long model_r128_enter_registered(long index, long to_submit,
					long min_complete, long flags)
{
	struct model_r128 *ring;
	long ret = model_r128_registered(index, &ring);

	if (ret)
		return model_r128_result(ret);
	return model_r128_result(model_r128_enter(ring, to_submit,
						  min_complete, flags));
}

/* close() of a simulated ring's memfd drops the descriptor's reference. */
static void model_r128_note_close(int fd)
{
	struct model_r128 *ring = model_r128_by_fd(fd);

	if (!ring)
		return;
	pthread_mutex_lock(&model_lock);
	ring->fd = -1;
	__atomic_sub_fetch(&model_r128_fd_rings, 1, __ATOMIC_RELAXED);
	model_r128_put_locked(ring);
	pthread_mutex_unlock(&model_lock);
}

/*
 * Like glibc's syscall(), this reads six argument slots whatever the caller
 * passed.  On x86-64 the sixth is the first one on the caller's stack, which
 * at the top frame of a new thread is an AddressSanitizer redzone.
 */
__attribute__((no_sanitize_address))
long syscall(long number, ...)
{
	struct model_r128 *ring128;
	struct model_ring *ring;
	va_list args;
	long a[6];
	int i;

	pthread_once(&model_once, model_init);
	va_start(args, number);
	for (i = 0; i < 6; i++)
		a[i] = va_arg(args, long);
	va_end(args);
	switch (number) {
	case SYS_statx:
		return model_statx(a[0], a[1], a[2], a[3], a[4]);
	case SYS_io_uring_setup:
		return model_setup(a[0], a[1]);
	case SYS_io_uring_register:
		return model_register(a[0], a[1], a[2], a[3]);
	case SYS_io_uring_enter:
		if ((unsigned long)a[3] & IORING_ENTER_REGISTERED_RING)
			return model_r128_enter_registered(a[0], a[1], a[2],
							   a[3]);
		ring128 = model_r128_by_fd(a[0]);
		if (ring128)
			return model_r128_result(model_r128_enter(ring128, a[1],
								  a[2], a[3]));
		ring = model_umem ? model_registered_ring(a[0]) : NULL;
		if (ring)
			return model_enter(ring, a[1]);
		break;
	default:
		break;
	}
	return real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}

static void model_count_call(void)
{
	pthread_once(&model_once, model_init);
	if (model_counting)
		model_counted_calls++;
}

/* glibc's own fcntl forwards its optional argument the same way. */
int fcntl(int fd, int command, ...)
{
	va_list args;
	void *argument;

	model_count_call();
	va_start(args, command);
	argument = va_arg(args, void *);
	va_end(args);
	if (!real_fcntl) {
		errno = ENOSYS;
		return -1;
	}
	return real_fcntl(fd, command, argument);
}

int fstat(int fd, struct stat *st)
{
	model_count_call();
	if (!real_fstat) {
		errno = ENOSYS;
		return -1;
	}
	return real_fstat(fd, st);
}

ssize_t readlink(const char *path, char *buffer, size_t size)
{
	model_count_call();
	if (!real_readlink) {
		errno = ENOSYS;
		return -1;
	}
	return real_readlink(path, buffer, size);
}

int close(int fd)
{
	int ret;

	model_count_call();
	if (!real_close) {
		errno = ENOSYS;
		return -1;
	}
	/* Unlocked check first: an unarmed close() stays as it was. */
	if (__atomic_load_n(&block_close_armed, __ATOMIC_ACQUIRE) &&
	    !model_block_if_armed(&block_close_armed)) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (__atomic_load_n(&model_r128_fd_rings, __ATOMIC_RELAXED))
		model_r128_note_close(fd);
	ret = real_close(fd);
	if (ret < 0 && errno == EBADF)
		__atomic_add_fetch(&model_ebadf_closes, 1, __ATOMIC_RELAXED);
	return ret;
}

/* Hooks for xdev_ext_preload_buffered_cost.c, resolved with dlsym(RTLD_DEFAULT). */
void xdev_ext_model_count_calls_begin(void)
{
	model_counted_calls = 0;
	model_counting = true;
}

uint64_t xdev_ext_model_count_calls_end(void)
{
	model_counting = false;
	return model_counted_calls;
}

/* Hooks for xdev_ext_preload_cancel_wait.c, resolved with dlsym(RTLD_DEFAULT). */
static int model_arm_block(bool *armed_flag)
{
	pthread_mutex_lock(&model_lock);
	/* Release: close() reads block_close_armed without the lock. */
	__atomic_store_n(armed_flag, true, __ATOMIC_RELEASE);
	block_reached = false;
	__atomic_store_n(&block_released, false, __ATOMIC_RELEASE);
	pthread_mutex_unlock(&model_lock);
	return 0;
}

int xdev_ext_model_block_next_request(void)
{
	return model_arm_block(&block_armed);
}

/* Hold the next XDEV_EXT_UMEM registration, whether the model or host answers. */
int xdev_ext_model_block_next_registration(void)
{
	return model_arm_block(&block_register_armed);
}

/* Hold the next close() of any thread; the model makes none of its own. */
int xdev_ext_model_block_next_close(void)
{
	return model_arm_block(&block_close_armed);
}

int xdev_ext_model_wait_until_blocked(void)
{
	uint64_t deadline = model_now_ns() + MODEL_BLOCK_TIMEOUT_NS;
	bool reached;

	for (;;) {
		pthread_mutex_lock(&model_lock);
		reached = block_reached;
		pthread_mutex_unlock(&model_lock);
		if (reached)
			return 0;
		if (model_now_ns() > deadline)
			return -ETIMEDOUT;
		sched_yield();
	}
}

int xdev_ext_model_release_request(void)
{
	__atomic_store_n(&block_released, true, __ATOMIC_RELEASE);
	return 0;
}

uint64_t xdev_ext_model_read_requests(void)
{
	uint64_t count;

	pthread_mutex_lock(&model_lock);
	count = model_counters_locked()->read_sqes;
	pthread_mutex_unlock(&model_lock);
	return count;
}

uint64_t xdev_ext_model_write_requests(void)
{
	uint64_t count;

	pthread_mutex_lock(&model_lock);
	count = model_counters_locked()->write_sqes;
	pthread_mutex_unlock(&model_lock);
	return count;
}

uint64_t xdev_ext_model_send_requests(void)
{
	uint64_t count;

	pthread_mutex_lock(&model_lock);
	count = model_counters_locked()->send_sqes;
	pthread_mutex_unlock(&model_lock);
	return count;
}

uint64_t xdev_ext_model_ebadf_closes(void)
{
	return __atomic_load_n(&model_ebadf_closes, __ATOMIC_RELAXED);
}

/* Hooks for xdev_ext_preload_ring128_model_check.c and later front-end tests. */
int xdev_ext_model_ring128_present(void)
{
	return 1;
}

uint64_t xdev_ext_model_ring128_setups(void)
{
	uint64_t count;

	pthread_mutex_lock(&model_lock);
	count = model_counters_locked()->ring128_setups;
	pthread_mutex_unlock(&model_lock);
	return count;
}

uint64_t xdev_ext_model_ring128_sqes(void)
{
	uint64_t count;

	pthread_mutex_lock(&model_lock);
	count = model_counters_locked()->ring128_sqes;
	pthread_mutex_unlock(&model_lock);
	return count;
}

/* Simulated rings this process still holds. */
uint64_t xdev_ext_model_ring128_rings(void)
{
	uint64_t count = 0;
	int i;

	pthread_mutex_lock(&model_lock);
	for (i = 0; i < MODEL_R128_MAX_RINGS; i++)
		count += model_r128_rings[i].used &&
			 model_r128_rings[i].owner == getpid();
	pthread_mutex_unlock(&model_lock);
	return count;
}
