/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_URING_MIN_H
#define CHAIN_URING_MIN_H

/*
 * The few io_uring operations the user-space arms need, on raw system
 * calls and the repository's io_uring UAPI (a superset of the upstream
 * one), so the binaries need no liburing in the guest.  Every system call
 * this file makes is counted in ur->syscalls; uo_bench reports the count.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../../../kernel/include/uapi/linux/io_uring.h"

struct ur {
	int fd;
	bool sqe128;
	unsigned int entries;
	void *sq_map, *cq_map, *sqes;
	size_t sq_len, cq_len, sqes_len;
	unsigned int *sq_head, *sq_tail, *sq_mask, *sq_array, *sq_flags;
	unsigned int *cq_head, *cq_tail, *cq_mask;
	struct io_uring_cqe *cqes;
	unsigned int pending;		/* SQEs written, not yet submitted */
	bool taskrun_flag;		/* IORING_SETUP_TASKRUN_FLAG */
	uint64_t syscalls;
};

/*
 * @spin: the caller polls the completion ring instead of waiting in
 * io_uring_enter().  Completions that need the submitting task (NVMe
 * passthrough, sockets) then run cooperatively (IORING_SETUP_COOP_TASKRUN)
 * and IORING_SQ_TASKRUN tells ur_taskrun() when one kernel entry is due,
 * instead of an interrupt or the next timer tick.
 */
static inline int ur_setup(struct ur *ur, unsigned int entries, bool sqe128,
			   bool spin)
{
	struct io_uring_params p;

	memset(ur, 0, sizeof(*ur));
	memset(&p, 0, sizeof(p));
	if (sqe128)
		p.flags |= IORING_SETUP_SQE128;
	if (spin)
		p.flags |= IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
	ur->fd = (int)syscall(__NR_io_uring_setup, entries, &p);
	ur->syscalls++;
	if (ur->fd < 0)
		return -errno;
	ur->sqe128 = sqe128;
	ur->taskrun_flag = spin;
	ur->entries = p.sq_entries;
	ur->sq_len = p.sq_off.array + p.sq_entries * sizeof(unsigned int);
	ur->cq_len = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
	if (p.features & IORING_FEAT_SINGLE_MMAP) {
		if (ur->cq_len > ur->sq_len)
			ur->sq_len = ur->cq_len;
		ur->cq_len = 0;
	}
	ur->sq_map = mmap(NULL, ur->sq_len, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE, ur->fd, IORING_OFF_SQ_RING);
	if (ur->sq_map == MAP_FAILED) {
		ur->sq_map = NULL;
		return -errno;
	}
	ur->cq_map = ur->sq_map;
	if (ur->cq_len) {
		ur->cq_map = mmap(NULL, ur->cq_len, PROT_READ | PROT_WRITE,
				  MAP_SHARED | MAP_POPULATE, ur->fd,
				  IORING_OFF_CQ_RING);
		if (ur->cq_map == MAP_FAILED) {
			ur->cq_map = NULL;
			return -errno;
		}
	}
	ur->sqes_len = p.sq_entries * sizeof(struct io_uring_sqe) * (sqe128 ? 2 : 1);
	ur->sqes = mmap(NULL, ur->sqes_len, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, ur->fd, IORING_OFF_SQES);
	if (ur->sqes == MAP_FAILED) {
		ur->sqes = NULL;
		return -errno;
	}
	ur->sq_head = (unsigned int *)((char *)ur->sq_map + p.sq_off.head);
	ur->sq_tail = (unsigned int *)((char *)ur->sq_map + p.sq_off.tail);
	ur->sq_mask = (unsigned int *)((char *)ur->sq_map + p.sq_off.ring_mask);
	ur->sq_array = (unsigned int *)((char *)ur->sq_map + p.sq_off.array);
	ur->sq_flags = (unsigned int *)((char *)ur->sq_map + p.sq_off.flags);
	ur->cq_head = (unsigned int *)((char *)ur->cq_map + p.cq_off.head);
	ur->cq_tail = (unsigned int *)((char *)ur->cq_map + p.cq_off.tail);
	ur->cq_mask = (unsigned int *)((char *)ur->cq_map + p.cq_off.ring_mask);
	ur->cqes = (struct io_uring_cqe *)((char *)ur->cq_map + p.cq_off.cqes);
	return 0;
}

static inline void ur_close(struct ur *ur)
{
	if (ur->sqes)
		munmap(ur->sqes, ur->sqes_len);
	if (ur->cq_map && ur->cq_map != ur->sq_map)
		munmap(ur->cq_map, ur->cq_len);
	if (ur->sq_map)
		munmap(ur->sq_map, ur->sq_len);
	if (ur->fd >= 0)
		close(ur->fd);
	memset(ur, 0, sizeof(*ur));
	ur->fd = -1;
}

/* A zeroed SQE, or NULL when the submission ring is full. */
static inline struct io_uring_sqe *ur_sqe(struct ur *ur)
{
	unsigned int tail = *ur->sq_tail + ur->pending;
	unsigned int head = __atomic_load_n(ur->sq_head, __ATOMIC_ACQUIRE);
	struct io_uring_sqe *sqe;
	unsigned int idx;

	if (tail - head >= ur->entries)
		return NULL;
	idx = tail & *ur->sq_mask;
	sqe = (struct io_uring_sqe *)((char *)ur->sqes +
				      idx * sizeof(*sqe) * (ur->sqe128 ? 2 : 1));
	memset(sqe, 0, sizeof(*sqe) * (ur->sqe128 ? 2 : 1));
	ur->sq_array[idx] = idx;
	ur->pending++;
	return sqe;
}

static inline unsigned int ur_free_sqes(const struct ur *ur)
{
	unsigned int tail = *ur->sq_tail + ur->pending;

	return ur->entries - (tail - __atomic_load_n(ur->sq_head, __ATOMIC_ACQUIRE));
}

/* Publish the written SQEs; submit them and wait for @wait completions. */
static inline int ur_enter(struct ur *ur, unsigned int wait)
{
	unsigned int n = ur->pending;
	int ret;

	__atomic_store_n(ur->sq_tail, *ur->sq_tail + n, __ATOMIC_RELEASE);
	ur->pending = 0;
	if (!n && !wait)
		return 0;
	for (;;) {
		ret = (int)syscall(__NR_io_uring_enter, ur->fd, n, wait,
				   wait ? IORING_ENTER_GETEVENTS : 0, NULL, 0);
		ur->syscalls++;
		if (ret >= 0 || errno != EINTR)
			break;
		/* Submit whatever the interrupted call left in the ring. */
		n = *ur->sq_tail - __atomic_load_n(ur->sq_head, __ATOMIC_ACQUIRE);
	}
	return ret < 0 ? -errno : ret;
}

/*
 * ur_enter() that gives up waiting after @timeout_ns (IORING_ENTER_EXT_ARG):
 * -ETIME then, with every written SQE still submitted.
 */
static inline int ur_enter_timeout(struct ur *ur, unsigned int wait,
				   uint64_t timeout_ns)
{
	struct __kernel_timespec ts = {
		.tv_sec = (long long)(timeout_ns / 1000000000ULL),
		.tv_nsec = (long long)(timeout_ns % 1000000000ULL),
	};
	struct io_uring_getevents_arg arg = { .ts = (uintptr_t)&ts };
	unsigned int n = ur->pending;
	int ret;

	if (!wait)
		return ur_enter(ur, 0);
	__atomic_store_n(ur->sq_tail, *ur->sq_tail + n, __ATOMIC_RELEASE);
	ur->pending = 0;
	for (;;) {
		ret = (int)syscall(__NR_io_uring_enter, ur->fd, n, wait,
				   IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG,
				   &arg, sizeof(arg));
		ur->syscalls++;
		if (ret >= 0 || errno != EINTR)
			break;
		n = *ur->sq_tail - __atomic_load_n(ur->sq_head, __ATOMIC_ACQUIRE);
	}
	return ret < 0 ? -errno : ret;
}

/* A spinning caller: enter the kernel once when task work waits for us. */
static inline int ur_taskrun(struct ur *ur)
{
	int ret;

	if (!ur->taskrun_flag ||
	    !(__atomic_load_n(ur->sq_flags, __ATOMIC_ACQUIRE) & IORING_SQ_TASKRUN))
		return 0;
	ret = (int)syscall(__NR_io_uring_enter, ur->fd, 0, 0, IORING_ENTER_GETEVENTS,
			   NULL, 0);
	ur->syscalls++;
	return ret < 0 && errno != EINTR ? -errno : 0;
}

/* The oldest completion, or NULL; ur_seen() consumes it. */
static inline struct io_uring_cqe *ur_peek(struct ur *ur)
{
	unsigned int head = *ur->cq_head;

	if (head == __atomic_load_n(ur->cq_tail, __ATOMIC_ACQUIRE))
		return NULL;
	return &ur->cqes[head & *ur->cq_mask];
}

static inline void ur_seen(struct ur *ur)
{
	__atomic_store_n(ur->cq_head, *ur->cq_head + 1, __ATOMIC_RELEASE);
}

static inline int ur_register(struct ur *ur, unsigned int op, void *arg,
			      unsigned int nr)
{
	int ret = (int)syscall(__NR_io_uring_register, ur->fd, op, arg, nr);

	ur->syscalls++;
	return ret < 0 ? -errno : ret;
}

static inline void ur_prep_rw(struct io_uring_sqe *sqe, int op, int fd,
			      void *buf, uint32_t len, uint64_t off,
			      uint64_t data)
{
	sqe->opcode = (uint8_t)op;
	sqe->fd = fd;
	sqe->addr = (uintptr_t)buf;
	sqe->len = len;
	sqe->off = off;
	sqe->user_data = data;
}

#endif /* CHAIN_URING_MIN_H */
