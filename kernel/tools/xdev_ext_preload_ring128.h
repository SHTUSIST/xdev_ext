/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_RING128_H
#define XDEV_EXT_PRELOAD_RING128_H

/*
 * Per-thread io_uring with 128-byte SQEs and 32-byte CQEs, for the NVMe
 * passthrough sink of io_uring_unified_preload.c (IORING_OP_URING_CMD with
 * NVME_URING_CMD_IO).  The ring never occupies a descriptor number of the
 * application:
 *
 *  1. IORING_SETUP_NO_MMAP | IORING_SETUP_REGISTERED_FD_ONLY (Linux 6.5+).
 *     The rings and the SQE array live in two private anonymous mappings the
 *     front end provides; the kernel pins them (io_uring/memmap.c
 *     io_region_pin_pages()) and returns an index into the calling task's
 *     registered-ring table instead of installing a descriptor
 *     (io_uring/io_uring.c io_uring_create()).
 *  2. Otherwise a plain setup, mmap of the rings, IORING_REGISTER_RING_FDS
 *     and close() of the returned number (Linux 5.19+ for SQE128).  The
 *     number exists only between setup and close; afterwards the
 *     registration and the two mappings each hold a reference to the ring
 *     file (io_uring/tctx.c io_ring_add_registered_fd(); mm/vma.c takes one
 *     per mapping).
 *  3. Otherwise this thread does not take over passthrough I/O.
 *
 * The registered-ring table belongs to the task (current->io_uring), so a
 * ring is usable only by the thread that set it up, and a fork child starts
 * with an empty table (kernel/fork.c).  Every mapping is MADV_DONTFORK.
 *
 * Fixed-file slots hold the NVMe generic character devices: sixteen empty
 * slots are registered with the ring, and a slot is filled from the
 * registration's private anchor descriptor only after fstat() shows that the
 * anchor still names the registered device.  Once installed, the ring holds
 * its own reference to the file, so the anchor number may be closed or
 * reused afterwards.
 *
 * Publication rules: a request is published once; after that only its own
 * terminal CQE ends the wait.  EINTR resumes the wait at once, any other
 * io_uring_enter() error after a short back-off, and a CQE with another token
 * marks the ring broken and returns -EIO.  Thread cancellation is disabled
 * for the whole publish and wait.  Everything the kernel sees goes through
 * struct xdev_ext_ring128_ops so host tests can replace it.
 */
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Always consume the ABI from this source tree. */
#include "../include/uapi/linux/io_uring.h"

#define XDEV_EXT_RING128_ENTRIES	4U
#define XDEV_EXT_RING128_SLOTS	16U
#define XDEV_EXT_RING128_SQE_SIZE	(2U * (unsigned int)sizeof(struct io_uring_sqe))
#define XDEV_EXT_RING128_CQE_SIZE	(2U * (unsigned int)sizeof(struct io_uring_cqe))
/* IO_RINGFD_REG_MAX in include/linux/io_uring_types.h */
#define XDEV_EXT_RING128_RING_FD_MAX	16U
#define XDEV_EXT_RING128_SETUP_FLAGS	(IORING_SETUP_SQE128 | IORING_SETUP_CQE32)
#define XDEV_EXT_RING128_FD_ONLY_FLAGS \
	(XDEV_EXT_RING128_SETUP_FLAGS | IORING_SETUP_NO_MMAP | \
	 IORING_SETUP_REGISTERED_FD_ONLY)
#define XDEV_EXT_RING128_ENTER_FLAGS \
	(IORING_ENTER_GETEVENTS | IORING_ENTER_REGISTERED_RING)
/* Back-off after a failed io_uring_enter(): 1 ms doubling to 64 ms. */
#define XDEV_EXT_RING128_BACKOFF_MAX_SHIFT 6U
/* sizeof(struct io_rings): cqes[] is ____cacheline_aligned_in_smp. */
#define XDEV_EXT_RING128_IO_RINGS_HEADER 64U
#define XDEV_EXT_RING128_CACHE_LINE	64U

struct xdev_ext_ring128 {
	enum { XDEV_EXT_R128_NONE, XDEV_EXT_R128_FD_ONLY, XDEV_EXT_R128_RING_FDS,
	       XDEV_EXT_R128_UNAVAILABLE } mode;
	int ring_index;			/* registered-ring index */
	void *rings_mem, *sqes_mem;	/* both MADV_DONTFORK */
	struct io_uring_params params;
	/* Registration generation installed in each slot; 0 = empty. */
	uint32_t installed[XDEV_EXT_RING128_SLOTS];
	pid_t owner_pid;
	size_t rings_len, sqes_len;
	int fd_only_error, ring_fds_error;	/* why a mode was not used */
	/*
	 * A published request whose CQE has not been seen.  While set, the
	 * kernel may still own the request, its buffer and its fixed file, so
	 * the ring and both mappings are kept until process exit.
	 */
	bool inflight;
	bool broken;			/* a CQE with another token was seen */
};

/* Each returns a non-negative value or a negative errno. */
struct xdev_ext_ring128_ops {
	void *opaque;
	int (*setup)(void *opaque, unsigned int entries,
		     struct io_uring_params *p);
	int (*enter)(void *opaque, unsigned int index, unsigned int to_submit,
		     unsigned int min_complete, unsigned int flags);
	int (*reg)(void *opaque, unsigned int fd, unsigned int opcode,
		   void *arg, unsigned int nr_args);
	int (*map)(void *opaque, void **addr, size_t length, int prot,
		   int flags, int fd, off_t offset);
	int (*unmap)(void *opaque, void *addr, size_t length);
	int (*advise)(void *opaque, void *addr, size_t length, int advice);
	int (*close)(void *opaque, int fd);
	int (*fstat)(void *opaque, int fd, struct stat *st);
	pid_t (*getpid)(void *opaque);
	void (*backoff)(void *opaque, unsigned int attempt);
};

static inline size_t xdev_ext_ring128_align(size_t value, size_t alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
}

/*
 * rings_size() of io_uring/io_uring.c: the header and CQEs (the whole of it
 * doubled for CQE32), cache-line aligned, then the u32 SQ index array.
 */
static inline size_t xdev_ext_ring128_rings_size(unsigned int sq_entries,
					    unsigned int cq_entries,
					    bool cqe32, size_t *sq_array_offset)
{
	size_t off = XDEV_EXT_RING128_IO_RINGS_HEADER +
		     (size_t)cq_entries * sizeof(struct io_uring_cqe);

	if (cqe32)
		off <<= 1;
	off = xdev_ext_ring128_align(off, XDEV_EXT_RING128_CACHE_LINE);
	*sq_array_offset = off;
	return off + (size_t)sq_entries * sizeof(uint32_t);
}

static inline size_t xdev_ext_ring128_page_size(void)
{
	long page = sysconf(_SC_PAGESIZE);

	return page > 0 ? (size_t)page : 4096;
}

static inline bool xdev_ext_ring128_usable(const struct xdev_ext_ring128 *r)
{
	return r->mode == XDEV_EXT_R128_FD_ONLY || r->mode == XDEV_EXT_R128_RING_FDS;
}

static inline const char *xdev_ext_ring128_mode_name(const struct xdev_ext_ring128 *r)
{
	switch (r->mode) {
	case XDEV_EXT_R128_FD_ONLY:
		return "registered-fd-only";
	case XDEV_EXT_R128_RING_FDS:
		return "ring-fds";
	case XDEV_EXT_R128_UNAVAILABLE:
		return "unavailable";
	default:
		return "none";
	}
}

static inline uint32_t *xdev_ext_ring128_word(const struct xdev_ext_ring128 *r,
					 uint32_t offset)
{
	return (uint32_t *)((unsigned char *)r->rings_mem + offset);
}

/* Drop the context without any call: it is gone or belongs to a parent. */
static inline void xdev_ext_ring128_forget(struct xdev_ext_ring128 *r)
{
	memset(r, 0, sizeof(*r));
	r->mode = XDEV_EXT_R128_NONE;
	r->ring_index = -1;
}

/*
 * Accept only what this code can address inside its own mappings, so a
 * layout change can never make it write outside them.
 */
static inline bool xdev_ext_ring128_layout_fits(const struct xdev_ext_ring128 *r)
{
	const struct io_uring_params *p = &r->params;
	const struct io_sqring_offsets *sq = &p->sq_off;
	const struct io_cqring_offsets *cq = &p->cq_off;
	size_t len = r->rings_len;

	if (p->sq_entries != XDEV_EXT_RING128_ENTRIES ||
	    p->cq_entries < p->sq_entries ||
	    (p->cq_entries & (p->cq_entries - 1)))
		return false;
	if ((size_t)sq->array + (size_t)p->sq_entries * sizeof(uint32_t) > len ||
	    (size_t)cq->cqes + (size_t)p->cq_entries * XDEV_EXT_RING128_CQE_SIZE > len ||
	    (size_t)p->sq_entries * XDEV_EXT_RING128_SQE_SIZE > r->sqes_len)
		return false;
	if ((size_t)sq->head + 4 > len || (size_t)sq->tail + 4 > len ||
	    (size_t)cq->head + 4 > len || (size_t)cq->tail + 4 > len ||
	    (sq->array | sq->head | sq->tail | cq->head | cq->tail) & 3 ||
	    cq->cqes & 7)
		return false;
	return *xdev_ext_ring128_word(r, sq->ring_mask) == p->sq_entries - 1 &&
	       *xdev_ext_ring128_word(r, cq->ring_mask) == p->cq_entries - 1;
}

static inline void xdev_ext_ring128_unregister(const struct xdev_ext_ring128_ops *ops,
					  unsigned int index)
{
	struct io_uring_rsrc_update update = { .offset = index };

	(void)ops->reg(ops->opaque, index,
		       IORING_UNREGISTER_RING_FDS |
		       IORING_REGISTER_USE_REGISTERED_RING, &update, 1);
}

static inline int xdev_ext_ring128_register_files(struct xdev_ext_ring128 *r,
					     const struct xdev_ext_ring128_ops *ops)
{
	int32_t empty[XDEV_EXT_RING128_SLOTS];
	unsigned int i;
	int ret;

	for (i = 0; i < XDEV_EXT_RING128_SLOTS; i++)
		empty[i] = -1;
	ret = ops->reg(ops->opaque, (unsigned int)r->ring_index,
		       IORING_REGISTER_FILES |
		       IORING_REGISTER_USE_REGISTERED_RING, empty,
		       XDEV_EXT_RING128_SLOTS);
	return ret < 0 ? ret : 0;
}

/* Undo a partial setup: registered index first, then the mappings. */
static inline void xdev_ext_ring128_undo(struct xdev_ext_ring128 *r,
				    const struct xdev_ext_ring128_ops *ops, int fd)
{
	if (r->ring_index >= 0)
		xdev_ext_ring128_unregister(ops, (unsigned int)r->ring_index);
	if (r->sqes_mem)
		(void)ops->unmap(ops->opaque, r->sqes_mem, r->sqes_len);
	if (r->rings_mem)
		(void)ops->unmap(ops->opaque, r->rings_mem, r->rings_len);
	if (fd >= 0)
		(void)ops->close(ops->opaque, fd);
	r->ring_index = -1;
	r->rings_mem = NULL;
	r->sqes_mem = NULL;
	r->rings_len = 0;
	r->sqes_len = 0;
	memset(&r->params, 0, sizeof(r->params));
}

static inline int xdev_ext_ring128_setup_fd_only(struct xdev_ext_ring128 *r,
					    const struct xdev_ext_ring128_ops *ops)
{
	size_t page = xdev_ext_ring128_page_size();
	size_t sq_array;
	int ret;

	r->rings_len = xdev_ext_ring128_align(
		xdev_ext_ring128_rings_size(XDEV_EXT_RING128_ENTRIES,
				       2 * XDEV_EXT_RING128_ENTRIES, true, &sq_array),
		page);
	r->sqes_len = xdev_ext_ring128_align(
		(size_t)XDEV_EXT_RING128_ENTRIES * XDEV_EXT_RING128_SQE_SIZE, page);
	ret = ops->map(ops->opaque, &r->rings_mem, r->rings_len,
		       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ret) {
		r->rings_mem = NULL;
		goto fail;
	}
	ret = ops->map(ops->opaque, &r->sqes_mem, r->sqes_len,
		       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ret) {
		r->sqes_mem = NULL;
		goto fail;
	}
	ret = ops->advise(ops->opaque, r->rings_mem, r->rings_len,
			  MADV_DONTFORK);
	if (!ret)
		ret = ops->advise(ops->opaque, r->sqes_mem, r->sqes_len,
				  MADV_DONTFORK);
	if (ret)
		goto fail;
	/* Fresh anonymous pages are zero: the kernel does not clear them. */
	memset(&r->params, 0, sizeof(r->params));
	r->params.flags = XDEV_EXT_RING128_FD_ONLY_FLAGS;
	r->params.sq_off.user_addr = (uintptr_t)r->sqes_mem;
	r->params.cq_off.user_addr = (uintptr_t)r->rings_mem;
	ret = ops->setup(ops->opaque, XDEV_EXT_RING128_ENTRIES, &r->params);
	if (ret < 0)
		goto fail;
	r->ring_index = ret;
	if ((unsigned int)ret >= XDEV_EXT_RING128_RING_FD_MAX ||
	    !xdev_ext_ring128_layout_fits(r)) {
		ret = -EPROTO;
		goto fail;
	}
	ret = xdev_ext_ring128_register_files(r, ops);
	if (ret)
		goto fail;
	return 0;
fail:
	xdev_ext_ring128_undo(r, ops, -1);
	return ret;
}

static inline int xdev_ext_ring128_setup_ring_fds(struct xdev_ext_ring128 *r,
					     const struct xdev_ext_ring128_ops *ops)
{
	struct io_uring_rsrc_update update;
	size_t page = xdev_ext_ring128_page_size();
	size_t sq_len, cq_len;
	int fd, ret;

	memset(&r->params, 0, sizeof(r->params));
	r->params.flags = XDEV_EXT_RING128_SETUP_FLAGS;
	fd = ops->setup(ops->opaque, XDEV_EXT_RING128_ENTRIES, &r->params);
	if (fd < 0)
		return fd;
	/* One mapping at IORING_OFF_SQ_RING covers SQ and CQ rings. */
	if (!(r->params.features & IORING_FEAT_SINGLE_MMAP)) {
		ret = -EOPNOTSUPP;
		goto fail;
	}
	sq_len = (size_t)r->params.sq_off.array +
		 (size_t)r->params.sq_entries * sizeof(uint32_t);
	cq_len = (size_t)r->params.cq_off.cqes +
		 (size_t)r->params.cq_entries * XDEV_EXT_RING128_CQE_SIZE;
	r->rings_len = xdev_ext_ring128_align(sq_len > cq_len ? sq_len : cq_len,
					 page);
	r->sqes_len = xdev_ext_ring128_align(
		(size_t)r->params.sq_entries * XDEV_EXT_RING128_SQE_SIZE, page);
	ret = ops->map(ops->opaque, &r->rings_mem, r->rings_len,
		       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
		       (off_t)IORING_OFF_SQ_RING);
	if (ret) {
		r->rings_mem = NULL;
		goto fail;
	}
	ret = ops->map(ops->opaque, &r->sqes_mem, r->sqes_len,
		       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
		       (off_t)IORING_OFF_SQES);
	if (ret) {
		r->sqes_mem = NULL;
		goto fail;
	}
	/* io_uring_mmap() does not set VM_DONTCOPY itself. */
	ret = ops->advise(ops->opaque, r->rings_mem, r->rings_len,
			  MADV_DONTFORK);
	if (!ret)
		ret = ops->advise(ops->opaque, r->sqes_mem, r->sqes_len,
				  MADV_DONTFORK);
	if (ret)
		goto fail;
	if (!xdev_ext_ring128_layout_fits(r)) {
		ret = -EPROTO;
		goto fail;
	}
	update = (struct io_uring_rsrc_update){
		.offset = ~0U,
		.data = (uint64_t)fd,
	};
	ret = ops->reg(ops->opaque, (unsigned int)fd, IORING_REGISTER_RING_FDS,
		       &update, 1);
	if (ret != 1) {
		ret = ret < 0 ? ret : -EIO;
		goto fail;
	}
	if (update.offset >= XDEV_EXT_RING128_RING_FD_MAX) {
		ret = -EPROTO;
		goto fail;
	}
	r->ring_index = (int)update.offset;
	(void)ops->close(ops->opaque, fd);
	fd = -1;
	ret = xdev_ext_ring128_register_files(r, ops);
	if (ret)
		goto fail;
	return 0;
fail:
	xdev_ext_ring128_undo(r, ops, fd);
	return ret;
}

/*
 * Make this thread's ring usable.  0 = usable, -ENODEV = this thread does
 * not take over passthrough, -EIO = the ring is broken.  A context inherited
 * across fork() is dropped without any io_uring call (the child has no
 * registered-ring table) and without munmap() (MADV_DONTFORK left nothing
 * mapped there, and the address may belong to another mapping by now).
 */
static inline int xdev_ext_ring128_ensure(struct xdev_ext_ring128 *r,
				     const struct xdev_ext_ring128_ops *ops)
{
	pid_t pid = ops->getpid(ops->opaque);
	int cancel_state;
	int ret;

	if (r->mode != XDEV_EXT_R128_NONE && r->owner_pid != pid)
		xdev_ext_ring128_forget(r);
	switch (r->mode) {
	case XDEV_EXT_R128_FD_ONLY:
	case XDEV_EXT_R128_RING_FDS:
		return r->broken ? -EIO : 0;
	case XDEV_EXT_R128_UNAVAILABLE:
		return -ENODEV;
	default:
		break;
	}
	/* close() in the ring-fds rollback is a cancellation point. */
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	xdev_ext_ring128_forget(r);
	r->owner_pid = pid;
	ret = xdev_ext_ring128_setup_fd_only(r, ops);
	if (!ret) {
		r->mode = XDEV_EXT_R128_FD_ONLY;
		goto out;
	}
	r->fd_only_error = ret;
	ret = xdev_ext_ring128_setup_ring_fds(r, ops);
	if (!ret) {
		r->mode = XDEV_EXT_R128_RING_FDS;
		goto out;
	}
	r->ring_fds_error = ret;
	r->mode = XDEV_EXT_R128_UNAVAILABLE;
	ret = -ENODEV;
out:
	(void)pthread_setcancelstate(cancel_state, NULL);
	return ret;
}

static inline int xdev_ext_ring128_update_slot(struct xdev_ext_ring128 *r,
					  const struct xdev_ext_ring128_ops *ops,
					  unsigned int slot, int fd)
{
	struct io_uring_rsrc_update update;
	int32_t value = fd;
	int ret;

	update = (struct io_uring_rsrc_update){
		.offset = slot,
		.data = (uint64_t)(uintptr_t)&value,
	};
	ret = ops->reg(ops->opaque, (unsigned int)r->ring_index,
		       IORING_REGISTER_FILES_UPDATE |
		       IORING_REGISTER_USE_REGISTERED_RING, &update, 1);
	if (ret < 0)
		return ret;
	return ret == 1 ? 0 : -EIO;
}

static inline bool xdev_ext_ring128_anchor_matches(const struct xdev_ext_ring128_ops *ops,
					      int anchor_fd, dev_t rdev,
					      ino_t ino)
{
	struct stat st;

	return !ops->fstat(ops->opaque, anchor_fd, &st) && S_ISCHR(st.st_mode) &&
	       st.st_rdev == rdev && st.st_ino == ino;
}

/*
 * Put the registration's anchor into fixed-file slot @slot unless this ring
 * already holds generation @generation there.  The anchor is checked before
 * and again after the update, so a number swapped underneath by a raw
 * close()/open() never stays installed.  0 = installed, -ESTALE = the anchor
 * no longer names the device, other negative errno = not installed.
 */
static inline int xdev_ext_ring128_install(struct xdev_ext_ring128 *r,
				      const struct xdev_ext_ring128_ops *ops,
				      unsigned int slot, uint32_t generation,
				      int anchor_fd, dev_t rdev, ino_t ino)
{
	int ret;

	if (slot >= XDEV_EXT_RING128_SLOTS || !generation)
		return -EINVAL;
	if (!xdev_ext_ring128_usable(r))
		return -ENODEV;
	if (r->broken)
		return -EIO;
	if (r->installed[slot] == generation)
		return 0;
	if (!xdev_ext_ring128_anchor_matches(ops, anchor_fd, rdev, ino))
		return -ESTALE;
	r->installed[slot] = 0;
	ret = xdev_ext_ring128_update_slot(r, ops, slot, anchor_fd);
	if (ret)
		return ret;
	if (!xdev_ext_ring128_anchor_matches(ops, anchor_fd, rdev, ino)) {
		(void)xdev_ext_ring128_update_slot(r, ops, slot, -1);
		return -ESTALE;
	}
	r->installed[slot] = generation;
	return 0;
}

static inline int xdev_ext_ring128_uninstall(struct xdev_ext_ring128 *r,
					const struct xdev_ext_ring128_ops *ops,
					unsigned int slot)
{
	int ret;

	if (slot >= XDEV_EXT_RING128_SLOTS)
		return -EINVAL;
	if (!xdev_ext_ring128_usable(r))
		return -ENODEV;
	ret = xdev_ext_ring128_update_slot(r, ops, slot, -1);
	if (!ret)
		r->installed[slot] = 0;
	return ret;
}

/* 1 = own CQE consumed, 0 = none yet, -EIO = a CQE with another token. */
static inline int xdev_ext_ring128_peek(struct xdev_ext_ring128 *r, uint64_t token,
				   int32_t *res, uint32_t *cflags)
{
	const struct io_cqring_offsets *cq = &r->params.cq_off;
	uint32_t head = __atomic_load_n(xdev_ext_ring128_word(r, cq->head),
					__ATOMIC_RELAXED);
	uint32_t tail = __atomic_load_n(xdev_ext_ring128_word(r, cq->tail),
					__ATOMIC_ACQUIRE);
	const struct io_uring_cqe *cqe;

	if (head == tail)
		return 0;
	cqe = (const struct io_uring_cqe *)
		((unsigned char *)r->rings_mem + cq->cqes +
		 (size_t)(head & (r->params.cq_entries - 1)) *
		 XDEV_EXT_RING128_CQE_SIZE);
	if (cqe->user_data != token) {
		r->broken = true;
		return -EIO;
	}
	*res = cqe->res;
	*cflags = cqe->flags;
	__atomic_store_n(xdev_ext_ring128_word(r, cq->head), head + 1,
			 __ATOMIC_RELEASE);
	return 1;
}

static inline int xdev_ext_ring128_publish(struct xdev_ext_ring128 *r, const void *sqe,
				      uint32_t *initial_head)
{
	const struct io_sqring_offsets *sq = &r->params.sq_off;
	const struct io_cqring_offsets *cq = &r->params.cq_off;
	uint32_t head = __atomic_load_n(xdev_ext_ring128_word(r, sq->head),
					__ATOMIC_ACQUIRE);
	uint32_t tail = __atomic_load_n(xdev_ext_ring128_word(r, sq->tail),
					__ATOMIC_RELAXED);
	uint32_t index;

	if (head != tail)
		return -EBUSY;
	/* Nothing else completes on a private ring: a waiting CQE is foreign. */
	if (__atomic_load_n(xdev_ext_ring128_word(r, cq->tail), __ATOMIC_ACQUIRE) !=
	    __atomic_load_n(xdev_ext_ring128_word(r, cq->head), __ATOMIC_RELAXED)) {
		r->broken = true;
		return -EIO;
	}
	index = tail & (r->params.sq_entries - 1);
	memcpy((unsigned char *)r->sqes_mem +
	       (size_t)index * XDEV_EXT_RING128_SQE_SIZE, sqe, XDEV_EXT_RING128_SQE_SIZE);
	xdev_ext_ring128_word(r, sq->array)[index] = index;
	__atomic_store_n(xdev_ext_ring128_word(r, sq->tail), tail + 1,
			 __ATOMIC_RELEASE);
	*initial_head = head;
	return 0;
}

/*
 * Publish one 128-byte SQE and wait for its CQE (the SQE's user_data is the
 * token).  Returns 0 with *res and *cflags from the CQE.  A negative return
 * with *published false means nothing reached the ring and the caller may
 * use libc; with *published true it is -EIO for a foreign CQE, after which
 * the request may still be in flight and the caller must not use libc.
 */
static inline int
xdev_ext_ring128_submit_and_wait(struct xdev_ext_ring128 *r,
			    const struct xdev_ext_ring128_ops *ops, const void *sqe,
			    int32_t *res, uint32_t *cflags, bool *published)
{
	unsigned int attempt = 0;
	uint32_t initial_head;
	uint64_t token;
	int cancel_state;
	int ret;

	*published = false;
	if (!xdev_ext_ring128_usable(r))
		return -ENODEV;
	if (r->broken)
		return -EIO;
	memcpy(&token, (const unsigned char *)sqe +
	       offsetof(struct io_uring_sqe, user_data), sizeof(token));
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	ret = xdev_ext_ring128_publish(r, sqe, &initial_head);
	if (ret)
		goto out;
	*published = true;
	r->inflight = true;
	for (;;) {
		unsigned int to_submit;

		ret = xdev_ext_ring128_peek(r, token, res, cflags);
		if (ret > 0) {
			r->inflight = false;
			ret = 0;
			break;
		}
		if (ret < 0)
			break;
		/* Submit until the kernel has consumed the entry, never again. */
		to_submit = __atomic_load_n(xdev_ext_ring128_word(r, r->params.sq_off.head),
					    __ATOMIC_ACQUIRE) == initial_head;
		ret = ops->enter(ops->opaque, (unsigned int)r->ring_index,
				 to_submit, 1, XDEV_EXT_RING128_ENTER_FLAGS);
		if (ret >= 0 || ret == -EINTR)
			continue;
		ops->backoff(ops->opaque, attempt);
		if (attempt < XDEV_EXT_RING128_BACKOFF_MAX_SHIFT)
			attempt++;
	}
out:
	(void)pthread_setcancelstate(cancel_state, NULL);
	return ret;
}

/*
 * Thread exit: unregister the ring index, then unmap.  Kept as is while a
 * request may be in flight; dropped without calls in a fork child.
 */
static inline void xdev_ext_ring128_destroy(struct xdev_ext_ring128 *r,
				       const struct xdev_ext_ring128_ops *ops)
{
	int cancel_state;

	if (r->mode == XDEV_EXT_R128_NONE)
		return;
	if (r->owner_pid != ops->getpid(ops->opaque)) {
		xdev_ext_ring128_forget(r);
		return;
	}
	if (r->inflight)
		return;
	if (xdev_ext_ring128_usable(r)) {
		(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
					     &cancel_state);
		xdev_ext_ring128_undo(r, ops, -1);
		(void)pthread_setcancelstate(cancel_state, NULL);
	}
	xdev_ext_ring128_forget(r);
}

/* Default operations: the system calls themselves. */
static inline int xdev_ext_ring128_sys_setup(void *opaque, unsigned int entries,
					struct io_uring_params *p)
{
	long ret;

	(void)opaque;
	ret = syscall(SYS_io_uring_setup, (long)entries, p);
	return ret < 0 ? -errno : (int)ret;
}

static inline int xdev_ext_ring128_sys_enter(void *opaque, unsigned int index,
					unsigned int to_submit,
					unsigned int min_complete,
					unsigned int flags)
{
	long ret;

	(void)opaque;
	ret = syscall(SYS_io_uring_enter, (long)index, (long)to_submit,
		      (long)min_complete, (long)flags, NULL, 0L);
	return ret < 0 ? -errno : (int)ret;
}

static inline int xdev_ext_ring128_sys_reg(void *opaque, unsigned int fd,
				      unsigned int opcode, void *arg,
				      unsigned int nr_args)
{
	long ret;

	(void)opaque;
	ret = syscall(SYS_io_uring_register, (long)fd, (long)opcode, arg,
		      (long)nr_args);
	return ret < 0 ? -errno : (int)ret;
}

static inline int xdev_ext_ring128_sys_map(void *opaque, void **addr,
				      size_t length, int prot, int flags,
				      int fd, off_t offset)
{
	void *view;

	(void)opaque;
	view = mmap(NULL, length, prot, flags, fd, offset);
	if (view == MAP_FAILED)
		return -errno;
	*addr = view;
	return 0;
}

static inline int xdev_ext_ring128_sys_unmap(void *opaque, void *addr,
					size_t length)
{
	(void)opaque;
	return munmap(addr, length) ? -errno : 0;
}

static inline int xdev_ext_ring128_sys_advise(void *opaque, void *addr,
					 size_t length, int advice)
{
	(void)opaque;
	return madvise(addr, length, advice) ? -errno : 0;
}

static inline int xdev_ext_ring128_sys_close(void *opaque, int fd)
{
	(void)opaque;
	return close(fd) ? -errno : 0;
}

static inline int xdev_ext_ring128_sys_fstat(void *opaque, int fd, struct stat *st)
{
	(void)opaque;
	return fstat(fd, st) ? -errno : 0;
}

static inline pid_t xdev_ext_ring128_sys_getpid(void *opaque)
{
	(void)opaque;
	return getpid();
}

static inline void xdev_ext_ring128_sys_backoff(void *opaque, unsigned int attempt)
{
	struct timespec pause = {
		.tv_nsec = 1000000L << (attempt < XDEV_EXT_RING128_BACKOFF_MAX_SHIFT ?
					attempt : XDEV_EXT_RING128_BACKOFF_MAX_SHIFT),
	};

	(void)opaque;
	(void)nanosleep(&pause, NULL);
}

/*
 * The front end passes its own operations so that close() and fstat() reach
 * libc rather than its wrappers; tests and stand-alone tools use these.
 */
static inline const struct xdev_ext_ring128_ops *xdev_ext_ring128_sys_ops(void)
{
	static const struct xdev_ext_ring128_ops ops = {
		.setup = xdev_ext_ring128_sys_setup,
		.enter = xdev_ext_ring128_sys_enter,
		.reg = xdev_ext_ring128_sys_reg,
		.map = xdev_ext_ring128_sys_map,
		.unmap = xdev_ext_ring128_sys_unmap,
		.advise = xdev_ext_ring128_sys_advise,
		.close = xdev_ext_ring128_sys_close,
		.fstat = xdev_ext_ring128_sys_fstat,
		.getpid = xdev_ext_ring128_sys_getpid,
		.backoff = xdev_ext_ring128_sys_backoff,
	};

	return &ops;
}

#endif /* XDEV_EXT_PRELOAD_RING128_H */
