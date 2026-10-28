// SPDX-License-Identifier: GPL-2.0
/*
 * libxdev_ext USER stage helpers: SPEC.md section 8, the user side of
 * Documentation/userspace-api/xdev_ext-user-stage.rst.  One user stage fd,
 * its mapping and a library-owned wakeup eventfd per handle.  One thread at
 * a time takes ready entries, and one thread at a time posts completions.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "../../../include/uapi/linux/io_uring.h"
#include "libxdev_ext.h"
#include "libxdev_ext_internal.h"

#define USER_DEFAULT_ENTRIES 64U

struct xdev_ext_user_stage {
	int fd, efd;
	void *map;
	size_t map_len;
	void *umem;
	__u32 entries;
	__u32 flags;
	bool attached;
	struct xdev_ext_user_ring_offsets off;
	atomic_flag owner_lock;
	bool owner_bound;
	unsigned long long owner_context_id, owner_stream_id;
	struct xdev_ext_user_ring_hdr *hdr;
	struct xdev_ext_user_ready *ready;
	struct xdev_ext_user_done *done;
	struct xdev_ext_user_slot *slots;
};

static void user_free(struct xdev_ext_user_stage *u)
{
	if (u->map)
		munmap(u->map, u->map_len);
	if (u->fd >= 0)
		close(u->fd);
	if (u->efd >= 0)
		close(u->efd);
	free(u);
}

int xdev_ext_user_stage_open(const struct xdev_ext_user_stage_opts *o,
			     struct xdev_ext_user_stage **out)
{
	struct xdev_ext_mech_user_stage r;
	struct io_uring_xdev_ext_mech req;
	struct xdev_ext_user_stage *u;
	__u32 entries;
	int ret;

	if (!o || !out)
		return -EINVAL;
	ret = xdev_ext__opts_check(o, o->sz, sizeof(*o));
	if (ret)
		return ret;
	if (o->flags & ~XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL)
		return -EOPNOTSUPP;
	entries = o->entries ? o->entries : USER_DEFAULT_ENTRIES;
	if (o->ring_fd < 0 || (entries & (entries - 1)) || entries > XDEV_EXT_USER_RING_MAX)
		return -EINVAL;
	u = calloc(1, sizeof(*u));
	if (!u)
		return -ENOMEM;
	u->fd = -1;
	atomic_flag_clear(&u->owner_lock);
	u->umem = o->umem;
	u->entries = entries;
	u->flags = o->flags;
	u->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (u->efd < 0) {
		ret = -errno;
		user_free(u);
		return ret;
	}
	memset(&r, 0, sizeof(r));
	r.size = sizeof(r);
	r.flags = o->flags;
	r.entries = entries;
	r.eventfd = u->efd;
	req = (struct io_uring_xdev_ext_mech){ .op = XDEV_EXT_MECH_OP_USER_STAGE,
		.arg = (uintptr_t)&r };
	ret = xdev_ext__uring_register(o->ring_fd, IORING_REGISTER_XDEV_EXT_MECH, &req);
	if (ret < 0) {
		user_free(u);
		return ret;
	}
	u->fd = r.fd;
	if (r.off.mmap_size < r.off.slots + entries * sizeof(struct xdev_ext_user_slot) ||
	    r.off.ready % 8 || r.off.done % 8 || r.off.slots % 8 ||
	    r.off.hdr + sizeof(*u->hdr) > r.off.mmap_size) {
		user_free(u);
		return -EPROTO;
	}
	u->map_len = r.off.mmap_size;
	u->off = r.off;
	u->map = mmap(NULL, u->map_len, PROT_READ | PROT_WRITE, MAP_SHARED, u->fd, 0);
	if (u->map == MAP_FAILED) {
		ret = -errno;
		u->map = NULL;
		user_free(u);
		return ret;
	}
	u->hdr = (void *)((char *)u->map + r.off.hdr);
	u->ready = (void *)((char *)u->map + r.off.ready);
	u->done = (void *)((char *)u->map + r.off.done);
	u->slots = (void *)((char *)u->map + r.off.slots);
	*out = u;
	return 0;
}

int xdev_ext_user_stage_fd(const struct xdev_ext_user_stage *u)
{
	return u ? u->fd : -EINVAL;
}

__u32 xdev_ext_user_stage_entries(const struct xdev_ext_user_stage *u)
{
	return u ? u->entries : 0;
}

bool xdev_ext__user_ctl_attached(const struct xdev_ext_user_stage *u)
{
	return u && u->attached;
}

int xdev_ext__user_bind_stream(struct xdev_ext_user_stage *u,
	unsigned long long context_id, unsigned long long stream_id)
{
	int ret = 0;
	if (!u) return -EINVAL;
	while (atomic_flag_test_and_set_explicit(&u->owner_lock, memory_order_acquire))
		sched_yield();
	if (u->owner_bound) {
		if (u->owner_context_id != context_id || u->owner_stream_id != stream_id)
			ret = -EINVAL;
	} else {
		u->owner_context_id = context_id;
		u->owner_stream_id = stream_id;
		u->owner_bound = true;
	}
	atomic_flag_clear_explicit(&u->owner_lock, memory_order_release);
	return ret;
}

static __u32 load_acquire(const __u32 *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static void store_release(__u32 *p, __u32 v)
{
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
}

/*
 * Copy the frames of slot @s while it still holds @ticket.  The kernel sets
 * a slot's ticket to 0 when its batch leaves the stage (deadline, stop,
 * completion) and only then rewrites the frames for the next batch in that
 * slot, so a ticket that matches both before and after the copy means the
 * copy is the batch's own.  False: the batch is gone.
 */
static bool slot_copy(const struct xdev_ext_user_slot *s, __u64 ticket, __u32 nr,
		      struct xdev_ext_user_frame *f)
{
	__u32 i;

	if (!ticket || __atomic_load_n(&s->ticket, __ATOMIC_ACQUIRE) != ticket)
		return false;
	for (i = 0; i < nr; i++) {
		f[i].umem_addr = __atomic_load_n(&s->f[i].umem_addr, __ATOMIC_RELAXED);
		f[i].data_off = __atomic_load_n(&s->f[i].data_off, __ATOMIC_RELAXED);
		f[i].data_len = __atomic_load_n(&s->f[i].data_len, __ATOMIC_RELAXED);
		f[i].capacity = __atomic_load_n(&s->f[i].capacity, __ATOMIC_RELAXED);
		f[i].out_len = f[i].data_len;	/* the kernel's preset */
	}
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
	return __atomic_load_n(&s->ticket, __ATOMIC_RELAXED) == ticket;
}

/*
 * 0 with *b filled, -EAGAIN when the ring is empty, -EPROTO for a bad entry.
 * An entry whose batch was cancelled before it was read (its slot no longer
 * holds the entry's ticket) is consumed and skipped: its slot may already
 * describe a later batch, which has its own entry.
 */
static int take(struct xdev_ext_user_stage *u, struct xdev_ext_user_batch *b)
{
	struct xdev_ext_user_frame f[XDEV_EXT_MECH_MAX_FRAMES];
	struct xdev_ext_user_ready r;
	__u32 cons, i;

	for (;;) {
		cons = u->hdr->ready_cons;
		if (load_acquire(&u->hdr->ready_prod) == cons)
			return -EAGAIN;
		r = u->ready[cons & (u->entries - 1)];
		store_release(&u->hdr->ready_cons, cons + 1);
		if (r.slot >= u->entries || !r.nr_frames || r.nr_frames > XDEV_EXT_MECH_MAX_FRAMES)
			return -EPROTO;
		if (slot_copy(&u->slots[r.slot], r.ticket, r.nr_frames, f))
			break;
	}
	memset(b, 0, sizeof(*b));
	b->slot = r.slot;
	b->nr_frames = r.nr_frames;
	b->ticket = r.ticket;
	b->batch_id = r.batch_id;
	b->key = r.key;
	b->arg = r.arg;
	memcpy(b->f, f, r.nr_frames * sizeof(f[0]));
	if (u->umem)
		for (i = 0; i < r.nr_frames; i++)
			b->data[i] = (char *)u->umem + b->f[i].umem_addr + b->f[i].data_off;
	return 0;
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* A wake is only a request to rescan, never custody of a ready entry. */
static bool user_wait_rescan(struct xdev_ext_user_stage *const *users, size_t nr)
{
	bool rescan = false;
	size_t i;

	for (i = 0; i < nr; i++) {
		struct xdev_ext_user_stage *u = users[i];

		if (load_acquire(&u->hdr->ready_prod) != u->hdr->ready_cons ||
		    (load_acquire(&u->hdr->kernel_flags) & XDEV_EXT_USER_K_STOPPED))
			rescan = true;
	}
	return rescan;
}

/* Ceil the remaining duration so sub-millisecond time never expires early. */
static int user_wait_timeout(const struct timespec *deadline, int *wait)
{
	struct timespec now;
	time_t sec;
	long nsec;

	*wait = -1;
	if (!deadline)
		return 0;
	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -errno;
	if (now.tv_sec > deadline->tv_sec ||
	    (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)) {
		*wait = 0;
		return 0;
	}
	sec = deadline->tv_sec - now.tv_sec;
	nsec = deadline->tv_nsec - now.tv_nsec;
	if (nsec < 0) {
		sec--;
		nsec += 1000000000L;
	}
	if (sec > INT_MAX / 1000 ||
	    (sec == INT_MAX / 1000 &&
	     (nsec + 999999L) / 1000000L > INT_MAX % 1000))
		*wait = INT_MAX;
	else
		*wait = (int)sec * 1000 + (nsec + 999999L) / 1000000L;
	return 0;
}

int xdev_ext__user_wait_any(struct xdev_ext_user_stage *const *users,
			  size_t nr, const struct timespec *deadline)
{
	struct pollfd p[2];
	size_t i;
	int ret, wait;

	if (!users || !nr || nr > 2 || !users[0] ||
	    (nr == 2 && (!users[1] || users[0] == users[1])) ||
	    (deadline && (deadline->tv_sec < 0 || deadline->tv_nsec < 0 ||
			  deadline->tv_nsec >= 1000000000L)))
		return -EINVAL;
	/* The endpoint has the same check before taking from either candidate.
	 * Owner changes/concurrent close remain outside the single-consumer contract. */
	for (i = 0; i < nr; i++)
		if (xdev_ext__user_ctl_attached(users[i]))
			return -EBUSY;
	if (user_wait_rescan(users, nr))
		return 0;
	ret = user_wait_timeout(deadline, &wait);
	if (ret)
		return ret;
	if (!wait)
		return user_wait_rescan(users, nr) ? 0 : -ETIMEDOUT;
	for (i = 0; i < nr; i++) {
		p[i] = (struct pollfd){ .fd = users[i]->efd, .events = POLLIN };
		__atomic_or_fetch(&users[i]->hdr->user_flags, XDEV_EXT_USER_F_SLEEPING,
				  __ATOMIC_SEQ_CST);
	}
	/* Paired with the kernel's publish/fence/SLEEPING observation. */
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	if (user_wait_rescan(users, nr)) {
		ret = 0;
		goto clear;
	}
	ret = user_wait_timeout(deadline, &wait);
	if (ret)
		goto clear;
	if (!wait) {
		ret = user_wait_rescan(users, nr) ? 0 : -ETIMEDOUT;
		goto clear;
	}
	ret = poll(p, nr, wait);
	if (ret < 0) {
		ret = errno == EINTR ? 0 : -errno;
		goto clear;
	}
	for (i = 0; i < nr; i++) {
		if (p[i].revents & POLLNVAL) {
			ret = -EBADF;
			goto clear;
		}
		if (p[i].revents & (POLLERR | POLLHUP)) {
			ret = -EIO;
			goto clear;
		}
	}
	for (i = 0; i < nr; i++) {
		__u64 count;
		ssize_t len;

		if (!(p[i].revents & POLLIN))
			continue;
		/* An eventfd read drains aggregated hints in one operation. Never
		 * turn the count into a number of ready entries to consume. */
		for (;;) {
			len = read(users[i]->efd, &count, sizeof(count));
			if (len >= 0 || errno != EINTR)
				break;
			ret = user_wait_timeout(deadline, &wait);
			if (ret || !wait) {
				if (!ret)
					ret = user_wait_rescan(users, nr) ? 0 : -ETIMEDOUT;
				goto clear;
			}
		}
		if (len < 0 && errno != EAGAIN) {
			ret = -errno;
			goto clear;
		}
		if (len >= 0 && len != sizeof(count)) {
			ret = -EIO;
			goto clear;
		}
	}
	/* Even timeout must yield to work/STOP published at the deadline. */
	ret = user_wait_timeout(deadline, &wait);
	if (!ret && !wait && !user_wait_rescan(users, nr))
		ret = -ETIMEDOUT;
clear:
	for (i = 0; i < nr; i++)
		__atomic_and_fetch(&users[i]->hdr->user_flags, ~XDEV_EXT_USER_F_SLEEPING,
				   __ATOMIC_SEQ_CST);
	return ret;
}

int xdev_ext_user_stage_next(struct xdev_ext_user_stage *u, int timeout_ms,
			     struct xdev_ext_user_batch *b)
{
	long long deadline = timeout_ms > 0 ? now_ms() + timeout_ms : 0;
	struct pollfd p;
	__u64 count;
	int ret, wait;

	if (!u || !b)
		return -EINVAL;
	for (;;) {
		ret = take(u, b);
		if (ret != -EAGAIN)
			return ret;
		if (__atomic_load_n(&u->hdr->kernel_flags, __ATOMIC_ACQUIRE) & XDEV_EXT_USER_K_STOPPED)
			return -ESHUTDOWN;
		if (!timeout_ms)
			return -EAGAIN;
		wait = -1;
		if (timeout_ms > 0) {
			long long left = deadline - now_ms();

			if (left <= 0)
				return -ETIMEDOUT;
			wait = (int)left;
		}
		/* Sleep only after the kernel can see the flag and the ring is still empty. */
		__atomic_or_fetch(&u->hdr->user_flags, XDEV_EXT_USER_F_SLEEPING, __ATOMIC_SEQ_CST);
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
		if (load_acquire(&u->hdr->ready_prod) == u->hdr->ready_cons &&
		    !(__atomic_load_n(&u->hdr->kernel_flags, __ATOMIC_ACQUIRE) & XDEV_EXT_USER_K_STOPPED)) {
			p = (struct pollfd){ .fd = u->efd, .events = POLLIN };
			ret = poll(&p, 1, wait);
			if (ret < 0 && errno != EINTR) {
				ret = -errno;
				__atomic_and_fetch(&u->hdr->user_flags, ~XDEV_EXT_USER_F_SLEEPING,
						   __ATOMIC_SEQ_CST);
				return ret;
			}
		}
		if (read(u->efd, &count, sizeof(count)) < 0 && errno != EAGAIN) {
			ret = -errno;
			__atomic_and_fetch(&u->hdr->user_flags, ~XDEV_EXT_USER_F_SLEEPING, __ATOMIC_SEQ_CST);
			return ret;
		}
		__atomic_and_fetch(&u->hdr->user_flags, ~XDEV_EXT_USER_F_SLEEPING, __ATOMIC_SEQ_CST);
	}
}

int xdev_ext_user_stage_complete(struct xdev_ext_user_stage *u,
				 const struct xdev_ext_user_batch *b, int status)
{
	struct xdev_ext_user_slot *s;
	struct xdev_ext_user_done *d;
	__u32 prod, i;

	if (!u || !b || status > 0 || b->slot >= u->entries || b->nr_frames > XDEV_EXT_MECH_MAX_FRAMES)
		return -EINVAL;
	prod = u->hdr->done_prod;
	if (prod - __atomic_load_n(&u->hdr->done_cons, __ATOMIC_ACQUIRE) >= u->entries)
		return -ENOSPC;
	/* Lengths only into a slot that still holds this batch, never a later one's. */
	s = &u->slots[b->slot];
	if (b->ticket && __atomic_load_n(&s->ticket, __ATOMIC_ACQUIRE) == b->ticket)
		for (i = 0; i < b->nr_frames; i++)
			__atomic_store_n(&s->f[i].out_len, b->f[i].out_len, __ATOMIC_RELAXED);
	d = &u->done[prod & (u->entries - 1)];
	d->ticket = b->ticket;
	d->slot = b->slot;
	d->status = status;
	/* out_len of the slot and this entry before the index. */
	store_release(&u->hdr->done_prod, prod + 1);
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	if (__atomic_load_n(&u->hdr->kernel_flags, __ATOMIC_ACQUIRE) & XDEV_EXT_USER_K_NEED_KICK) {
		int ret = xdev_ext__ioctl(u->fd, XDEV_EXT_USER_IOC_KICK, 0);

		return ret < 0 ? ret : 0;
	}
	return 0;
}

int xdev_ext_user_stage_close(struct xdev_ext_user_stage *u)
{
	if (u && u->attached)
		return -EBUSY;
	if (u)
		user_free(u);
	return 0;
}

int xdev_ext_user_stage_control(struct xdev_ext_user_stage *u, void **base,
	struct xdev_ext_user_ring_offsets *off)
{
	if (!u || !base || !off)
		return -EINVAL;
	if (!(u->flags & XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL))
		return -EOPNOTSUPP;
	*base = u->map;
	*off = u->off;
	return 0;
}

int xdev_ext_user_stage_ctl_attach(struct xdev_ext_user_stage *u)
{
	int ret;
	if (!u)
		return -EINVAL;
	if (!(u->flags & XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL))
		return -EOPNOTSUPP;
	if (u->attached)
		return -EALREADY;
	ret = xdev_ext__ioctl(u->fd, XDEV_EXT_USER_IOC_CTL_ATTACH, 0);
	if (!ret)
		u->attached = true;
	return ret;
}

int xdev_ext_user_stage_ctl_detach(struct xdev_ext_user_stage *u)
{
	int ret;
	if (!u)
		return -EINVAL;
	if (!(u->flags & XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL))
		return -EOPNOTSUPP;
	if (!u->attached)
		return -ENOENT;
	ret = xdev_ext__ioctl(u->fd, XDEV_EXT_USER_IOC_CTL_DETACH, 0);
	if (!ret)
		u->attached = false;
	return ret;
}

int xdev_ext_user_batch_peer_span(const struct xdev_ext_user_batch *b, __u32 pos,
	__u64 allocation_va, __u64 allocation_bytes, __u32 frame_size,
	struct xdev_ext_peer_span *out)
{
	const struct xdev_ext_user_frame *f;
	struct xdev_ext_peer_span span;
	__u64 offset;
	if (!b || !out || !frame_size || !b->nr_frames ||
	    b->nr_frames > XDEV_EXT_MECH_MAX_FRAMES || pos >= b->nr_frames)
		return -EINVAL;
	f = &b->f[pos];
	if (f->umem_addr % frame_size || f->umem_addr / frame_size > UINT32_MAX ||
	    f->data_off > frame_size || f->capacity > frame_size - f->data_off ||
	    f->data_len > f->capacity || f->umem_addr > allocation_bytes ||
	    frame_size > allocation_bytes - f->umem_addr)
		return -ERANGE;
	offset = f->umem_addr + f->data_off;
	if (allocation_va > UINT64_MAX - offset ||
	    f->capacity > UINT64_MAX - (allocation_va + offset))
		return -EOVERFLOW;
	span = (struct xdev_ext_peer_span) {
		.offset = offset, .device_address = allocation_va + offset,
		.frame_index = f->umem_addr / frame_size,
		.data_len = f->data_len, .capacity = f->capacity,
	};
	*out = span;
	return 0;
}
