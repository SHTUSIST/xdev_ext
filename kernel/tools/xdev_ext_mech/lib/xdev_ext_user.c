// SPDX-License-Identifier: GPL-2.0
/*
 * libxdev_ext USER stage helpers: SPEC.md section 8, the user side of
 * Documentation/userspace-api/xdev_ext-user-stage.rst.  One user stage fd,
 * its mapping and a library-owned wakeup eventfd per handle.  One thread at
 * a time takes ready entries, and one thread at a time posts completions.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
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
	if (o->flags)
		return -EOPNOTSUPP;
	entries = o->entries ? o->entries : USER_DEFAULT_ENTRIES;
	if (o->ring_fd < 0 || (entries & (entries - 1)) || entries > XDEV_EXT_USER_RING_MAX)
		return -EINVAL;
	u = calloc(1, sizeof(*u));
	if (!u)
		return -ENOMEM;
	u->fd = -1;
	u->umem = o->umem;
	u->entries = entries;
	u->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (u->efd < 0) {
		ret = -errno;
		user_free(u);
		return ret;
	}
	memset(&r, 0, sizeof(r));
	r.size = sizeof(r);
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

static __u32 load_acquire(const __u32 *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static void store_release(__u32 *p, __u32 v)
{
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
}

/* 0 with *b filled, -EAGAIN when the ring is empty, -EPROTO for a bad entry. */
static int take(struct xdev_ext_user_stage *u, struct xdev_ext_user_batch *b)
{
	__u32 cons = u->hdr->ready_cons, i;
	struct xdev_ext_user_ready r;

	if (load_acquire(&u->hdr->ready_prod) == cons)
		return -EAGAIN;
	r = u->ready[cons & (u->entries - 1)];
	store_release(&u->hdr->ready_cons, cons + 1);
	if (r.slot >= u->entries || !r.nr_frames || r.nr_frames > XDEV_EXT_MECH_MAX_FRAMES)
		return -EPROTO;
	memset(b, 0, sizeof(*b));
	b->slot = r.slot;
	b->nr_frames = r.nr_frames;
	b->ticket = r.ticket;
	b->batch_id = r.batch_id;
	b->key = r.key;
	b->arg = r.arg;
	b->f = u->slots[r.slot].f;
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
	struct xdev_ext_user_done *d;
	__u32 prod;

	if (!u || !b || status > 0 || b->slot >= u->entries)
		return -EINVAL;
	prod = u->hdr->done_prod;
	if (prod - __atomic_load_n(&u->hdr->done_cons, __ATOMIC_ACQUIRE) >= u->entries)
		return -ENOSPC;
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
	if (u)
		user_free(u);
	return 0;
}
