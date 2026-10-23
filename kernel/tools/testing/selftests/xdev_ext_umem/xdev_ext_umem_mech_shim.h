/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_UMEM_MECH_SHIM_H
#define XDEV_EXT_UMEM_MECH_SHIM_H

/*
 * The slice of linux/xdev_ext_mech.h and io_uring/xdev_ext_mech_core.h that
 * the CONFIG_XDEV_EXT_MECH part of io_uring/xdev_ext_umem.c uses.  Frame
 * ownership words and their legal edges copy xdev_ext_mech_frame_edge_ok().
 */
#define _LINUX_XDEV_EXT_MECH_H
#define IO_URING_XDEV_EXT_MECH_CORE_H

#include "xdev_ext_umem_kernel_shim.h"

typedef struct {
	pthread_mutex_t native;
} spinlock_t;

static inline void spin_lock_init(spinlock_t *lock)
{
	pthread_mutex_init(&lock->native, NULL);
}

#define spin_lock_irqsave(lock, flags) \
	do { (flags) = 0; pthread_mutex_lock(&(lock)->native); } while (0)
#define spin_unlock_irqrestore(lock, flags) \
	do { (void)(flags); pthread_mutex_unlock(&(lock)->native); } while (0)

#define WARN_ON_ONCE(cond) (!!(cond))
#define struct_size(p, member, n) \
	(sizeof(*(p)) + (size_t)(n) * sizeof((p)->member[0]))

static inline void *kvzalloc(size_t size, int flags)
{
	(void)flags;
	return calloc(1, size);
}

enum xdev_ext_mech_frame_state {
	XDEV_EXT_MECH_F_USER		= 0,
	XDEV_EXT_MECH_F_K_FREE	= 1,
	XDEV_EXT_MECH_F_HELD		= 2,
	XDEV_EXT_MECH_F_INFLIGHT	= 3,
	XDEV_EXT_MECH_F_SEQUESTERED	= 4,
	XDEV_EXT_MECH_F_NIC_RX	= 5,
	XDEV_EXT_MECH_F_NR,
};

#define XDEV_EXT_MECH_POOL_IOU_UMEM 2

struct xdev_ext_mech_layout {
	u32 frame_size;
	u32 hdr_room;
	u32 seg_len;
	u32 group_bytes;
};

struct xdev_ext_mech_frame {
	void *kaddr;
	u64 umem_addr;
	u32 index;
	u32 data_off;
	u32 data_len;
	void *pool_priv;
};

struct xdev_ext_mech_pool;

struct xdev_ext_mech_pool_ops {
	int  (*alloc)(struct xdev_ext_mech_pool *pool, struct xdev_ext_mech_frame *f,
		      u32 nr);
	int  (*resolve)(struct xdev_ext_mech_pool *pool, struct xdev_ext_mech_frame *f);
	void (*recycle)(struct xdev_ext_mech_pool *pool, struct xdev_ext_mech_frame *f);
	void (*release)(struct xdev_ext_mech_pool *pool);
};

struct xdev_ext_mech_pool {
	const struct xdev_ext_mech_pool_ops *ops;
	void *priv;
	u8 *state;
	struct page **pages;
	void *vaddr;
	u64 size;
	u32 kind;
	u32 capabilities;
	u32 frame_size;
	u32 nr_frames;
	u32 nr_pages;
	u32 first_page_off;
};

static inline bool xdev_ext_mech_frame_edge_ok(u32 from, u32 to)
{
	if (to >= XDEV_EXT_MECH_F_NR)
		return false;
	switch (from) {
	case XDEV_EXT_MECH_F_USER:
		return to == XDEV_EXT_MECH_F_K_FREE || to == XDEV_EXT_MECH_F_HELD ||
		       to == XDEV_EXT_MECH_F_NIC_RX;
	case XDEV_EXT_MECH_F_K_FREE:
		return to == XDEV_EXT_MECH_F_HELD || to == XDEV_EXT_MECH_F_USER ||
		       to == XDEV_EXT_MECH_F_NIC_RX;
	case XDEV_EXT_MECH_F_NIC_RX:
		return to == XDEV_EXT_MECH_F_HELD || to == XDEV_EXT_MECH_F_K_FREE ||
		       to == XDEV_EXT_MECH_F_USER || to == XDEV_EXT_MECH_F_SEQUESTERED;
	case XDEV_EXT_MECH_F_HELD:
		return to == XDEV_EXT_MECH_F_INFLIGHT || to == XDEV_EXT_MECH_F_K_FREE ||
		       to == XDEV_EXT_MECH_F_USER || to == XDEV_EXT_MECH_F_SEQUESTERED;
	case XDEV_EXT_MECH_F_INFLIGHT:
		return to == XDEV_EXT_MECH_F_HELD || to == XDEV_EXT_MECH_F_SEQUESTERED;
	default:
		return false;
	}
}

static inline u8 xdev_ext_mech_frame_state(const u8 *word)
{
	return __atomic_load_n(word, __ATOMIC_RELAXED);
}

static inline int xdev_ext_mech_frame_move(u8 *word, u32 from, u32 to)
{
	u8 old = (u8)from;

	if (!xdev_ext_mech_frame_edge_ok(from, to))
		return -EINVAL;
	return __atomic_compare_exchange_n(word, &old, (u8)to, false,
					   __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST) ?
	       0 : -EBUSY;
}

#endif /* XDEV_EXT_UMEM_MECH_SHIM_H */
