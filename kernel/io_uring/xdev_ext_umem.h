/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_UMEM_H
#define IO_URING_XDEV_EXT_UMEM_H

#include "xdev_ext_config.h"

#ifdef XDEV_EXT_UMEM_ZEROCOPY

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/refcount.h>

#ifdef XDEV_EXT_LIFECYCLE_SM
#include "../xdev_ext_frame_sm.h"
#endif

struct io_ring_ctx;
struct io_uring_unified_shared;
struct user_struct;

struct io_xdev_ext_umem {
	struct page	**pages;
	void		*vmap_addr;	/* raw vmap base (page-aligned) */
	u32		page_offset;	/* offset within first page */
	u64		user_addr;
	u64		size;
	u32		nr_pages;
	u32		frame_size;
	u32		nr_frames;
	/*
	 * A virtual address identifies memory only within its owning address
	 * space. Hold mm_count so this identity cannot be freed and reused while
	 * the registry entry exists.
	 */
	struct mm_struct *mm;
	refcount_t	refcount;	/* shared across io_ring_ctx instances */
	/*
	 * Locked-memory charge of the long-term pins, taken the way io_uring
	 * registered buffers take it (io_account_mem()): @acct_pages against
	 * the ring creator's RLIMIT_MEMLOCK through @user (NULL when the
	 * creator had CAP_IPC_LOCK) and against @mm_account->pinned_vm.  The
	 * UMEM can outlive the registering ring, so it holds its own uid and
	 * mm_count references and drops the charge together with the pins.
	 */
	struct user_struct *user;
	struct mm_struct *mm_account;
	unsigned long	acct_pages;
#ifdef CONFIG_XDEV_EXT_MECH
	/*
	 * One mechanism-layer ownership word per frame (enum
	 * xdev_ext_mech_frame_state), allocated by the first session bound to this
	 * UMEM and shared by all of them; freed with the UMEM.  Non-NULL also
	 * means the UMEM belongs to mechanism sessions for the rest of its life.
	 */
	u8		*mech_state;
	/*
	 * Set by the first legacy unified op on this UMEM.  Legacy ops name
	 * frames by UMEM offset and never consult @mech_state, so one UMEM
	 * serves either legacy ops or mechanism sessions, never both.  Both
	 * fields change under xdev_ext_umem_lock.
	 */
	bool		legacy_used;
#endif
#ifdef XDEV_EXT_LIFECYCLE_SM
	/*
	 * Per-frame lifecycle SM, advanced from IRQ/softirq completion
	 * context (CAS claim / release publish / atomic_dec retire — see
	 * xdev_ext_frame_sm.h). use_stack=false: userspace names the frame via
	 * the op's UMEM offset and the kernel CAS-claims that index.
	 */
	struct xdev_ext_pool		frame_pool;
	struct xdev_ext_frame	*frames;
#endif
};

int io_xdev_ext_umem_register(struct io_ring_ctx *ctx, void __user *arg);
int io_xdev_ext_umem_unregister(struct io_ring_ctx *ctx);
void io_xdev_ext_umem_destroy(struct io_ring_ctx *ctx);
/*
 * Hold/release a UMEM across io-wq work or async I/O whose lifetime can
 * outlive unregister. put() may free and must run in task context.
 *
 * get_ctx_with_stats() is the legacy unified-op acquisition: it marks the
 * UMEM legacy_used and returns NULL once a mechanism session has bound it
 * (the op then fails as if no UMEM were registered).  get_ctx() is the
 * mechanism-binding acquisition and leaves that mark alone.
 */
struct io_xdev_ext_umem *io_xdev_ext_umem_get_ctx(struct io_ring_ctx *ctx);
struct io_xdev_ext_umem *io_xdev_ext_umem_get_ctx_with_stats(
		struct io_ring_ctx *ctx,
		struct io_uring_unified_shared __user **shared);
void io_xdev_ext_umem_get(struct io_xdev_ext_umem *umem);
void io_xdev_ext_umem_put(struct io_xdev_ext_umem *umem);

/* Get kernel virtual address for a UMEM offset+len. Returns NULL if out of bounds. */
static inline void *io_xdev_ext_umem_kaddr(struct io_xdev_ext_umem *umem, u64 offset, u32 len)
{
	if (!len || offset >= umem->size || len > umem->size - offset)
		return NULL;
	return umem->vmap_addr + umem->page_offset + offset;
}

/* Get page and offset-within-page for a given UMEM offset */
static inline struct page *io_xdev_ext_umem_offset_to_page(struct io_xdev_ext_umem *umem,
						       u64 offset, u32 *pgoff)
{
	u64 abs_off;
	u32 idx;

	if (offset >= umem->size || offset > ((u64)~0ULL) - umem->page_offset)
		return NULL;

	abs_off = umem->page_offset + offset;
	idx = abs_off >> PAGE_SHIFT;
	if (idx >= umem->nr_pages)
		return NULL;
	if (pgoff)
		*pgoff = abs_off & ~PAGE_MASK;
	return umem->pages[idx];
}

#endif /* XDEV_EXT_UMEM_ZEROCOPY */
#endif /* IO_URING_XDEV_EXT_UMEM_H */
