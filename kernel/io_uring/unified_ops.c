// SPDX-License-Identifier: GPL-2.0
/*
 * Unified operations handler for io_uring.
 * Supports READ, SEND, CALCULATE, WRITE, and IAA operations.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/time64.h>
#include <linux/xdev_ext_binding.h>
#include <asm/futex.h>
#include <net/sock.h>
#include <net/xdp_sock.h>		/* xsk_kernel_xmit (self-guarding stubs) */
#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "rsrc.h"
#include "unified_ops.h"
#include "unified_ops_core.h"
#include "sched_hints.h"
#include "iaa/xdev_ext_iaa.h"
#include "xdev_ext_send_hook.h"
#include "xdev_ext_umem.h"

struct io_unified_ops {
	struct file			*file;
	u64				addr;		/* Buffer address */
	u64				shared_addr;	/* Shared memory address */
	/* Full 64-bit file offset (sqe->off) or send flags. Was u32, which
	 * silently truncated offsets >= 4 GiB and read/wrote the wrong LBA
	 * on any large namespace (review finding nvme-1). */
	u64				offset;
	u64				dst_cap;	/* IAA destination capacity */
	u32				len;		/* Buffer length */
	u32				opcode;		/* Sub-opcode */
#ifdef XDEV_EXT_UMEM_ZEROCOPY
	bool				use_umem;
#endif
};

static inline bool io_unified_is_iaa(u32 opcode)
{
	return opcode == IO_UNIFIED_OP_IAA_COMPRESS ||
	       opcode == IO_UNIFIED_OP_IAA_DECOMPRESS;
}

/*
 * SEND dispatch tiers. Kept as a pure, testable classification independent of
 * any runtime socket state so the decision can be unit-tested in userspace.
 * Plan Y has no ZC runtime arm: a TX-capable AF_XDP socket maps to the
 * in-kernel COPY-mode send, everything else to the existing sock/UMEM path.
 */
enum xdev_ext_send_path {
	XDEV_EXT_SEND_SOCK		= 0,	/* existing sock_sendmsg / UMEM path */
	XDEV_EXT_SEND_XDP_COPY	= 1,	/* in-kernel COPY-mode AF_XDP send */
};

static inline enum xdev_ext_send_path
xdev_ext_pick_send_path(bool afxdp_compiled, bool is_xdp_sock, bool xsk_bound,
		   bool has_tx_ring)
{
	if (!afxdp_compiled)
		return XDEV_EXT_SEND_SOCK;
	return (is_xdp_sock && xsk_bound && has_tx_ring) ? XDEV_EXT_SEND_XDP_COPY :
							   XDEV_EXT_SEND_SOCK;
}

static atomic64_t io_unified_xdev_ext_policy_errors;

static int
io_unified_xdev_ext_dispatch_send(struct io_unified_ops *op, bool afxdp,
			     struct xdev_ext_binding_ctx_v2 *ctx,
			     struct xdev_ext_binding_token *token,
			     struct xdev_ext_send_hook_state *hook)
{
	struct xdev_ext_binding_plan plan;

	if (!xdev_ext_binding_policy_active())
		return 0;

#ifdef XDEV_EXT_UMEM_ZEROCOPY
	*ctx = xdev_ext_send_hook_make_ctx(afxdp, op->use_umem, op->addr, op->len);
#else
	*ctx = xdev_ext_send_hook_make_ctx(afxdp, false, op->addr, op->len);
#endif
	return xdev_ext_send_hook_dispatch_binding(hook, ctx, token, &plan, NULL);
}

static void
io_unified_xdev_ext_finish_send(struct xdev_ext_binding_ctx_v2 *ctx,
			   struct xdev_ext_binding_token *token,
			   struct xdev_ext_send_hook_state *hook,
			   bool native_called,
			   ssize_t native_result)
{
	struct xdev_ext_binding_plan plan;
	int ret;

	ret = xdev_ext_send_hook_finish_binding(hook, ctx, token, native_called,
					   native_result, &plan);
	if (ret)
		atomic64_inc(&io_unified_xdev_ext_policy_errors);
}

/*
 * The shared stats block lives in userspace, but multiple io-wq workers can
 * update it concurrently. Use the same user-address atomic cmpxchg primitive
 * as futexes for the lock word; never fall back to unlocked RMW updates.
 */
#define IO_UNIFIED_SHARED_UNLOCKED	0
#define IO_UNIFIED_SHARED_LOCKED	1
#define IO_UNIFIED_SHARED_LOCK_RETRIES	4096

static inline int io_unified_fault_in_shared_lock(u32 __user *lockp)
{
	struct mm_struct *mm = current->mm;
	int ret;

	if (!mm)
		return -EFAULT;

	mmap_read_lock(mm);
	ret = fixup_user_fault(mm, (unsigned long)lockp, FAULT_FLAG_WRITE,
			       NULL);
	mmap_read_unlock(mm);

	return ret < 0 ? ret : 0;
}

static inline int io_unified_lock_shared(struct io_uring_unified_shared __user *shared)
{
	u32 old;
	int ret;
	int retries = IO_UNIFIED_SHARED_LOCK_RETRIES;
	u32 __user *lockp = &shared->lock;

	if (!IS_ALIGNED((unsigned long)lockp, sizeof(*lockp)))
		return -EINVAL;

	do {
		pagefault_disable();
		ret = futex_atomic_cmpxchg_inatomic(&old, lockp,
						    IO_UNIFIED_SHARED_UNLOCKED,
						    IO_UNIFIED_SHARED_LOCKED);
		pagefault_enable();
		if (ret == -EFAULT) {
			ret = io_unified_fault_in_shared_lock(lockp);
			if (ret)
				return ret;
			continue;
		}
		if (ret == -EAGAIN) {
			cond_resched();
			continue;
		}
		if (ret)
			return ret;
		if (old == IO_UNIFIED_SHARED_UNLOCKED) {
			smp_mb();
			return 0;
		}
		cpu_relax();
	} while (--retries);

	return -EBUSY;
}

static inline int io_unified_unlock_shared(struct io_uring_unified_shared __user *shared)
{
	smp_wmb();
	return put_user(IO_UNIFIED_SHARED_UNLOCKED, &shared->lock);
}

/* Helper to update shared memory statistics using locked get_user/put_user */
static inline void io_unified_update_read_stats(struct io_uring_unified_shared __user *shared,
						ssize_t bytes, bool error)
{
	u64 val64;
	u32 val32;

	if (io_unified_lock_shared(shared))
		return;
	if (error) {
		if (get_user(val32, &shared->read_errors))
			goto out_unlock;
		val32++;
		if (put_user(val32, &shared->read_errors))
			goto out_unlock;
	} else {
		if (get_user(val64, &shared->read_count))
			goto out_unlock;
		val64++;
		if (put_user(val64, &shared->read_count))
			goto out_unlock;
		if (get_user(val64, &shared->read_bytes))
			goto out_unlock;
		val64 += (u64)bytes;
		if (put_user(val64, &shared->read_bytes))
			goto out_unlock;
	}
	put_user(ktime_get_ns(), &shared->timestamp);
out_unlock:
	io_unified_unlock_shared(shared);
}

static inline void io_unified_update_send_stats(struct io_uring_unified_shared __user *shared,
						ssize_t bytes, bool error)
{
	u64 val64;
	u32 val32;

	if (io_unified_lock_shared(shared))
		return;
	if (error) {
		if (get_user(val32, &shared->send_errors))
			goto out_unlock;
		val32++;
		if (put_user(val32, &shared->send_errors))
			goto out_unlock;
	} else {
		if (get_user(val64, &shared->send_count))
			goto out_unlock;
		val64++;
		if (put_user(val64, &shared->send_count))
			goto out_unlock;
		if (get_user(val64, &shared->send_bytes))
			goto out_unlock;
		val64 += (u64)bytes;
		if (put_user(val64, &shared->send_bytes))
			goto out_unlock;
	}
	put_user(ktime_get_ns(), &shared->timestamp);
out_unlock:
	io_unified_unlock_shared(shared);
}

static inline void io_unified_update_calc_stats(struct io_uring_unified_shared __user *shared,
						u64 result, bool error)
{
	u64 val64;
	u32 val32;

	if (io_unified_lock_shared(shared))
		return;
	if (error) {
		if (get_user(val32, &shared->calc_errors))
			goto out_unlock;
		val32++;
		if (put_user(val32, &shared->calc_errors))
			goto out_unlock;
	} else {
		if (get_user(val64, &shared->calc_count))
			goto out_unlock;
		val64++;
		if (put_user(val64, &shared->calc_count))
			goto out_unlock;
		if (put_user(result, &shared->calc_result))
			goto out_unlock;
	}
	put_user(ktime_get_ns(), &shared->timestamp);
out_unlock:
	io_unified_unlock_shared(shared);
}

#ifdef XDEV_EXT_UMEM_ZEROCOPY

#ifdef XDEV_EXT_LIFECYCLE_SM
/*
 * IAA and legacy UMEM operations share this pool.  Every legacy window must
 * therefore resolve to one owned frame; a producer also has to start at the
 * frame boundary because valid_len describes a prefix rather than a range.
 */
static int
io_unified_sm_window(struct io_xdev_ext_umem *umem, u64 addr, u32 len,
		     bool producer, struct xdev_ext_lifecycle_window *window)
{
	int ret;

	if (!umem->frames)
		return -ENODEV;
	ret = xdev_ext_lifecycle_decode_window(addr, len, umem->size,
					  umem->frame_size, producer, window);
	if (ret)
		return ret;
	return window->frame < umem->nr_frames ? 0 : -ERANGE;
}

struct io_unified_async_read {
	struct kiocb	kiocb;
	struct iov_iter	iter;
	struct io_kiocb	*req;
	struct io_uring_unified_shared __user *shared;
	struct io_xdev_ext_umem *umem;	/* ref held across the async I/O (SM-1) */
	struct xdev_ext_mech_life_pool	*pool;
	struct xdev_ext_lifecycle_window window;
	bool		recycle_on_completion;
	u32		nr_bvecs;
	struct bio_vec	bvecs[];
};

static void io_unified_read_tw(struct io_kiocb *req, io_tw_token_t tw)
{
	struct io_unified_async_read *ar = req->async_data;
	long res = req->cqe.res;

	/* get_user/put_user need task context — this is why the completion
	 * bounces here instead of finishing in io_unified_read_done(). */
	if (res >= 0)
		fsnotify_access(ar->kiocb.ki_filp);
	io_unified_update_read_stats(ar->shared, res, res < 0);
	if (req->tctx)
		io_sched_record_op(req->tctx, 0, res > 0 ? res : 0);
	io_xdev_ext_umem_put(ar->umem);	/* SM-1: drop the async-I/O hold */
	io_req_task_complete(req, tw);
}

/*
 * I/O completion path (bio end_io -> ki_complete), IRQ or softirq context.
 * The frame publication (IO_PENDING->READY, release) happens HERE, lock-
 * free — the transition the paper describes. Everything that needs task
 * context is bounced to task work (mirrors io_uring/rw.c io_complete_rw).
 */
static void io_unified_read_done(struct kiocb *kiocb, long res)
{
	struct io_unified_async_read *ar =
		container_of(kiocb, struct io_unified_async_read, kiocb);
	struct io_kiocb *req = ar->req;

	int state_ret;

	state_ret = xdev_ext_unified_read_finish(ar->pool, ar->window.frame, ar->window.claim, res,
					 ar->recycle_on_completion);
	if (state_ret)
		res = -EIO;
	if (res < 0)
		req_set_fail(req);
	io_req_set_res(req, res, 0);
	req->io_task_work.func = io_unified_read_tw;
	io_req_task_work_add(req);
}

/*
 * Async UMEM read: same bvec construction as the sync path, but the kiocb
 * lives in req->async_data and completes via ki_complete. Requires a file
 * with a real read_iter (block dev /dev/nvmeXnY: blkdev_read_iter; the NVMe
 * CHAR dev /dev/ngXnY has none and still returns -EINVAL here). IOCB_DIRECT
 * alignment rules are the block layer's, unchanged.
 */
static int io_unified_do_read_umem_async(struct io_kiocb *req,
					 struct io_unified_ops *op,
					 struct io_xdev_ext_umem *umem,
					 struct io_uring_unified_shared __user *shared,
					 bool recycle_on_completion)
{
	struct io_unified_async_read *ar;
	struct xdev_ext_mech_life_pool *pool;
	struct xdev_ext_lifecycle_window window;
	struct page *page;
	u32 pgoff, nr_pages, remaining, i;
	u64 cur_off;
	int state_ret;
	ssize_t ret;

	if (!op->file)
		return -EBADF;
	if (!op->file->f_op->read_iter)
		return -EINVAL;
	if (!io_xdev_ext_umem_kaddr(umem, op->addr, op->len))
		return -EINVAL;
	ret = io_unified_sm_window(umem, op->addr, op->len, true, &window);
	if (ret)
		return ret;

	pgoff = (umem->page_offset + op->addr) & ~PAGE_MASK;
	nr_pages = (pgoff + op->len + PAGE_SIZE - 1) >> PAGE_SHIFT;

	ar = kmalloc(struct_size(ar, bvecs, nr_pages), GFP_KERNEL);
	if (!ar)
		return -ENOMEM;

	cur_off = op->addr;
	remaining = op->len;
	for (i = 0; i < nr_pages; i++) {
		u32 this_pgoff, this_len;

		page = io_xdev_ext_umem_offset_to_page(umem, cur_off, &this_pgoff);
		if (!page) {
			kfree(ar);
			return -EINVAL;
		}
		this_len = min_t(u32, remaining, PAGE_SIZE - this_pgoff);
		bvec_set_page(&ar->bvecs[i], page, this_len, this_pgoff);
		cur_off += this_len;
		remaining -= this_len;
	}

	pool = &umem->frame_pool;
	ret = xdev_ext_lifecycle_producer_begin(pool, &window);
	if (ret) {
		kfree(ar);
		return ret;
	}

	iov_iter_bvec(&ar->iter, ITER_DEST, ar->bvecs, nr_pages, op->len);
	init_sync_kiocb(&ar->kiocb, op->file);
	ar->kiocb.ki_pos = op->offset;
	ar->kiocb.ki_flags |= IOCB_DIRECT;
	ar->kiocb.ki_complete = io_unified_read_done;	/* now async */
	ar->req = req;
	ar->shared = shared;
	ar->umem = umem;
	ar->pool = pool;
	ar->window = window;
	ar->recycle_on_completion = recycle_on_completion;
	ar->nr_bvecs = nr_pages;

	/*
	 * SM-1: hold the UMEM across the async I/O. Without this, a
	 * concurrent IORING_UNREGISTER_XDEV_EXT_UMEM could unpin the pages
	 * MID-DMA and free frame_pool before io_unified_read_done() runs.
	 * Dropped in the task-work (async) or below (sync completion).
	 */
	io_xdev_ext_umem_get(umem);

	req->async_data = ar;
	req->flags |= REQ_F_ASYNC_DATA;		/* io_clean_op() kfrees it */

	ret = vfs_iocb_iter_read(op->file, &ar->kiocb, &ar->iter);
	if (ret == -EIOCBQUEUED)
		return -EIOCBQUEUED;	/* ki_complete will publish+finish;
					 * ar/req must not be touched again */

	/* Completed synchronously (or failed to queue): publish/abort here;
	 * ki_complete was not and will not be called (read_iter contract). */
	state_ret = xdev_ext_unified_read_finish(pool, window.frame, window.claim, ret,
					 recycle_on_completion);
	if (state_ret)
		ret = -EIO;
	io_unified_update_read_stats(shared, ret, ret < 0);
	io_xdev_ext_umem_put(umem);		/* SM-1: drop the async-I/O hold */
	return ret;
}
#endif /* XDEV_EXT_LIFECYCLE_SM */

#ifndef XDEV_EXT_LIFECYCLE_SM
/*
 * UMEM direct-I/O read: bypass page cache entirely.
 * NVMe driver receives IOCB_DIRECT + bvec pointing to UMEM physical
 * pages → sets up DMA scatter-gather → hardware writes directly to UMEM.
 *
 * Data path: NVMe SSD → DMA → UMEM pages (zero software copies)
 *
 * (Compiled out when XDEV_EXT_LIFECYCLE_SM is on: the async variant above
 * replaces it as the only caller path.)
 */
static int io_unified_do_read_umem(struct io_kiocb *req, struct io_unified_ops *op,
				   struct io_xdev_ext_umem *umem,
				   struct io_uring_unified_shared __user *shared)
{
	struct kiocb kiocb;
	struct iov_iter iter;
	struct bio_vec *bvecs;
	struct bio_vec stack_bvecs[4];
	struct page *page;
	u32 pgoff, nr_pages, remaining, i;
	u64 cur_off;
	ssize_t ret;

	if (!op->file)
		return -EBADF;
	if (!op->file->f_op->read_iter)
		return -EINVAL;

	/* Validate UMEM bounds */
	if (!io_xdev_ext_umem_kaddr(umem, op->addr, op->len))
		return -EINVAL;

	/* Build bvec array pointing to UMEM pages */
	pgoff = (umem->page_offset + op->addr) & ~PAGE_MASK;
	nr_pages = (pgoff + op->len + PAGE_SIZE - 1) >> PAGE_SHIFT;

	bvecs = (nr_pages <= ARRAY_SIZE(stack_bvecs)) ? stack_bvecs :
		kmalloc_array(nr_pages, sizeof(struct bio_vec), GFP_KERNEL);
	if (!bvecs)
		return -ENOMEM;

	cur_off = op->addr;
	remaining = op->len;
	for (i = 0; i < nr_pages; i++) {
		u32 this_pgoff, this_len;
		page = io_xdev_ext_umem_offset_to_page(umem, cur_off, &this_pgoff);
		if (!page) {
			ret = -EINVAL;
			goto out;
		}
		this_len = min_t(u32, remaining, PAGE_SIZE - this_pgoff);
		bvec_set_page(&bvecs[i], page, this_len, this_pgoff);
		cur_off += this_len;
		remaining -= this_len;
	}

	iov_iter_bvec(&iter, ITER_DEST, bvecs, nr_pages, op->len);

	/* Direct I/O: bypasses page cache, NVMe DMA goes straight to UMEM */
	init_sync_kiocb(&kiocb, op->file);
	kiocb.ki_pos = op->offset;
	kiocb.ki_flags |= IOCB_DIRECT;

	ret = vfs_iocb_iter_read(op->file, &kiocb, &iter);

	/* EIOCBQUEUED should not happen with sync kiocb */
	if (ret == -EIOCBQUEUED)
		ret = -EIO;

	io_unified_update_read_stats(shared, ret, ret < 0);

out:
	if (bvecs != stack_bvecs)
		kfree(bvecs);
	return ret;
}
#endif /* !XDEV_EXT_LIFECYCLE_SM */

/*
 * UMEM direct-I/O write: NIC→NVMe direction.
 * Data in UMEM pages (from AF_XDP RX or GPU DMA) is written directly
 * to NVMe via DMA, bypassing page cache.
 *
 * Data path: UMEM pages → DMA → NVMe SSD (zero software copies)
 */
static int io_unified_do_write_umem(struct io_kiocb *req, struct io_unified_ops *op,
				    struct io_xdev_ext_umem *umem,
				    struct io_uring_unified_shared __user *shared,
				    bool force_dsync)
{
#ifdef XDEV_EXT_LIFECYCLE_SM
	struct xdev_ext_lifecycle_window sm_window;
	int sm_tracked = 0;
#endif
	struct kiocb kiocb;
	struct iov_iter iter;
	struct bio_vec *bvecs;
	struct bio_vec stack_bvecs[4];
	struct page *page;
	u32 pgoff, nr_pages, remaining, i;
	u64 cur_off;
	ssize_t ret;

	if (!op->file)
		return -EBADF;
	if (!op->file->f_op->write_iter)
		return -EINVAL;

	if (!io_xdev_ext_umem_kaddr(umem, op->addr, op->len))
		return -EINVAL;

#ifdef XDEV_EXT_LIFECYCLE_SM
	ret = io_unified_sm_window(umem, op->addr, op->len, false,
				   &sm_window);
	if (ret)
		return ret;
#endif

	pgoff = (umem->page_offset + op->addr) & ~PAGE_MASK;
	nr_pages = (pgoff + op->len + PAGE_SIZE - 1) >> PAGE_SHIFT;

	bvecs = (nr_pages <= ARRAY_SIZE(stack_bvecs)) ? stack_bvecs :
		kmalloc_array(nr_pages, sizeof(struct bio_vec), GFP_KERNEL);
	if (!bvecs)
		return -ENOMEM;

	cur_off = op->addr;
	remaining = op->len;
	for (i = 0; i < nr_pages; i++) {
		u32 this_pgoff, this_len;
		page = io_xdev_ext_umem_offset_to_page(umem, cur_off, &this_pgoff);
		if (!page) { ret = -EINVAL; goto out; }
		this_len = min_t(u32, remaining, PAGE_SIZE - this_pgoff);
		bvec_set_page(&bvecs[i], page, this_len, this_pgoff);
		cur_off += this_len;
		remaining -= this_len;
	}

	iov_iter_bvec(&iter, ITER_SOURCE, bvecs, nr_pages, op->len);

	init_sync_kiocb(&kiocb, op->file);
	kiocb.ki_pos = op->offset;
	kiocb.ki_flags |= IOCB_DIRECT;
	if (force_dsync)
		kiocb.ki_flags |= IOCB_DSYNC;

#ifdef XDEV_EXT_LIFECYCLE_SM
	sm_tracked = xdev_ext_lifecycle_consume_begin(&umem->frame_pool,
						 &sm_window);
	if (sm_tracked < 0) {
		ret = sm_tracked;
		goto out;
	}
#endif

	ret = vfs_iocb_iter_write(op->file, &kiocb, &iter);

#ifdef XDEV_EXT_LIFECYCLE_SM
	if (sm_tracked)
		xdev_ext_lifecycle_consume_end(&umem->frame_pool, &sm_window,
					  sm_tracked);
#endif

	if (ret == -EIOCBQUEUED)
		ret = -EIO;

	/* Reuse send stats for write tracking */
	io_unified_update_send_stats(shared, ret, ret < 0);

out:
	if (bvecs != stack_bvecs)
		kfree(bvecs);
	return ret;
}
#endif

static int io_unified_do_read(struct io_kiocb *req, struct io_unified_ops *op,
			      struct io_uring_unified_shared __user *shared)
{
	ssize_t ret;
	loff_t pos;
	void *buf;

	if (!op->file)
		return -EBADF;

	/* Allocate kernel buffer */
	buf = kmalloc(op->len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Non-UMEM path: sqe->off is overlapped with sqe->addr2 (shared_addr),
	 * so op->offset is not a valid file offset. Always read from 0. */
	pos = 0;

	/* Perform the read using kernel_read */
	ret = kernel_read(op->file, buf, op->len, &pos);

	/* Copy to userspace if successful */
	if (ret > 0) {
		if (copy_to_user(u64_to_user_ptr(op->addr), buf, ret))
			ret = -EFAULT;
	}

	kfree(buf);

	/* Update shared memory statistics */
	io_unified_update_read_stats(shared, ret, ret < 0);

	return ret;
}

#ifdef XDEV_EXT_UMEM_ZEROCOPY
static int io_unified_do_send_umem(struct io_kiocb *req, struct io_unified_ops *op,
				   struct io_xdev_ext_umem *umem,
				   struct io_uring_unified_shared __user *shared,
				   bool *native_called)
{
#ifdef XDEV_EXT_LIFECYCLE_SM
	struct xdev_ext_lifecycle_window sm_window;
	int sm_tracked = 0;
#endif
	struct socket *sock;
	struct msghdr msg = {};
	struct bio_vec stack_bvecs[4];
	struct bio_vec *bvecs = stack_bvecs;
	struct page *page;
	u32 pgoff, nr_pages, remaining, i;
	u64 cur_off;
	ssize_t ret;

	if (!op->file)
		return -EBADF;

	sock = sock_from_file(op->file);
	if (!sock)
		return -ENOTSOCK;
	if (op->offset & MSG_ZEROCOPY)
		return -EOPNOTSUPP;

	/* Validate bounds */
	if (!io_xdev_ext_umem_kaddr(umem, op->addr, op->len))
		return -EINVAL;

#ifdef XDEV_EXT_LIFECYCLE_SM
	ret = io_unified_sm_window(umem, op->addr, op->len, false,
				   &sm_window);
	if (ret)
		return ret;
#endif

	/* Calculate number of pages needed */
	pgoff = (umem->page_offset + op->addr) & ~PAGE_MASK;
	nr_pages = (pgoff + op->len + PAGE_SIZE - 1) >> PAGE_SHIFT;

	if (nr_pages > ARRAY_SIZE(stack_bvecs)) {
		bvecs = kmalloc_array(nr_pages, sizeof(struct bio_vec), GFP_KERNEL);
		if (!bvecs)
			return -ENOMEM;
	}

	/* Build bvec array spanning all pages */
	cur_off = op->addr;
	remaining = op->len;
	for (i = 0; i < nr_pages; i++) {
		u32 this_pgoff, this_len;

		page = io_xdev_ext_umem_offset_to_page(umem, cur_off, &this_pgoff);
		if (!page) {
			ret = -EINVAL;
			goto out;
		}

		this_len = min_t(u32, remaining, PAGE_SIZE - this_pgoff);
		bvec_set_page(&bvecs[i], page, this_len, this_pgoff);

		cur_off += this_len;
		remaining -= this_len;
	}

	iov_iter_bvec(&msg.msg_iter, ITER_SOURCE, bvecs, nr_pages, op->len);
	msg.msg_flags = xdev_ext_send_hook_effective_flags(
		(__u32)op->offset, op->file->f_flags & O_NONBLOCK,
		MSG_DONTWAIT);

#ifdef XDEV_EXT_LIFECYCLE_SM
	sm_tracked = xdev_ext_lifecycle_consume_begin(&umem->frame_pool,
						 &sm_window);
	if (sm_tracked < 0) {
		ret = sm_tracked;
		goto out;
	}
#endif

	ret = xdev_ext_send_hook_call_native(native_called,
					sock_sendmsg(sock, &msg));

#ifdef XDEV_EXT_LIFECYCLE_SM
	if (sm_tracked)
		xdev_ext_lifecycle_consume_end(&umem->frame_pool, &sm_window,
					  sm_tracked);
#endif

	io_unified_update_send_stats(shared, ret, ret < 0);

out:
	if (bvecs != stack_bvecs)
		kfree(bvecs);
	return ret;
}
#endif

#if defined(XDEV_EXT_AFXDP_SEND) && IS_ENABLED(CONFIG_XDP_SOCKETS)
/*
 * In-kernel COPY-mode AF_XDP send: hand a single UMEM frame straight to the
 * NIC via xsk_kernel_xmit(), bypassing sock_sendmsg and any CQ round-trip.
 * op->addr is a UMEM byte offset (validated inside xsk_kernel_xmit); op->len
 * is the frame length. @sock must already be a TX-capable PF_XDP socket
 * (see xsk_kernel_tx_capable in the dispatch).
 */
static int io_unified_do_send_xdp(struct io_unified_ops *op,
				  struct io_uring_unified_shared __user *shared,
				  struct socket *sock, bool *native_called)
{
	int ret;

	ret = xdev_ext_send_hook_call_native(native_called,
					xsk_kernel_xmit(sock, op->addr,
							op->len, 0));

	io_unified_update_send_stats(shared, ret, ret < 0);
	return ret;
}
#endif

static int io_unified_do_send(struct io_kiocb *req, struct io_unified_ops *op,
			      struct io_uring_unified_shared __user *shared,
			      bool *native_called)
{
	struct socket *sock;
	struct msghdr msg;
	struct iovec iov;
	ssize_t ret;

	if (!op->file)
		return -EBADF;

	sock = sock_from_file(op->file);
	if (!sock)
		return -ENOTSOCK;

	/* Setup message */
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = u64_to_user_ptr(op->addr);
	iov.iov_len = op->len;
	iov_iter_init(&msg.msg_iter, ITER_SOURCE, &iov, 1, op->len);
	msg.msg_flags = xdev_ext_send_hook_effective_flags(
		(__u32)op->offset, op->file->f_flags & O_NONBLOCK,
		MSG_DONTWAIT);

	/* Perform the send */
	ret = xdev_ext_send_hook_call_native(native_called,
					sock_sendmsg(sock, &msg));

	/* Update shared memory statistics */
	io_unified_update_send_stats(shared, ret, ret < 0);

	return ret;
}

#ifdef XDEV_EXT_UMEM_ZEROCOPY
static int io_unified_do_calc_umem(struct io_kiocb *req, struct io_unified_ops *op,
				   struct io_xdev_ext_umem *umem,
				   struct io_uring_unified_shared __user *shared)
{
#ifdef XDEV_EXT_LIFECYCLE_SM
	struct xdev_ext_lifecycle_window sm_window;
	int sm_mode = 0;
	int ret;
#endif
	void *kbuf;
	u64 *data;
	u64 result = 0;
	u32 i, count;

	count = op->len / sizeof(u64);
	if (count == 0)
		return -EINVAL;

	kbuf = io_xdev_ext_umem_kaddr(umem, op->addr, op->len);
	if (!kbuf)
		return -EINVAL;

#ifdef XDEV_EXT_LIFECYCLE_SM
	ret = io_unified_sm_window(umem, op->addr, op->len, false,
				   &sm_window);
	if (ret)
		return ret;
	sm_mode = xdev_ext_lifecycle_consume_begin(&umem->frame_pool, &sm_window);
	if (sm_mode < 0)
		return sm_mode;
#endif

	data = (u64 *)kbuf;
	for (i = 0; i < count; i++)
		result += data[i];

	/* Write result back in-place */
	data[0] = result;

#ifdef XDEV_EXT_LIFECYCLE_SM
	xdev_ext_lifecycle_consume_end(&umem->frame_pool, &sm_window, sm_mode);
#endif

	io_unified_update_calc_stats(shared, result, false);
	return sizeof(result);
}
#endif

static int io_unified_do_calc(struct io_kiocb *req, struct io_unified_ops *op,
			      struct io_uring_unified_shared __user *shared)
{
	u64 *data;
	u64 result = 0;
	int ret = 0;
	u32 i, count;

	/* Simple calculation: sum all u64 values in the buffer */
	count = op->len / sizeof(u64);
	if (count == 0)
		return -EINVAL;

	data = kmalloc(op->len, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* Copy data from userspace */
	if (copy_from_user(data, u64_to_user_ptr(op->addr), op->len)) {
		kfree(data);
		return -EFAULT;
	}

	/* Perform calculation */
	for (i = 0; i < count; i++)
		result += data[i];

	/* Write result back */
	if (copy_to_user(u64_to_user_ptr(op->addr), &result, sizeof(result))) {
		ret = -EFAULT;
	} else {
		ret = sizeof(result);
	}

	kfree(data);

	/* Update shared memory statistics */
	io_unified_update_calc_stats(shared, result, ret < 0);

	return ret;
}

int io_unified_ops_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_unified_ops *op = io_kiocb_to_cmd(req, struct io_unified_ops);
	bool use_umem = false;
	bool iaa;

	/*
	 * op->file must alias req->file (the io_kiocb union starts with
	 * struct file *file): io_file_get_normal() writes req->file and
	 * io_put_file(req) fputs it on every completion. Adding a separate
	 * fput for op->file would be a double-fput/UAF -- see Y_SPEC PRE-1.
	 */
	BUILD_BUG_ON(offsetof(struct io_unified_ops, file) != 0);
	BUILD_BUG_ON(sizeof(struct io_unified_ops) > sizeof(struct io_cmd_data));
#ifdef CONFIG_64BIT
	BUILD_BUG_ON(offsetof(struct io_unified_ops, addr) != 8);
	BUILD_BUG_ON(offsetof(struct io_unified_ops, shared_addr) != 16);
	BUILD_BUG_ON(offsetof(struct io_unified_ops, offset) != 24);
	BUILD_BUG_ON(offsetof(struct io_unified_ops, dst_cap) != 32);
	BUILD_BUG_ON(offsetof(struct io_unified_ops, len) != 40);
	BUILD_BUG_ON(offsetof(struct io_unified_ops, opcode) != 44);
#ifdef XDEV_EXT_UMEM_ZEROCOPY
	BUILD_BUG_ON(offsetof(struct io_unified_ops, use_umem) != 48);
#endif
#endif

	/* sqe->len contains the sub-opcode */
	op->opcode = READ_ONCE(sqe->len);
	iaa = io_unified_is_iaa(op->opcode);

	if (op->opcode > IO_UNIFIED_OP_WRITE_COMPAT)
		return -EINVAL;

	/* addr2 is shared stats for legacy ops and dst_off for IAA. */
	op->shared_addr = READ_ONCE(sqe->addr2);
	if (iaa) {
		struct xdev_ext_iaa_sqe_fields fields =
			xdev_ext_iaa_sqe_fields_from_words(READ_ONCE(sqe->addr),
						      READ_ONCE(sqe->off),
						      READ_ONCE(sqe->rw_flags),
						      READ_ONCE(sqe->addr3));

		op->addr = fields.src_off;
		op->offset = fields.dst_off;
		op->dst_cap = fields.dst_cap;
		op->len = fields.src_len;
	} else {
		/* Preserve the legacy READ/SEND/CALC/WRITE field mapping. */
		op->addr = READ_ONCE(sqe->addr);
		op->offset = READ_ONCE(sqe->off);
		op->dst_cap = 0;
		op->len = READ_ONCE(sqe->rw_flags);
	}

#ifdef XDEV_EXT_UMEM_ZEROCOPY
	op->use_umem = (READ_ONCE(sqe->flags) & IOSQE_XDEV_EXT_UMEM) != 0;
	use_umem = op->use_umem;
	if (iaa && (!IS_ENABLED(CONFIG_IO_URING_XDEV_EXT_IAA) || !op->use_umem))
		return -EOPNOTSUPP;
	if ((op->opcode == IO_UNIFIED_OP_READ_COMPAT ||
	     op->opcode == IO_UNIFIED_OP_WRITE_COMPAT) && !op->use_umem)
		return -EOPNOTSUPP;
#else
	if (iaa || op->opcode == IO_UNIFIED_OP_READ_COMPAT ||
	    op->opcode == IO_UNIFIED_OP_WRITE_COMPAT)
		return -EOPNOTSUPP;
#endif

	if (op->opcode == IO_UNIFIED_OP_SEND) {
		struct xdev_ext_send_sqe_fields fields =
			xdev_ext_send_sqe_fields_from_words(use_umem,
						       READ_ONCE(sqe->off),
						       READ_ONCE(sqe->addr3));

		op->shared_addr = fields.shared_addr;
		op->offset = fields.send_flags;
	}

#ifdef XDEV_EXT_UMEM_ZEROCOPY
	if (!iaa && !op->use_umem && !op->shared_addr)
		return -EINVAL;
#else
	if (!iaa && !op->shared_addr)
		return -EINVAL;
#endif
	/* For non-UMEM path, addr must be a valid userspace pointer (non-zero).
	 * For UMEM path, addr=0 is valid (first frame at offset 0). */
#ifdef XDEV_EXT_UMEM_ZEROCOPY
	if (!op->use_umem && !op->addr) {
#if defined(XDEV_EXT_AFXDP_SEND) && IS_ENABLED(CONFIG_XDP_SOCKETS)
		/* AF_XDP SEND: addr is a UMEM byte offset; 0 is the first
		 * frame and is validated later by xp_validate_desc(). Don't
		 * reject it here. (Flag-gated: flag-OFF is unchanged.)
		 */
		if (op->opcode != IO_UNIFIED_OP_SEND)
#endif
			return -EINVAL;
	}
#else
	if (!op->addr) {
#if defined(XDEV_EXT_AFXDP_SEND) && IS_ENABLED(CONFIG_XDP_SOCKETS)
		if (op->opcode != IO_UNIFIED_OP_SEND)
#endif
			return -EINVAL;
	}
#endif

	/* For READ and SEND, manually resolve file since needs_file is
	 * not set in opdef (CALC legitimately uses fd=-1). */
	if (op->opcode == IO_UNIFIED_OP_READ ||
	    op->opcode == IO_UNIFIED_OP_READ_COMPAT ||
	    op->opcode == IO_UNIFIED_OP_SEND || op->opcode == IO_UNIFIED_OP_WRITE ||
	    op->opcode == IO_UNIFIED_OP_WRITE_COMPAT) {
		op->file = io_file_get_normal(req, READ_ONCE(sqe->fd));
		if (!op->file)
			return -EBADF;
	}

	/*
	 * Unified ops may sleep: direct read/write paths allocate and enter
	 * f_op iter callbacks, SEND can enter socket/XSK locks, and CALC may
	 * fault user pages. Route execution through io-wq instead of running
	 * in io_uring's initial nonblocking submit pass.
	 */
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

int io_unified_ops_issue(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_unified_ops *op = io_kiocb_to_cmd(req, struct io_unified_ops);
	struct io_uring_unified_shared __user *shared = NULL;
#ifdef XDEV_EXT_UMEM_ZEROCOPY
	struct io_xdev_ext_umem *umem = NULL;
	struct io_uring_unified_shared __user *registered_shared = NULL;
	bool iaa = io_unified_is_iaa(op->opcode);
#endif
	int stats_source;
	int ret;

	if (WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK))
		return -EAGAIN;

	/*
	 * Get shared stats structure.
	 * UMEM path: shared was registered with the UMEM.
	 * Non-UMEM SEND: addr3 is preferred; addr2/off is the legacy form.
	 * Other non-UMEM operations retain the addr2/off mapping.
	 */
#ifdef XDEV_EXT_UMEM_ZEROCOPY
	if (op->use_umem) {
		umem = io_xdev_ext_umem_get_ctx_with_stats(req->ctx,
						      &registered_shared);
		if (!umem)
			return iaa ? -EOPNOTSUPP : -ENODEV;
	}
	stats_source = xdev_ext_unified_stats_source(op->use_umem, iaa,
						!!registered_shared,
						!!op->shared_addr);
#else
	stats_source = xdev_ext_unified_stats_source(false, false, false,
						!!op->shared_addr);
#endif
	if (stats_source < 0) {
#ifdef XDEV_EXT_UMEM_ZEROCOPY
		if (umem)
			io_xdev_ext_umem_put(umem);
#endif
		return stats_source;
	}
	if (stats_source == XDEV_EXT_UNIFIED_STATS_REGISTERED) {
#ifdef XDEV_EXT_UMEM_ZEROCOPY
		shared = registered_shared;
#endif
	} else if (stats_source == XDEV_EXT_UNIFIED_STATS_SQE) {
		shared = (struct io_uring_unified_shared __user *)op->shared_addr;
	}
#ifdef XDEV_EXT_UMEM_ZEROCOPY
	if (iaa) {
		/* IAA statistics are optional and never alias addr2/dst_off. */
		if (xdev_ext_iaa_has_registered_stats(!!shared,
						 op->shared_addr) &&
		    (!access_ok(shared, sizeof(*shared)) ||
		     !IS_ALIGNED((unsigned long)&shared->lock, sizeof(u32))))
			shared = NULL;
	} else {
#endif
		if (!shared || !access_ok(shared, sizeof(*shared))) {
#ifdef XDEV_EXT_UMEM_ZEROCOPY
			if (umem)
				io_xdev_ext_umem_put(umem);
#endif
			return -EFAULT;
		}
		if (!IS_ALIGNED((unsigned long)&shared->lock, sizeof(u32))) {
#ifdef XDEV_EXT_UMEM_ZEROCOPY
			if (umem)
				io_xdev_ext_umem_put(umem);
#endif
			return -EINVAL;
		}
#ifdef XDEV_EXT_UMEM_ZEROCOPY
	}
#endif

	/* Execute the appropriate operation based on opcode */
	switch (op->opcode) {
	case IO_UNIFIED_OP_READ:
	case IO_UNIFIED_OP_READ_COMPAT:
#ifdef XDEV_EXT_UMEM_ZEROCOPY
		if (op->use_umem) {
#ifdef XDEV_EXT_LIFECYCLE_SM
			ret = io_unified_do_read_umem_async(req, op,
					umem, shared,
					op->opcode == IO_UNIFIED_OP_READ_COMPAT);
			if (ret == -EIOCBQUEUED) {
				io_xdev_ext_umem_put(umem);
				return IOU_ISSUE_SKIP_COMPLETE;
			}
#else
			ret = io_unified_do_read_umem(req, op,
					umem, shared);
#endif
		} else
#endif
			ret = io_unified_do_read(req, op, shared);
		if (req->tctx)
			io_sched_record_op(req->tctx, 0, ret > 0 ? ret : 0);
		break;
	case IO_UNIFIED_OP_SEND: {
		struct xdev_ext_binding_token token = {};
		struct xdev_ext_binding_ctx_v2 binding_ctx = {};
		struct xdev_ext_send_hook_state hook = {};
		struct socket *send_sock;
		bool native_called = false;
		bool afxdp = false;

		/* Immutable classification and UMEM bounds precede policy. */
		if (!op->file) {
			ret = -EBADF;
			goto send_done;
		}
		send_sock = sock_from_file(op->file);
		if (!send_sock) {
			ret = -ENOTSOCK;
			goto send_done;
		}
#if defined(XDEV_EXT_AFXDP_SEND) && IS_ENABLED(CONFIG_XDP_SOCKETS)
		afxdp = xsk_kernel_tx_capable(send_sock);
#endif
#ifdef XDEV_EXT_UMEM_ZEROCOPY
		ret = xdev_ext_send_hook_check_buffer_source(afxdp, op->use_umem,
							op->addr);
		if (ret)
			goto send_done;
		ret = xdev_ext_send_hook_check_flags(afxdp, op->offset);
		if (ret)
			goto send_done;
		ret = xdev_ext_send_hook_check_umem_compat(afxdp, op->use_umem,
						      !!(op->offset & MSG_ZEROCOPY));
		if (ret) {
			/*
			 * An XSK pool has no alias/lifetime contract with the
			 * registered io_uring UMEM.  That UMEM path also cannot
			 * combine its bvec iterator with MSG_ZEROCOPY.
			 */
			if (afxdp)
				io_unified_update_send_stats(shared, ret, true);
			goto send_done;
		}
		if (op->use_umem) {
			if (!io_xdev_ext_umem_kaddr(umem, op->addr, op->len)) {
				ret = -EINVAL;
				goto send_done;
			}
		}
#else
		ret = xdev_ext_send_hook_check_buffer_source(afxdp, false, op->addr);
		if (ret)
			goto send_done;
		ret = xdev_ext_send_hook_check_flags(afxdp, op->offset);
		if (ret)
			goto send_done;
#endif

		ret = io_unified_xdev_ext_dispatch_send(op, afxdp, &binding_ctx,
						   &token, &hook);
		if (ret)
			goto send_done;

#if defined(XDEV_EXT_AFXDP_SEND) && IS_ENABLED(CONFIG_XDP_SOCKETS)
		if (afxdp) {
			ret = io_unified_do_send_xdp(op, shared, send_sock,
						     &native_called);
			goto send_done;
		}
#endif
#ifdef XDEV_EXT_UMEM_ZEROCOPY
		if (op->use_umem)
			ret = io_unified_do_send_umem(req, op, umem, shared,
						      &native_called);
		else
#endif
			ret = io_unified_do_send(req, op, shared, &native_called);

send_done:
		io_unified_xdev_ext_finish_send(&binding_ctx, &token, &hook,
					   native_called, ret);
		if (req->tctx)
			io_sched_record_op(req->tctx, 1, ret > 0 ? ret : 0);
		break;
	}
	case IO_UNIFIED_OP_CALC:
#ifdef XDEV_EXT_UMEM_ZEROCOPY
		if (op->use_umem)
			ret = io_unified_do_calc_umem(req, op, umem, shared);
		else
#endif
			ret = io_unified_do_calc(req, op, shared);
		if (req->tctx)
			io_sched_record_op(req->tctx, 2, 0);
		break;
	case IO_UNIFIED_OP_WRITE:
	case IO_UNIFIED_OP_WRITE_COMPAT:
#ifdef XDEV_EXT_UMEM_ZEROCOPY
		if (op->use_umem)
			ret = io_unified_do_write_umem(req, op, umem, shared,
					xdev_ext_unified_write_force_dsync(op->opcode));
		else
#endif
		{
			/* WRITE is a UMEM-only operation in this implementation. */
			ret = -EOPNOTSUPP;
		}
		if (req->tctx)
			io_sched_record_op(req->tctx, 1, ret > 0 ? ret : 0);
		break;
	case IO_UNIFIED_OP_IAA_COMPRESS:
	case IO_UNIFIED_OP_IAA_DECOMPRESS:
#if defined(XDEV_EXT_UMEM_ZEROCOPY) && IS_ENABLED(CONFIG_IO_URING_XDEV_EXT_IAA)
	{
		struct io_xdev_ext_iaa_params params = {
			.opcode = op->opcode,
			.src_off = op->addr,
			.dst_off = op->offset,
			.src_len = op->len,
			.dst_cap = op->dst_cap,
		};

		ret = io_xdev_ext_iaa_issue(req, umem, shared, &params,
				       io_unified_update_calc_stats);
		if (ret == -EIOCBQUEUED) {
			io_xdev_ext_umem_put(umem);
			return IOU_ISSUE_SKIP_COMPLETE;
		}
		break;
	}
#else
		ret = -EOPNOTSUPP;
		break;
#endif
	default:
		ret = -EINVAL;
		break;
	}

	if (ret < 0)
		req_set_fail(req);

#ifdef XDEV_EXT_UMEM_ZEROCOPY
	if (umem)
		io_xdev_ext_umem_put(umem);
#endif
	io_req_set_res(req, ret, 0);
	return IOU_COMPLETE;
}

void io_unified_ops_cleanup(struct io_kiocb *req)
{
	/* No cleanup needed for now */
}
