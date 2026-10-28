// SPDX-License-Identifier: GPL-2.0
/*
 * xdev_ext_sm_fence_bench — per-hand-off synchronization cost, measured in
 * hrtimer (softirq/hardirq) context so the cross-context concurrency is
 * real (HANDOFF §2.c / SM_SPEC §6):
 *   arm A: Conduit lifecycle SM (claim/publish/acquire/to_tx/retire atomics)
 *   arm B: a real dma_fence per hand-off (init + add_callback + signal + put)
 *
 * Build (compile-only on the dev box):
 *   make -C "$KDIR" M="$PWD" modules
 * Load on an isolated machine running the matching xdev_ext kernel:
 *   insmod xdev_ext_sm_fence_bench.ko iters=100000
 * Results: dmesg — ns/hand-off per arm. No performance claims are made
 * from a build alone; the numbers exist only after the gated run.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/dma-fence.h>
#include <linux/slab.h>
#include <linux/completion.h>

#define XDEV_EXT_LIFECYCLE_SM 1
#include "../xdev_ext_frame_sm.h"

static int iters = 100000;
module_param(iters, int, 0444);
MODULE_PARM_DESC(iters, "hand-offs per arm");

static int period_ns = 1000;
module_param(period_ns, int, 0444);
MODULE_PARM_DESC(period_ns, "hrtimer period per hand-off (ns)");

struct bench_arm {
	struct hrtimer timer;
	struct completion done;
	atomic_t remaining;
	u64 ns_total;
	int (*one)(void);
};

/* ---- arm A: lifecycle SM ------------------------------------------------ */
static struct xdev_ext_frame sm_frame;
static struct xdev_ext_pool sm_pool;

static int sm_one(void)
{
	xdev_ext_sm_u32 len;
	int ret = 0;

	/* producer edges (claim+publish) and consumer edges (acquire+to_tx+
	 * retire) of ONE hand-off, in completion context — the same per-edge
	 * cost shape the io_uring completion path pays. */
	ret |= xdev_ext_frame_claim(&sm_pool, 0);
	ret |= xdev_ext_frame_publish(&sm_pool, 0, 4096);
	ret |= xdev_ext_frame_acquire_ready(&sm_pool, 0, &len);
	ret |= xdev_ext_frame_to_tx(&sm_pool, 0, 1);
	ret |= xdev_ext_frame_consumer_done(&sm_pool, 0);
	return ret;
}

/* ---- arm B: real dma_fence ---------------------------------------------- */
static DEFINE_SPINLOCK(fence_lock);
static u64 fence_ctx;
static u64 fence_seq;

static const char *bench_fence_name(struct dma_fence *f)
{
	return "xdev_ext_sm_fence_bench";
}

static const struct dma_fence_ops bench_fence_ops = {
	.get_driver_name	= bench_fence_name,
	.get_timeline_name	= bench_fence_name,
};

static void bench_fence_cb(struct dma_fence *f, struct dma_fence_cb *cb)
{
}

static int fence_one(void)
{
	struct dma_fence *f;
	struct dma_fence_cb cb;

	f = kmalloc(sizeof(*f), GFP_ATOMIC);
	if (!f)
		return -ENOMEM;
	dma_fence_init(f, &bench_fence_ops, &fence_lock, fence_ctx,
		       ++fence_seq);
	/* consumer registers, producer signals: the dma-buf hand-off shape */
	if (dma_fence_add_callback(f, &cb, bench_fence_cb)) {
		dma_fence_put(f);	/* unreachable in practice; don't leak */
		return -EINVAL;
	}
	dma_fence_signal(f);
	dma_fence_put(f);	/* default .release = dma_fence_free (RCU) */
	return 0;
}

/* ---- shared driver ------------------------------------------------------ */
static enum hrtimer_restart bench_tick(struct hrtimer *t)
{
	struct bench_arm *arm = container_of(t, struct bench_arm, timer);
	u64 t0 = ktime_get_ns();

	if (arm->one())
		pr_warn_once("xdev_ext_sm_fence_bench: hand-off error\n");
	arm->ns_total += ktime_get_ns() - t0;

	if (atomic_dec_return(&arm->remaining) > 0) {
		hrtimer_forward_now(t, ns_to_ktime(period_ns));
		return HRTIMER_RESTART;
	}
	complete(&arm->done);
	return HRTIMER_NORESTART;
}

static u64 run_arm(struct bench_arm *arm, const char *name)
{
	hrtimer_setup(&arm->timer, bench_tick, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL);
	init_completion(&arm->done);
	atomic_set(&arm->remaining, iters);
	arm->ns_total = 0;
	hrtimer_start(&arm->timer, ns_to_ktime(period_ns), HRTIMER_MODE_REL);
	wait_for_completion(&arm->done);
	pr_info("xdev_ext_sm_fence_bench: %-10s iters=%d total_ns=%llu ns/handoff=%llu\n",
		name, iters, arm->ns_total, arm->ns_total / iters);
	return arm->ns_total / iters;
}

static struct bench_arm arm_sm, arm_fence;

static int __init bench_init(void)
{
	u64 sm_ns, fe_ns;

	if (iters < 1)
		return -EINVAL;
	if (xdev_ext_pool_init(&sm_pool, &sm_frame, 1, false))
		return -EINVAL;
	fence_ctx = dma_fence_context_alloc(1);

	arm_sm.one = sm_one;
	arm_fence.one = fence_one;
	sm_ns = run_arm(&arm_sm, "sm-atomics");
	fe_ns = run_arm(&arm_fence, "dma-fence");
	pr_info("xdev_ext_sm_fence_bench: dma_fence/sm ns ratio = %llu/%llu\n",
		fe_ns, sm_ns);
	return 0;
}

static void __exit bench_exit(void)
{
}

module_init(bench_init);
module_exit(bench_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Conduit lifecycle-SM vs dma_fence hand-off cost");
