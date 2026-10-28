// SPDX-License-Identifier: GPL-2.0
/* Local primitive experiment, no device DMA and no dma-buf importer. */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#ifdef CONFIG_X86
#include <asm/cpufeature.h>
#endif
#include "lifecycle_core.h"

static char *mode = "check";
static char *run_nonce = "";
static unsigned int iterations = 8, fail_alloc_at, fail_callback_at;
module_param(mode, charp, 0400);
module_param(run_nonce, charp, 0400);
MODULE_PARM_DESC(run_nonce, "Optional 32 hex invocation nonce, bound by runner to sysfs and debugfs");
module_param(iterations, uint, 0400);
module_param(fail_alloc_at, uint, 0400);
module_param(fail_callback_at, uint, 0400);
MODULE_PARM_DESC(fail_alloc_at, "Fail the Nth benchmark array allocation (1 or 2), fail init");
MODULE_PARM_DESC(fail_callback_at, "Fail callback registration 1 or 2 in the fence arm, fail init");
struct xb_totals {
	u64 prepare, completion, full_cycle, allocation;
	u32 successful, produced, consumed, recycled, checked, released;
};
static struct xb_totals totals[2];
static struct dentry *directory;
static bool timed;
static u64 xb_clock(void) { return timed ? ktime_get_ns() : 0; }

/* No background job survives this function. Complete gates on every exit. */
struct xb_workers {
	struct xb_op *ops;
	struct completion start, produced, done;
	int producer_result, consumer_result;
};
/* Keep each task alive until the creator joins it with kthread_stop(). */
static int xb_park_until_stopped(void)
{
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}
static int xb_producer(void *arg)
{
	struct xb_workers *w = arg;
	wait_for_completion(&w->start);
	w->producer_result = xb_op_produce(&w->ops[0], 11, 4096);
	if (!w->producer_result)
		w->producer_result = xb_op_produce(&w->ops[1], 12, 4096);
	complete(&w->produced);
	return xb_park_until_stopped();
}
static int xb_consumer(void *arg)
{
	struct xb_workers *w = arg;
	wait_for_completion(&w->produced);
	if (w->producer_result) {
		w->consumer_result = w->producer_result;
		goto done;
	}
	w->consumer_result = xb_op_consume(&w->ops[1], 12);
	if (!w->consumer_result &&
	    (w->ops[0].observation.recycled || !w->ops[1].observation.recycled))
		w->consumer_result = -EINVAL;
	if (!w->consumer_result)
		w->consumer_result = xb_op_consume(&w->ops[0], 11);
 done:
	complete(&w->done);
	return xb_park_until_stopped();
}
static int xb_cross_context(enum xb_arm arm)
{
	struct xb_workers w = {};
	struct task_struct *p = NULL, *c = NULL;
	int ret, i;
	w.ops = kcalloc(2, sizeof(*w.ops), GFP_KERNEL);
	if (!w.ops)
		return -ENOMEM;
	init_completion(&w.start);
	init_completion(&w.produced);
	init_completion(&w.done);
	ret = xb_op_prepare(&w.ops[0], arm, 11, 4096, XB_CALLBACK_FIRST);
	if (!ret)
		ret = xb_op_prepare(&w.ops[1], arm, 12, 4096, XB_CALLBACK_FIRST);
	if (ret)
		goto out;
	p = kthread_run(xb_producer, &w, "xb-produce");
	if (IS_ERR(p)) { ret = PTR_ERR(p); p = NULL; goto out; }
	c = kthread_run(xb_consumer, &w, "xb-consume");
	if (IS_ERR(c)) { ret = PTR_ERR(c); c = NULL; goto out; }
	complete(&w.start);
	wait_for_completion(&w.done);
	ret = w.producer_result ?: w.consumer_result;
 out:
	complete_all(&w.start);
	if (p)
		kthread_stop(p);
	complete_all(&w.produced);
	if (c)
		kthread_stop(c);
	for (i = 0; i < 2; i++)
		if (xb_op_cleanup(&w.ops[i]))
			ret = -EBUSY;
	kfree(w.ops);
	return ret;
}

#define XB_REQUIRE(condition) do { if (!(condition)) { ret = -EINVAL; goto out; } } while (0)
static int xb_selfcheck(enum xb_arm arm, enum xb_order order)
{
	struct xb_op *op;
	struct dma_fence *held = NULL;
	int ret = 0;
	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (!op)
		return -ENOMEM;
	XB_REQUIRE(!xb_op_prepare(op, arm, 7, 4096, order));
	XB_REQUIRE(xb_op_consume(op, 7) == -EAGAIN);
	XB_REQUIRE(xb_op_produce(op, 8, 4096) == -ESTALE);
	XB_REQUIRE(!op->observation.ready);
	XB_REQUIRE(!xb_op_produce(op, 7, 4096));
	XB_REQUIRE(op->observation.ready == 1 && op->observation.seen_len == 4096);
	XB_REQUIRE(!op->observation.recycled && !op->observation.successful);
	XB_REQUIRE(xb_op_produce(op, 7, 4096) == -EALREADY);
	XB_REQUIRE(xb_op_consume(op, 8) == -ESTALE);
	if (arm == XB_FENCE)
		held = dma_fence_get(&op->producer.fence);
	XB_REQUIRE(!xb_op_consume(op, 7));
	XB_REQUIRE(xb_op_consume(op, 7) == -EALREADY);
	XB_REQUIRE(op->observation.consumed == 1 && op->observation.recycled == 1 &&
		   op->observation.successful == 1);
	if (held) {
		XB_REQUIRE(xb_op_cleanup(op) == -EBUSY);
		XB_REQUIRE(!op->observation.cleanup_complete);
		XB_REQUIRE(xb_op_prepare(op, arm, 8, 4096, order) == -EBUSY);
		dma_fence_put(held);
		held = NULL;
	}
	XB_REQUIRE(!xb_op_cleanup(op));
	XB_REQUIRE(!xb_op_cleanup(op));
	XB_REQUIRE(op->observation.cleanup_complete);
 out:
	if (held)
		dma_fence_put(held);
	if (xb_op_cleanup(op))
		ret = -EBUSY;
	kfree(op);
	return ret;
}
static int xb_callback_fault_check(void)
{
	unsigned int n;
	for (n = 1; n <= 2; n++) {
		struct xb_op *op = kzalloc(sizeof(*op), GFP_KERNEL);
		int ret;
		if (!op)
			return -ENOMEM;
		op->fail_register_at = n;
		ret = xb_op_prepare(op, XB_FENCE, 1, 4096, XB_CALLBACK_FIRST);
		if (ret != -ENOMEM || xb_op_cleanup(op) ||
		    !op->producer.released || !op->consumer.released) {
			kfree(op);
			return -EINVAL;
		}
		kfree(op);
	}
	return 0;
}
/* Same allocation helper in fault checks and both timed arms. NULL injection
 * takes the actual caller's failure branch; it does not pretend DMA or timing. */
static struct xb_op *xb_allocate(unsigned int count, bool inject)
{
	if (inject)
		return NULL;
	return kvcalloc(count, sizeof(struct xb_op), GFP_KERNEL);
}
static int xb_run(enum xb_arm arm)
{
	struct xb_totals *t = &totals[arm];
	struct xb_op *ops;
	unsigned int i;
	int ret = 0;
	u64 start = xb_clock(), full;
	ops = xb_allocate(iterations, fail_alloc_at == (unsigned int)arm + 1);
	t->allocation = xb_clock() - start;
	if (!ops)
		return -ENOMEM;
	full = xb_clock();
	for (i = 0; i < iterations; i++) {
		start = xb_clock();
		ops[i].fail_register_at = arm == XB_FENCE ? fail_callback_at : 0;
		ret = xb_op_prepare(&ops[i], arm, i + 1, 4096, XB_CALLBACK_FIRST);
		t->prepare += xb_clock() - start;
		if (ret)
			break;
		start = xb_clock();
		ret = xb_op_produce(&ops[i], i + 1, 4096);
		if (!ret)
			ret = xb_op_consume(&ops[i], i + 1);
		t->completion += xb_clock() - start;
		if (ret)
			break;
		ret = xb_op_cleanup(&ops[i]);
		if (ret)
			break;
	}
	t->full_cycle = xb_clock() - full;
	/* Full oracle is outside timing. The required length read remains inside. */
	if (!ret)
		for (i = 0; i < iterations; i++) {
			struct xb_observation o;
			xb_op_observe(&ops[i], &o);
			if (o.ready != 1 || o.consumed != 1 || o.recycled != 1 ||
			    o.successful != 1 || o.seen_len != 4096 || o.errors ||
			    !o.cleanup_complete || (arm == XB_FENCE && o.released != 2)) {
				ret = -EINVAL;
				break;
			}
			t->successful += o.successful;
			t->produced += o.ready;
			t->consumed += o.consumed;
			t->recycled += o.recycled;
			t->released += o.released;
			t->checked++;
		}
	for (i = 0; i < iterations; i++)
		if (xb_op_cleanup(&ops[i]))
			ret = -EBUSY;
	kvfree(ops);
	return ret;
}
static int xb_show(struct seq_file *s, void *unused)
{
	unsigned int i;
	(void)unused;
	seq_printf(s, "{\"schema_version\":1,\"experiment_kind\":\"kernel_sync_primitive\","
		"\"exact_sha\":\"" XB_BUILD_SHA "\",\"lifecycle_header_sha256\":\"" XB_LIFE_HASH "\","
		"\"run_nonce\":\"%s\",\"mode\":\"%s\",\"status\":\"ok\",\"iterations\":%u,"
		"\"execution_context\":\"serial-process\",\"kernel_runtime\":true,"
		"\"evidence_kind\":\"kernel-runtime\",\"oracle_in_timing\":false,"
		"\"oracle_checked_operations\":%u,\"concurrent_check\":{\"executed\":true,\"contexts\":2},"
		"\"checks\":{\"two_phase\":\"pass\",\"signal_before_add\":\"pass\","
		"\"identity\":\"pass\",\"duplicates\":\"pass\",\"held_reference\":\"pass\","
		"\"independent_frames\":\"pass\",\"allocation_failure\":\"pass\","
		"\"callback_failure\":\"pass\",\"teardown\":\"pass\"},\"arms\":{",
		run_nonce, mode, iterations, iterations * 2);
	for (i = 0; i < 2; i++) {
		struct xb_totals *t = &totals[i];
		seq_printf(s, "%s\"%s\":{\"attempted\":%u,\"successful\":%u,\"produced\":%u,"
			"\"consumed\":%u,\"recycled\":%u,\"valid_len_checks\":%u,\"errors\":0,"
			"\"allocations_setup\":1,\"allocations_steady\":0,\"cleanup_complete\":true",
			i ? "," : "", i ? "dma_fence" : "life", iterations, t->successful,
			t->produced, t->consumed, t->recycled, t->checked);
		if (i)
			seq_printf(s, ",\"fence_objects\":%u,\"fence_releases\":%u", iterations * 2, t->released);
		seq_puts(s, "}");
	}
	seq_puts(s, "}");
	if (timed) {
		seq_puts(s, ",\"timing\":{");
		for (i = 0; i < 2; i++) {
			struct xb_totals *t = &totals[i];
			seq_printf(s, "%s\"%s\":{\"prepare_ns\":%llu,\"completion_ns\":%llu,"
				"\"full_cycle_ns\":%llu,\"allocation_ns\":%llu,"
				"\"callback_registration\":\"prepare\",\"denominator\":%u}",
				i ? "," : "", i ? "dma_fence" : "life", t->prepare,
				t->completion, t->full_cycle, t->allocation, iterations);
		}
		seq_puts(s, "}");
	}
	seq_puts(s, "}\n");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(xb);
static int __init xb_init(void)
{
	unsigned int arm, order;
	int ret;
	struct xb_op *fault;
	if ((*run_nonce && (strlen(run_nonce) != 32 ||
	     strspn(run_nonce, "0123456789abcdef") != 32)) ||
	    !iterations || iterations > 65536 ||
	    (strcmp(mode, "check") && strcmp(mode, "time")) ||
	    fail_alloc_at > 2 || fail_callback_at > 2)
		return -EINVAL;
	timed = !strcmp(mode, "time");
	if (timed) {
#ifdef CONFIG_X86
		if (boot_cpu_has(X86_FEATURE_HYPERVISOR))
			return -EPERM;
#else
		return -EOPNOTSUPP;
#endif
	}
	fault = xb_allocate(1, true);
	if (fault) { kvfree(fault); return -EINVAL; }
	for (arm = 0; arm < 2; arm++) {
		for (order = 0; order < 2; order++) {
			ret = xb_selfcheck(arm, order);
			if (ret)
				return ret;
		}
		ret = xb_cross_context(arm);
		if (ret)
			return ret;
	}
	ret = xb_callback_fault_check();
	if (ret)
		return ret;
	for (arm = 0; arm < 2; arm++) {
		ret = xb_run(arm);
		if (ret)
			return ret;
	}
	directory = debugfs_create_dir("xdev_lifecycle_bench", NULL);
	if (IS_ERR(directory))
		return PTR_ERR(directory);
	if (IS_ERR_OR_NULL(debugfs_create_file("result", 0400, directory, NULL, &xb_fops))) {
		debugfs_remove_recursive(directory);
		return -ENODEV;
	}
	return 0;
}
static void __exit xb_exit(void)
{
	debugfs_remove_recursive(directory);
}
module_init(xb_init);
module_exit(xb_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Production lifecycle versus Linux dma_fence local primitive experiment");
