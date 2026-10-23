/* SPDX-License-Identifier: GPL-2.0 */
/* Executes the same future core included by lifecycle_bench.c, through a
 * constrained host API shim. Never kernel performance/concurrency evidence. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "lifecycle_core.h"

static struct xb_observation observe(struct xb_op *op)
{
    struct xb_observation value = {0};
    xb_op_observe(op, &value);
    return value;
}

static void complete(struct xb_op *op, unsigned identity, unsigned len)
{
    assert(xb_op_produce(op, identity, len) == 0);
    assert(xb_op_consume(op, identity) == 0);
}

static void two_phase(enum xb_arm arm, enum xb_order order)
{
    struct xb_op op = {0};
    struct xb_observation result;
    assert(xb_op_prepare(&op, arm, 7, 4096, order) == 0);
    assert(xb_op_consume(&op, 7) == -EAGAIN);
    result = observe(&op);
    assert(result.ready == 0 && result.consumed == 0 && result.recycled == 0);
    assert(xb_op_produce(&op, 7, 4096) == 0);
    result = observe(&op);
    assert(result.ready == 1 && result.seen_len == 4096);
    assert(result.consumed == 0 && result.recycled == 0 && result.successful == 0);
    assert(xb_op_consume(&op, 7) == 0);
    result = observe(&op);
    assert(result.ready == 1 && result.consumed == 1 && result.recycled == 1);
    assert(result.successful == 1);
    assert(xb_op_cleanup(&op) == 0);
    result = observe(&op);
    assert(result.cleanup_complete);
    if (arm == XB_FENCE) {
        assert(result.released == 2);
        assert(xb_shim_inits == 2 && xb_shim_releases == 2);
        assert(xb_shim_signal_calls == 2 && xb_shim_add_calls == 2);
        assert(xb_shim_callbacks == (order == XB_CALLBACK_FIRST ? 2U : 0U));
    }
}

static void identity(enum xb_arm arm)
{
    struct xb_op old = {0}, current = {0};
    assert(xb_op_prepare(&old, arm, 7, 4096, XB_CALLBACK_FIRST) == 0);
    assert(xb_op_prepare(&current, arm, 8, 8192, XB_CALLBACK_FIRST) == 0);
    assert(xb_op_produce(&current, 7, 4096) == -ESTALE);
    assert(observe(&current).ready == 0);
    complete(&old, 7, 4096);
    assert(xb_op_consume(&current, 7) == -ESTALE);
    assert(observe(&current).recycled == 0);
    complete(&current, 8, 8192);
    assert(observe(&old).successful == 1 && observe(&current).successful == 1);
    assert(xb_op_cleanup(&old) == 0 && xb_op_cleanup(&current) == 0);
}

static void duplicate(enum xb_arm arm)
{
    struct xb_op op = {0};
    assert(xb_op_prepare(&op, arm, 7, 4096, XB_CALLBACK_FIRST) == 0);
    assert(xb_op_produce(&op, 7, 4096) == 0);
    assert(xb_op_produce(&op, 7, 4096) == -EALREADY);
    assert(xb_op_consume(&op, 7) == 0);
    assert(xb_op_consume(&op, 7) == -EALREADY);
    assert(observe(&op).recycled == 1 && observe(&op).successful == 1);
    assert(xb_op_cleanup(&op) == 0);
}

static void held_reference(void)
{
    struct xb_op op = {0};
    struct dma_fence *held;
    assert(xb_op_prepare(&op, XB_FENCE, 7, 4096, XB_CALLBACK_FIRST) == 0);
    held = dma_fence_get(&op.producer.fence);
    complete(&op, 7, 4096);
    assert(xb_op_cleanup(&op) == -EBUSY);
    assert(!observe(&op).cleanup_complete && observe(&op).released == 1);
    assert(xb_op_prepare(&op, XB_FENCE, 8, 8192, XB_CALLBACK_FIRST) == -EBUSY);
    assert(xb_shim_inits == 2);
    dma_fence_put(held);
    assert(xb_op_cleanup(&op) == 0);
    assert(observe(&op).cleanup_complete && observe(&op).released == 2);
    assert(xb_op_cleanup(&op) == 0); /* no repeated put of private references */
}

static void independent_frames(enum xb_arm arm)
{
    struct xb_op slow = {0}, fast = {0};
    assert(xb_op_prepare(&slow, arm, 7, 4096, XB_CALLBACK_FIRST) == 0);
    assert(xb_op_prepare(&fast, arm, 8, 4096, XB_CALLBACK_FIRST) == 0);
    assert(xb_op_produce(&slow, 7, 4096) == 0);
    complete(&fast, 8, 4096);
    assert(observe(&slow).ready == 1 && observe(&slow).recycled == 0);
    assert(observe(&fast).recycled == 1 && observe(&fast).successful == 1);
    assert(xb_op_cleanup(&fast) == 0);
    assert(xb_op_consume(&slow, 7) == 0);
    assert(xb_op_cleanup(&slow) == 0);
}

static void callback_failure(unsigned ordinal)
{
    struct xb_op op = {0};
    xb_shim_fail_add_at = ordinal;
    assert(xb_op_prepare(&op, XB_FENCE, 7, 4096, XB_CALLBACK_FIRST) < 0);
    assert(observe(&op).successful == 0);
    assert(xb_op_cleanup(&op) == 0);
    assert(observe(&op).cleanup_complete);
    assert(xb_shim_inits == xb_shim_releases);
}

static void invalid(void)
{
    struct xb_op op = {0};
    assert(xb_op_prepare(&op, (enum xb_arm)99, 7, 4096, XB_CALLBACK_FIRST) == -EINVAL);
    assert(xb_op_prepare(&op, XB_FENCE, 7, 0, XB_CALLBACK_FIRST) == -EINVAL);
    assert(xb_op_prepare(&op, XB_FENCE, 7, 4096, (enum xb_order)99) == -EINVAL);
    assert(xb_shim_inits == 0 && xb_shim_releases == 0);
}

int main(int argc, char **argv)
{
    enum xb_arm arm;
    assert(argc == 3);
    arm = !strcmp(argv[2], "life") ? XB_LIFE : XB_FENCE;
    if (!strcmp(argv[1], "two-phase")) two_phase(arm, XB_CALLBACK_FIRST);
    else if (!strcmp(argv[1], "signal-first")) two_phase(arm, XB_SIGNAL_FIRST);
    else if (!strcmp(argv[1], "identity")) identity(arm);
    else if (!strcmp(argv[1], "duplicate")) duplicate(arm);
    else if (!strcmp(argv[1], "held-reference")) held_reference();
    else if (!strcmp(argv[1], "independent-frames")) independent_frames(arm);
    else if (!strcmp(argv[1], "callback-failure-1")) callback_failure(1);
    else if (!strcmp(argv[1], "callback-failure-2")) callback_failure(2);
    else if (!strcmp(argv[1], "invalid")) invalid();
    else abort();
    assert(xb_shim_inits == xb_shim_releases);
    puts("host-contract: non-kernel-runtime; no timing evidence");
    return 0;
}
