/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XB_LIFECYCLE_CORE_H
#define XB_LIFECYCLE_CORE_H
#include <linux/dma-fence.h>
#include "../../../kernel/io_uring/xdev_ext_mech_lifecycle.h"

enum xb_arm { XB_LIFE, XB_FENCE };
enum xb_order { XB_CALLBACK_FIRST, XB_SIGNAL_FIRST };
struct xb_observation {
	u32 ready, consumed, recycled, errors, released, seen_len, successful;
	bool cleanup_complete;
};
struct xb_op;
struct xb_fence {
	struct dma_fence fence;
	struct dma_fence_cb cb;
	spinlock_t lock;
	struct xb_op *op;
	bool consumer, initialized, registered, dropped, released;
};
/* Callers serialize entry points for a given operation; different operations
 * are independent. signal invokes callbacks synchronously under the fence lock.
 * Cleanup is after producer/consumer contexts have joined. No live-op reuse. */
struct xb_op {
	struct xb_fence producer, consumer;
	struct xdev_ext_mech_life life;
	u64 identity, claim;
	u32 len, valid_len, registration_calls, fail_register_at;
	enum xb_arm arm;
	enum xb_order order;
	bool prepared, produced, consumed;
	struct xb_observation observation;
};
static inline const char *xb_fence_name(struct dma_fence *f)
{
	(void)f;
	return "xdev-lifecycle-bench";
}
static inline void xb_fence_release(struct dma_fence *f)
{
	struct xb_fence *w = container_of(f, struct xb_fence, fence);
	/* Embedded storage remains owned by the run until both releases finish. */
	WRITE_ONCE(w->released, true);
}
static const struct dma_fence_ops xb_fence_ops = {
	.get_driver_name = xb_fence_name, .get_timeline_name = xb_fence_name,
	.release = xb_fence_release,
};
static inline void xb_notify(struct xb_fence *w)
{
	struct xb_op *op = w->op;
	if (w->consumer) {
		op->observation.consumed = 1;
		op->observation.recycled = 1;
		op->observation.successful = 1;
	} else {
		op->observation.seen_len = op->valid_len;
		op->observation.ready = 1;
	}
}
static inline void xb_callback(struct dma_fence *f, struct dma_fence_cb *cb)
{
	struct xb_fence *w = container_of(cb, struct xb_fence, cb);
	(void)f;
	w->registered = false;
	xb_notify(w);
}
static inline int xb_register(struct xb_fence *w)
{
	int ret;
	if (++w->op->registration_calls == w->op->fail_register_at)
		return -ENOMEM;
	ret = dma_fence_add_callback(&w->fence, &w->cb, xb_callback);
	if (ret == -ENOENT) {
		xb_notify(w);
		return 0;
	}
	if (!ret)
		w->registered = true;
	return ret;
}
static inline int xb_op_cleanup(struct xb_op *op)
{
	struct xb_fence *w[2] = { &op->producer, &op->consumer };
	unsigned int i;
	if (!op->prepared)
		return 0;
	if (op->arm == XB_FENCE) {
		for (i = 0; i < 2; i++) {
			if (!w[i]->initialized || w[i]->dropped)
				continue;
			/* remove_callback takes the fence lock, joining any callback. */
			if (w[i]->registered)
				dma_fence_remove_callback(&w[i]->fence, &w[i]->cb);
			w[i]->registered = false;
			w[i]->dropped = true;
			dma_fence_put(&w[i]->fence);
		}
		if (!READ_ONCE(op->producer.released) || !READ_ONCE(op->consumer.released))
			return -EBUSY;
	} else if (!op->consumed) {
		if (!op->produced)
			xdev_ext_mech_life_fail_produce(&op->life, op->claim);
		else {
			u64 claim;
			if (!xdev_ext_mech_life_acquire(&op->life, 0, 0, &claim))
				xdev_ext_mech_life_put(&op->life, claim);
		}
	}
	op->observation.cleanup_complete = true;
	return 0;
}
static inline int xb_op_prepare(struct xb_op *op, enum xb_arm arm,
		u64 identity, u32 len, enum xb_order order)
{
	struct xb_fence *w[2];
	unsigned int i;
	int ret;
	if ((arm != XB_LIFE && arm != XB_FENCE) || !len ||
	    (order != XB_CALLBACK_FIRST && order != XB_SIGNAL_FIRST))
		return -EINVAL;
	if (op->prepared)
		return -EBUSY;
	op->prepared = true;
	op->arm = arm;
	op->order = order;
	op->identity = identity;
	op->len = len;
	if (arm == XB_LIFE) {
		xdev_ext_mech_life_init(&op->life);
		return xdev_ext_mech_life_claim(&op->life, 0, &op->claim);
	}
	w[0] = &op->producer;
	w[1] = &op->consumer;
	for (i = 0; i < 2; i++) {
		w[i]->op = op;
		w[i]->consumer = i == 1;
		spin_lock_init(&w[i]->lock);
		dma_fence_init(&w[i]->fence, &xb_fence_ops, &w[i]->lock,
				dma_fence_context_alloc(1), identity);
		w[i]->initialized = true;
	}
	if (order == XB_CALLBACK_FIRST) {
		for (i = 0; i < 2; i++) {
			ret = xb_register(w[i]);
			if (ret) {
				op->observation.errors++;
				xb_op_cleanup(op);
				return ret;
			}
		}
	}
	return 0;
}
static inline int xb_op_produce(struct xb_op *op, u64 identity, u32 valid_len)
{
	int ret;
	if (!op->prepared || op->observation.cleanup_complete || op->producer.dropped)
		return -EINVAL;
	if (identity != op->identity)
		return -ESTALE;
	if (valid_len != op->len)
		return -EINVAL;
	if (op->produced)
		return -EALREADY;
	op->valid_len = valid_len;
	if (op->arm == XB_LIFE) {
		ret = xdev_ext_mech_life_publish(&op->life, op->claim, 1, valid_len);
		if (!ret) {
			op->observation.ready = 1;
			op->observation.seen_len = op->life.valid_len;
		}
	} else {
		ret = dma_fence_signal(&op->producer.fence);
		if (!ret && op->order == XB_SIGNAL_FIRST)
			ret = xb_register(&op->producer);
	}
	if (!ret)
		op->produced = true;
	else
		op->observation.errors++;
	return ret;
}
static inline int xb_op_consume(struct xb_op *op, u64 identity)
{
	int ret;
	u64 claim;
	if (!op->prepared || op->observation.cleanup_complete || op->producer.dropped)
		return -EINVAL;
	if (identity != op->identity)
		return -ESTALE;
	if (op->consumed)
		return -EALREADY;
	if (!op->produced || !op->observation.ready)
		return -EAGAIN;
	if (op->arm == XB_LIFE) {
		ret = xdev_ext_mech_life_acquire(&op->life, 0, 0, &claim);
		if (!ret) {
			op->observation.seen_len = op->life.valid_len;
			ret = xdev_ext_mech_life_put(&op->life, claim);
			if (ret == XDEV_EXT_MECH_L_FREED)
				ret = 0;
		}
		if (!ret) {
			op->observation.consumed = 1;
			op->observation.recycled = 1;
			op->observation.successful = 1;
		}
	} else {
		/* Consumer owns a real reference for the duration of its access. */
		struct dma_fence *ref = dma_fence_get(&op->producer.fence);
		ret = dma_fence_get_status(ref) > 0 ? 0 : -EAGAIN;
		dma_fence_put(ref);
		if (!ret)
			ret = dma_fence_signal(&op->consumer.fence);
		if (!ret && op->order == XB_SIGNAL_FIRST)
			ret = xb_register(&op->consumer);
	}
	if (!ret)
		op->consumed = true;
	else
		op->observation.errors++;
	return ret;
}
static inline void xb_op_observe(const struct xb_op *op, struct xb_observation *out)
{
	*out = op->observation;
	out->released = READ_ONCE(op->producer.released) + READ_ONCE(op->consumer.released);
}
#endif
