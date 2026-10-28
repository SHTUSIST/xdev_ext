/* SPDX-License-Identifier: GPL-2.0 */
/* Included by stack_boundary.c: observations and deterministic device actions.
 * Production ring code owns its queues, descriptors and callback retirement.
 * This adapter never reads/copies data payload or invents an X5 completion.
 */
#include "stack_nhi_api.h"

static struct native *native_frame(struct tb_ring *ring, struct ring_frame *frame)
{
	for (unsigned i = world->nn; i; i--) {
		struct native *n = &world->n[i - 1];

		if (n->r == ring && n->f == frame && n->live)
			return n;
	}
	return NULL;
}

void stack_nhi_observe(unsigned kind, struct tb_ring *ring, struct ring_frame *frame,
		       unsigned index, unsigned nr)
{
	/* request_irq happens inside allocation, before a recorder exists. */
	if (kind == STACK_NHI_IRQ_ALLOC || kind == STACK_NHI_IRQ_FREE) {
		stack_record((struct stack_event){
			.kind = kind == STACK_NHI_IRQ_ALLOC ? STACK_EV_NHI_IRQ_ALLOC :
				STACK_EV_NHI_IRQ_FREE,
			.endpoint = ring->nhi->pdev->dev.endpoint,
			.direction = ring->is_tx ? 1 : 2,
			.control = ring->size == XDEV_EXT_XD_CTL_RING,
			.owner = (uintptr_t)ring, .seq = index, .length = nr,
		});
		return;
	}
	struct stack_ring_info *info = ring_info(ring);
	struct stack_event event = {
		.endpoint = info->endpoint, .control = info->control,
		.direction = info->is_tx ? 1 : 2, .channel = info->channel,
		.owner = (uintptr_t)(frame ? (void *)frame : (void *)ring),
		.seq = index, .bytes = ring->size,
	};

	if (kind == STACK_NHI_DOORBELL) {
		event.kind = STACK_EV_NHI_DOORBELL;
		event.length = nr;
	} else {
		assert(kind == STACK_NHI_POST || kind == STACK_NHI_COMPLETE);
		struct ring_desc *desc = &ring->descriptors[index];
		struct native *n = native_frame(ring, frame);

		assert(n); /* Every real descriptor belongs to accepted X4 storage. */
		event.kind = kind == STACK_NHI_POST ? STACK_EV_NHI_POST : STACK_EV_NHI_COMPLETE;
		event.address = desc->phys;
		event.length = desc->length ? desc->length : 4096;
		event.pdf = desc->sof | (desc->eof << 8);
		event.flags = desc->flags;
		event.group = n->group;
		event.generation = n->generation;
		event.session_id = n->session_id;
	}
	stack_record(event);
}

/* Called ONLY by real ring_work or by a frame returned by real tb_ring_poll.
 * Assert violations instead of hiding stale/duplicate invocations behind the
 * old event-model rejection guard. Restore the original callback before it
 * runs: X4 control callbacks can immediately reuse/requeue the same frame.
 */
static void native_callback(struct tb_ring *ring, struct ring_frame *frame, bool canceled)
{
	struct stack_ring_info *info = ring_info(ring);
	struct native *n = native_frame(ring, frame);
	unsigned origin = stack_nhi_callback_origin();

	assert(n && !info->freed && origin && !world->in_callback && !stack_spins);
	assert(canceled || n->completed);
	n->live = false;
	frame->callback = n->callback;
	struct stack_event event = {
		.kind = STACK_EV_NHI_CALLBACK, .endpoint = info->endpoint,
		.control = info->control, .direction = info->is_tx ? 1 : 2,
		.channel = info->channel, .owner = (uintptr_t)frame,
		.group = n->group, .seq = n->seq, .generation = n->generation,
		.session_id = n->session_id, .address = frame->buffer_phy,
		.length = canceled ? 0 : n->len, .flags = origin,
		.status = canceled ? -ECANCELED : 0,
	};
	stack_record(event);
	if (!info->control) {
		event.kind = STACK_EV_DATA_CALLBACK;
		event.flags = frame->flags;
		event.pdf = frame->sof | (frame->eof << 8);
		stack_record(event);
	} else if (!info->is_tx && !canceled) {
		event.kind = STACK_EV_CONTROL_RX;
		event.raw_len = n->raw_len;
		event.length = frame->size;
		event.control_type = n->raw[5];
		memcpy(event.raw, n->raw, n->raw_len);
		stack_record(event);
	}
	u64 dropped = info->control && !info->is_tx ? link(info->endpoint)->ctl_dropped : 0;
	world->in_callback = true;
	n->callback(ring, frame, canceled);
	world->in_callback = false;
	/* Do not dereference frame here: the production callback owns its life. */
	if (info->control && info->is_tx) {
		event.kind = canceled ? STACK_EV_RETAIN : STACK_EV_CONTROL_DONE;
		event.flags = 0;
		stack_record(event);
	} else if (info->control && !canceled && link(info->endpoint)->ctl_dropped != dropped) {
		stack_record((struct stack_event){
			.kind = STACK_EV_REJECT, .endpoint = info->endpoint, .control = 1,
			.control_type = n->raw[5], .length = link(info->endpoint)->ctl_dropped - dropped,
		});
	}
}

static bool native_ring_refused(struct tb_nhi *nhi)
{
	unsigned endpoint = endpoint_pci(nhi->pdev);

	if (!world->ring_refuse[endpoint]) return false;
	world->ring_refuse[endpoint] = false;
	stack_record((struct stack_event){
		.kind = STACK_EV_REJECT, .endpoint = endpoint, .status = -ENOMEM,
	});
	return true;
}

static struct tb_ring *native_ring_record(struct tb_ring *ring, unsigned original_size)
{
	if (!ring) return NULL;
	unsigned endpoint = endpoint_pci(ring->nhi->pdev);
	unsigned ordinal = world->side[endpoint].ring_allocs++;
	unsigned i = world->nrings++;

	assert(i < ARRAY_SIZE(world->rings));
	world->rings[i] = ring;
	world->ring_info[i] = (struct stack_ring_info){
		.ring = ring, .nhi = ring->nhi, .endpoint = endpoint,
		.control = original_size == XDEV_EXT_XD_CTL_RING,
		.channel = ordinal < 2 ? 0 : (ordinal - 2) / 2,
		.size = ring->size, .is_tx = ring->is_tx,
	};
	stack_record((struct stack_event){
		.kind = STACK_EV_RING_ALLOC, .endpoint = endpoint,
		.control = world->ring_info[i].control, .direction = ring->is_tx ? 1 : 2,
		.channel = world->ring_info[i].channel, .owner = (uintptr_t)ring,
		.address = (uintptr_t)ring->nhi->pdev, .length = ring->size,
	});
	return ring;
}

static int native_ring_size(int original)
{
	return original == XDEV_EXT_XD_DATA_RING && world->cfg.nhi_ring_size ?
		world->cfg.nhi_ring_size : original;
}

struct tb_ring *stack_ring_alloc_tx(struct tb_nhi *nhi, int hop, int size, unsigned flags)
{
	if (native_ring_refused(nhi)) return NULL;
	if (world->cfg.nhi_poll) flags |= RING_FLAG_NO_INTERRUPT;
	return native_ring_record(tb_ring_alloc_tx(nhi, hop, native_ring_size(size), flags), size);
}

struct tb_ring *stack_ring_alloc_rx(struct tb_nhi *nhi, int hop, int size, unsigned flags,
				   int tx, u16 sof, u16 eof, void (*poll)(void *), void *arg)
{
	if (native_ring_refused(nhi)) return NULL;
	if (world->cfg.nhi_poll) flags |= RING_FLAG_NO_INTERRUPT;
	return native_ring_record(tb_ring_alloc_rx(nhi, hop, native_ring_size(size),
						flags, tx, sof, eof, poll, arg), size);
}

void stack_ring_start(struct tb_ring *ring)
{
	struct stack_ring_info *info = ring_info(ring);

	info->retiring = false;
	tb_ring_start(ring);
	stack_record((struct stack_event){
		.kind = STACK_EV_RING_START, .endpoint = info->endpoint,
		.control = info->control, .direction = info->is_tx ? 1 : 2,
		.owner = (uintptr_t)ring, .status = ring->running ? 0 : -ENODEV,
	});
}

void stack_ring_stop(struct tb_ring *ring)
{
	struct stack_ring_info *info = ring_info(ring);

	/* The deterministic poll/notify producer is excluded before teardown.
	 * This is not a concurrent-poller teardown proof. tb_ring_stop has no
	 * error return; the legacy STOP_RESULT fault now makes the NHI unavailable.
	 */
	info->retiring = true;
	if (world->stop_result[info->endpoint]) ring->nhi->going_away = true;
	tb_ring_stop(ring);
	stack_record((struct stack_event){
		.kind = STACK_EV_RING_STOP, .endpoint = info->endpoint,
		.control = info->control, .direction = info->is_tx ? 1 : 2,
		.owner = (uintptr_t)ring, .status = ring->running ? -ENODEV : 0,
	});
}

static void native_retired(struct tb_ring *ring, bool unknown, dma_addr_t dma,
			   unsigned dma_frees)
{
	struct stack_ring_info *info = ring_info(ring);

	info->freed = true;
	info->unknown = unknown;
	/* Query external registration state: quarantine memset cannot hide a leak. */
	stack_record((struct stack_event){
		.kind = STACK_EV_NHI_RETIRE, .endpoint = info->endpoint,
		.control = info->control, .direction = info->is_tx ? 1 : 2,
		.owner = (uintptr_t)ring, .address = unknown ? dma : 0,
		.length = unknown ? ring->size : info->size,
		.bytes = dma_frees, .flags = stack_nhi_key_registered(ring),
		.status = unknown ? -ENOLINK : 0,
	});
	stack_record((struct stack_event){
		.kind = unknown ? STACK_EV_RETAIN : STACK_EV_RING_FREE,
		.endpoint = info->endpoint, .control = info->control,
		.direction = info->is_tx ? 1 : 2, .owner = (uintptr_t)ring,
		.status = unknown ? -ENODEV : 0,
	});
}

void stack_ring_free(struct tb_ring *ring)
{
	struct stack_nhi_stats before, after;
	struct tb_nhi *nhi = ring->nhi;

	assert(!ring_info(ring)->freed && !ring->running);
	ring_info(ring)->retiring = true;
	stack_nhi_snapshot(nhi, &before);
	tb_ring_free(ring);
	stack_nhi_snapshot(nhi, &after);
	native_retired(ring, false, 0, after.dma_frees - before.dma_frees);
}

void stack_ring_free_quarantined(struct tb_ring *ring)
{
	struct stack_nhi_stats before, after;
	struct tb_nhi *nhi = ring->nhi;

	assert(!ring_info(ring)->freed);
	ring_info(ring)->retiring = true;
	stack_nhi_snapshot(nhi, &before);
	tb_ring_free_quarantined(ring);
	stack_nhi_snapshot(nhi, &after);
	/* Read surviving storage after the real barrier and observe real free
	 * calls; a saved pre-retirement address cannot establish retention. */
	native_retired(ring, true, ring->descriptors ? ring->descriptors_dma : 0,
		       after.dma_frees - before.dma_frees);
}

static int native_enqueue(struct tb_ring *ring, struct ring_frame *frame, bool more)
{
	if (!ring->running) return -ESHUTDOWN;
	/* Acceptance is observed before the synchronous real descriptor write. */
	native_post(ring, frame);
	struct native *n = &world->n[world->nn - 1];

	n->callback = frame->callback;
	n->completion_len = n->len;
	n->completion_sof = frame->sof;
	n->completion_eof = frame->eof;
	frame->callback = native_callback;
	bool batch = more || (world->cfg.nhi_batch && !ring_info(ring)->control);
	int ret = ring->is_tx ? (batch ? tb_ring_tx_more(ring, frame) : tb_ring_tx(ring, frame)) :
		(batch ? tb_ring_rx_more(ring, frame) : tb_ring_rx(ring, frame));

	assert(!ret); /* X4 owns the link lock for this admitted submission. */
	return ret;
}

int stack_ring_tx(struct tb_ring *ring, struct ring_frame *frame)
{
	assert(ring->is_tx);
	return native_enqueue(ring, frame, false);
}

int stack_ring_rx(struct tb_ring *ring, struct ring_frame *frame)
{
	assert(!ring->is_tx);
	return native_enqueue(ring, frame, false);
}

int stack_ring_tx_more(struct tb_ring *ring, struct ring_frame *frame)
{
	assert(ring->is_tx);
	return native_enqueue(ring, frame, true);
}

int stack_ring_rx_more(struct tb_ring *ring, struct ring_frame *frame)
{
	assert(!ring->is_tx);
	return native_enqueue(ring, frame, true);
}

static bool native_live(const struct native *n)
{
	struct stack_ring_info *info = ring_info(n->r);

	return n->live && !n->completed && !info->freed && !info->retiring &&
		!info->nhi->going_away && n->r->running && !n->lost;
}

static struct native *matching_rx(struct native *tx)
{
	struct stack_ring_info *t = ring_info(tx->r);

	for (unsigned i = 0; i < world->nn; i++) {
		struct native *rx = &world->n[i];
		struct stack_ring_info *r = ring_info(rx->r);

		if (native_live(rx) && !r->is_tx && !rx->delivered &&
		    r->endpoint != t->endpoint && r->control == t->control &&
		    r->channel == t->channel && stack_nhi_visible(rx->r, rx->f))
			return rx;
	}
	return NULL;
}

static struct native *native_ready(void)
{
	/* Hardware completes RX after delivery. HOLD_CALLBACK withholds the
	 * descriptor completion, so no software filter hides a real callback. */
	for (unsigned i = 0; i < world->nn; i++) {
		struct native *n = &world->n[i];
		struct stack_ring_info *info = ring_info(n->r);

		if (!native_live(n) || !stack_nhi_visible(n->r, n->f)) continue;
		if (!info->is_tx) {
			if (n->delivered && (info->control || !world->hold_callbacks[info->endpoint]))
				return n;
			continue;
		}
		unsigned e = info->endpoint;
		if (info->control && (n->held || (world->hold_controls[e] &&
		    (!world->hold_control_type[e] || world->hold_control_type[e] == n->raw[5]))))
			continue;
		if (!n->delivered) {
			if (matching_rx(n)) return n;
		} else if (info->control || world->drop_callback[e] || !world->hold_callbacks[e]) {
			return n;
		}
	}
	return NULL;
}

static void native_complete(struct native *n)
{
	n->completed = true;
	stack_nhi_complete(n->r, n->f, n->completion_len, n->completion_sof,
			   n->completion_eof, n->completion_flags);
}

static bool one_native(void)
{
	struct native *n = native_ready();

	if (!n) return false;
	struct stack_ring_info *info = ring_info(n->r);
	if (!info->is_tx || n->delivered) {
		if (!info->control && world->drop_callback[info->endpoint]) {
			n->lost = true;
			world->drop_callback[info->endpoint] = false;
		} else {
			native_complete(n);
		}
		return true;
	}
	struct native *rx = matching_rx(n);

	assert(rx);
	n->delivered = rx->delivered = true;
	rx->completion_len = n->len;
	rx->completion_sof = n->f->sof;
	rx->completion_eof = n->f->eof;
	if (info->control) {
		/* Control storage is host memory. Data payload is never CPU accessed. */
		memcpy((void *)(uintptr_t)rx->f->buffer_phy, n->raw, n->raw_len);
		memcpy(rx->raw, n->raw, n->raw_len);
		rx->raw_len = n->raw_len;
	} else {
		unsigned endpoint = ring_info(rx->r)->endpoint;
		if (world->rx_length_set[endpoint]) rx->completion_len = world->rx_length[endpoint];
		rx->completion_flags = world->rx_flags[endpoint];
		world->rx_length_set[endpoint] = false;
		world->rx_flags[endpoint] = 0;
	}
	return true;
}

static struct tb_ring *native_notify_ready(void)
{
	if (!world->cfg.nhi_batch) return NULL;
	for (unsigned i = 0; i < world->nrings; i++) {
		struct stack_ring_info *info = &world->ring_info[i];

		if (!info->freed && !info->retiring && !info->control && !info->nhi->going_away &&
		    info->ring->running && info->ring->notify_pending)
			return info->ring;
	}
	return NULL;
}

static struct tb_ring *native_poll_ready(void)
{
	if (!world->cfg.nhi_poll) return NULL;
	for (unsigned i = 0; i < world->nrings; i++) {
		struct stack_ring_info *info = &world->ring_info[i];

		if (!info->freed && !info->retiring && !info->nhi->going_away &&
		    tb_ring_poll_pending(info->ring))
			return info->ring;
	}
	return NULL;
}
