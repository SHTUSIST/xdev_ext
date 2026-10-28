/* SPDX-License-Identifier: GPL-2.0 */
/* Reuse the shared real-NHI composition environment without changing its
 * original cases or adapter. These additions only observe queue state and
 * stimulate one actual descriptor completion at the hardware boundary. */
#define stack_ring_tx shared_stack_ring_tx
#define stack_ring_rx shared_stack_ring_rx
#include "stack_boundary.c"
#undef stack_ring_tx
#undef stack_ring_rx
#include <stdatomic.h>
#include <sched.h>

static pthread_t stopper;
static atomic_bool stop_attempted;
static bool race_enabled, stopper_live;
static unsigned race_endpoint, race_accepted;

static void *native_stopper(void *unused)
{
	struct xdev_ext_xd_link *xl = link(race_endpoint);
	(void)unused;
	/* Confirm actual lock contention before letting producer continue. Merely
	 * starting a thread would not prove the competing stop reached this lock. */
	assert(pthread_mutex_trylock(&xl->lock.native) == EBUSY);
	atomic_store(&stop_attempted, true);
	spin_lock_irq(&xl->lock);
	struct tb_ring *ring = xl->chan[0].tx;
	struct ring_frame *frame;
	race_accepted = 0;
	list_for_each_entry(frame, &ring->in_flight, list)
		race_accepted++;
	list_for_each_entry(frame, &ring->queue, list)
		race_accepted++;
	xl->up = false;
	spin_unlock_irq(&xl->lock);
	mutex_lock(&xl->ctl_mutex);
	xdev_ext_xd_rings_stop(xl);
	mutex_unlock(&xl->ctl_mutex);
	return NULL;
}

/* A real competing stop thread blocks at the production link lock. The
 * environment pauses the first native enqueue until that thread attempts it;
 * after production releases the link lock, join before scheduler continuation.
 * This adds no production lock and never changes the enqueue/stop algorithm. */
static void native_interleave(struct tb_ring *ring)
{
	if (!race_enabled || ring_info(ring)->control || !ring->is_tx)
		return;
	race_enabled = false;
	assert(link(race_endpoint)->lock.held);
	atomic_store(&stop_attempted, false);
	stopper_live = true;
	assert(!pthread_create(&stopper, NULL, native_stopper, NULL));
	while (!atomic_load(&stop_attempted))
		sched_yield();
}

void native_progress_unlock(spinlock_t *lock)
{
	if (!stopper_live || lock != &link(race_endpoint)->lock || pthread_equal(pthread_self(), stopper))
		return;
	assert(!pthread_join(stopper, NULL));
	stopper_live = false;
}

void native_progress_race_enable(unsigned endpoint)
{
	race_endpoint = endpoint;
	race_enabled = true;
	race_accepted = 0;
}

unsigned native_progress_race_accepted(void)
{
	assert(!race_enabled && !stopper_live);
	return race_accepted;
}

int stack_ring_tx(struct tb_ring *ring, struct ring_frame *frame)
{
	int result = shared_stack_ring_tx(ring, frame);
	native_interleave(ring);
	return result;
}

int stack_ring_rx(struct tb_ring *ring, struct ring_frame *frame)
{
	return shared_stack_ring_rx(ring, frame);
}

static struct tb_ring *data_tx(unsigned endpoint)
{
	for (unsigned i = 0; i < world->nrings; i++) {
		struct stack_ring_info *info = &world->ring_info[i];
		if (info->endpoint == endpoint && !info->control && info->is_tx && !info->freed)
			return info->ring;
	}
	assert(!"missing actual data TX ring");
	return NULL;
}

void native_progress_counts(unsigned endpoint, unsigned *inflight, unsigned *queued)
{
	struct tb_ring *ring = data_tx(endpoint);
	struct ring_frame *frame;
	*inflight = *queued = 0;
	list_for_each_entry(frame, &ring->in_flight, list)
		(*inflight)++;
	list_for_each_entry(frame, &ring->queue, list)
		(*queued)++;
}

void native_progress_complete_one(unsigned endpoint)
{
	struct tb_ring *ring = data_tx(endpoint);
	assert(!list_empty(&ring->in_flight));
	struct ring_frame *frame = list_first_entry(&ring->in_flight, struct ring_frame, list);
	struct native *n = native_frame(ring, frame);
	assert(n && n->live && n->delivered && !n->completed);
	native_complete(n);
}

/* Production *_more must go through the same recorder as ordinary enqueue.
 * The flag selects the real NHI API for this call only; it cannot make the
 * scheduler synthesize a group notification. */
int native_progress_more(struct tb_ring *ring, struct ring_frame *frame)
{
	assert(!world->cfg.nhi_batch && !ring_info(ring)->control);
	world->cfg.nhi_batch = true;
	int result = native_enqueue(ring, frame);
	world->cfg.nhi_batch = false;
	native_interleave(ring);
	return result;
}
