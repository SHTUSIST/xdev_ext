/* SPDX-License-Identifier: GPL-2.0 */
/* External NHI host environment. The ring algorithms below are production.
 * This deterministic descriptor/doorbell simulator never accesses payload.
 */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"

#define NHI_HOPS 32
#define NHI_MMIO_BYTES 0x50000
#define NHI_IRQS 32
#define NHI_KEYS 4096
#define NHI_WORKS 4096

struct simulated_slot { struct ring_frame *frame; bool visible; };
struct simulated_ring {
	struct tb_ring *ring;
	struct simulated_slot *slots;
	unsigned size, advertised;
	struct stack_nhi_stats stats;
};
struct simulated_irq {
	int irq;
	irqreturn_t (*handler)(int, void *);
	void *data;
	bool active;
};
struct simulated_nhi {
	struct simulated_nhi *next;
	struct tb_nhi *nhi;
	struct simulated_ring rings[2][NHI_HOPS];
	struct simulated_irq irqs[NHI_IRQS];
	struct stack_nhi_stats stats;
};
static struct simulated_nhi *controllers;
static struct { const struct lock_class_key *key; bool live; } keys[NHI_KEYS];
static unsigned key_count, key_registers, key_unregisters;
static struct { struct work_struct *work; void (*fn)(struct work_struct *); } works[NHI_WORKS];
static unsigned work_count, callback_origin;

static struct simulated_nhi *controller(const struct tb_nhi *nhi)
{
	struct simulated_nhi *c;
	for (c = controllers; c; c = c->next)
		if (c->nhi == nhi) return c;
	assert(!"unknown NHI");
	return NULL;
}
static struct simulated_nhi *controller_device(const struct device *dev)
{
	struct simulated_nhi *c;
	for (c = controllers; c; c = c->next)
		if (&c->nhi->pdev->dev == dev) return c;
	assert(!"unknown NHI device");
	return NULL;
}
static struct simulated_ring *sim_ring(struct tb_ring *ring)
{
	assert(ring->hop >= 0 && ring->hop < NHI_HOPS);
	return &controller(ring->nhi)->rings[!ring->is_tx][ring->hop];
}
static struct simulated_nhi *mmio_controller(const void *address, size_t *offset)
{
	struct simulated_nhi *c;
	uintptr_t p = (uintptr_t)address;
	for (c = controllers; c; c = c->next) {
		uintptr_t base = (uintptr_t)c->nhi->iobase;
		if (p >= base && p + sizeof(u32) <= base + NHI_MMIO_BYTES) {
			assert(!c->nhi->going_away);
			*offset = p - base;
			assert(!(*offset & 3));
			return c;
		}
	}
	assert(!"MMIO outside the simulated controller");
	return NULL;
}
static u32 *mmio_word(struct tb_nhi *nhi, size_t offset)
{
	return (u32 *)((u8 *)nhi->iobase + offset);
}
static struct ring_frame *frame_at(struct tb_ring *ring, unsigned slot)
{
	struct ring_frame *frame;
	unsigned index = ring->tail;
	list_for_each_entry(frame, &ring->in_flight, list) {
		if (index == slot) return frame;
		index = (index + 1) % ring->size;
	}
	return NULL;
}
static int frame_slot(struct tb_ring *ring, struct ring_frame *wanted)
{
	struct ring_frame *frame;
	unsigned index = ring->tail;
	list_for_each_entry(frame, &ring->in_flight, list) {
		if (frame == wanted) return index;
		index = (index + 1) % ring->size;
	}
	return -1;
}

static u32 ioread32(void *address)
{
	size_t offset;
	struct simulated_nhi *c = mmio_controller(address, &offset);
	u32 value = *mmio_word(c->nhi, offset);
	c->stats.mmio_reads++;
	if (offset >= REG_RING_NOTIFY_BASE &&
	    offset < REG_RING_NOTIFY_BASE + 4 * RING_NOTIFY_REG_COUNT(c->nhi))
		*mmio_word(c->nhi, offset) = 0;
	return value;
}

static void enable_ring(struct simulated_nhi *c, unsigned rx, unsigned hop, u32 value)
{
	struct simulated_ring *sim = &c->rings[rx][hop];
	struct tb_ring *ring = rx ? c->nhi->rx_rings[hop] : c->nhi->tx_rings[hop];
	if (!(value & RING_FLAG_ENABLE)) {
		if (sim->slots) memset(sim->slots, 0, sim->size * sizeof(*sim->slots));
		sim->advertised = 0;
		return;
	}
	assert(ring && ring->size > 1);
	if (sim->ring != ring) memset(&sim->stats, 0, sizeof(sim->stats));
	if (sim->size != (unsigned)ring->size) {
		free(sim->slots);
		sim->slots = calloc(ring->size, sizeof(*sim->slots));
		assert(sim->slots);
		sim->size = ring->size;
	}
	sim->ring = ring;
	sim->advertised = 0;
	memset(sim->slots, 0, sim->size * sizeof(*sim->slots));
}

static void iowrite32(u32 value, void *address)
{
	size_t offset;
	struct simulated_nhi *c = mmio_controller(address, &offset);
	struct tb_nhi *nhi = c->nhi;
	u32 *word = mmio_word(nhi, offset);
	c->stats.mmio_writes++;
	for (unsigned rx = 0; rx < 2; rx++) {
		size_t base = rx ? REG_RX_OPTIONS_BASE : REG_TX_OPTIONS_BASE;
		if (offset >= base && offset < base + NHI_HOPS * 32 && (offset - base) % 32 == 0) {
			/* E2E updates the enabled option word a second time. */
			if (!(*word & RING_FLAG_ENABLE) || !(value & RING_FLAG_ENABLE))
				enable_ring(c, rx, (offset - base) / 32, value);
			*word = value;
			return;
		}
		base = rx ? REG_RX_RING_BASE : REG_TX_RING_BASE;
		if (offset < base || offset >= base + NHI_HOPS * 16 || (offset - base) % 16 != 8)
			continue;
		unsigned hop = (offset - base) / 16;
		struct simulated_ring *sim = &c->rings[rx][hop];
		struct tb_ring *ring = rx ? nhi->rx_rings[hop] : nhi->tx_rings[hop];
		size_t options = (rx ? REG_RX_OPTIONS_BASE : REG_TX_OPTIONS_BASE) + hop * 32;
		/* Preserve the hardware-owned half of the index register. */
		*word = rx ? ((*word & 0xffff0000U) | (value & 0xffffU)) :
			    ((*word & 0xffffU) | (value & 0xffff0000U));
		if (!ring || !ring->running || !(*mmio_word(nhi, options) & RING_FLAG_ENABLE))
			return; /* stop/reset, not a producer notification */
		unsigned head = rx ? value & 0xffffU : value >> 16;
		assert(head < sim->size && sim->ring == ring);
		unsigned count = 0;
		for (unsigned index = sim->advertised; index != head; index = (index + 1) % sim->size) {
			struct ring_frame *frame = frame_at(ring, index);
			assert(frame && (ring->descriptors[index].flags & RING_DESC_POSTED));
			sim->slots[index] = (struct simulated_slot){frame, true};
			count++;
			stack_nhi_observe(STACK_NHI_POST, ring, frame, index, 1);
		}
		sim->advertised = head;
		sim->stats.doorbells++;
		sim->stats.descriptors += count;
		c->stats.doorbells++;
		c->stats.descriptors += count;
		stack_nhi_observe(STACK_NHI_DOORBELL, ring, NULL, head, count);
		return;
	}
	*word = value;
}

void lockdep_register_key(struct lock_class_key *key)
{
	unsigned i;
	assert(!key->registered);
	for (i = 0; i < key_count; i++) if (keys[i].key == key) break;
	assert(i < NHI_KEYS && (i == key_count || !keys[i].live));
	if (i == key_count) key_count++;
	keys[i].key = key;
	keys[i].live = true;
	key->registered = true;
	key_registers++;
}
void lockdep_unregister_key(struct lock_class_key *key)
{
	for (unsigned i = 0; i < key_count; i++) {
		if (keys[i].key != key) continue;
		assert(keys[i].live && key->registered);
		keys[i].live = false;
		key->registered = false;
		key_unregisters++;
		return;
	}
	assert(!"unregistering an unknown lockdep key");
}
bool stack_nhi_key_registered(const struct tb_ring *ring)
{
	uintptr_t key = (uintptr_t)ring + offsetof(struct tb_ring, lock_key);
	for (unsigned i = 0; i < key_count; i++)
		if ((uintptr_t)keys[i].key == key) return keys[i].live;
	return false;
}
void stack_nhi_keys_snapshot(unsigned *registered, unsigned *unregistered, unsigned *live)
{
	*registered = key_registers;
	*unregistered = key_unregisters;
	*live = key_registers - key_unregisters;
}

static int ida_alloc_max(struct ida *ida, unsigned max, int flags)
{
	(void)flags;
	for (unsigned i = 0; i <= max; i++)
		if (!(ida->used & (1U << i))) { ida->used |= 1U << i; return i; }
	return -ENOSPC;
}
static void ida_free(struct ida *ida, unsigned id)
{
	assert(ida->used & (1U << id));
	ida->used &= ~(1U << id);
}
static int pci_irq_vector(struct pci_dev *pdev, int vector)
{
	return 100 + pdev->dev.endpoint * NHI_IRQS + vector;
}
static int request_irq(int irq, irqreturn_t (*fn)(int, void *),
		       unsigned flags, const char *name, void *data)
{
	struct tb_ring *ring = data;
	struct simulated_nhi *c = controller(ring->nhi);
	(void)flags;
	(void)name;
	for (unsigned i = 0; i < NHI_IRQS; i++) {
		if (c->irqs[i].active) continue;
		c->irqs[i] = (struct simulated_irq){irq, fn, data, true};
		c->stats.irq_allocs++;
		stack_nhi_observe(STACK_NHI_IRQ_ALLOC, ring, NULL, irq, 1);
		return 0;
	}
	return -ENOSPC;
}
static void free_irq(int irq, void *data)
{
	struct tb_ring *ring = data;
	struct simulated_nhi *c = controller(ring->nhi);
	assert(!stack_spins);
	for (unsigned i = 0; i < NHI_IRQS; i++) {
		struct simulated_irq *entry = &c->irqs[i];
		if (entry->active && entry->irq == irq && entry->data == data) {
			entry->active = false;
			c->stats.irq_frees++;
			stack_nhi_observe(STACK_NHI_IRQ_FREE, ring, NULL, irq, 1);
			return;
		}
	}
	assert(!"freeing an unregistered IRQ");
}
static void *nhi_dma_alloc(struct device *dev, size_t size, dma_addr_t *dma, int flags)
{
	void *p = dma_alloc_coherent(dev, size, dma, flags);
	if (p) controller_device(dev)->stats.dma_allocs++;
	return p;
}
static void nhi_dma_free(struct device *dev, size_t size, void *p, dma_addr_t dma)
{
	assert(!stack_spins);
	controller_device(dev)->stats.dma_frees++;
	dma_free_coherent(dev, size, p, dma);
}
static bool schedule_work(struct work_struct *);
static bool flush_work(struct work_struct *);
#define dev_warn(...) ((void)0)
#define dev_WARN(...) ((void)0)
#define dma_alloc_coherent nhi_dma_alloc
#define dma_free_coherent nhi_dma_free
/* Entire ring prefix and real MSI dispatch; no local ring helper is replaced. */
#include "stack_nhi_source.inc"
#undef dma_alloc_coherent
#undef dma_free_coherent

static void run_nhi_work(struct work_struct *work)
{
	for (unsigned i = 0; i < work_count; i++) {
		if (works[i].work != work) continue;
		unsigned previous = callback_origin;
		callback_origin = works[i].fn == ring_work ? 1 : 0;
		works[i].fn(work);
		callback_origin = previous;
		return;
	}
	assert(!"unregistered NHI work");
}
static bool schedule_work(struct work_struct *work)
{
	if (work->fn != run_nhi_work) {
		unsigned i;
		for (i = 0; i < work_count; i++) if (works[i].work == work) break;
		assert(i < NHI_WORKS);
		if (i == work_count) work_count++;
		works[i].work = work;
		works[i].fn = work->fn;
		work->fn = run_nhi_work;
	}
	return queue_work(NULL, work);
}
static bool flush_work(struct work_struct *work)
{
	bool was = work->pending;
	assert(!stack_spins);
	for (unsigned i = 0; i < work_count; i++) {
		if (works[i].work != work || works[i].fn != ring_work) continue;
		struct tb_ring *ring = container_of(work, struct tb_ring, work);
		controller(ring->nhi)->stats.work_flushes++;
		break;
	}
	while (work->pending) {
		/* Retire the queued pointer before the real function can free anything. */
		cancel_work_sync(work);
		work->fn(work);
	}
	return was;
}

void stack_nhi_init(struct tb_nhi *nhi, struct pci_dev *pdev)
{
	struct simulated_nhi *c = calloc(1, sizeof(*c));
	assert(c);
	memset(nhi, 0, sizeof(*nhi));
	nhi->pdev = pdev;
	nhi->hop_count = NHI_HOPS;
	nhi->quirks = QUIRK_AUTO_CLEAR_INT;
	nhi->iobase = calloc(1, NHI_MMIO_BYTES);
	nhi->tx_rings = calloc(NHI_HOPS, sizeof(*nhi->tx_rings));
	nhi->rx_rings = calloc(NHI_HOPS, sizeof(*nhi->rx_rings));
	assert(nhi->iobase && nhi->tx_rings && nhi->rx_rings);
	spin_lock_init(&nhi->lock);
	INIT_WORK(&nhi->interrupt_work, nhi_interrupt_work);
	pdev->msix_enabled = true;
	c->nhi = nhi;
	c->next = controllers;
	controllers = c;
}
void stack_nhi_destroy(struct tb_nhi *nhi)
{
	struct simulated_nhi *c = controller(nhi), **at = &controllers;
	for (unsigned i = 0; i < NHI_HOPS; i++) {
		assert(!nhi->tx_rings[i] && !nhi->rx_rings[i]);
		free(c->rings[0][i].slots);
		free(c->rings[1][i].slots);
	}
	for (unsigned i = 0; i < NHI_IRQS; i++) assert(!c->irqs[i].active);
	cancel_work_sync(&nhi->interrupt_work);
	while (*at != c) at = &(*at)->next;
	*at = c->next;
	free(nhi->tx_rings);
	free(nhi->rx_rings);
	free(nhi->iobase);
	nhi->tx_rings = nhi->rx_rings = NULL;
	nhi->iobase = NULL;
	free(c);
}
bool stack_nhi_visible(struct tb_ring *ring, struct ring_frame *frame)
{
	if (!ring->running || ring->nhi->going_away) return false;
	struct simulated_ring *sim = sim_ring(ring);
	int index = frame_slot(ring, frame);
	return index >= 0 && sim->ring == ring && sim->slots[index].visible &&
	       sim->slots[index].frame == frame &&
	       !(ring->descriptors[index].flags & RING_DESC_COMPLETED);
}
void stack_nhi_complete(struct tb_ring *ring, struct ring_frame *frame,
			unsigned length, unsigned sof, unsigned eof, unsigned flags)
{
	assert(stack_nhi_visible(ring, frame));
	struct simulated_nhi *c = controller(ring->nhi);
	struct simulated_ring *sim = sim_ring(ring);
	int index = frame_slot(ring, frame);
	struct ring_desc *desc = &ring->descriptors[index];
	bool interrupt = desc->flags & RING_DESC_INTERRUPT;
	/* POSTED aliases receive overrun: hardware replaces, rather than ORs it. */
	if (!ring->is_tx) {
		desc->length = length;
		desc->sof = sof;
		desc->eof = eof;
	}
	desc->flags = RING_DESC_COMPLETED | flags |
		(interrupt ? RING_DESC_INTERRUPT : 0);
	sim->slots[index].visible = false;
	sim->stats.completions++;
	c->stats.completions++;
	stack_nhi_observe(STACK_NHI_COMPLETE, ring, frame, index, 1);
	if (!interrupt) return;
	assert(!(ring->flags & RING_FLAG_NO_INTERRUPT));
	sim->stats.irq_dispatches++;
	c->stats.irq_dispatches++;
	if (ring->irq > 0) {
		for (unsigned i = 0; i < NHI_IRQS; i++) {
			struct simulated_irq *irq = &c->irqs[i];
			if (irq->active && irq->data == ring) {
				irq->handler(irq->irq, irq->data);
				return;
			}
		}
		assert(!"completion targeted a retired IRQ");
	} else {
		unsigned bit = ring->hop + (!ring->is_tx ? NHI_HOPS : 0);
		*mmio_word(ring->nhi, REG_RING_NOTIFY_BASE + (bit / 32) * 4) |= BIT(bit % 32);
		nhi_msi(0, ring->nhi);
	}
}
bool stack_nhi_poll_one(struct tb_ring *ring)
{
	assert(ring->flags & RING_FLAG_NO_INTERRUPT);
	if (!tb_ring_poll_pending(ring)) return false;
	struct ring_frame *frame = tb_ring_poll(ring);
	assert(frame && !stack_spins);
	struct simulated_nhi *c = controller(ring->nhi);
	sim_ring(ring)->stats.polls++;
	c->stats.polls++;
	unsigned previous = callback_origin;
	callback_origin = 2;
	if (frame->callback) frame->callback(ring, frame, false);
	callback_origin = previous;
	return true;
}
unsigned stack_nhi_callback_origin(void) { return callback_origin; }
void stack_nhi_snapshot(struct tb_nhi *nhi, struct stack_nhi_stats *stats)
{
	*stats = controller(nhi)->stats;
}
void stack_nhi_ring_snapshot(struct tb_ring *ring, struct stack_nhi_stats *stats)
{
	*stats = sim_ring(ring)->stats;
}
