/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_STACK_NHI_COMPAT_H
#define XDEV_EXT_STACK_NHI_COMPAT_H

/* Environmental additions; shared list/lock/work/PCI types precede this. */
#define __iomem
#define __packed __attribute__((packed))
#define __GFP_ZERO 0
#define GENMASK(h,l) (((~0UL) << (l)) & (~0UL >> (8*sizeof(long)-1-(h))))
#define WARN_ON(x) WARN_ON_ONCE(x)
#define module_param(...)
struct ida { unsigned used; };
struct lock_class_key { bool registered; };
struct tb_nhi_ops;
struct tb_ring;
typedef int irqreturn_t;
#define IRQ_HANDLED 1
#define IRQF_NO_SUSPEND 1

static inline void list_move_tail(struct list_head *n, struct list_head *h)
{
	list_del_init(n);
	list_add_tail(n, h);
}
static inline void list_splice_tail_init(struct list_head *list, struct list_head *head)
{
	struct list_head *first, *last;
	if (list_empty(list)) return;
	first = list->next;
	last = list->prev;
	first->prev = head->prev;
	head->prev->next = first;
	last->next = head;
	head->prev = last;
	INIT_LIST_HEAD(list);
}
#define list_for_each_entry_safe(p,n,h,m) \
	for (p=list_first_entry(h,typeof(*p),m), \
	     n=list_first_entry(&(p)->m,typeof(*p),m); &(p)->m!=(h); \
	     p=n,n=list_first_entry(&(n)->m,typeof(*n),m))

static inline void stack_nhi_guard_release(spinlock_t **lock) { spin_unlock(*lock); }
static inline spinlock_t *stack_nhi_guard_acquire(spinlock_t *lock)
{
	spin_lock(lock);
	return lock;
}
#define stack_nhi_cat_(a,b) a##b
#define stack_nhi_cat(a,b) stack_nhi_cat_(a,b)
#define guard(t) stack_nhi_guard_##t
#define stack_nhi_guard_spinlock_irqsave(lock) \
	spinlock_t *stack_nhi_cat(stack_nhi_guard_,__COUNTER__) \
	__attribute__((cleanup(stack_nhi_guard_release))) = stack_nhi_guard_acquire(lock)

void lockdep_register_key(struct lock_class_key *);
void lockdep_unregister_key(struct lock_class_key *);
/* Dependency graph simulation is out of scope; registration is observable. */
#define lockdep_init_map(m,n,k,s) do { (void)(n); (void)(k); } while (0)

#include "stack_nhi_types.h"

enum stack_nhi_observation {
	STACK_NHI_POST = 1, STACK_NHI_COMPLETE, STACK_NHI_DOORBELL,
	STACK_NHI_IRQ_ALLOC, STACK_NHI_IRQ_FREE,
};
void stack_nhi_observe(unsigned kind, struct tb_ring *, struct ring_frame *,
		       unsigned index, unsigned count);
struct stack_nhi_stats {
	uint64_t doorbells, descriptors, completions, polls, irq_dispatches;
	uint64_t irq_allocs, irq_frees, dma_allocs, dma_frees, work_flushes;
	uint64_t mmio_reads, mmio_writes;
};
void stack_nhi_init(struct tb_nhi *, struct pci_dev *);
void stack_nhi_destroy(struct tb_nhi *);
bool stack_nhi_visible(struct tb_ring *, struct ring_frame *);
void stack_nhi_complete(struct tb_ring *, struct ring_frame *, unsigned length,
			unsigned sof, unsigned eof, unsigned flags);
bool stack_nhi_poll_one(struct tb_ring *);
unsigned stack_nhi_callback_origin(void); /* 1=real ring_work, 2=real poll */
void stack_nhi_snapshot(struct tb_nhi *, struct stack_nhi_stats *);
void stack_nhi_ring_snapshot(struct tb_ring *, struct stack_nhi_stats *);
/* Address-only query remains safe immediately after real free/memset. */
bool stack_nhi_key_registered(const struct tb_ring *);
void stack_nhi_keys_snapshot(unsigned *registered, unsigned *unregistered,
			    unsigned *live);

#endif
