/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef uintptr_t dma_addr_t;
#define __iomem
#define __packed __attribute__((packed))
#define BIT(n) (1UL<<(n))
#define GENMASK(h,l) (((~0UL) << (l)) & (~0UL >> (8*sizeof(long)-1-(h))))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define GFP_KERNEL 0
#define __GFP_ZERO 0
#define EXPORT_SYMBOL_GPL(x)
#define module_param(...)
#define MODULE_PARM_DESC(...)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define static_assert _Static_assert
#define WARN_ON_ONCE(x) ({bool _b=!!(x); assert(!_b);_b;})
#define WARN_ON(x) WARN_ON_ONCE(x)
#define dev_dbg(...) ((void)0)
#define dev_warn(...) ((void)0)
static unsigned warnings;
#define dev_WARN(...) (++warnings)
#define lockdep_assert_held(p) assert((p)->held)
/* Upstream ring backports: per-ring lockdep key, throttling, scoped lock. */
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
struct lock_class_key {bool registered;};
static unsigned lockdep_registers,lockdep_unregisters;
static void lockdep_register_key(struct lock_class_key *k) {assert(!k->registered);k->registered=true;lockdep_registers++;}
static void lockdep_unregister_key(struct lock_class_key *k) {assert(k->registered);k->registered=false;lockdep_unregisters++;}
#define lockdep_init_map(m,n,k,s) do {(void)(n);(void)(k);} while (0)
typedef struct { bool held;pthread_mutex_t native; } spinlock_t;
static _Thread_local unsigned held_locks;
static spinlock_t *gate_nhi_lock;
static pthread_t gate_retire_thread;
static atomic_bool retire_lock_attempted;
static bool shared_lookup_gate;
static void *shared_lookup_address;
static void shared_lookup_interleave(void);
#define DEFINE_SPINLOCK(n) spinlock_t n={.native=PTHREAD_MUTEX_INITIALIZER}
static void spin_lock_init(spinlock_t *p) {p->held=false;assert(!pthread_mutex_init(&p->native,NULL));}
static void spin_lock(spinlock_t *p) {if(p==gate_nhi_lock&&pthread_equal(pthread_self(),gate_retire_thread))atomic_store(&retire_lock_attempted,true);assert(!pthread_mutex_lock(&p->native));assert(!p->held);p->held=true;held_locks++;}
static void spin_unlock(spinlock_t *p) {assert(p->held);p->held=false;held_locks--;assert(!pthread_mutex_unlock(&p->native));}
#define spin_lock_irq spin_lock
#define spin_unlock_irq spin_unlock
#define spin_lock_irqsave(p,f) do {(f)=0;spin_lock(p);}while(0)
#define spin_unlock_irqrestore(p,f) do {(void)(f);spin_unlock(p);}while(0)
static void __guard_spin_release(spinlock_t **p) {spin_unlock(*p);}
static spinlock_t *__guard_spin_acquire(spinlock_t *p) {spin_lock(p);return p;}
#define __guard_cat2(a,b) a##b
#define __guard_cat(a,b) __guard_cat2(a,b)
#define guard(t) __guard_##t
#define __guard_spinlock_irqsave(l) \
 spinlock_t *__guard_cat(__guard_,__COUNTER__) __attribute__((cleanup(__guard_spin_release)))=__guard_spin_acquire(l)
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD_INIT(n) {&(n),&(n)}
#define LIST_HEAD(n) struct list_head n=LIST_HEAD_INIT(n)
static void INIT_LIST_HEAD(struct list_head *h) {h->next=h->prev=h;}
static bool list_empty(const struct list_head *h) {return h->next==h;}
static void list_add_tail(struct list_head *n,struct list_head *h) {n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
static void list_del_init(struct list_head *n) {n->prev->next=n->next;n->next->prev=n->prev;INIT_LIST_HEAD(n);}
static void list_move_tail(struct list_head *n,struct list_head *h) {list_del_init(n);list_add_tail(n,h);}
static void list_splice_tail_init(struct list_head *l,struct list_head *h) {
 if(list_empty(l))return;struct list_head *first=l->next,*last=l->prev;
 first->prev=h->prev;h->prev->next=first;last->next=h;h->prev=last;INIT_LIST_HEAD(l);
}
#define list_first_entry(h,t,m) container_of((h)->next,t,m)
#define list_for_each_entry_safe(p,n,h,m) \
 for(p=list_first_entry(h,typeof(*p),m),n=list_first_entry(&(p)->m,typeof(*p),m);&(p)->m!=(h);p=n,n=list_first_entry(&(n)->m,typeof(*n),m))
struct work_struct {void (*func)(struct work_struct *);bool pending;unsigned schedules,runs;pthread_t thread;bool asynchronous;atomic_bool active;};
static bool run_async_once;
static atomic_bool callback_entered,callback_release;
#define INIT_WORK(w,f) do {memset((w),0,sizeof(*(w)));(w)->func=(f);}while(0)
struct device {int id;};
struct pci_dev {struct device dev;bool msix_enabled;unsigned refs;};
struct ida {unsigned used;};
struct tb_ring;struct ring_frame;struct tb_nhi_ops;
typedef int irqreturn_t;
#define IRQ_HANDLED 1
#define IRQF_NO_SUSPEND 1
#define TB_FRAME_SIZE 256
static bool retiring;
static unsigned allocation_calls,alloc_fail_at,pdev_gets,pdev_puts,dma_frees,heap_frees;
static unsigned irq_frees,global_irq_disables,global_work_cancels,flushes,event_clock,irq_free_event,last_flush_event;
static bool inject_irq_at_free;
static struct {void *p;size_t n;bool freed;} allocations[128];
static unsigned allocation_nr;
static void *kzalloc(size_t n,int flags) {
 assert(!retiring);if(++allocation_calls==alloc_fail_at)return NULL;
 void *p=calloc(1,n);assert(p);allocations[allocation_nr++]=(typeof(allocations[0])){p,n,false};return p;
}
static void kfree(void *p) {if(!p)return;for(unsigned i=0;i<allocation_nr;i++)if(allocations[i].p==p){assert(!allocations[i].freed);allocations[i].freed=true;heap_frees++;return;}assert(!"foreign heap free");}
static struct pci_dev *pci_dev_get(struct pci_dev *p) {assert(!retiring);pdev_gets++;p->refs++;return p;}
static void pci_dev_put(struct pci_dev *p) {assert(p&&p->refs);pdev_puts++;p->refs--;}
static void *dma_alloc_coherent(struct device *dev,size_t n,dma_addr_t *dma,int flags) {void *p=kzalloc(n,flags);if(p)*dma=(dma_addr_t)p;return p;}
static void dma_free_coherent(struct device *dev,size_t n,void *p,dma_addr_t dma) {
 assert(!held_locks&&p==(void *)dma);for(unsigned i=0;i<allocation_nr;i++)if(allocations[i].p==p){assert(!allocations[i].freed&&allocations[i].n==n);allocations[i].freed=true;dma_frees++;return;}assert(!"foreign DMA free");
}
static void *async_work(void *arg) {struct work_struct *w=arg;w->runs++;w->func(w);atomic_store(&w->active,false);return NULL;}
static bool schedule_work(struct work_struct *w) {
 assert(w->func);w->pending=true;w->schedules++;
 if(run_async_once){run_async_once=false;w->pending=false;atomic_store(&w->active,true);w->asynchronous=true;assert(!pthread_create(&w->thread,NULL,async_work,w));}
 return true;
}
static bool flush_work(struct work_struct *w) {assert(!held_locks);flushes++;last_flush_event=++event_clock;bool had=w->pending;
 if(w->asynchronous){atomic_store(&callback_release,true);assert(!pthread_join(w->thread,NULL));w->asynchronous=false;}
 while(w->pending){assert(w->func);w->pending=false;w->runs++;w->func(w);}return had;}
static bool cancel_work_sync(struct work_struct *w) {global_work_cancels++;w->pending=false;return true;}
static void disable_irq(int irq) {global_irq_disables++;}
static int ida_alloc_max(struct ida *a,unsigned max,int flags) {if(a->used>max)return -ENOSPC;return a->used++;}
static void ida_free(struct ida *a,unsigned id) {assert(a->used);a->used--;}
static int pci_irq_vector(struct pci_dev *p,int v) {return 100+v;}
static struct {int irq;irqreturn_t (*fn)(int,void *);void *data;bool active;} irqs[32];
static unsigned irq_nr;
static int request_irq(int irq,irqreturn_t (*fn)(int,void *),unsigned flags,const char *name,void *p) {irqs[irq_nr++]=(typeof(irqs[0])){irq,fn,p,true};return 0;}
static void free_irq(int irq,void *p) {
 assert(!held_locks);for(unsigned i=0;i<irq_nr;i++)if(irqs[i].irq==irq&&irqs[i].data==p&&irqs[i].active){
  if(inject_irq_at_free)irqs[i].fn(irq,p);irqs[i].active=false;irq_frees++;irq_free_event=++event_clock;return;}assert(!"unregistered IRQ");
}
static unsigned char mmio[0x50000];
static bool mmio_dead;
static unsigned mmio_reads,mmio_writes;
static u32 ioread32(void *addr) {assert(!mmio_dead&&(u8 *)addr>=mmio&&(u8 *)addr+4<=mmio+sizeof(mmio));mmio_reads++;if(shared_lookup_gate&&addr==shared_lookup_address)shared_lookup_interleave();return *(u32 *)addr;}
static void iowrite32(u32 v,void *addr) {assert(!mmio_dead&&(u8 *)addr>=mmio&&(u8 *)addr+4<=mmio+sizeof(mmio));mmio_writes++;*(u32 *)addr=v;}
