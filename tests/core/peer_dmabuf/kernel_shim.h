/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DMABUF_TEST_KERNEL_SHIM_H
#define _DMABUF_TEST_KERNEL_SHIM_H
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/resource.h>
#include <sys/types.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef unsigned long long u64;
typedef int32_t s32;
typedef long long s64;
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __le32;
typedef __u64 __le64;
#define __aligned_u64 __u64 __attribute__((aligned(8)))
typedef u64 dma_addr_t;
typedef unsigned int gfp_t;
#define __KERNEL__ 1
#define CONFIG_XDEV_EXT_PEER_DMABUF 1
#define CONFIG_DMA_SHARED_BUFFER 1
#define CONFIG_DMABUF_MOVE_NOTIFY 1
#define IS_ENABLED(c) (c)
#define U32_MAX UINT32_MAX
#define U64_MAX UINT64_MAX
#define S64_MAX ((s64)INT64_MAX)
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_ALIGNED(v) (!((v) & (PAGE_SIZE - 1)))
#define GFP_KERNEL 0
#define GFP_KERNEL_ACCOUNT 0
#define __GFP_ZERO 0
#define __user
#define __init
#define __exit
#define __maybe_unused __attribute__((unused))
#define EXPORT_SYMBOL_GPL(x)
#define EXPORT_SYMBOL_NS_GPL(x, n)
#define MODULE_IMPORT_NS(x)
#define MODULE_LICENSE(x)
#define module_init(x)
#define module_exit(x)
#define THIS_MODULE NULL
#define MAX_SCHEDULE_TIMEOUT LONG_MAX
#define MAX_ERRNO 4095
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-MAX_ERRNO)
#define IS_ERR_OR_NULL(p) (!(p) || IS_ERR(p))
#define WARN_ON(x) (!!(x))
#define WARN_ON_ONCE(x) (!!(x))
#define BUG_ON(x) assert(!(x))
#define likely(x) (x)
#define unlikely(x) (x)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define check_add_overflow(a, b, d) __builtin_add_overflow((a), (b), (d))
#define check_mul_overflow(a, b, d) __builtin_mul_overflow((a), (b), (d))
#define pr_warn(...) ((void)0)
#define pr_warn_ratelimited(...) ((void)0)
#define pr_warn_once(...) ((void)0)
#define might_sleep() ((void)0)
typedef struct { _Atomic int counter; } atomic_t;
typedef struct { _Atomic long counter; } atomic_long_t;
typedef struct { _Atomic long long counter; } atomic64_t;
#define ATOMIC_INIT(v) { (v) }
#define ATOMIC_LONG_INIT(v) { (v) }
#define ATOMIC64_INIT(v) { (v) }
#define atomic_read(a) atomic_load(&(a)->counter)
#define atomic_set(a, v) atomic_store(&(a)->counter, (v))
#define atomic_inc(a) ((void)atomic_fetch_add(&(a)->counter, 1))
#define atomic_dec(a) ((void)atomic_fetch_sub(&(a)->counter, 1))
#define atomic_inc_return(a) (atomic_fetch_add(&(a)->counter, 1) + 1)
#define atomic_dec_and_test(a) (atomic_fetch_sub(&(a)->counter, 1) == 1)
#define atomic_long_read(a) atomic_load(&(a)->counter)
#define atomic_long_set(a, v) atomic_store(&(a)->counter, (v))
#define atomic_long_add(v, a) ((void)atomic_fetch_add(&(a)->counter, (v)))
#define atomic_long_sub(v, a) ((void)atomic_fetch_sub(&(a)->counter, (v)))
#define atomic_long_try_cmpxchg(a, old, v) atomic_compare_exchange_strong(&(a)->counter, (old), (v))
#define atomic64_read(a) atomic_load(&(a)->counter)
#define atomic64_set(a, v) atomic_store(&(a)->counter, (v))
#define atomic64_add(v, a) ((void)atomic_fetch_add(&(a)->counter, (v)))
#define atomic64_sub(v, a) ((void)atomic_fetch_sub(&(a)->counter, (v)))
#define atomic64_inc_return(a) (atomic_fetch_add(&(a)->counter, 1) + 1)
#define atomic64_try_cmpxchg(a, old, v) atomic_compare_exchange_strong(&(a)->counter, (old), (v))
typedef atomic_t refcount_t;
#define refcount_set atomic_set
#define refcount_inc atomic_inc
#define refcount_dec_and_test atomic_dec_and_test
struct mutex { pthread_mutex_t raw; bool held; };
#define DEFINE_MUTEX(n) struct mutex n = {PTHREAD_MUTEX_INITIALIZER, false}
#define __MUTEX_INITIALIZER(n) {PTHREAD_MUTEX_INITIALIZER, false}
extern unsigned test_mutex_acquisitions;
static inline void mutex_init(struct mutex *m)
{ assert(!pthread_mutex_init(&m->raw, NULL)); m->held = false; }
static inline void mutex_lock(struct mutex *m)
{ assert(!pthread_mutex_trylock(&m->raw)); assert(!m->held); m->held = true; test_mutex_acquisitions++; }
static inline int mutex_lock_interruptible(struct mutex *m)
{ mutex_lock(m); return 0; }
static inline void mutex_unlock(struct mutex *m)
{ assert(m->held); m->held = false; assert(!pthread_mutex_unlock(&m->raw)); }
static inline bool mutex_is_locked(struct mutex *m) { return m->held; }
#define lockdep_assert_held(m) assert((m)->held)
/* Deferred work: these fixtures record queuing and never run it. */
struct work_struct { void (*func)(struct work_struct *); bool pending; };
#define DECLARE_WORK(n, f) struct work_struct n = { .func = (f) }
static inline bool schedule_work(struct work_struct *w)
{ bool idle = !w->pending; w->pending = true; return idle; }
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n = LIST_HEAD_INIT(n)
#define INIT_LIST_HEAD(n) ((n)->next = (n)->prev = (n))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_entry(p, t, m) container_of(p, t, m)
#define list_for_each_entry(p, h, m) for (p = container_of((h)->next, __typeof__(*p), m); &(p)->m != (h); p = container_of((p)->m.next, __typeof__(*p), m))
#define list_for_each_entry_safe(p, n, h, m) for (p = container_of((h)->next, __typeof__(*p), m), n = container_of((p)->m.next, __typeof__(*p), m); &(p)->m != (h); p = n, n = container_of((n)->m.next, __typeof__(*n), m))
static inline void list_add_tail(struct list_head *n, struct list_head *h)
{ n->next = h; n->prev = h->prev; h->prev->next = n; h->prev = n; }
static inline void list_add(struct list_head *n, struct list_head *h)
{ n->prev = h; n->next = h->next; h->next->prev = n; h->next = n; }
static inline void list_del(struct list_head *n)
{ n->prev->next = n->next; n->next->prev = n->prev; }
static inline void list_del_init(struct list_head *n) { list_del(n); INIT_LIST_HEAD(n); }
static inline bool list_empty(const struct list_head *h) { return h->next == h; }
struct module { unsigned refs; bool dying; };
static inline bool try_module_get(struct module *m)
{ if (m && m->dying) return false; if (m) m->refs++; return true; }
static inline void module_put(struct module *m) { if (m) { assert(m->refs); m->refs--; } }
struct inode;
struct file;
struct file_operations { int (*release)(struct inode *, struct file *); };
struct file { const struct file_operations *f_op; unsigned refs; struct module *exporter; void *private_data; };
static inline void get_file(struct file *f) { assert(f->refs); f->refs++; }
static inline void fput(struct file *f)
{ assert(f->refs); if (!--f->refs) { if (f->f_op && f->f_op->release) f->f_op->release(NULL, f); module_put(f->exporter); } }
struct io_tlb_mem { bool force_bounce; };
struct device { bool dma_coherent; struct io_tlb_mem *dma_io_tlb_mem; };
struct pci_dev { struct device dev; unsigned refs, id; unsigned int untrusted:1; };
static inline struct pci_dev *pci_dev_get(struct pci_dev *p) { p->refs++; return p; }
static inline void pci_dev_put(struct pci_dev *p) { assert(p->refs); p->refs--; }
static inline bool dev_is_dma_coherent(struct device *d) { return d->dma_coherent; }
static inline bool is_swiotlb_force_bounce(struct device *d)
{ return d->dma_io_tlb_mem && d->dma_io_tlb_mem->force_bounce; }
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE, DMA_NONE };
struct user_struct { atomic_long_t locked_vm; unsigned refs; };
struct mm_struct { atomic64_t pinned_vm; unsigned refs; };
struct task_struct { struct mm_struct *mm; };
extern struct task_struct *current;
extern struct user_struct *test_current_user;
struct user_struct *get_current_user(void);
static inline struct user_struct *get_uid(struct user_struct *u) { u->refs++; return u; }
static inline void free_uid(struct user_struct *u) { assert(u->refs); u->refs--; }
static inline void mmgrab(struct mm_struct *m) { m->refs++; }
static inline void mmdrop(struct mm_struct *m) { assert(m->refs); m->refs--; }
unsigned long test_rlimit(unsigned int);
#define rlimit(n) test_rlimit(n)
#define capable(c) (true)
#define CAP_SYS_RAWIO 17
#define CAP_IPC_LOCK 14
void *test_kalloc(size_t, bool);
void *test_karray(size_t, size_t, bool);
void test_kfree(const void *);
#define kzalloc(n, f) test_kalloc((n), true)
#define kmalloc(n, f) test_kalloc((n), false)
#define kcalloc(n, s, f) test_karray((n), (s), true)
#define kvcalloc(n, s, f) test_karray((n), (s), true)
#define kvmalloc_array(n, s, f) test_karray((n), (s), false)
#define kmalloc_array(n, s, f) test_karray((n), (s), false)
#define kfree(p) test_kfree(p)
#define kvfree(p) test_kfree(p)
struct scatterlist { dma_addr_t dma_address; unsigned dma_length, length, offset; struct scatterlist *next; };
struct sg_table { struct scatterlist *sgl; unsigned nents, orig_nents; };
#define sg_dma_address(s) ((s)->dma_address)
#define sg_dma_len(s) ((s)->dma_length)
#define sg_next(s) ((s)->next)
#define for_each_sg(sgl, sg, n, i) for ((i)=0, (sg)=(sgl); (i)<(n); (i)++, (sg)=sg_next(sg))
#define for_each_sgtable_dma_sg(t, sg, i) for_each_sg((t)->sgl, sg, (t)->nents, i)
struct dma_resv { struct mutex lock; };
enum dma_resv_usage { DMA_RESV_USAGE_KERNEL, DMA_RESV_USAGE_WRITE, DMA_RESV_USAGE_READ, DMA_RESV_USAGE_BOOKKEEP };
static inline int dma_resv_lock(struct dma_resv *r, void *ctx)
{ (void)ctx; mutex_lock(&r->lock); return 0; }
static inline int dma_resv_lock_interruptible(struct dma_resv *r, void *ctx)
{ return dma_resv_lock(r, ctx); }
static inline void dma_resv_unlock(struct dma_resv *r) { mutex_unlock(&r->lock); }
#define dma_resv_assert_held(r) assert((r)->lock.held)
long dma_resv_wait_timeout(struct dma_resv *, enum dma_resv_usage, bool, unsigned long);
struct dma_buf;
struct dma_buf_attachment;
struct dma_buf_ops {
	int (*attach)(struct dma_buf *, struct dma_buf_attachment *);
	void (*detach)(struct dma_buf *, struct dma_buf_attachment *);
	int (*pin)(struct dma_buf_attachment *);
	void (*unpin)(struct dma_buf_attachment *);
	struct sg_table *(*map_dma_buf)(struct dma_buf_attachment *, enum dma_data_direction);
	void (*unmap_dma_buf)(struct dma_buf_attachment *, struct sg_table *, enum dma_data_direction);
	void (*release)(struct dma_buf *);
};
struct dma_buf_attach_ops { bool allow_peer2peer; void (*move_notify)(struct dma_buf_attachment *); };
struct dma_buf { size_t size; const struct dma_buf_ops *ops; struct file *file; struct dma_resv *resv; void *priv; const char *exp_name; };
struct dma_buf_attachment { struct dma_buf *dmabuf; struct device *dev; const struct dma_buf_attach_ops *importer_ops; void *importer_priv, *priv; bool peer2peer; };
struct dma_buf_attachment *dma_buf_dynamic_attach(struct dma_buf *, struct device *, const struct dma_buf_attach_ops *, void *);
void dma_buf_detach(struct dma_buf *, struct dma_buf_attachment *);
int dma_buf_pin(struct dma_buf_attachment *);
void dma_buf_unpin(struct dma_buf_attachment *);
struct sg_table *dma_buf_map_attachment(struct dma_buf_attachment *, enum dma_data_direction);
void dma_buf_unmap_attachment(struct dma_buf_attachment *, struct sg_table *, enum dma_data_direction);
struct dma_buf *dma_buf_get(int);
void dma_buf_put(struct dma_buf *);
static inline void get_dma_buf(struct dma_buf *b) { get_file(b->file); }
static inline bool dma_buf_is_dynamic(struct dma_buf *b) { return !!b->ops->pin; }
bool dma_need_sync(struct device *, dma_addr_t);
struct test_env {
	struct user_struct user;
	struct mm_struct mm;
	struct task_struct task;
	struct module exporter, descriptor;
	struct file file;
	struct dma_resv resv;
	struct dma_buf buf;
	struct scatterlist sg[2];
	unsigned long limit;
	unsigned alloc_calls, live_allocs, fail_alloc;
	unsigned attaches, detaches, pins, unpins, maps, unmaps, waits, puts;
	int attach_error, pin_error, map_error, wait_error;
	bool move_on_pin, move_on_map;
	u64 needs_sync_address;
	struct dma_buf_attachment *last_attach;
};
extern struct test_env env;
void test_env_init(const struct dma_buf_ops *);
void test_notify(struct dma_buf_attachment *);
#endif
