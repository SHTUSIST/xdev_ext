/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel environment for compiling the production requester unit
 * (io_uring/family/xdev_ext_requester.c) on the host.  Every Linux header the
 * unit includes is an empty file; the declarations it needs are here.  The DMA
 * API, PCI references and allocations record what the unit asks for; no
 * production algorithm is restated.
 */
#ifndef REQUESTER_HOST_SHIM_H
#define REQUESTER_HOST_SHIM_H
#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#define __user
#define __init
#define __exit
#define __maybe_unused __attribute__((unused))
#define EXPORT_SYMBOL_GPL(x)
#define THIS_MODULE NULL
#define GFP_KERNEL 0
#define U32_MAX UINT32_MAX
#define U64_MAX UINT64_MAX
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define MAX_ERRNO 4095
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-MAX_ERRNO)
#define WARN_ON(x) (!!(x))
#define WARN_ON_ONCE(x) (!!(x))
#define likely(x) (x)
#define unlikely(x) (x)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define check_add_overflow(a, b, d) __builtin_add_overflow((a), (b), (d))
#define check_mul_overflow(a, b, d) __builtin_mul_overflow((a), (b), (d))
#define try_cmpxchg(p, o, n) __atomic_compare_exchange_n(p, o, n, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define capable(c) (true)
#define CAP_SYS_ADMIN 21

typedef struct { _Atomic int counter; } atomic_t;
typedef struct { _Atomic long long counter; } atomic64_t;
#define ATOMIC_INIT(v) { (v) }
#define atomic_read(a) atomic_load(&(a)->counter)
#define atomic_set(a, v) atomic_store(&(a)->counter, (v))
#define atomic_inc(a) ((void)atomic_fetch_add(&(a)->counter, 1))
#define atomic_dec(a) ((void)atomic_fetch_sub(&(a)->counter, 1))
#define atomic_inc_return(a) (atomic_fetch_add(&(a)->counter, 1) + 1)
#define atomic_dec_return(a) (atomic_fetch_sub(&(a)->counter, 1) - 1)
#define atomic64_inc_return(a) (atomic_fetch_add(&(a)->counter, 1) + 1)
#define smp_mb__before_atomic() atomic_thread_fence(memory_order_seq_cst)

typedef struct { bool held; } spinlock_t;
#define DEFINE_SPINLOCK(n) spinlock_t n = { false }
extern unsigned shim_spins;
#define spin_lock_init(s) ((s)->held = false)
#define spin_lock_irqsave(s, f) do { (f) = 0; assert(!(s)->held); (s)->held = true; shim_spins++; } while (0)
#define spin_unlock_irqrestore(s, f) do { (void)(f); assert((s)->held); (s)->held = false; shim_spins--; } while (0)
#define spin_lock(s) do { assert(!(s)->held); (s)->held = true; shim_spins++; } while (0)
#define spin_unlock(s) do { assert((s)->held); (s)->held = false; shim_spins--; } while (0)

struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n = LIST_HEAD_INIT(n)
#define INIT_LIST_HEAD(n) ((n)->next = (n)->prev = (n))
#define list_for_each_entry(p, h, m) for (p = container_of((h)->next, __typeof__(*p), m); &(p)->m != (h); p = container_of((p)->m.next, __typeof__(*p), m))
static inline void list_add_tail(struct list_head *n, struct list_head *h)
{ n->next = h; n->prev = h->prev; h->prev->next = n; h->prev = n; }
static inline void list_del(struct list_head *n)
{ n->prev->next = n->next; n->next->prev = n->prev; }
static inline bool list_empty(const struct list_head *h) { return h->next == h; }

struct module;
struct file { unsigned id; };
struct page { unsigned index; };
struct device { bool dma_coherent; bool force_bounce; bool iommu; unsigned id; };
struct pci_bus { unsigned char number; };
struct pci_dev { struct device dev; unsigned refs; unsigned int untrusted:1; struct pci_bus *bus; unsigned int devfn; };
static inline int pci_domain_nr(struct pci_bus *bus) { (void)bus; return 0; }
struct pci_dev *pci_dev_get(struct pci_dev *p);
void pci_dev_put(struct pci_dev *p);
int pci_p2pdma_distance(struct pci_dev *provider, struct device *client, bool verbose);
bool is_swiotlb_force_bounce(struct device *d);
bool use_dma_iommu(struct device *d);
const void *get_dma_ops(struct device *d);

enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE, DMA_NONE };
#define DMA_ATTR_SKIP_CPU_SYNC (1UL << 5)
#define DMA_MAPPING_ERROR (~(dma_addr_t)0)
dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page, size_t offset, size_t size,
			      enum dma_data_direction dir, unsigned long attrs);
void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
			  enum dma_data_direction dir, unsigned long attrs);
int dma_mapping_error(struct device *dev, dma_addr_t addr);
bool dma_need_sync(struct device *dev, dma_addr_t addr);
void dma_sync_single_for_device(struct device *dev, dma_addr_t addr, size_t size,
				enum dma_data_direction dir);
void dma_sync_single_for_cpu(struct device *dev, dma_addr_t addr, size_t size,
			     enum dma_data_direction dir);
#define dma_map_page(d, p, o, s, r) dma_map_page_attrs(d, p, o, s, r, 0)
#define dma_unmap_page(d, a, s, r) dma_unmap_page_attrs(d, a, s, r, 0)

void *shim_alloc(size_t n, bool zero);
void shim_free(const void *p);
#define kzalloc(n, f) shim_alloc((n), true)
#define kmalloc(n, f) shim_alloc((n), false)
#define kcalloc(n, s, f) shim_alloc((size_t)(n) * (s), true)
#define kvcalloc(n, s, f) shim_alloc((size_t)(n) * (s), true)
#define kvmalloc_array(n, s, f) shim_alloc((size_t)(n) * (s), false)
#define kfree(p) shim_free(p)
#define kvfree(p) shim_free(p)
#endif
