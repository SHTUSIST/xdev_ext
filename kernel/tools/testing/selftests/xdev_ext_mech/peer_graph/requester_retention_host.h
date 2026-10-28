/* SPDX-License-Identifier: GPL-2.0 */
#ifndef REQUESTER_RETENTION_HOST_H
#define REQUESTER_RETENTION_HOST_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <limits.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;
typedef uint16_t u16;
#ifndef EINVAL
#define EINVAL 22
#define ENOMEM 12
#define ENOSPC 28
#define EOVERFLOW 75
#define EBUSY 16
#define E2BIG 7
#endif
#define GFP_KERNEL 0
#define SZ_64M (64UL * 1024 * 1024)
#define U64_MAX UINT64_MAX
#define U32_MAX UINT32_MAX
#define ERR_PTR(err) ((void *)(intptr_t)(err))
#define PTR_ERR(ptr) ((long)(intptr_t)(ptr))
#define IS_ERR(ptr) ((uintptr_t)(ptr) >= (uintptr_t)-4095)
#define IS_ERR_OR_NULL(ptr) (!(ptr) || IS_ERR(ptr))
#define EXPORT_SYMBOL_GPL(name)
#define EXPORT_SYMBOL(name)
#define MODULE_LICENSE(name)
#define MODULE_DESCRIPTION(name)
static inline bool retention_host_warn(bool cond) { return cond; }
#define WARN_ON_ONCE(cond) retention_host_warn(!!(cond))
#define WARN_ON(cond) ((bool)(cond))
#define WARN_ONCE(cond, ...) ((bool)(cond))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, value) ((x) = (value))
#define unlikely(x) (x)
#define likely(x) (x)
#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))
#define min_t(t,a,b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t,a,b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define check_add_overflow(a,b,d) __builtin_add_overflow((a),(b),(d))
#define check_mul_overflow(a,b,d) __builtin_mul_overflow((a),(b),(d))
struct pci_dev { atomic_int refs; };
static inline struct pci_dev *pci_dev_get(struct pci_dev *p) { if (p) atomic_fetch_add(&p->refs, 1); return p; }
static inline void pci_dev_put(struct pci_dev *p) { if (p) atomic_fetch_sub(&p->refs, 1); }
static inline void *kzalloc(size_t n, unsigned flags) { (void)flags; return calloc(1, n); }
static inline void *kmalloc(size_t n, unsigned flags) { (void)flags; return malloc(n); }
static inline void kfree(const void *p) { free((void *)p); }
typedef pthread_mutex_t spinlock_t;
#define DEFINE_SPINLOCK(name) spinlock_t name = PTHREAD_MUTEX_INITIALIZER
#define spin_lock_irqsave(lock, flags) do { (flags) = 0; if (pthread_mutex_lock(lock)) abort(); } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(flags); if (pthread_mutex_unlock(lock)) abort(); } while (0)
struct mutex { pthread_mutex_t native; };
#define DEFINE_MUTEX(name) struct mutex name = { PTHREAD_MUTEX_INITIALIZER }
static inline void mutex_lock(struct mutex *m) { if (pthread_mutex_lock(&m->native)) abort(); }
static inline void mutex_unlock(struct mutex *m) { if (pthread_mutex_unlock(&m->native)) abort(); }
#define lockdep_assert_held(lock) ((void)(lock))
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)
static inline void INIT_LIST_HEAD(struct list_head *h) { h->next = h; h->prev = h; }
static inline void list_add_tail(struct list_head *n, struct list_head *h) { n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n; }
static inline void list_add(struct list_head *n, struct list_head *h) { n->next = h->next; n->prev = h; h->next->prev = n; h->next = n; }
static inline void list_del(struct list_head *n) { n->next->prev = n->prev; n->prev->next = n->next; }
static inline void list_del_init(struct list_head *n) { list_del(n); INIT_LIST_HEAD(n); }
static inline int list_empty(const struct list_head *h) { return h->next == h; }
#define container_of(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
#define list_entry(p,t,m) container_of(p,t,m)
#define list_first_entry(p,t,m) list_entry((p)->next,t,m)
#define list_next_entry(p,m) list_entry((p)->m.next, __typeof__(*(p)),m)
#define list_entry_is_head(p,h,m) (&(p)->m == (h))
#define list_for_each_entry(p,h,m) for ((p)=list_first_entry(h,__typeof__(*(p)),m); !list_entry_is_head(p,h,m); (p)=list_next_entry(p,m))
#define list_for_each_entry_safe(p,n,h,m) for ((p)=list_first_entry(h,__typeof__(*(p)),m), (n)=list_next_entry(p,m); !list_entry_is_head(p,h,m); (p)=(n), (n)=list_next_entry(n,m))
#endif
