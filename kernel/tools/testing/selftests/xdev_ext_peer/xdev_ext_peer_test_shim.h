/* SPDX-License-Identifier: GPL-2.0 */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
#define U32_MAX UINT32_MAX
#define GFP_KERNEL 0
#define EXPORT_SYMBOL_GPL(x)
#define kzalloc(n,f) calloc(1,n)
#define kfree free
struct mutex { pthread_mutex_t m; };
#define DEFINE_MUTEX(n) struct mutex n = { PTHREAD_MUTEX_INITIALIZER }
#define mutex_init(l) pthread_mutex_init(&(l)->m, NULL)
#define mutex_lock(l) pthread_mutex_lock(&(l)->m)
#define mutex_unlock(l) pthread_mutex_unlock(&(l)->m)
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
#define INIT_LIST_HEAD(n) ((n)->next = (n)->prev = (n))
#define container_of(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
#define list_for_each_entry(p,h,m) for (p = container_of((h)->next, __typeof__(*p), m); &(p)->m != (h); p = container_of((p)->m.next, __typeof__(*p), m))
static inline void list_add_tail(struct list_head *n, struct list_head *h) { n->next=h; n->prev=h->prev; h->prev->next=n; h->prev=n; }
static inline void list_del(struct list_head *n) { n->prev->next=n->next; n->next->prev=n->prev; }
static inline bool list_empty(struct list_head *h) { return h->next == h; }
typedef atomic_ullong atomic64_t;
#define ATOMIC64_INIT(n) (n)
#define atomic64_inc_return(a) (atomic_fetch_add(a,1)+1)
struct module { int refs; };
static inline bool try_module_get(struct module *m) { if(m) m->refs++; return true; }
static inline void module_put(struct module *m) { if(m) m->refs--; }
struct file_operations { int unused; };
struct file { const struct file_operations *f_op; int refs; };
static inline void get_file(struct file *f) { f->refs++; }
static inline void fput(struct file *f) { f->refs--; }
struct pci_dev { int refs; };
static inline struct pci_dev *pci_dev_get(struct pci_dev *p) { p->refs++; return p; }
static inline void pci_dev_put(struct pci_dev *p) { p->refs--; }
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE, DMA_NONE };
