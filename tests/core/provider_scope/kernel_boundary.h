/* SPDX-License-Identifier: GPL-2.0 */
#ifndef INDEPENDENT_DMA_KERNEL_BOUNDARY_H
#define INDEPENDENT_DMA_KERNEL_BOUNDARY_H
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
typedef __u8 u8;typedef __u16 u16;typedef __u32 u32;typedef __u64 u64;
typedef __s8 s8;typedef __s16 s16;typedef __s32 s32;typedef __s64 s64;
typedef unsigned int gfp_t;
#define U32_MAX UINT32_MAX
#define U64_MAX UINT64_MAX
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096U
#define PAGE_MASK (~(PAGE_SIZE-1UL))
#define GFP_KERNEL 0U
#define __init
#define __user
#define __rcu
#define __maybe_unused __attribute__((unused))
#define EXPORT_SYMBOL_GPL(x)
#define THIS_MODULE NULL
#define pr_err(...) fprintf(stderr,__VA_ARGS__)
#define READ_ONCE(x) __atomic_load_n(&(x),__ATOMIC_RELAXED)
#define WRITE_ONCE(x,v) __atomic_store_n(&(x),(v),__ATOMIC_RELAXED)
#define try_cmpxchg(p,o,v) __atomic_compare_exchange_n(p,o,v,false,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST)
#define check_add_overflow(a,b,out) __builtin_add_overflow(a,b,out)
#define check_mul_overflow(a,b,out) __builtin_mul_overflow(a,b,out)
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
#define min_t(t,a,b) min((t)(a),(t)(b))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define struct_size(p,member,n) (sizeof(*(p))+sizeof((p)->member[0])*(n))
#define container_of(p,type,member) ((type *)((char *)(p)-offsetof(type,member)))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define IS_ERR_OR_NULL(p) (!(p)||IS_ERR(p))
#define might_sleep() ((void)0)

struct boundary_event {const char *what;const void *who;};
static struct boundary_event events[4096];
static unsigned int nr_events,held_locks,warnings;
static int fail_next_allocation;
static void event(const char *what,const void *who)
{assert(nr_events<ARRAY_SIZE(events));events[nr_events++]=(struct boundary_event){what,who};}
static int boundary_warning(int condition)
{if(condition){warnings++;event("WARN",NULL);}return condition;}
#define WARN_ON_ONCE(x) boundary_warning(!!(x))
#define WARN_ONCE(x,...) boundary_warning(!!(x))
#define WARN_ON(x) boundary_warning(!!(x))
struct mutex {unsigned int held;const char *name;};
#define DEFINE_MUTEX(name) struct mutex name={0,#name}
static inline void mutex_lock(struct mutex *m)
{assert(!m->held);m->held=1;held_locks++;}
static inline void mutex_unlock(struct mutex *m)
{assert(m->held&&held_locks);m->held=0;held_locks--;}
#define lockdep_assert_held(m) assert((m)->held)
#define lockdep_assert_not_held(m) assert(!(m)->held)
struct module {const char *name;int refs;bool going;};
static inline bool try_module_get(struct module *m)
{if(!m)return true;if(m->going)return false;m->refs++;event("module_get",m);return true;}
static inline void module_put(struct module *m)
{if(m){assert(m->refs>0);event("module_put",m);m->refs--;}}
static inline void *boundary_alloc(size_t n,bool zero)
{
 void *p;if(fail_next_allocation){fail_next_allocation=0;event("allocation_failed",NULL);return NULL;}
 p=malloc(n);if(p)memset(p,zero?0:0xa5,n);return p;
}
static inline void *kmalloc(size_t n,gfp_t flags){(void)flags;return boundary_alloc(n,false);}
static inline void *kzalloc(size_t n,gfp_t flags){(void)flags;return boundary_alloc(n,true);}
static inline void *kvzalloc(size_t n,gfp_t flags){return kzalloc(n,flags);}
static inline void *kcalloc(size_t n,size_t size,gfp_t flags)
{if(size&&n>SIZE_MAX/size)return NULL;return kzalloc(n*size,flags);}
static inline void kfree(void *p){if(p)event("free",p);free(p);}
static inline void kvfree(void *p){kfree(p);}
typedef struct {int counter;} atomic_t;
static inline void atomic_set(atomic_t *a,int v){a->counter=v;}
static inline int atomic_read(const atomic_t *a){return a->counter;}
static inline void atomic_inc(atomic_t *a){a->counter++;}
typedef struct {unsigned int refs;} refcount_t;
static inline void refcount_set(refcount_t *r,unsigned int n){r->refs=n;}
static inline bool refcount_inc_not_zero(refcount_t *r){if(!r->refs)return false;assert(r->refs<UINT_MAX);r->refs++;return true;}
static inline bool refcount_dec_and_test(refcount_t *r){assert(r->refs);return --r->refs==0;}
static inline unsigned int refcount_read(const refcount_t *r){return r->refs;}
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD(name) struct list_head name={&name,&name}
static inline void INIT_LIST_HEAD(struct list_head *head){head->next=head->prev=head;}
static inline bool list_empty(const struct list_head *head){return head->next==head;}
static inline void list_add_tail(struct list_head *node,struct list_head *head)
{node->prev=head->prev;node->next=head;head->prev->next=node;head->prev=node;event("list_add",node);}
static inline void list_del(struct list_head *node)
{node->prev->next=node->next;node->next->prev=node->prev;event("list_del",node);node->next=node->prev=NULL;}
static inline void list_del_init(struct list_head *node){list_del(node);INIT_LIST_HEAD(node);}
#define list_entry(p,type,member) container_of(p,type,member)
#define list_for_each_entry(pos,head,member) \
 for(pos=list_entry((head)->next,__typeof__(*pos),member);&(pos)->member!=(head);pos=list_entry((pos)->member.next,__typeof__(*pos),member))
#define list_for_each_entry_safe(pos,tmp,head,member) \
 for(pos=list_entry((head)->next,__typeof__(*pos),member),tmp=list_entry((pos)->member.next,__typeof__(*pos),member); \
 &(pos)->member!=(head);pos=tmp,tmp=list_entry((tmp)->member.next,__typeof__(*tmp),member))

/* Public plain-data section supplies the authoritative UAPI and state enums. */
#ifdef __KERNEL__
#undef __KERNEL__
#define BOUNDARY_RESTORE_KERNEL
#endif
#include XDEV_PUBLIC_HEADER
#ifdef BOUNDARY_RESTORE_KERNEL
#define __KERNEL__ 1
#endif
struct page {unsigned char bytes[4096];};
struct file_operations {unsigned int tag;};
struct file {const struct file_operations *f_op;void *private_data;};
struct xdev_ext_mech_class_ops;
struct xdev_ext_mech_pool_ops;
struct xdev_ext_mech_life;
struct pci_dev;
struct xdev_ext_rel_policy;
struct xdev_ext_net_hooks;
struct xdev_ext_stor_hooks;
struct xdev_ext_mech_pool {
 struct xdev_ext_mech_life *life;const struct xdev_ext_mech_pool_ops *ops;void *priv;u8 *state;struct page **pages;void *vaddr;
 u64 size;u32 kind,capabilities,frame_size,nr_frames,nr_pages,first_page_off;
};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout layout;u32 depth;};
struct xdev_ext_mech_stage {
 struct xdev_ext_mech_session *s;const struct xdev_ext_mech_class_ops *cls;struct file *file;void *priv;
 u64 arg0,arg1;u32 class_id,direction,flags,index;bool poll;struct xdev_ext_mech_stage_caps caps;
 bool create_reporting;u32 create_phase,create_valid;struct xdev_ext_mech_requester_id create_requester_id;
 struct pci_dev *create_requester;struct xdev_ext_mech_stage_diag create_observed;
};
struct xdev_ext_mech_frame {void *kaddr;u64 umem_addr;u32 index,data_off,data_len;void *pool_priv;};
struct xdev_ext_mech_batch {
 u32 slot,nr_frames;u64 id,ticket;void *priv,*cookie;struct xdev_ext_mech_frame frame;
 bool claimed,uncertain,owners_valid;int error;unsigned int published;
};
struct xdev_ext_dma_cookie;
struct xdev_ext_dma_provider_ops;
struct xdev_ext_dma_region {const struct xdev_ext_dma_provider_ops *ops;void *priv;u64 len;u32 segment_size,max_entry_len,alignment,directions;bool polled;};
struct xdev_ext_dma_xfer {u64 owner,generation,host_byte_off,device_off;u32 len,flags;};
struct xdev_ext_dma_provider_ops {
 struct module *owner;const struct file_operations *fops;
 int (*bind_region)(struct file *,u64,u64,struct xdev_ext_dma_region *);
 int (*unbind_region)(struct xdev_ext_dma_region *);
 int (*bind_host)(struct xdev_ext_dma_region *,struct page **,u32,void **);
 int (*unbind_host)(void *);
 int (*submit)(struct xdev_ext_dma_region *,void *,u32,const struct xdev_ext_dma_xfer *,u32,struct xdev_ext_dma_cookie *,u64);
 int (*poll)(struct xdev_ext_dma_region *);
};
#ifdef XDEV_SCOPE_HEADER
#include XDEV_SCOPE_HEADER
#else
#include "contract.h"
#endif
struct xdev_ext_dma_scope_info {u32 kind,reserved;struct xdev_ext_dma_scope *scope;u64 canonical_start,canonical_len;};
#define XDEV_EXT_DMA_SCOPE_OPS_VERSION 1U
struct xdev_ext_dma_scope_ops {u32 size,version,flags,reserved;int (*acquire)(struct file *,u64,u64,struct xdev_ext_dma_scope_info *);};
struct xdev_ext_dma_scope *xdev_ext_dma_scope_create(struct module *,void *,void (*)(void *));
void xdev_ext_dma_scope_owner_put(struct xdev_ext_dma_scope *);
int xdev_ext_dma_scope_get(struct xdev_ext_dma_scope *);
void xdev_ext_dma_scope_put(struct xdev_ext_dma_scope *);
int xdev_ext_dma_provider_register_scoped(const struct xdev_ext_dma_provider_ops *,const struct xdev_ext_dma_scope_ops *);
int xdev_ext_dma_provider_register(const struct xdev_ext_dma_provider_ops *);
void xdev_ext_dma_provider_unregister(const struct xdev_ext_dma_provider_ops *);
void xdev_ext_dma_complete(struct xdev_ext_dma_cookie *,u64,int,bool,u64);

struct xdev_ext_family_hooks_hdr {u32 family;};
struct xdev_ext_comp_hooks {struct xdev_ext_family_hooks_hdr hdr;u32 kinds,producer_visibility;};
#include <linux/xdev_ext_compfam_core.h>
struct xdev_ext_mech_class_ops {
 const struct xdev_ext_mech_class_desc *decl;u32 class_id,flags,desc_size,desc_cap,info_size,cqe_size,cqe_cap,batch_priv_size,batch_cookie_size;
 struct module *owner;int (*bind)(struct xdev_ext_mech_stage *,const struct xdev_ext_mech_stage_uapi *);
 void (*unbind)(struct xdev_ext_mech_stage *);int (*unbind_checked)(struct xdev_ext_mech_stage *);
 void (*fill_info)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *,void *);
 int (*default_build)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *,u8 *);
 int (*validate)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *,const u8 *,u32);
 int (*submit)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *);
 void (*fill_cqe)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *,void *);
 void (*mark_dead)(struct xdev_ext_mech_stage *);
 void (*batch_end)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *,int);
 void (*batch_release)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_batch *,bool);
 unsigned long (*progress)(struct xdev_ext_mech_stage *);
 int (*stage_diag)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_stage_diag *);
 void (*transport_stats)(struct xdev_ext_mech_stage *,u32 *,u32 *);
 void (*transport_counters)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_transport_stats_v2 *);
 void (*transport_policy)(struct xdev_ext_mech_stage *,struct xdev_ext_rel_policy *);
 int (*poll)(struct xdev_ext_mech_stage *);
 union {const struct xdev_ext_family_hooks_hdr *hdr;const struct xdev_ext_net_hooks *net;const struct xdev_ext_stor_hooks *stor;const struct xdev_ext_comp_hooks *comp;} fam;
};
static const struct xdev_ext_mech_class_ops *registered_class;
static inline int xdev_ext_mech_class_register(const struct xdev_ext_mech_class_ops *ops){registered_class=ops;return 0;}
#define late_initcall_sync(fn) static void __attribute__((constructor)) boundary_init_##fn(void){assert(fn()==0);}
static inline struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return &s->pool;}
static inline u32 xdev_ext_mech_session_depth(const struct xdev_ext_mech_session *s){return s->depth;}
static inline const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(const struct xdev_ext_mech_session *s){return &s->layout;}
static inline u32 xdev_ext_mech_batch_slot(const struct xdev_ext_mech_batch *b){return b->slot;}
static inline u64 xdev_ext_mech_batch_id(const struct xdev_ext_mech_batch *b){return b->id;}
static inline u64 xdev_ext_mech_batch_ticket(const struct xdev_ext_mech_batch *b){return b->ticket;}
static inline u32 xdev_ext_mech_batch_nr_frames(const struct xdev_ext_mech_batch *b){return b->nr_frames;}
static inline void *xdev_ext_mech_batch_priv(const struct xdev_ext_mech_batch *b){return b->priv;}
static inline void *xdev_ext_mech_batch_cookie(const struct xdev_ext_mech_batch *b){return b->cookie;}
static inline int xdev_ext_mech_batch_frame(const struct xdev_ext_mech_batch *b,u32 pos,struct xdev_ext_mech_frame *out)
{if(pos>=b->nr_frames)return -ERANGE;*out=b->frame;return 0;}
static inline int xdev_ext_mech_batch_frame_claim(const struct xdev_ext_mech_batch *b,u32 pos,u64 *owner,u64 *generation)
{if(pos>=b->nr_frames)return -ERANGE;*owner=1;*generation=b->id;return 0;}
static inline bool xdev_ext_mech_batch_dma_owners_valid(const struct xdev_ext_mech_batch *b,u64 ticket,const struct xdev_ext_dma_xfer *x,u32 n)
{(void)x;(void)n;return b->owners_valid && b->ticket==ticket;}
static inline int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 ticket)
{if(b->ticket!=ticket||b->claimed)return -ESTALE;b->claimed=true;return 0;}
static inline void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 ticket,int error,bool uncertain)
{assert(ticket==b->ticket);b->published++;b->error=error;b->uncertain=uncertain;}
#endif
