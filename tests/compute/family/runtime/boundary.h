/* Kernel/core/native boundaries only. No copy executor logic is defined here. */
#ifndef RUNTIME_TEST_BOUNDARY_H
#define RUNTIME_TEST_BOUNDARY_H
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/types.h>
typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
#include "include/linux/xdev_ext_mech.h"
#include "include/linux/xdev_ext_family_core.h"
#include "include/linux/xdev_ext_dma_scope_core.h"
#define GFP_KERNEL 0
#define PAGE_SHIFT 12
#define U64_MAX UINT64_MAX
#define U32_MAX UINT32_MAX
#define BIT(n) (1U<<(n))
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x,v) ((x)=(v))
#define smp_load_acquire(p) __atomic_load_n(p,__ATOMIC_ACQUIRE)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define struct_size(p,m,n) (sizeof(*(p))+sizeof((p)->m[0])*(n))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
static int assertions;
#define CHECK(c) do { assertions++; if (!(c)) { fprintf(stderr,"ASSERT %s:%d: %s\n",__FILE__,__LINE__,#c); exit(70); } } while(0)
static char trace[4096];
static void event(const char *s) {
    CHECK(strlen(trace)+strlen(s)+2<sizeof(trace));
    strcat(trace,s);
    strcat(trace," ");
}
static void clear_trace(void) {
    trace[0]=0;
}
static void expect_trace(const char *s) {
    CHECK(!strcmp(trace,s));
}
struct mutex {
    int held;
}
;
static int lock_depth;
#define __MUTEX_INITIALIZER(n) {0}
#define DEFINE_MUTEX(n) struct mutex n={0}
static void mutex_lock(struct mutex *m) {
    CHECK(!m->held);
    m->held=1;
    lock_depth++;
}
static void mutex_unlock(struct mutex *m) {
    CHECK(m->held);
    m->held=0;
    lock_depth--;
}
struct list_head {
    struct list_head *next,*prev;
}
;
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n=LIST_HEAD_INIT(n)
#define INIT_LIST_HEAD(n) do {(n)->next=(n);(n)->prev=(n);}while(0)
static bool list_empty(const struct list_head *h) {
    return h->next==h;
}
static void list_add_tail(struct list_head *n,struct list_head *h) {
    n->prev=h->prev;
    n->next=h;
    h->prev->next=n;
    h->prev=n;
}
static void list_del(struct list_head *n) {
    n->prev->next=n->next;
    n->next->prev=n->prev;
}
#define list_del_init(n) do {list_del(n);INIT_LIST_HEAD(n);}while(0)
#define list_for_each_entry(p,h,m) for (p=container_of((h)->next,__typeof__(*p),m); &(p)->m!=(h); p=container_of((p)->m.next,__typeof__(*p),m))
#define list_for_each_entry_safe(p,q,h,m) for (p=container_of((h)->next,__typeof__(*p),m), q=container_of((p)->m.next,__typeof__(*p),m); &(p)->m!=(h); p=q,q=container_of((q)->m.next,__typeof__(*q),m))
typedef struct {
    int value;
}
atomic_t;
static int atomic_read(const atomic_t *a) {
    return a->value;
}
static void atomic_inc(atomic_t *a) {
    a->value++;
}
static void atomic_set(atomic_t *a,int n) {
    a->value=n;
}
typedef struct {
    int value;
}
refcount_t;
static void refcount_set(refcount_t *r,int n){
    r->value=n;
}
static bool refcount_inc_not_zero(refcount_t *r){
    if(!r->value)return false;
    r->value++;
    return true;
}
static bool refcount_dec_and_test(refcount_t *r){
    CHECK(r->value>0);
    return --r->value==0;
}
struct module {
    int refs;
    bool unavailable;
}
;
static struct module self_module;
#define THIS_MODULE (&self_module)
static bool expect_registry_pin;
static bool try_module_get(struct module *m){
    if(expect_registry_pin)CHECK(lock_depth>0);
    if(m&&m->unavailable)return false;
    if(m)m->refs++;
    return true;
}
static void module_put(struct module *m){
    if(m){
        CHECK(m->refs>0);
        m->refs--;
    }
}
static int allocation_fail,allocations,frees,failed_allocations,allocation_fail_after;
static void *kmalloc(size_t n,int g){
    allocations++;
    if(allocation_fail||(allocation_fail_after&&!--allocation_fail_after)){
        if(allocation_fail)allocation_fail--;
        failed_allocations++;
        return NULL;
    }
    return malloc(n);
}
static void *kzalloc(size_t n,int g){
    void*p=kmalloc(n,g);
    if(p)memset(p,0,n);
    return p;
}
#define kvzalloc kzalloc
static void kfree(void *p){
    if(p){
        frees++;
        free(p);
    }
}
#define kvfree kfree
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
static int warnings;
#define WARN_ON_ONCE(c) ({bool _v=!!(c);if(_v)warnings++;_v;})
#define WARN_ONCE(c,...) WARN_ON_ONCE(c)
#define EXPORT_SYMBOL_GPL(n)
#define __init
#define late_initcall_sync(n)
#define pr_err(...) ((void)0)
struct file_operations {
    int id;
}
;
struct file {
    const struct file_operations *f_op;
}
;
struct page {
    int unused;
}
;
struct xdev_ext_mech_session;
struct xdev_ext_mech_batch;
struct xdev_ext_mech_class_ops;
struct xdev_ext_ce_backend_ops;
struct xdev_ext_dma_provider_ops;
struct xdev_ext_dma_cookie;
struct xdev_ext_ce_cookie;
struct xdev_ext_rel_policy;
struct xdev_ext_mech_pool_ops;
struct xdev_ext_mech_life;
struct xdev_ext_mech_class_desc;
struct pci_dev;
struct xdev_ext_family_hooks_hdr {
    u32 family;
}
;
struct xdev_ext_comp_hooks {
    struct xdev_ext_family_hooks_hdr hdr;
    u32 kinds,producer_visibility;
}
;
#define XDEV_EXT_CAP_NOT_WIRED 0
#define XDEV_EXT_DMA_SCOPE_OPS_VERSION 1U
#include "public.h"
struct xdev_ext_mech_session {
    struct xdev_ext_mech_pool pool;
    struct xdev_ext_mech_layout layout;
    u32 depth;
}
;
struct xdev_ext_mech_batch {
    void *priv,*cookie;
    u64 id,ticket;
    u32 slot,nr;
    struct xdev_ext_mech_frame frames[XDEV_EXT_MECH_MAX_FRAMES];
    int frame_error,claim_error;
    bool owners_valid,claimed;
    struct {
        u64 ctrl;
    }
    completion;
    int phase,publishes,publish_errno;
    bool sequestered;
}
;
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){
    return &s->pool;
}
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session*s){
    return &s->layout;
}
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session*s){
    return s->depth;
}
static u32 xdev_ext_mech_batch_slot(struct xdev_ext_mech_batch*b){
    return b->slot;
}
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch*b){
    return b->id;
}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch*b){
    return b->ticket;
}
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch*b){
    return b->nr;
}
static int frame_reads;
static int claim_attempts,fail_claim_call;
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch*b,u32 i,struct xdev_ext_mech_frame*f){
    frame_reads++;
    if(b->frame_error)return b->frame_error;
    *f=b->frames[i];
    return 0;
}
static int xdev_ext_mech_batch_frame_claim(const struct xdev_ext_mech_batch*b,u32 i,u64 *o,u64*g){
    if(b->claim_error||i>=b->nr||(++claim_attempts==fail_claim_call))return -ESTALE;
    *o=21+i;
    *g=55+i;
    return 0;
}
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch*b){
    return b->priv;
}
static void *xdev_ext_mech_batch_cookie(struct xdev_ext_mech_batch*b){
    return b->cookie;
}
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch*b,u64 t){
    if(!t||t!=b->ticket||b->claimed)return -ESTALE;
    b->claimed=true;
    b->phase=2;
    b->completion.ctrl=(t<<3)|2;
    event("claim");
    return 0;
}
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch*b,u64 t,int e,bool s){
    CHECK(t==b->ticket&&b->claimed);
    b->publishes++;
    b->publish_errno=e;
    b->sequestered=s;
    event("publish");
}
bool xdev_ext_mech_batch_ce_owners_valid(const struct xdev_ext_mech_batch*,u64,const struct xdev_ext_ce_xfer*,u32);
bool xdev_ext_mech_batch_dma_owners_valid(const struct xdev_ext_mech_batch*,u64,const struct xdev_ext_dma_xfer*,u32);
static bool xdev_ext_mech_batch_copy_owner_valid(const struct xdev_ext_mech_batch*b,u64 owner,u64 generation,u64 host,u32 len){
    return b->owners_valid&&owner==21&&generation==55&&host==272&&len==128;
}
/* Core scheduler OS boundary: notify enqueues, never runs a CE hook inline. */
static unsigned int core_kicks;
static struct xdev_ext_mech_stage *last_kicked;
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) {
    core_kicks++; last_kicked=st;
}
static int xdev_ext_mech_class_register(const struct xdev_ext_mech_class_ops*c){
    return 0;
}
void xdev_ext_ce_complete(struct xdev_ext_ce_cookie*,u64,int,bool,u64);
void xdev_ext_dma_complete(struct xdev_ext_dma_cookie*,u64,int,bool,u64);
#endif
