/* SPDX-License-Identifier: GPL-2.0 */
/* Controlled host kernel primitive/OS/BPF-reference boundary. This is NOT a
 * replacement registry, actual kernel mutex/RCU proof, or a BPF ABI certificate. */
#ifndef INSTANCE_REGISTRY_TEST_SHIM_H
#define INSTANCE_REGISTRY_TEST_SHIM_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "xdev_ext_mech.h"
#include INSTANCE_FAMILY_HEADER

typedef __u32 u32;typedef __u64 u64;
#define BPF_LINK_TYPE_STRUCT_OPS 91 /* Host type tag; no kernel numeric ABI claim. */
#define __rcu
#define GFP_KERNEL 0
#define EXPORT_SYMBOL_GPL(name)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define smp_store_release(p,v) (*(p)=(v))
#define smp_load_acquire(p) (*(p))
#define ERR_PTR(err) ((void *)(intptr_t)(err))
#define PTR_ERR(ptr) ((long)(intptr_t)(ptr))
#define IS_ERR(ptr) ((uintptr_t)(ptr)>=(uintptr_t)-4095)
#define container_of(ptr,type,member) ((type *)((char *)(ptr)-offsetof(type,member)))
static unsigned held_mutexes,failures,default_gone,ops_pins,temp_gets,temp_puts,records_allocated,records_freed,hash_queries;
static void check(bool ok,const char *why){if(!ok){failures++;fprintf(stderr,"REGISTRY_ASSERT %s\n",why);}}
#define WARN_ON(x) ({bool bad=!!(x);check(!bad,"unexpected kernel WARN_ON");bad;})
#define WARN_ON_ONCE(x) WARN_ON(x)
struct mutex {bool held;};struct static_key_false {bool enabled;};
#define DEFINE_MUTEX(name) struct mutex name={0}
static void mutex_lock(struct mutex *m){check(!m->held,"no reentrant local registry mutex");m->held=true;held_mutexes++;}
static void mutex_unlock(struct mutex *m){check(m->held&&held_mutexes,"unlock owned registry mutex");m->held=false;held_mutexes--;}
#define lockdep_assert_held(m) check((m)->held,"expected owned mutex")
#define lockdep_assert_not_held(m) check(!(m)->held,"operation must be outside owned mutex")
#define rcu_access_pointer(p) (p)
#define rcu_dereference(p) (p)
#define rcu_assign_pointer(p,v) ((p)=(v))
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
static void synchronize_rcu(void){check(!held_mutexes,"grace period outside all owned registry mutexes");}
static void static_branch_enable(struct static_key_false *k){k->enabled=true;}
static void static_branch_disable(struct static_key_false *k){k->enabled=false;}

typedef struct {unsigned refs;} refcount_t;
static void refcount_set(refcount_t *r,unsigned n){r->refs=n;}
static void refcount_inc(refcount_t *r){check(r->refs>0,"retired zero-ref record never resurrected");r->refs++;}
static bool refcount_inc_not_zero(refcount_t *r){if(!r->refs)return false;r->refs++;return true;}
static bool refcount_dec_and_test(refcount_t *r){check(r->refs>0,"record ref released exactly once");return --r->refs==0;}
struct allocation_record {void *p;bool live;};
static struct allocation_record allocation_records[1024];
static void *kzalloc(size_t n,int flags){(void)flags;void *p=calloc(1,n);if(p){allocation_records[records_allocated]=(struct allocation_record){p,true};records_allocated++;}return p;}
static bool allocation_live(const void *p){for(unsigned i=0;i<records_allocated;i++)if(allocation_records[i].p==p&&allocation_records[i].live)return true;return false;}
static void kfree(const void *p){if(!p)return;check(!held_mutexes,"record final free outside local registry mutex");check(allocation_live(p),"record freed exactly once");for(unsigned i=0;i<records_allocated;i++)if(allocation_records[i].p==p&&allocation_records[i].live){allocation_records[i].live=false;records_freed++;break;}free((void *)p);}
struct hlist_node {struct hlist_node *next,**pprev;};
struct hlist_head {struct hlist_node *first;};
#define DEFINE_HASHTABLE(name,bits) struct hlist_head name[1U<<(bits)]
#define HASH_SIZE(table) ARRAY_SIZE(table)
#define HASH_BITS(table) (__builtin_ctzl(HASH_SIZE(table)))
static void hlist_add_head(struct hlist_node *node,struct hlist_head *head){node->next=head->first;if(head->first)head->first->pprev=&node->next;head->first=node;node->pprev=&head->first;}
static void hlist_del_init(struct hlist_node *node){if(node->pprev){*node->pprev=node->next;if(node->next)node->next->pprev=node->pprev;}node->pprev=NULL;node->next=NULL;}
#define hash_add(table,node,key) hlist_add_head((node),&(table)[(uintptr_t)(key)&(HASH_SIZE(table)-1)])
#define hash_del(node) hlist_del_init(node)
#define hash_for_each_possible(table,obj,member,key) \
 for(struct hlist_node *_node=(++hash_queries,(table)[(uintptr_t)(key)&(HASH_SIZE(table)-1)].first); \
     _node&&((obj)=container_of(_node,__typeof__(*(obj)),member),true);_node=_node->next)

struct xdev_ext_nvme_mech_ops {u32 abi_version,flags;int oracle;unsigned pins;bool pin_failure;};
struct bpf_link {unsigned type,id,refs;u32 class_id;const void *ops;bool detached;};
struct xdev_ext_mech_instance;
int xdev_ext_mech_instance_register(u32,const void *,struct bpf_link *);
bool xdev_ext_mech_instance_unregister(u32,const void *,struct bpf_link *);
int xdev_ext_mech_instance_get_from_fd(u32,int,struct xdev_ext_mech_instance **);
bool xdev_ext_mech_instance_current(const struct xdev_ext_mech_instance *);
const void *xdev_ext_mech_instance_ops(const struct xdev_ext_mech_instance *);
void xdev_ext_mech_instance_put(struct xdev_ext_mech_instance *);
void xdev_ext_mech_instance_gone(struct xdev_ext_mech_instance *);
static void owned_link_unregister(struct bpf_link *);
static struct bpf_link *fd_links[128];
static bool nonlink_fd[128],close_fd_on_put;
static bool bpf_struct_ops_get(const void *ops){struct xdev_ext_nvme_mech_ops *p=(void *)ops;if(p->pin_failure)return false;p->pins++;ops_pins++;return true;}
static void bpf_struct_ops_put(const void *ops){struct xdev_ext_nvme_mech_ops *p=(void *)ops;check(!held_mutexes,"ops final put outside registry locks");check(p->pins&&ops_pins,"ops pin released exactly once");p->pins--;ops_pins--;}
static struct bpf_link *bpf_link_get_from_fd(u32 fd){if(fd>=ARRAY_SIZE(fd_links))return ERR_PTR(-EBADF);if(nonlink_fd[fd])return ERR_PTR(-EINVAL);if(!fd_links[fd])return ERR_PTR(-EBADF);temp_gets++;fd_links[fd]->refs++;return fd_links[fd];}
static void bpf_link_put(struct bpf_link *link){
 check(!held_mutexes,"temporary link put outside every owned local mutex");temp_puts++;
 if(close_fd_on_put){close_fd_on_put=false;for(unsigned i=0;i<ARRAY_SIZE(fd_links);i++)if(fd_links[i]==link){fd_links[i]=NULL;check(link->refs>1,"temporary getter ref exists at final fd close");link->refs--;break;}}
 check(link->refs>0,"link reference released exactly once");link->refs--;
 if(!link->refs&&!link->detached)owned_link_unregister(link);
}
static void close_fd(unsigned fd){struct bpf_link *link=fd_links[fd];check(link!=NULL,"close actual owned fd");fd_links[fd]=NULL;bpf_link_put(link);}
#endif
