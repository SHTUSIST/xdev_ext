/* SPDX-License-Identifier: GPL-2.0 */
/* Host kernel primitive/BPF/module ref boundaries; no registry decisions. */
#include "include/linux/xdev_ext_family_core.h"
#include "io_uring/xdev_ext_mech_poll.h"
#define __rcu
#define rcu_access_pointer(p) (p)
#define rcu_assign_pointer(p,v) ((p)=(v))
#define rcu_dereference(p) (p)
#define smp_store_release(p,v) (*(p)=(v))
#define smp_load_acquire(p) (*(p))
typedef __s32 s32;
struct hlist_node {struct hlist_node *next,**pprev;};
struct hlist_head {struct hlist_node *first;};
#define DEFINE_HASHTABLE(n,b) struct hlist_head n[1]
static void hash_add_host(struct hlist_node *n,struct hlist_head *h){n->next=h->first;if(n->next)n->next->pprev=&n->next;h->first=n;n->pprev=&h->first;}
static void hash_del_host(struct hlist_node *n){assert(n->pprev);*n->pprev=n->next;if(n->next)n->next->pprev=n->pprev;n->pprev=NULL;n->next=NULL;}
#define hash_add(t,n,k) ((void)(k),hash_add_host(n,&(t)[0]))
#define hash_del(n) hash_del_host(n)
#define hash_for_each_possible(t,o,m,k) for(struct hlist_node *hn=((void)(k),(t)[0].first);hn&&((o)=container_of(hn,__typeof__(*(o)),m),true);hn=hn->next)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef struct{unsigned refs;} refcount_t;
static void refcount_set(refcount_t *r,unsigned n){r->refs=n;}
static void refcount_inc(refcount_t *r){assert(r->refs);r->refs++;}
static bool refcount_dec_and_test(refcount_t *r){assert(r->refs);return !--r->refs;}
struct xdev_ext_mech_ctx;
/* ACTUAL_OPS_TYPES */
struct host_selected_program {struct xdev_ext_nvme_mech_ops ops;unsigned pins;};
static unsigned selected_gets,selected_puts,link_gets,link_puts;
static bool bpf_struct_ops_get(const void *p){struct host_selected_program *h=container_of(p,struct host_selected_program,ops);h->pins++;selected_gets++;return true;}
static void bpf_struct_ops_put(const void *p){struct host_selected_program *h=container_of(p,struct host_selected_program,ops);assert(h->pins);h->pins--;selected_puts++;}
#define BPF_LINK_TYPE_STRUCT_OPS 91 /* host type tag, not numeric kernel ABI */
struct bpf_link {unsigned type,refs;u32 class_id;const void *ops;bool detached;};
static struct bpf_link *program_fds[128];
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
static struct bpf_link *bpf_link_get_from_fd(u32 fd){if(fd>=ARRAY_SIZE(program_fds)||!program_fds[fd])return ERR_PTR(-EBADF);link_gets++;program_fds[fd]->refs++;return program_fds[fd];}
static void bpf_link_put(struct bpf_link *l){assert(l->refs>1);l->refs--;link_puts++;}
struct xdev_ext_mech_instance;
int xdev_ext_mech_instance_register(u32,const void *,struct bpf_link *);
bool xdev_ext_mech_instance_unregister(u32,const void *,struct bpf_link *);
int xdev_ext_mech_instance_get_from_fd(u32,int,struct xdev_ext_mech_instance **);
bool xdev_ext_mech_instance_current(const struct xdev_ext_mech_instance *);
const void *xdev_ext_mech_instance_ops(const struct xdev_ext_mech_instance *);
void xdev_ext_mech_instance_put(struct xdev_ext_mech_instance *);
void xdev_ext_mech_instance_gone(struct xdev_ext_mech_instance *);
void xdev_ext_mech_generation_gone(u32,const void *);
/* ACTUAL_GLOBAL_REGISTRY_STRUCT */
static const void *default_slots[XDEV_EXT_MECH_CLASS_MAX];
static struct xdev_ext_ops_registry xdev_ext_mech_registry={.lock=PTHREAD_MUTEX_INITIALIZER,.slots=default_slots,.nr_slots=XDEV_EXT_MECH_CLASS_MAX};
static DEFINE_MUTEX(xdev_ext_mech_class_lock);
static const struct xdev_ext_mech_c_ops *xdev_ext_mech_c_table[XDEV_EXT_MECH_CLASS_MAX];
static struct module *xdev_ext_mech_c_owner[XDEV_EXT_MECH_CLASS_MAX];
struct static_key_false {int unused;};
static void static_branch_enable(struct static_key_false *k){(void)k;}
static void static_branch_disable(struct static_key_false *k){(void)k;}
static bool xdev_ext_mech_ops_current(u32,const void *,bool);
bool xdev_ext_mech_session_admits(const struct xdev_ext_mech_session *);
static int xdev_ext_mech_stop_reason(struct xdev_ext_mech_session *);
static LIST_HEAD(xdev_ext_mech_all);
