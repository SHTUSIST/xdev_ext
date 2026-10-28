/* SPDX-License-Identifier: GPL-2.0 */
/* Host OS/BPF-reference primitives. Actual instance lookup, liveness and puts
 * come from programs/instances.c; actual bind/call/invoke are compiled too.
 * These single-threaded primitives do not certify kernel synchronization. */
typedef uint8_t u8;typedef int64_t s64;
#define __bpf_kfunc
#define likely(x) (x)
#define unlikely(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define EXPORT_SYMBOL_GPL(x)
struct hlist_node{struct hlist_node *next,**pprev;};
struct hlist_head{struct hlist_node *first;};
#define DEFINE_HASHTABLE(n,b) struct hlist_head n[1]
static void host_hash_add(struct hlist_node *n,struct hlist_head *h)
{n->next=h->first;if(n->next)n->next->pprev=&n->next;h->first=n;n->pprev=&h->first;}
static void host_hash_del(struct hlist_node *n)
{assert(n->pprev);*n->pprev=n->next;if(n->next)n->next->pprev=n->pprev;n->pprev=NULL;n->next=NULL;}
#define hash_add(t,n,k) ((void)(k),host_hash_add(n,&(t)[0]))
#define hash_del(n) host_hash_del(n)
#define hash_for_each_possible(t,o,m,k) for(struct hlist_node *hn=((void)(k),(t)[0].first);hn&&((o)=container_of(hn,__typeof__(*(o)),m),true);hn=hn->next)
struct host_mutex{unsigned held;};
#define DEFINE_MUTEX(n) struct host_mutex n={0}
#undef mutex_lock
#undef mutex_unlock
static unsigned mutexes;
static void mutex_lock(struct host_mutex *m){assert(!m->held);m->held=1;mutexes++;}
static void mutex_unlock(struct host_mutex *m){assert(m->held&&mutexes);m->held=0;mutexes--;}
typedef struct{unsigned refs;} refcount_t;
static void refcount_set(refcount_t *r,unsigned n){r->refs=n;}
static void refcount_inc(refcount_t *r){assert(r->refs);r->refs++;}
static bool refcount_dec_and_test(refcount_t *r){assert(r->refs);return !--r->refs;}
#define DEFINE_PER_CPU(t,n) t n
#define this_cpu_read(n) (n)
#define this_cpu_write(n,v) ((n)=(v))
#define DEFINE_RAW_SPINLOCK(n) int n
#define raw_spin_lock_irqsave spin_lock_irqsave
#define raw_spin_unlock_irqrestore spin_unlock_irqrestore
#define task_struct task
static unsigned preempt_depth;
static void preempt_disable(void){preempt_depth++;}
static void preempt_enable(void){assert(preempt_depth);preempt_depth--;}
static bool in_task(void){return true;}
static u32 crc32c(u32 seed,const void *p,size_t n){(void)seed;(void)p;(void)n;abort();}
/* Actual declarations are inserted by the runner. */
/* SELECTION_DECLARATIONS */
struct host_program{struct xdev_ext_nvme_mech_ops ops;unsigned pins;};
struct bpf_link{unsigned type,refs;u32 class_id;const void *ops;bool detached;};
#define BPF_LINK_TYPE_STRUCT_OPS 91 /* host type tag only, no kernel ABI claim */
static struct bpf_link *host_fds[128];
static struct bpf_link *retire_on_copyout;
static void host_copyout_hook(void);
static struct host_program programs[4];
static const void *host_default;
static unsigned pin_gets,pin_puts,temp_gets,temp_puts,default_gets;
static bool bpf_struct_ops_get(const void *p)
{struct host_program *h=container_of(p,struct host_program,ops);h->pins++;pin_gets++;return true;}
static void bpf_struct_ops_put(const void *p)
{struct host_program *h=container_of(p,struct host_program,ops);assert(!mutexes&&h->pins);h->pins--;pin_puts++;}
static struct bpf_link *bpf_link_get_from_fd(u32 fd)
{if(fd>=128||!host_fds[fd])return ERR_PTR(-EBADF);struct bpf_link *l=host_fds[fd];l->refs++;temp_gets++;return l;}
static void bpf_link_put(struct bpf_link *l)
{assert(!mutexes&&l->refs>1);l->refs--;temp_puts++;}
struct xdev_ext_mech_instance;
int xdev_ext_mech_instance_get_from_fd(u32,int,struct xdev_ext_mech_instance **);
bool xdev_ext_mech_instance_current(const struct xdev_ext_mech_instance *);
const void *xdev_ext_mech_instance_ops(const struct xdev_ext_mech_instance *);
void xdev_ext_mech_instance_put(struct xdev_ext_mech_instance *);
void xdev_ext_mech_instance_gone(struct xdev_ext_mech_instance *);
static u64 xdev_ext_mech_session_id(const struct xdev_ext_mech_session *s){return s->id;}
#define list_for_each_entry(p,h,m) for(struct list_head *ln=(h)->next;ln!=(h)&&((p)=container_of(ln,__typeof__(*(p)),m),true);ln=ln->next)
