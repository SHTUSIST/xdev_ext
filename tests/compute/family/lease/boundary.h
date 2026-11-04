#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <linux/types.h>
#define __KERNEL__ 1
#define CONFIG_XDEV_EXT_MECH 1
#define IS_ENABLED(x) 1
#define __user
#define __rcu
#define __init
#undef __always_inline
#define __always_inline inline
#define EXPORT_SYMBOL_GPL(x)
#define late_initcall_sync(x)
#define pr_err(...) ((void)0)
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096
#define PAGE_MASK (~4095UL)
#define U64_MAX UINT64_MAX
#define GFP_KERNEL 0
#define THIS_MODULE NULL
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p,v) (*(p)=(v))
#define cmpxchg(p,o,n) __sync_val_compare_and_swap(p,o,n)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define min(a,b) ((a)<(b)?(a):(b))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define max(a,b) ((a)>(b)?(a):(b))
#define struct_size(p,m,n) (sizeof(*(p))+sizeof((p)->m[0])*(n))
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef __u64 u64; typedef int32_t s32; typedef int64_t s64;
static unsigned checks,allocs,frees,held,fail_alloc,warnings; static const char *test_name;
#define EQ(a,b) do { long long av=(long long)(a),bv=(long long)(b); checks++; if(av!=bv){fprintf(stderr,"ASSERT %s:%d %s got=%lld want=%lld\n",test_name,__LINE__,#a,av,bv);exit(70);} }while(0)
#define OK(a) EQ(!!(a),1)
#define WARN_ON_ONCE(x) ({static bool warned;bool w=!!(x);if(w&&!warned){warned=true;warnings++;}w;})
#define WARN_ONCE(x,...) WARN_ON_ONCE(x)
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD_INIT(n) {&(n),&(n)}
#define LIST_HEAD(n) struct list_head n=LIST_HEAD_INIT(n)
static void INIT_LIST_HEAD(struct list_head *h){h->next=h->prev=h;}
static void list_add_tail(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
static void list_del(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;n->next=n->prev=NULL;}
static bool list_empty(const struct list_head *h){return h->next==h;}
#define list_for_each_entry(p,h,m) for(p=container_of((h)->next,typeof(*p),m); &(p)->m!=(h); p=container_of((p)->m.next,typeof(*p),m))
struct mutex{unsigned held;};
#define __MUTEX_INITIALIZER(n) {0}
#define DEFINE_MUTEX(n) struct mutex n={0}
static void (*lock_observer)(struct mutex*);
static void mutex_lock(struct mutex *m){if(lock_observer)lock_observer(m);EQ(m->held,0);m->held=1;held++;}
static void (*unlock_observer)(void);
static void (*free_observer)(void*);
static void mutex_unlock(struct mutex *m){EQ(m->held,1);m->held=0;held--;if(unlock_observer)unlock_observer();}
struct module{int refs;}; struct file_operations{int id;};struct file{const struct file_operations *f_op;}; struct page{char data[4096];};
static bool try_module_get(struct module*m){if(m)m->refs++;return true;}
static void module_put(struct module*m){EQ(held,0);if(m){OK(m->refs>0);m->refs--;}}
typedef struct {int counter;} atomic_t;
static int atomic_read(const atomic_t*a){return a->counter;}
static void atomic_inc(atomic_t*a){a->counter++;}
typedef struct{int refs;}refcount_t;
static void refcount_set(refcount_t*r,int n){r->refs=n;}
static bool refcount_dec_and_test(refcount_t*r){return --r->refs==0;}
static bool refcount_inc_not_zero(refcount_t*r){if(!r->refs)return false;r->refs++;return true;}
static void *kalloc(size_t n){allocs++;if(fail_alloc && allocs==fail_alloc)return NULL;return calloc(1,n);}
#define kzalloc(n,f) kalloc(n)
#define kvzalloc(n,f) group_alloc(n)
#define kmalloc(n,f) kalloc(n)
static void *allocated_groups[256];static unsigned allocated_group_count;
static void *group_alloc(size_t n){void*p=kalloc(n);if(p){OK(allocated_group_count<ARRAY_SIZE(allocated_groups));allocated_groups[allocated_group_count++]=p;}return p;}
static void kfree(void*p){if(p){EQ(held,0);for(unsigned i=0;i<allocated_group_count;i++)if(allocated_groups[i]==p){struct list_head*n=p,*regions=n+1;OK(n->next==NULL||n->next==n);OK(n->prev==NULL||n->prev==n);OK(list_empty(regions));allocated_groups[i]=NULL;}if(free_observer)free_observer(p);frees++;free(p);}}
#define kvfree(p) kfree(p)
#define ERR_PTR(n) ((void *)(intptr_t)(n))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)

#define U32_MAX UINT32_MAX
#define check_add_overflow(a,b,p) __builtin_add_overflow(a,b,p)
#define try_cmpxchg(p,o,n) __atomic_compare_exchange_n(p,o,n,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST)
