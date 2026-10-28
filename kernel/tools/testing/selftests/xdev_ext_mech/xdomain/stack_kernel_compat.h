/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_STACK_COMPAT_H
#define XDEV_EXT_STACK_COMPAT_H
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <asm-generic/errno.h>
#include <linux/if_xdp.h>
#include <sys/types.h>
#include <linux/types.h>
/* Declaration-only interface frozen by independent §8.2 test author.
 * Copy into stack_kernel_compat.h. These are host recorder contracts, not UAPI. */
#include <stdint.h>
#include <stddef.h>
#define STACK_MAX_FRAMES 64
#define STACK_CTL_BYTES 256
#define STACK_SESSION_GENERATIONS 3
struct stack_world;
struct stack_span { uint64_t allocation_off, data_off, len; };
struct stack_config {
 uint64_t mapping_base[2], local_inc[2], generation[2], first_seq;
 uint32_t depth, nr_frames, frame_size, native_elems, channels;
 struct stack_span span[STACK_MAX_FRAMES];
 /* Explicit host adapter stress options, not production XDOMAIN settings. */
 bool nhi_poll, nhi_batch;
 uint32_t nhi_ring_size; /* 0 preserves production geometry; data rings only */
};
struct stack_session_config {
 uint32_t direction, stage_index, groups;
 uint64_t token; /* 0 asks actual just-probed endpoint token */
 uint64_t allocation_bias, generation;
};
enum stack_event_kind {
 STACK_EV_PROBE=1, STACK_EV_LOGIN, STACK_EV_PATH_ENABLE,
 STACK_EV_HOP_ALLOC, STACK_EV_HOP_FREE, STACK_EV_RING_ALLOC,
 STACK_EV_RING_FREE, STACK_EV_RING_START, STACK_EV_RING_STOP,
 STACK_EV_CONTROL_TX, STACK_EV_CONTROL_RX, STACK_EV_DISPATCH,
 STACK_EV_DATA_POST, STACK_EV_DATA_CALLBACK, STACK_EV_LEASE_ACQUIRE,
 STACK_EV_LEASE_RELEASE, STACK_EV_BUILD, STACK_EV_PUBLISH,
 STACK_EV_BATCH_RELEASE, STACK_EV_PROTOCOL, STACK_EV_FAILURE,
 STACK_EV_RETAIN, STACK_EV_REJECT, STACK_EV_LOCK_VIOLATION,
 STACK_EV_FORBIDDEN, STACK_EV_UNHANDLED, STACK_EV_QUIESCED,
 STACK_EV_START_RESULT, STACK_EV_STOP_RESULT, STACK_EV_HANDLER,
 STACK_EV_DEVICE_PUT, STACK_EV_CONTROL_DONE = 32, STACK_EV_SCHED_STEP = 33,
 STACK_EV_NHI_POST, STACK_EV_NHI_COMPLETE, STACK_EV_NHI_CALLBACK,
 STACK_EV_NHI_DOORBELL, STACK_EV_NHI_RETIRE,
 STACK_EV_NHI_IRQ_ALLOC, STACK_EV_NHI_IRQ_FREE
};
/* event.id strictly increases; owner identifies the accepted ring_frame;
 * seq/group are actual native/batch identities, not test-case counters.
 * status is the actual operation result, flags the actual callback flags.
 * control_type=actual wire type, raw/raw_len=actual control buffer bytes;
 * all copies of data payload are forbidden, not represented here. */
struct stack_event {
 uint64_t id, now_ns, address, seq, generation, owner, group, token;
 uint64_t local_inc, remote_inc;
 uint32_t kind, endpoint, direction, control, channel, stage_index;
 uint32_t length, pdf, flags, control_type, raw_len;
 int32_t status;
 uint8_t raw[STACK_CTL_BYTES];
 uint64_t bytes; /* actual X5 fill CQE bytes only */
 uint32_t elems_done; /* actual X5 fill CQE elems_done only */
 uint64_t session_id; /* actual owning session, never inferred from current endpoint */
};
/* Observation-only: copied raw from actual session, ns slot and X5 reply.
 * session_id=0 selects current; nonzero selects retained generation exactly.
 * No BPF phase calculation or mutating xd_snapshot call is allowed. */
struct stack_stage_facts {
 uint64_t session_id, generation, stage_owner, slot_owner, slot_group, slot_ticket;
 uint32_t native_controls, inflight, sequestered, pending, uncertain, stage_dead;
 uint32_t slot_state, slot_remote, slot_busy, slot_nr;
 uint32_t slot_local_known, slot_local_quiesced, slot_withdrawn, slot_sequestered;
 uint32_t fact_reserved, fact_accepted, fact_cts_received;
 uint32_t reply_used, reply_admission, reply_chain_done, reply_closed;
 uint32_t reply_native_posted, reply_cts, reply_final;
 uint32_t reply_admissions, rts_admissions;
};
enum stack_scheduler_step { STACK_STEP_WORK=1, STACK_STEP_PROGRESS,
 STACK_STEP_FINALIZE, STACK_STEP_NATIVE, STACK_STEP_NHI_NOTIFY,
 STACK_STEP_NHI_POLL };
/* SCHED_STEP: seq=actual pump invocation serial, bytes=step ordinal1..N,
 * length=passed budget, flags=the actual step kind. Emitted only for execution;
 * exhausted budgets do not execute or emit a step. */
int stack_stage_facts(struct stack_world *, unsigned endpoint, uint64_t session_id,
                      unsigned slot_index, struct stack_stage_facts *);
enum stack_fault_kind {
 STACK_FAULT_HOLD_CALLBACK=1, STACK_FAULT_DROP_CALLBACK,
 STACK_FAULT_DUP_CALLBACK, STACK_FAULT_REPLAY_CALLBACK,
 STACK_FAULT_HOLD_CONTROL, STACK_FAULT_DROP_CONTROL,
 STACK_FAULT_DUP_CONTROL, STACK_FAULT_CORRUPT_CONTROL,
 STACK_FAULT_RING_REFUSE, STACK_FAULT_CONTROL_REFUSE,
 STACK_FAULT_RX_FLAGS, STACK_FAULT_RX_LENGTH,
 STACK_FAULT_GOING_AWAY, STACK_FAULT_STOP_RESULT,
 STACK_FAULT_RELEASE_CALLBACKS, STACK_FAULT_RELEASE_CONTROLS,
 STACK_FAULT_REPLAY_CONTROL, STACK_FAULT_REPLAY_HANDLER,
 STACK_FAULT_BPF_INTENT, STACK_FAULT_SHIFT_OFFSET
};
/* ordinal=0 next matching boundary; otherwise actual event.id from log.
 * arg0/arg1 are raw fault arguments: no synthetic control/CQE injection.
 * BPF_INTENT arg0: 1 malicious action,2 duplicate,3 stale,4 no-verdict,
 * 5 unsafe release,6 wrong event,7 compatible WAIT once then real resume. */
struct stack_fault { uint32_t kind,endpoint,control_type; uint64_t ordinal,arg0,arg1; };
int stack_new(const struct stack_config *, struct stack_world **);
int stack_probe(struct stack_world *, unsigned endpoint);
int stack_pump(struct stack_world *, unsigned event_budget, uint64_t advance_ns);
int stack_session(struct stack_world *, unsigned endpoint, const struct stack_session_config *);
int stack_next_session(struct stack_world *, unsigned endpoint, const struct stack_session_config *);
int stack_start(struct stack_world *, unsigned endpoint, uint64_t group, unsigned stage_index);
int stack_stop(struct stack_world *, unsigned endpoint);
int stack_release(struct stack_world *, unsigned endpoint, uint64_t group);
int stack_fault(struct stack_world *, const struct stack_fault *);
int stack_remove(struct stack_world *, unsigned endpoint);
int stack_suspend(struct stack_world *, unsigned endpoint);
int stack_resume(struct stack_world *, unsigned endpoint);
size_t stack_log_count(const struct stack_world *);
int stack_log_get(const struct stack_world *, size_t index, struct stack_event *);
void stack_destroy(struct stack_world *);

#ifdef STACK_INTERNAL
/* Environmental kernel facade; all project declarations and algorithms below
 * are included from their complete production headers. */
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef __u64 u64;
typedef int32_t s32; typedef int64_t s64; typedef uintptr_t dma_addr_t;
#define __KERNEL__ 1
#define CONFIG_XDEV_EXT_MECH 1
#define __user
#define __ksym
#define __init
#define __exit
#define GFP_KERNEL 0
#define THIS_MODULE NULL
#define EXPORT_SYMBOL_GPL(x)
#define MODULE_LICENSE(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_PARM_DESC(...)
#define MODULE_DEVICE_TABLE(...)
#define module_init(x)
#define module_exit(x)
#define module_param_named(...)
#define SEC(x)
#define BPF_PROG(name,...) name(void *ctx __attribute__((unused)), __VA_ARGS__)
#define BIT(n) (1UL<<(n))
#define BIT_ULL(n) (1ULL<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BITS_TO_LONGS(n) (((n)+8*sizeof(long)-1)/(8*sizeof(long)))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define static_assert _Static_assert
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define U64_MAX UINT64_MAX
#define U32_MAX UINT32_MAX
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL<<PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))
#define NSEC_PER_MSEC 1000000ULL
#define NSEC_PER_SEC 1000000000ULL
#define upper_32_bits(x) ((u32)((u64)(x)>>32))
#define lower_32_bits(x) ((u32)(x))
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
#define min_t(t,a,b) min((t)(a),(t)(b))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define check_add_overflow(a,b,p) __builtin_add_overflow(a,b,p)
#define try_cmpxchg(p,o,n) __atomic_compare_exchange_n(p,o,n,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define WARN_ON_ONCE(x) ({bool bad=!!(x); assert(!bad); bad;})
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD_INIT(n) {&(n),&(n)}
#define LIST_HEAD(n) struct list_head n=LIST_HEAD_INIT(n)
static inline void INIT_LIST_HEAD(struct list_head *h){h->next=h->prev=h;}
static inline bool list_empty(const struct list_head *h){return h->next==h;}
static inline void list_add_tail(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
static inline void list_del(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;}
static inline void list_del_init(struct list_head *n){list_del(n);INIT_LIST_HEAD(n);}
#define list_first_entry(h,t,m) container_of((h)->next,t,m)
#define list_for_each_entry(p,h,m) for(p=list_first_entry(h,typeof(*p),m);&(p)->m!=(h);p=list_first_entry(&(p)->m,typeof(*p),m))
struct mutex {unsigned held;};
typedef struct {unsigned held;} spinlock_t;
extern unsigned stack_spins,stack_mutexes;
void stack_lock_error(void);
static inline void mutex_init(struct mutex *m){m->held=0;}
static inline void mutex_lock(struct mutex *m){if(m->held)stack_lock_error();assert(!m->held);m->held=1;stack_mutexes++;}
static inline void mutex_unlock(struct mutex *m){assert(m->held&&stack_mutexes);m->held=0;stack_mutexes--;}
static inline void spin_lock_init(spinlock_t *s){s->held=0;}
static inline void spin_lock_irq(spinlock_t *s){if(s->held)stack_lock_error();assert(!s->held);s->held=1;stack_spins++;}
static inline void spin_unlock_irq(spinlock_t *s){assert(s->held&&stack_spins);s->held=0;stack_spins--;}
#define spin_lock spin_lock_irq
#define spin_unlock spin_unlock_irq
#define spin_lock_irqsave(s,f) do{(f)=0;spin_lock_irq(s);}while(0)
#define spin_unlock_irqrestore(s,f) do{(void)(f);spin_unlock_irq(s);}while(0)
#define lockdep_assert_held(s) assert((s)->held)
#define DEFINE_MUTEX(n) struct mutex n={0}
#define DEFINE_SPINLOCK(n) spinlock_t n={0}
struct kref {unsigned n;};
static inline void kref_init(struct kref *r){r->n=1;}
static inline void kref_get(struct kref *r){assert(r->n);r->n++;}
static inline void kref_put(struct kref *r,void(*f)(struct kref*)){assert(r->n);if(!--r->n)f(r);}
typedef struct{int n;} atomic_t;
typedef struct{long long n;} atomic64_t;
#define ATOMIC64_INIT(v) {.n=(v)}
static inline int atomic_read(const atomic_t *a){return a->n;}
static inline int atomic_read_acquire(const atomic_t *a){return a->n;}
static inline void atomic_set_release(atomic_t *a,int n){a->n=n;}
static inline int atomic_cmpxchg(atomic_t*a,int o,int n){int old=a->n;if(old==o)a->n=n;return old;}
static inline int atomic_dec_return(atomic_t*a){return --a->n;}
static inline int atomic_inc_return(atomic_t*a){return ++a->n;}
static inline long long atomic64_inc_return(atomic64_t*a){return ++a->n;}
static inline void __set_bit(unsigned n,unsigned long*p){p[n/(8*sizeof(long))]|=BIT(n%(8*sizeof(long)));}
static inline void __clear_bit(unsigned n,unsigned long*p){p[n/(8*sizeof(long))]&=~BIT(n%(8*sizeof(long)));}
static inline bool test_bit(unsigned n,const unsigned long*p){return !!(p[n/(8*sizeof(long))]&BIT(n%(8*sizeof(long))));}
static inline unsigned find_first_bit(const unsigned long*p,unsigned n){unsigned i;for(i=0;i<n;i++)if(test_bit(i,p))break;return i;}
static inline void bitmap_zero(unsigned long*p,unsigned n){memset(p,0,BITS_TO_LONGS(n)*sizeof(long));}
static inline void bitmap_fill(unsigned long*p,unsigned n){bitmap_zero(p,n);for(unsigned i=0;i<n;i++)__set_bit(i,p);}
static inline bool bitmap_empty(const unsigned long*p,unsigned n){return find_first_bit(p,n)==n;}
#define DECLARE_BITMAP(n,b) unsigned long n[BITS_TO_LONGS(b)]
struct work_struct{void(*fn)(struct work_struct*);bool pending;u64 due;};
struct delayed_work{struct work_struct work;};
#define INIT_WORK(w,f) do{*(w)=(struct work_struct){.fn=(f)};}while(0)
#define INIT_DELAYED_WORK(w,f) INIT_WORK(&(w)->work,f)
#define to_delayed_work(w) container_of(w,struct delayed_work,work)
#define system_long_wq NULL
bool queue_work(void*,struct work_struct*);
bool queue_delayed_work(void*,struct delayed_work*,unsigned long);
bool mod_delayed_work(void*,struct delayed_work*,unsigned long);
bool cancel_work_sync(struct work_struct*);
bool cancel_delayed_work_sync(struct delayed_work*);
static inline unsigned long msecs_to_jiffies(unsigned long n){return n;}
static inline unsigned long nsecs_to_jiffies(u64 n){return (n+NSEC_PER_MSEC-1)/NSEC_PER_MSEC;}
u64 ktime_get_boottime_ns(void);
typedef struct{u8 b[16];} uuid_t;
#define UUID_INIT(a,b,c,d,e,f,g,h,i,j,k) {{(a)>>24,((a)>>16)&255,((a)>>8)&255,(a)&255,(b)>>8,(b)&255,(c)>>8,(c)&255,d,e,f,g,h,i,j,k}}
static inline bool uuid_equal(const uuid_t*a,const uuid_t*b){return !memcmp(a,b,16);}
static inline void uuid_copy(uuid_t*a,const uuid_t*b){memcpy(a,b,16);}
struct device{void *owner;const char *name;unsigned endpoint;};
struct pci_dev{struct device dev;unsigned refs;bool msix_enabled;};
#ifdef STACK_REAL_NHI
#include "stack_nhi_compat.h"
#else
struct tb_nhi{struct pci_dev *pdev;bool going_away;};
#endif
struct tb{struct tb_nhi*nhi;};
struct tb_xdomain{u64 route;const uuid_t*local_uuid,*remote_uuid;struct tb*tb;struct device dev;};
struct tb_service{struct device dev;void*drvdata;struct tb_xdomain*parent;u32 prtcstns;};
struct tb_service_id{const char*key;u32 id;};
#define TB_SERVICE(k,i) .key=(k),.id=(i)
struct tb_property_dir{int unused;};
struct attribute{const char*name;unsigned mode;};
struct device_attribute{struct attribute attr;ssize_t(*show)(struct device*,struct device_attribute*,char*);};
struct attribute_group{struct attribute**attrs;};
#define DEVICE_ATTR_RO(n) struct device_attribute dev_attr_##n={.attr={#n,0444},.show=n##_show}
#define ATTRIBUTE_GROUPS(n) static const struct attribute_group n##_group={n##_attrs};static const struct attribute_group *n##_groups[]={&n##_group,NULL}
#define DEFINE_SIMPLE_DEV_PM_OPS(n,s,r) int n
#define pm_sleep_ptr(p) (p)
struct tb_service_driver{struct{void*owner;const char*name;const struct attribute_group**dev_groups;void*pm;}driver;int(*probe)(struct tb_service*,const struct tb_service_id*);void(*remove)(struct tb_service*);const struct tb_service_id*id_table;};
struct tb_protocol_handler{const uuid_t*uuid;int(*callback)(const void*,size_t,void*);void*data;struct list_head list;};
#define TB_CFG_PKG_XDOMAIN_RESP 1
#ifndef STACK_REAL_NHI
struct tb_ring;struct ring_frame;
typedef void(*ring_cb)(struct tb_ring*,struct ring_frame*,bool);
struct ring_frame{dma_addr_t buffer_phy;ring_cb callback;struct list_head list;u32 size:12,flags:12,eof:4,sof:4;};
struct tb_ring{struct tb_nhi*nhi;int size,hop;bool is_tx,running;unsigned flags,endpoint,control,channel;bool freed,unknown;};
#define RING_FLAG_FRAME BIT(1)
#define RING_FLAG_E2E BIT(2)
#define RING_DESC_CRC_ERROR 1U
#define RING_DESC_BUFFER_OVERRUN 4U
struct tb_ring *tb_ring_alloc_tx(struct tb_nhi*,int,int,unsigned);
struct tb_ring *tb_ring_alloc_rx(struct tb_nhi*,int,int,unsigned,int,u16,u16,void(*)(void*),void*);
void tb_ring_start(struct tb_ring*);void tb_ring_stop(struct tb_ring*);void tb_ring_free(struct tb_ring*);void tb_ring_free_quarantined(struct tb_ring*);
int tb_ring_tx(struct tb_ring*,struct ring_frame*);int tb_ring_rx(struct tb_ring*,struct ring_frame*);
struct device*tb_ring_dma_device(struct tb_ring*);
#endif
int tb_xdomain_alloc_in_hopid(struct tb_xdomain*,int);int tb_xdomain_alloc_out_hopid(struct tb_xdomain*,int);
void tb_xdomain_release_in_hopid(struct tb_xdomain*,int);void tb_xdomain_release_out_hopid(struct tb_xdomain*,int);
int tb_xdomain_enable_paths(struct tb_xdomain*,int,int,int,int);int tb_xdomain_disable_paths(struct tb_xdomain*,int,int,int,int);
int tb_xdomain_request(struct tb_xdomain*,const void*,size_t,int,void*,size_t,int,unsigned);
int tb_xdomain_response(struct tb_xdomain*,const void*,size_t,int);
struct pci_dev*pci_dev_get(struct pci_dev*);void pci_dev_put(struct pci_dev*);
u64 get_random_u64(void);
static inline struct tb_service*tb_to_service(struct device*d){return d->owner;}
static inline void*tb_service_get_drvdata(struct tb_service*s){return s->drvdata;}
static inline void tb_service_set_drvdata(struct tb_service*s,void*p){s->drvdata=p;}
static inline struct tb_xdomain*tb_service_parent(struct tb_service*s){return s->parent;}
static inline const char*dev_name(const struct device*d){return d->name;}
static inline const char*pci_name(const struct pci_dev*p){return p->dev.name;}
static inline int sysfs_emit(char*b,const char*f,...){va_list a;va_start(a,f);int n=vsprintf(b,f,a);va_end(a);return n;}
void dev_info(const struct device*,const char*,...);void dev_dbg(const struct device*,const char*,...);
struct tb_property_dir*tb_property_create_dir(const uuid_t*);int tb_property_add_immediate(struct tb_property_dir*,const char*,u32);void tb_property_free_dir(struct tb_property_dir*);
int tb_register_protocol_handler(struct tb_protocol_handler*);void tb_unregister_protocol_handler(struct tb_protocol_handler*);
int tb_register_property_dir(const char*,struct tb_property_dir*);void tb_unregister_property_dir(const char*,struct tb_property_dir*);
int tb_register_service_driver(struct tb_service_driver*);void tb_unregister_service_driver(struct tb_service_driver*);
void*kzalloc(size_t,int);void*kcalloc(size_t,size_t,int);void*kvcalloc(size_t,size_t,int);void kfree(void*);void kvfree(void*);
void*dma_alloc_coherent(struct device*,size_t,dma_addr_t*,int);void dma_free_coherent(struct device*,size_t,void*,dma_addr_t);
u32 crc32c(u32,const void*,size_t);
enum dma_data_direction{DMA_BIDIRECTIONAL,DMA_TO_DEVICE,DMA_FROM_DEVICE};
#include "../../../../../include/linux/xdev_ext_mech.h"
#include "../../../../../include/linux/xdev_ext_netfam.h"
#include "../../../../../io_uring/xdev_ext_mech_core.h"
#include "../../../../../io_uring/xdomain/xdev_ext_xdomain.h"
/* Mechanism adapter objects. The complete batch engine is a separate guest
 * gate; this boundary owns only invocation storage and lifecycle records. */
struct file{unsigned endpoint;struct xdev_ext_mech_session *session;};
struct xdev_ext_mech_session{spinlock_t lock;struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout l;struct xdev_ext_mech_sess ss;struct xdev_ext_mech_stage st;u64 id,generation,stop_started_ns;u32 depth,native_controls;bool kicked;struct file authority;};
struct xdev_ext_mech_batch{struct xdev_ext_mech_session*s;struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES];void*priv,*cookie;u64 ticket,key,group;u32 nr,claims,publishes;bool cqe_filled,released,sequester;int status;};
int stack_x3_init(void);void stack_x3_exit(void);int stack_x3_probe(struct tb_service*);void stack_x3_remove(struct tb_service*);int stack_x3_suspend(struct tb_service*);int stack_x3_resume(struct tb_service*);
void stack_x3_pci_put(struct pci_dev*);void stack_x4_quarantine_records(void);
void stack_x4_control_pressure(struct xdev_ext_xd_link*,bool);
const struct xdev_ext_mech_class_ops*stack_x5_ops(void);
int stack_x5_stage_facts(struct xdev_ext_mech_stage *,unsigned,struct stack_stage_facts *);
int stack_x6_call(struct xdev_ext_mech_stage*,const struct xdev_ext_mech_call_args*,s32*);
void stack_record_dispatch(struct xdev_ext_mech_stage*,const struct xdev_ext_xd_msg*);
void stack_record(struct stack_event);
int stack_endpoint_stage(const struct xdev_ext_mech_stage*);
int stack_policy_fault(unsigned,u32);
#endif
#endif
