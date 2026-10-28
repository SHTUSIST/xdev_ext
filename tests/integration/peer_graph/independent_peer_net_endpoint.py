#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the actual native NET endpoint: per-descriptor cost, STOP-bounded
waits and netdev unregistration.

Compiles the real wait/finish/work, endpoint bind/unbind/send and netdevice
notifier code of io_uring/xdev_ext_peer_net.c against deterministic OS
adapters with a virtual clock. The native driver adapter only completes or
withholds callbacks; no device, provider, DMA or wire is involved.
"""
# P4: this checks the one-at-a-time synchronous NET path, kept under XDEV_EXT_PEER_NET_SYNC_ONE.
from pathlib import Path
import subprocess
import sys
import tempfile

KERNEL = Path(__file__).resolve().parents[5]
SHIM = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <linux/types.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
#define U64_MAX UINT64_MAX
#define UNUSED __attribute__((unused))
#define GFP_KERNEL 0
#define GFP_ATOMIC 1
#define DMA_TO_DEVICE 1
#define HZ 1000
#define CAP_SYS_RAWIO 17
#define CAP_NET_RAW 13
#define EXPORT_SYMBOL_GPL(x)
#define __init
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((intptr_t)(p))
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define min(a,b) ((a)<(b)?(a):(b))
#define xchg(p,v) __atomic_exchange_n((p),(v),__ATOMIC_SEQ_CST)
#define device_initcall(fn) int test_initcall(void){return fn();}
#define late_initcall(fn) device_initcall(fn)
#define subsys_initcall(fn) device_initcall(fn)
struct pci_dev {int refs;};struct file {int unused;};
/* Field names of the real leases: acquire refuses a non-empty handle and a
 * refused release keeps the file and mapping, like xdev_ext_peer_fd.c. */
struct xdev_ext_peer_lease {void *mapping;void *next;u64 ticket;u64 dma_address;u32 len;};
struct xdev_ext_peer_fd_lease {struct xdev_ext_peer_lease lease;struct file *file;};
struct xdev_ext_peer_tx {u64 dma_address;u32 len;u16 header_len;const u8 *header;void(*complete)(struct xdev_ext_peer_tx*,int,bool);struct xdev_ext_peer_tx *next;};
/* RX owner-token API adapter; existing TX/refcount assertions unchanged. */
struct xdev_ext_peer_rx {struct xdev_ext_peer_rx *next;u64 dma_address;u32 len;u16 header_room;u8 *header;void(*complete)(struct xdev_ext_peer_rx*,int,u32,u32,bool);};
struct xdev_ext_peer_net_endpoint;
int xdev_ext_peer_net_rx_flush(struct xdev_ext_peer_net_endpoint *);
#define rcu_read_lock() do {} while(0)
#define rcu_read_unlock() do {} while(0)
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD(n) struct list_head n={&(n),&(n)}
static UNUSED void INIT_LIST_HEAD(struct list_head *l){l->next=l->prev=l;}
static UNUSED void list_add(struct list_head *n,struct list_head *h){n->next=h->next;n->prev=h;h->next->prev=n;h->next=n;}
static UNUSED void list_add_tail(struct list_head *n,struct list_head *h){list_add(n,h->prev);}
static UNUSED void list_del(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;n->next=n->prev=NULL;}
#define list_entry(p,t,m) container_of(p,t,m)
#define list_for_each_entry(pos,head,m) for(pos=list_entry((head)->next,__typeof__(*pos),m);&pos->m!=(head);pos=list_entry(pos->m.next,__typeof__(*pos),m))
struct mutex {int held;};
#define DEFINE_MUTEX(n) struct mutex n={0}
static int mutex_depth;
static UNUSED void mutex_lock(struct mutex *m){assert(!m->held);m->held=1;mutex_depth++;}
static UNUSED void mutex_unlock(struct mutex *m){assert(m->held);m->held=0;mutex_depth--;}
typedef struct {int held;} spinlock_t;
static UNUSED void spin_lock_init(spinlock_t *l){l->held=0;}
static UNUSED void spin_lock(spinlock_t *l){assert(!l->held);l->held=1;}
static UNUSED void spin_unlock(spinlock_t *l){assert(l->held);l->held=0;}
/* Counting, like kernel/sched/completion.c: a successful wait consumes done. */
struct completion {unsigned int done;};
struct work_struct {void(*fn)(struct work_struct*);};
typedef struct {int value;} refcount_t;typedef struct {int value;} atomic_t;
static void refcount_set(refcount_t *r,int n){r->value=n;}
static UNUSED void refcount_inc(refcount_t *r){assert(r->value>0);r->value++;}
static bool refcount_dec_and_test(refcount_t *r){assert(r->value>0);return --r->value==0;}
static UNUSED bool refcount_dec_not_one(refcount_t *r){assert(r->value>0);if(r->value==1)return false;r->value--;return true;}
static void atomic_set(atomic_t *a,int n){a->value=n;}
static int atomic_cmpxchg(atomic_t *a,int old,int n){int prev=a->value;if(prev==old)a->value=n;return prev;}
static void init_completion(struct completion *c){c->done=0;}
static UNUSED void reinit_completion(struct completion *c){c->done=0;}
static void complete(struct completion *c){assert(!c->done);c->done++;}
#define INIT_WORK(w,f) ((w)->fn=(f))
static int system_unbound_wq;
static struct work_struct *pending_work;
static void queue_work(int q,struct work_struct *w){(void)q;assert(!pending_work);pending_work=w;}
static void run_work(void){struct work_struct *w=pending_work;if(w){pending_work=NULL;w->fn(w);}}
/* Virtual time, one native command and its completion deadline. */
static unsigned long now,native_due,stop_at=~0UL;static bool native_pending,native_quiesced=true;static int native_status;
static struct xdev_ext_peer_tx *native_tx;
static void native_fire(void){if(!native_pending)return;native_pending=false;native_tx->complete(native_tx,native_status,native_quiesced);run_work();}
static unsigned long wait_for_completion_timeout(struct completion *c,unsigned long ticks)
{
 assert(!mutex_depth);run_work();
 if(!c->done&&native_pending&&native_due<=now+ticks){unsigned long used=native_due-now;now=native_due;native_fire();if(!c->done)return 0;c->done--;return ticks-used?ticks-used:1;}
 if(c->done){c->done--;return ticks?ticks:1;}
 now+=ticks;return 0;
}
static void wait_for_completion(struct completion *c)
{run_work();if(!c->done){fprintf(stderr,"wait_for_completion with done==0 sleeps uninterruptibly forever\n");exit(3);}c->done--;}
static int allocs,frees,wait_allocs,rtnl_depth,rtnl_calls,ndo_calls,ndo_under_rtnl,acquired,released,released_quiesced,dead_calls,release_stale,stale_releases;
static size_t wait_size;static void *live[64];static int nlive;
static void *track(void *p,size_t n){assert(p&&nlive<64);live[nlive++]=p;allocs++;if(wait_size&&n==wait_size)wait_allocs++;return p;}
static UNUSED void *kzalloc(size_t n,int flags){(void)flags;return track(calloc(1,n),n);}
/* No init_on_alloc: kmalloc memory holds stale bytes. */
static UNUSED void *kmalloc(size_t n,int flags){void *p=malloc(n);(void)flags;assert(p);memset(p,0xa5,n);return track(p,n);}
static void kfree(const void *p){if(!p)return;for(int i=0;i<nlive;i++)if(live[i]==p){live[i]=live[--nlive];frees++;free((void*)p);return;}assert(!"kfree of untracked pointer");}
static UNUSED void rtnl_lock(void){assert(!rtnl_depth);rtnl_depth++;rtnl_calls++;}
static UNUSED void rtnl_unlock(void){assert(rtnl_depth==1);rtnl_depth--;}
static UNUSED bool capable(int c){(void)c;return true;}
struct net {int unused;};struct nsproxy {struct net *net_ns;};struct task {struct nsproxy *nsproxy;};
static struct net test_net;static struct nsproxy test_ns={&test_net};static struct task test_task={&test_ns};
#define current (&test_task)
#define NETREG_REGISTERED 1
#define NETREG_UNREGISTERING 2
typedef struct {int unused;} netdevice_tracker;
struct net_device;
struct net_device_ops {struct pci_dev *(*ndo_xdev_ext_peer_device)(struct net_device*);int(*ndo_xdev_ext_peer_tx)(struct net_device*,u32,struct xdev_ext_peer_tx*);int(*ndo_xdev_ext_peer_rx)(struct net_device*,u32,u64,struct xdev_ext_peer_rx*);int(*ndo_xdev_ext_peer_rx_flush)(struct net_device*,u32,u64);int(*ndo_xdev_ext_peer_rx_open)(struct net_device*,u32,u64);};
struct net_device {const struct net_device_ops *netdev_ops;int refs,ifindex,reg_state;u32 mtu,real_num_tx_queues,real_num_rx_queues;bool running,present;};
static struct net_device devices[2];
static UNUSED struct net_device *dev_get_by_index(struct net *n,int ifindex){assert(n==&test_net);for(int i=0;i<2;i++)if(devices[i].ifindex==ifindex){devices[i].refs++;return &devices[i];}return NULL;}
static UNUSED struct net_device *netdev_get_by_index(struct net *n,int ifindex,netdevice_tracker *t,int gfp){(void)t;(void)gfp;return dev_get_by_index(n,ifindex);}
static UNUSED void dev_put(struct net_device *d){if(d){assert(d->refs>0);d->refs--;}}
static UNUSED void dev_hold(struct net_device *d){if(d)d->refs++;}
static UNUSED void netdev_hold(struct net_device *d,netdevice_tracker *t,int gfp){(void)t;(void)gfp;dev_hold(d);}
static UNUSED void netdev_put(struct net_device *d,netdevice_tracker *t){(void)t;dev_put(d);}
static bool netif_running(struct net_device *d){return d->running;}
static bool netif_device_present(struct net_device *d){return d->present;}
static UNUSED void pci_dev_get(struct pci_dev *p){p->refs++;}
static UNUSED void pci_dev_put(struct pci_dev *p){if(p){assert(p->refs>0);p->refs--;}}
struct notifier_block {int(*notifier_call)(struct notifier_block*,unsigned long,void*);};
#define NOTIFY_DONE 0
#define NETDEV_UNREGISTER 6
#define NETDEV_DOWN 2
static struct notifier_block *notifier;
static UNUSED int register_netdevice_notifier(struct notifier_block *nb){assert(!notifier);notifier=nb;return 0;}
static UNUSED struct net_device *netdev_notifier_info_to_dev(void *p){return p;}
static void notify(unsigned long event,struct net_device *d){assert(notifier);rtnl_lock();notifier->notifier_call(notifier,event,d);rtnl_unlock();}
static int xdev_ext_peer_file_acquire(struct file *f,struct pci_dev *p,u64 gen,u64 off,u32 len,int dir,struct xdev_ext_peer_fd_lease *h)
{
 assert(f&&p&&gen==5&&len==512&&dir==DMA_TO_DEVICE&&off>=4096);
 if(h->file||h->lease.mapping){fprintf(stderr,"acquire on a non-empty handle returns -EINVAL\n");return -EINVAL;}
 acquired++;h->file=f;h->lease=(struct xdev_ext_peer_lease){.mapping=p,.ticket=(u64)acquired,.dma_address=0x700000+off,.len=len};return 0;
}
/* A refused (stale) release returns early and keeps file and mapping. */
static void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *h,bool q)
{
 if(!h->file)return;
 assert(h->lease.mapping);
 if(release_stale){stale_releases++;return;}
 h->lease.mapping=NULL;h->lease.dma_address=0;h->lease.len=0;h->file=NULL;released++;released_quiesced+=q;
}
/* 0 completes inside the ndo, 1 completes after native_delay, 2 never. */
static int native_mode;static unsigned long native_delay;static struct pci_dev peer_pci;
static struct pci_dev *driver_device(struct net_device *d){assert(rtnl_depth==1&&d);return &peer_pci;}
static int driver_tx(struct net_device *dev,u32 q,struct xdev_ext_peer_tx *tx)
{
 assert(dev==&devices[0]&&q==2&&tx->len==512&&tx->header_len==42&&tx->header[0]==0xAB&&!native_pending);
 ndo_calls++;ndo_under_rtnl+=rtnl_depth;native_tx=tx;
 if(native_mode==0){tx->complete(tx,0,true);return 0;}
 native_pending=true;native_status=0;native_quiesced=true;native_due=native_mode==1?now+native_delay:~0UL/2;return 0;
}
static const struct net_device_ops ops={.ndo_xdev_ext_peer_device=driver_device,.ndo_xdev_ext_peer_tx=driver_tx};
static bool stop_flag(void *arg){assert(arg==&stop_at);return now>=stop_at;}
static void endpoint_dead(void *arg){assert(arg==&dead_calls&&rtnl_depth==1);dead_calls++;}
int test_initcall(void) __attribute__((weak));
struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind_stage(u32,u32,void(*)(void*),void*) __attribute__((weak));
int xdev_ext_peer_net_send_stoppable(struct xdev_ext_peer_net_endpoint*,struct file*,u64,const struct xdev_ext_peer_net_desc*,bool*,bool(*)(void*),void*) __attribute__((weak));
'''
# Compile the real policy getter alongside the extracted native wait path.
import re as _policy_re
_policy_source = (KERNEL / 'io_uring/xdev_ext_policy.c').read_text()
_policy_getter = _policy_re.search(r'^unsigned long xdev_ext_policy_peer_net_timeout\(void\)\n\{.*?^\}', _policy_source, _policy_re.M | _policy_re.S)[0]
SHIM += ('\n#include "' + str(KERNEL / 'io_uring/xdev_ext_policy.h') + '"\n'
         '#define msecs_to_jiffies(n) (((unsigned long)(n)*HZ+999)/1000)\n' + _policy_getter + '\n')

MAIN = r'''
static struct file allocation;
static struct xdev_ext_peer_net_desc desc(u32 i){return (struct xdev_ext_peer_net_desc){.offset=4096+512*(u64)i,.bytes=512,.header_len=42,.header={0xAB}};}
static void reset(void)
{
 memset(devices,0,sizeof(devices));
 devices[0]=(struct net_device){&ops,0,4,NETREG_REGISTERED,1500,4,4,true,true};
 devices[1]=(struct net_device){&ops,0,5,NETREG_REGISTERED,1500,4,4,true,true};
 peer_pci.refs=0;now=0;stop_at=~0UL;native_pending=false;native_mode=0;native_delay=0;native_tx=NULL;
 allocs=frees=wait_allocs=rtnl_calls=ndo_calls=ndo_under_rtnl=acquired=released=released_quiesced=dead_calls=release_stale=stale_releases=0;
 wait_size=sizeof(struct xdev_ext_peer_tx_wait);assert(!pending_work&&!rtnl_depth&&!nlive);
}
static int init_once(void){static int done;if(!test_initcall)return -1;if(!done){assert(!test_initcall());done=1;}return 0;}
static int case_cost(void)
{
 struct xdev_ext_peer_net_endpoint *e;bool accepted;
 reset();if(init_once()){}
 e=xdev_ext_peer_net_bind(4,2);assert(!IS_ERR(e)&&devices[0].refs==1&&peer_pci.refs==1);
 int rtnl_before=rtnl_calls,allocs_before=wait_allocs;
 for(u32 i=0;i<8;i++){struct xdev_ext_peer_net_desc d=desc(i);accepted=false;assert(!xdev_ext_peer_net_send(e,&allocation,5,&d,&accepted)&&accepted);}
 assert(ndo_calls==8&&acquired==8&&released==8&&released_quiesced==8);
 if(rtnl_calls-rtnl_before||ndo_under_rtnl||wait_allocs-allocs_before>1){fprintf(stderr,"RED 8 descriptors took RTNL %d times (%d native submissions under RTNL) and allocated %d native wait contexts\n",rtnl_calls-rtnl_before,ndo_under_rtnl,wait_allocs-allocs_before);return 1;}
 xdev_ext_peer_net_unbind(e);assert(!devices[0].refs&&!peer_pci.refs&&allocs==frees&&!nlive);
 puts("ok 1 - actual endpoint sends 8 descriptors with no RTNL and at most one wait context, and unbind frees it");
 return 0;
}
static int case_stop(void)
{
 struct xdev_ext_peer_net_endpoint *e;bool accepted=false;struct xdev_ext_peer_net_desc d=desc(0);int ret;
 if(!xdev_ext_peer_net_send_stoppable){fprintf(stderr,"RED no STOP-aware send: a native wait holds the session worker for up to 30 s, beyond the 5 s drain timeout\n");return 1;}
 reset();init_once();e=xdev_ext_peer_net_bind(4,2);assert(!IS_ERR(e));
 /* STOP at 200 ms while the CQE is 10 s away: the wait ends below 5 s. */
 native_mode=1;native_delay=10*HZ;stop_at=HZ/5;
 ret=xdev_ext_peer_net_send_stoppable(e,&allocation,5,&d,&accepted,stop_flag,&stop_at);
 assert(accepted&&ret==-ECANCELED&&now>=stop_at&&now<5*HZ&&native_pending);
 assert(released==1&&!released_quiesced);
 int live_before=nlive;
 native_fire();assert(released==1&&nlive==live_before-1);
 /* STOP at 200 ms and the CQE at 300 ms: normal success, lease reusable. */
 now=0;native_delay=3*HZ/10;accepted=false;
 assert(!xdev_ext_peer_net_send_stoppable(e,&allocation,5,&d,&accepted,stop_flag,&stop_at)&&accepted&&released==2&&released_quiesced==1);
 /* Without STOP a 6 s CQE is still a success within the 30 s budget. */
 now=0;stop_at=~0UL;native_delay=6*HZ;
 assert(!xdev_ext_peer_net_send_stoppable(e,&allocation,5,&d,&accepted,stop_flag,&stop_at)&&released==3&&released_quiesced==2&&now==6*HZ);
 /* No CQE at all and no STOP: unknown ownership only after 30 s. */
 now=0;native_mode=2;
 assert(xdev_ext_peer_net_send(e,&allocation,5,&d,&accepted)==-ETIMEDOUT&&now==30*HZ&&released==4&&released_quiesced==2);
 native_fire();
 xdev_ext_peer_net_unbind(e);assert(allocs==frees&&!nlive&&!devices[0].refs);
 puts("ok 2 - actual native wait ends within a bounded grace after STOP, keeps the 30 s budget otherwise, and frees late contexts once");
 return 0;
}
static int case_unregister(void)
{
 struct xdev_ext_peer_net_endpoint *e;bool accepted=false;struct xdev_ext_peer_net_desc d=desc(0);
 reset();
 if(init_once()||!notifier){fprintf(stderr,"RED no netdevice notifier is registered: unregistering the bound netdev waits for user space to close the session\n");return 1;}
 if(!xdev_ext_peer_net_bind_stage){fprintf(stderr,"RED endpoint cannot report device removal to its stage\n");return 1;}
 e=xdev_ext_peer_net_bind_stage(4,2,endpoint_dead,&dead_calls);assert(!IS_ERR(e)&&devices[0].refs==1);
 notify(NETDEV_DOWN,&devices[0]);notify(NETDEV_UNREGISTER,&devices[1]);assert(devices[0].refs==1&&!dead_calls);
 notify(NETDEV_UNREGISTER,&devices[0]);
 assert(!devices[0].refs&&dead_calls==1);
 assert(!xdev_ext_peer_net_mtu(e));
 assert(xdev_ext_peer_net_send(e,&allocation,5,&d,&accepted)==-ENODEV&&!accepted&&!ndo_calls&&!acquired);
 notify(NETDEV_UNREGISTER,&devices[0]);assert(!devices[0].refs&&dead_calls==1);
 xdev_ext_peer_net_unbind(e);assert(!devices[0].refs&&!peer_pci.refs&&allocs==frees);
 /* A device already unregistering cannot be bound and keeps no reference. */
 devices[0].reg_state=NETREG_UNREGISTERING;
 assert(IS_ERR(xdev_ext_peer_net_bind_stage(4,2,endpoint_dead,&dead_calls))&&!devices[0].refs&&!peer_pci.refs&&allocs==frees);
 /* Unbinding a live endpoint takes it off the notifier list. */
 devices[0].reg_state=NETREG_REGISTERED;e=xdev_ext_peer_net_bind_stage(4,2,endpoint_dead,&dead_calls);assert(!IS_ERR(e));
 xdev_ext_peer_net_unbind(e);notify(NETDEV_UNREGISTER,&devices[0]);assert(dead_calls==1&&!devices[0].refs&&allocs==frees);
 puts("ok 3 - actual NETDEV_UNREGISTER drops the endpoint's device reference once, reports the stage dead and refuses later sends");
 return 0;
}
static int case_stale(void)
{
 struct xdev_ext_peer_net_endpoint *e;bool accepted=false;struct xdev_ext_peer_net_desc d=desc(0);
 reset();init_once();e=xdev_ext_peer_net_bind(4,2);assert(!IS_ERR(e));
 /* The lease release of descriptor 0 is refused: its handle stays set. */
 release_stale=1;assert(!xdev_ext_peer_net_send(e,&allocation,5,&d,&accepted)&&accepted&&stale_releases==1);
 release_stale=0;d=desc(1);accepted=false;
 if(xdev_ext_peer_net_send(e,&allocation,5,&d,&accepted)||!accepted){fprintf(stderr,"RED a context whose lease release was refused is reused; the next descriptor fails\n");return 1;}
 assert(acquired==2&&released==1&&wait_allocs==2);
 xdev_ext_peer_net_unbind(e);assert(allocs==frees&&!nlive);
 puts("ok 4 - actual endpoint never reuses a wait context whose lease release was refused");
 return 0;
}
int main(int argc,char **argv)
{
 assert(argc==2);
 if(!strcmp(argv[1],"stale"))return case_stale();
 if(!strcmp(argv[1],"cost"))return case_cost();
 if(!strcmp(argv[1],"stop"))return case_stop();
 if(!strcmp(argv[1],"unregister"))return case_unregister();
 return 2;
}
'''
CASES = ("cost", "stop", "unregister", "stale")


def build(code, directory, name):
    source = directory / (name + ".c")
    binary = directory / name
    source.write_text('#include "' + str(KERNEL / "include/uapi/linux/xdev_ext_peer.h") + '"\n'
                      '#include "' + str(KERNEL / "io_uring/xdev_ext_peer_net_core.h") + '"\n' + SHIM + code + MAIN)
    compiled = subprocess.run(["cc", "-std=gnu11", "-DXDEV_EXT_PEER_NET_SYNC_ONE", "-Wall", "-Wextra", "-Werror", "-Wno-address", "-Wno-missing-field-initializers", "-fsanitize=undefined", str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return binary


def run(binary, case):
    return subprocess.run([str(binary), case], capture_output=True, text=True, timeout=15)


def main():
    source = (KERNEL / "io_uring/xdev_ext_peer_net.c").read_text()
    code = source[source.index("struct xdev_ext_peer_tx_wait {"):source.index("long xdev_ext_peer_net_ioctl(")]
    mutations = [
        ("RTNL around every native submission", "cost", code.replace(" ret = dev->netdev_ops->ndo_xdev_ext_peer_tx(dev, queue, &p->tx);", " { rtnl_lock(); ret = dev->netdev_ops->ndo_xdev_ext_peer_tx(dev, queue, &p->tx); rtnl_unlock(); }")),
        ("wait context never reused", "cost", code.replace(" else xdev_ext_peer_tx_keep(spare, p);\n return ret;", " else kfree(p);\n return ret;")),
        ("fresh wait context not zeroed", "cost", code.replace("  p = kzalloc(sizeof(*p), GFP_KERNEL);", "  p = kmalloc(sizeof(*p), GFP_KERNEL);")),
        ("completion consumed twice after a successful timed wait", "cost", code.replace(" if (!completed) wait_for_completion(&p->done);", " (void)completed; wait_for_completion(&p->done);")),
        ("context reused after a refused lease release", "stale", code.replace(" if (p->handle.file || p->handle.lease.mapping) kfree(p);\n else xdev_ext_peer_tx_keep(spare, p);", " xdev_ext_peer_tx_keep(spare, p);")),
        ("STOP ignored while waiting", "stop", code.replace("if (stopped && !stopping && stopped(arg)) {", "if (stopped && !stopping && stopped(arg) && false) {")),
        ("late context reused while native still owns it", "stop", code.replace(" if (refcount_dec_not_one(&p->refs)) return ret;", " refcount_dec_not_one(&p->refs);")),
        ("unregister keeps the device reference", "unregister", code.replace("  netdev_put(dev, &endpoint->tracker);\n  if (endpoint->dead)", "  if (endpoint->dead)")),
        ("bind races device unregistration", "unregister", code.replace("else if (dev->reg_state != NETREG_REGISTERED) ret = -ENODEV;", "")),
    ]
    failed = []
    with tempfile.TemporaryDirectory(prefix="independent-peer-net-endpoint-") as tmp:
        directory = Path(tmp)
        actual = build(code, directory, "actual")
        for case in CASES:
            result = run(actual, case)
            print(result.stdout, end="")
            if result.returncode:
                failed.append(case)
                print(result.stderr, end="", file=sys.stderr)
        if failed:
            raise SystemExit("not ok - actual endpoint failed: " + ", ".join(failed))
        for i, (name, case, changed) in enumerate(mutations):
            assert changed != code, name
            result = run(build(changed, directory, "mutation" + str(i)), case)
            assert result.returncode != 0, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by behavior assertions")


if __name__ == "__main__":
    main()
