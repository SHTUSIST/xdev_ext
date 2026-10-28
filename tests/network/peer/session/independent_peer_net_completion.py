#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual peer TX wait/finish/work code under deterministic CQE interleavings.

Host reference-ownership proof only; this test never exercises physical DMA.
"""
# P4: this checks the one-at-a-time synchronous NET path, kept under XDEV_EXT_PEER_NET_SYNC_ONE.
from pathlib import Path
import subprocess
import tempfile

KERNEL = Path(__file__).resolve().parents[4]
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
#define GFP_KERNEL 0
#define DMA_TO_DEVICE 1
#define HZ 100
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define min(a,b) ((a)<(b)?(a):(b))
#define xchg(p,v) __atomic_exchange_n((p),(v),__ATOMIC_SEQ_CST)
struct pci_dev { int unused; };struct file { int unused; };
/* Real field names: acquire refuses a handle whose file or mapping is set. */
struct xdev_ext_peer_lease {void *mapping;void *next;u64 ticket;u64 dma_address;u32 len;};
struct xdev_ext_peer_fd_lease {struct xdev_ext_peer_lease lease;struct file *file;};
struct xdev_ext_peer_tx {u64 dma_address;u32 len;u16 header_len;const u8 *header;void(*complete)(struct xdev_ext_peer_tx*,int,bool);};
/* Counting, like kernel/sched/completion.c: a successful wait consumes done. */
struct completion {unsigned int done;};
struct work_struct {void(*fn)(struct work_struct*);};
typedef struct {int value;} refcount_t;typedef struct {int value;} atomic_t;
static void refcount_set(refcount_t *r,int n){r->value=n;}
static void refcount_inc(refcount_t *r){assert(r->value>0);r->value++;}
static bool refcount_dec_and_test(refcount_t *r){assert(r->value>0);return --r->value==0;}
static bool refcount_dec_not_one(refcount_t *r){assert(r->value>0);if(r->value==1)return false;r->value--;return true;}
static void atomic_set(atomic_t *a,int n){a->value=n;}
static int atomic_cmpxchg(atomic_t *a,int old,int n){int prev=a->value;if(prev==old)a->value=n;return prev;}
static void init_completion(struct completion *c){c->done=0;}
static void complete(struct completion *c){assert(!c->done);c->done++;}
#define INIT_WORK(w,f) ((w)->fn=(f))
static int system_unbound_wq;
static struct work_struct *pending_work;
static void queue_work(int q,struct work_struct *w){(void)q;assert(!pending_work);pending_work=w;}
static void flush_work(void){struct work_struct *w=pending_work;if(w){pending_work=NULL;w->fn(w);}}
static int scenario,freed,released,submitted,acquired,acquire_error,rtnl_depth;
/* Native XDP ring pointers are RCU-managed, including the legacy send path. */
static int rcu_depth;
static __attribute__((unused)) void rcu_read_lock(void){rcu_depth++;}
static __attribute__((unused)) void rcu_read_unlock(void){assert(rcu_depth);rcu_depth--;}
static bool released_quiesced,device_running=true,device_present=true;
static void *live_context;
static struct xdev_ext_peer_tx *native_tx;
__attribute__((unused)) static void *kzalloc(size_t n,int flags){(void)flags;assert(!live_context);live_context=calloc(1,n);return live_context;}
/* No init_on_alloc: kmalloc memory holds stale bytes. */
__attribute__((unused)) static void *kmalloc(size_t n,int flags){(void)flags;assert(!live_context);live_context=malloc(n);assert(live_context);memset(live_context,0xa5,n);return live_context;}
static void kfree(void *p){if(!p)return;assert(p==live_context && !freed);freed++;}
struct net_device;
struct net_device_ops {int(*ndo_xdev_ext_peer_tx)(struct net_device*,u32,struct xdev_ext_peer_tx*);};
struct net_device {const struct net_device_ops *netdev_ops;};
static bool netif_running(struct net_device *d){assert(d);return device_running;}
static bool netif_device_present(struct net_device *d){assert(d);return device_present;}
static int xdev_ext_peer_file_acquire(struct file *f,struct pci_dev *p,u64 gen,u64 off,u32 len,int dir,struct xdev_ext_peer_fd_lease *h)
{
 assert(f && p && gen==5 && off==4096 && len==512 && dir==DMA_TO_DEVICE);acquired++;
 if(h->file || h->lease.mapping)return -EINVAL;
 if(acquire_error)return acquire_error;
 h->file=f;h->lease=(struct xdev_ext_peer_lease){.mapping=p,.ticket=1,.dma_address=0x700000,.len=len};return 0;
}
static void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *h,bool q)
{assert(h->file && h->lease.mapping && !released);h->lease.mapping=NULL;h->lease.dma_address=0;h->file=NULL;released++;released_quiesced=q;}
static int driver_tx(struct net_device *dev,u32 q,struct xdev_ext_peer_tx *tx)
{
 assert(rcu_depth == 1);
 assert(dev && q==2 && !rtnl_depth && tx->dma_address==0x700000 && tx->len==512 && tx->header_len==42 && tx->header[0]==0xAB);
 submitted++;native_tx=tx;
 if(scenario==1)return -EAGAIN;
 if(scenario==2){tx->complete(tx,0,true);flush_work();}
 if(scenario==3)tx->complete(tx,0,true);
 if(scenario==6)tx->complete(tx,-EIO,false);
 return 0;
}
static unsigned long wait_for_completion_timeout(struct completion *c,unsigned long ticks)
{
 assert(!rtnl_depth && ticks==30*HZ);
 if(scenario==4){native_tx->complete(native_tx,0,true);flush_work();}
 if(scenario==3 || scenario==6)flush_work();
 if(!c->done)return 0;
 c->done--;return 1;
}
static void wait_for_completion(struct completion *c)
{assert(!rtnl_depth);flush_work();if(!c->done){fprintf(stderr,"Assertion: wait_for_completion with done==0 sleeps uninterruptibly forever\n");exit(3);}c->done--;}
'''
# Compile the real policy getter alongside the extracted native wait path.
import re as _policy_re
_policy_source = (KERNEL / 'io_uring/xdev_ext_policy.c').read_text()
_policy_getter = _policy_re.search(r'^unsigned long xdev_ext_policy_peer_net_timeout\(void\)\n\{.*?^\}', _policy_source, _policy_re.M | _policy_re.S)[0]
SHIM += ('\n#include "' + str(KERNEL / 'io_uring/xdev_ext_policy.h') + '"\n'
         '#define msecs_to_jiffies(n) (((unsigned long)(n)*HZ+999)/1000)\n' + _policy_getter + '\n')

MAIN = r'''
static struct xdev_ext_peer_tx_wait *spare;
static int one(struct net_device *dev,struct pci_dev *peer,struct file *f,const struct xdev_ext_peer_net_desc *d)
{int ret=xdev_ext_peer_net_one(dev,peer,f,5,2,d,NULL,&spare,NULL,NULL);kfree(xchg(&spare,NULL));return ret;}
static void reset(int mode)
{free(live_context);live_context=NULL;scenario=mode;freed=released=submitted=acquired=acquire_error=0;device_running=device_present=true;released_quiesced=false;native_tx=NULL;assert(!pending_work && !rtnl_depth);}
int main(void)
{
 const struct net_device_ops ops={driver_tx};struct net_device dev={&ops};struct file f={};struct pci_dev peer={};
 struct xdev_ext_peer_net_desc d={.offset=4096,.bytes=512,.header_len=42,.header={0xAB}};
 reset(1);assert(one(&dev,&peer,&f,&d)==-EAGAIN && submitted==1 && released==1 && released_quiesced && freed==1);
 reset(0);device_running=false;assert(one(&dev,&peer,&f,&d)==-ENETDOWN && !submitted && released==1 && released_quiesced && freed==1);
 puts("ok 1 - actual net control: preaccept refusal/down releases exactly once after all native ownership is excluded");
 for(int mode=2;mode<=4;mode++){reset(mode);assert(one(&dev,&peer,&f,&d)==0 && submitted==1 && released==1 && released_quiesced && freed==1);}
 puts("ok 2 - actual net control: synchronous CQE/work, synchronous CQE/deferred work, and asynchronous CQE all free once");
 reset(0);assert(one(&dev,&peer,&f,&d)==-ETIMEDOUT && submitted==1 && released==1 && !released_quiesced && !freed);
 assert(((struct xdev_ext_peer_tx_wait*)live_context)->refs.value==1);
 native_tx->complete(native_tx,0,true);
 assert(freed==1 && released==1 && !pending_work && !released_quiesced);
 puts("ok 3 - actual net control: timeout claims unknown, quarantines lease once, late success only releases remaining native context");
 reset(6);assert(one(&dev,&peer,&f,&d)==-EIO && released==1 && !released_quiesced && freed==1);
 reset(0);acquire_error=-ESTALE;assert(one(&dev,&peer,&f,&d)==-ESTALE && !submitted && !released && freed==1);
 puts("ok 4 - actual net control: error CQE retains DMA resources and stale allocation never reaches the native driver");
 reset(0);assert(one(&dev,&peer,&f,&d)==-ETIMEDOUT && !freed);
 native_tx->complete(native_tx,-ECANCELED,false);assert(freed==1 && released==1 && !pending_work);
 puts("ok 5 - actual net control: timeout followed by native teardown cannot double release or turn quarantine into success");
 free(live_context);return 0;
}
'''


def execute(code, directory, name):
    source = directory / (name + ".c")
    source.write_text('#include "' + str(KERNEL / "include/uapi/linux/xdev_ext_peer.h") + '"\n' + SHIM + code + MAIN)
    binary = directory / name
    compiled = subprocess.run(["cc", "-std=gnu11", "-DXDEV_EXT_PEER_NET_SYNC_ONE", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return subprocess.run([str(binary)], capture_output=True, text=True)


def main():
    source = (KERNEL / "io_uring/xdev_ext_peer_net.c").read_text()
    code = source[source.index("struct xdev_ext_peer_tx_wait {"):source.index("/* A configured native endpoint")]
    mutations = [
        ("timeout falsely quiesced", code.replace("stopping ? -ECANCELED : -ETIMEDOUT, false)", "stopping ? -ECANCELED : -ETIMEDOUT, true)")),
        ("native context dropped on timeout", code.replace("   refcount_inc(&p->refs);\n", "   if (0) refcount_inc(&p->refs);\n")),
        ("late CQE can claim completed result twice", code.replace("if (atomic_cmpxchg(&p->claimed, 0, 1)) return false;", "if (atomic_cmpxchg(&p->claimed, 0, 1) && false) return false;")),
        ("fresh wait context not zeroed", code.replace("  p = kzalloc(sizeof(*p), GFP_KERNEL);", "  p = kmalloc(sizeof(*p), GFP_KERNEL);")),
        ("completion consumed twice after a successful timed wait", code.replace(" if (!completed) wait_for_completion(&p->done);", " (void)completed; wait_for_completion(&p->done);")),
        ("preaccept error leaks caller context", code.replace("xdev_ext_peer_tx_finish(p, ret, true); /* refused: no native owner */", "xdev_ext_peer_tx_finish(p, ret, true); refcount_inc(&p->refs); /* faulty extra owner */")),
    ]
    with tempfile.TemporaryDirectory(prefix="independent-peer-net-") as tmp:
        directory = Path(tmp)
        result = execute(code, directory, "actual")
        print(result.stdout, end="")
        assert result.returncode == 0, result.stderr
        for i, (name, changed) in enumerate(mutations):
            assert changed != code, name
            result = execute(changed, directory, "mutation" + str(i))
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by behavior assertions")


if __name__ == "__main__":
    main()
