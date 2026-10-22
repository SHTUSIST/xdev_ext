#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual peer TX wait/finish/work code under deterministic CQE interleavings.

Host reference-ownership proof only; this test never exercises physical DMA.
"""
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
struct pci_dev { int unused; };struct file { int unused; };
struct xdev_ext_peer_lease {u64 dma_address;};
struct xdev_ext_peer_fd_lease {struct xdev_ext_peer_lease lease;bool held;};
struct xdev_ext_peer_tx {u64 dma_address;u32 len;u16 header_len;const u8 *header;void(*complete)(struct xdev_ext_peer_tx*,int,bool);};
struct completion {bool done;};
struct work_struct {void(*fn)(struct work_struct*);};
typedef struct {int value;} refcount_t;typedef struct {int value;} atomic_t;
static void refcount_set(refcount_t *r,int n){r->value=n;}
static void refcount_inc(refcount_t *r){assert(r->value>0);r->value++;}
static bool refcount_dec_and_test(refcount_t *r){assert(r->value>0);return --r->value==0;}
static void atomic_set(atomic_t *a,int n){a->value=n;}
static int atomic_cmpxchg(atomic_t *a,int old,int n){int prev=a->value;if(prev==old)a->value=n;return prev;}
static void init_completion(struct completion *c){c->done=false;}
static void complete(struct completion *c){assert(!c->done);c->done=true;}
#define INIT_WORK(w,f) ((w)->fn=(f))
static int system_unbound_wq;
static struct work_struct *pending_work;
static void queue_work(int q,struct work_struct *w){(void)q;assert(!pending_work);pending_work=w;}
static void flush_work(void){struct work_struct *w=pending_work;if(w){pending_work=NULL;w->fn(w);}}
static int scenario,freed,released,submitted,acquired,acquire_error,rtnl_depth;
static bool released_quiesced,device_running=true,device_present=true;
static void *live_context;
static struct xdev_ext_peer_tx *native_tx;
static void *kzalloc(size_t n,int flags){(void)flags;assert(!live_context);live_context=calloc(1,n);return live_context;}
static void kfree(void *p){assert(p==live_context && !freed);freed++;}
static void rtnl_lock(void){assert(!rtnl_depth);rtnl_depth++;}
static void rtnl_unlock(void){assert(rtnl_depth==1);rtnl_depth--;}
struct net_device;
struct net_device_ops {int(*ndo_xdev_ext_peer_tx)(struct net_device*,u32,struct xdev_ext_peer_tx*);};
struct net_device {const struct net_device_ops *netdev_ops;};
static bool netif_running(struct net_device *d){assert(d);return device_running;}
static bool netif_device_present(struct net_device *d){assert(d);return device_present;}
static int xdev_ext_peer_file_acquire(struct file *f,struct pci_dev *p,u64 gen,u64 off,u32 len,int dir,struct xdev_ext_peer_fd_lease *h)
{assert(f && p && gen==5 && off==4096 && len==512 && dir==DMA_TO_DEVICE);acquired++;if(acquire_error)return acquire_error;h->held=true;h->lease.dma_address=0x700000;return 0;}
static void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *h,bool q)
{assert(h->held && !released);h->held=false;released++;released_quiesced=q;}
static int driver_tx(struct net_device *dev,u32 q,struct xdev_ext_peer_tx *tx)
{
 assert(dev && q==2 && rtnl_depth==1 && tx->dma_address==0x700000 && tx->len==512 && tx->header_len==42 && tx->header[0]==0xAB);
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
 return c->done?1:0;
}
static void wait_for_completion(struct completion *c){assert(!rtnl_depth);flush_work();assert(c->done);}
'''
MAIN = r'''
static void reset(int mode)
{free(live_context);live_context=NULL;scenario=mode;freed=released=submitted=acquired=acquire_error=0;device_running=device_present=true;released_quiesced=false;native_tx=NULL;assert(!pending_work && !rtnl_depth);}
int main(void)
{
 const struct net_device_ops ops={driver_tx};struct net_device dev={&ops};struct file f={};struct pci_dev peer={};
 struct xdev_ext_peer_net_desc d={.offset=4096,.bytes=512,.header_len=42,.header={0xAB}};
 reset(1);assert(xdev_ext_peer_net_one(&dev,&peer,&f,5,2,&d,NULL)==-EAGAIN && submitted==1 && released==1 && released_quiesced && freed==1);
 reset(0);device_running=false;assert(xdev_ext_peer_net_one(&dev,&peer,&f,5,2,&d,NULL)==-ENETDOWN && !submitted && released==1 && released_quiesced && freed==1);
 puts("ok 1 - actual net control: preaccept refusal/down releases exactly once after all native ownership is excluded");
 for(int mode=2;mode<=4;mode++){reset(mode);assert(xdev_ext_peer_net_one(&dev,&peer,&f,5,2,&d,NULL)==0 && submitted==1 && released==1 && released_quiesced && freed==1);}
 puts("ok 2 - actual net control: synchronous CQE/work, synchronous CQE/deferred work, and asynchronous CQE all free once");
 reset(0);assert(xdev_ext_peer_net_one(&dev,&peer,&f,5,2,&d,NULL)==-ETIMEDOUT && submitted==1 && released==1 && !released_quiesced && !freed);
 assert(((struct xdev_ext_peer_tx_wait*)live_context)->refs.value==1);
 native_tx->complete(native_tx,0,true);
 assert(freed==1 && released==1 && !pending_work && !released_quiesced);
 puts("ok 3 - actual net control: timeout claims unknown, quarantines lease once, late success only releases remaining native context");
 reset(6);assert(xdev_ext_peer_net_one(&dev,&peer,&f,5,2,&d,NULL)==-EIO && released==1 && !released_quiesced && freed==1);
 reset(0);acquire_error=-ESTALE;assert(xdev_ext_peer_net_one(&dev,&peer,&f,5,2,&d,NULL)==-ESTALE && !submitted && !released && freed==1);
 puts("ok 4 - actual net control: error CQE retains DMA resources and stale allocation never reaches the native driver");
 reset(0);assert(xdev_ext_peer_net_one(&dev,&peer,&f,5,2,&d,NULL)==-ETIMEDOUT && !freed);
 native_tx->complete(native_tx,-ECANCELED,false);assert(freed==1 && released==1 && !pending_work);
 puts("ok 5 - actual net control: timeout followed by native teardown cannot double release or turn quarantine into success");
 free(live_context);return 0;
}
'''


def execute(code, directory, name):
    source = directory / (name + ".c")
    source.write_text('#include "' + str(KERNEL / "include/uapi/linux/xdev_ext_peer.h") + '"\n' + SHIM + code + MAIN)
    binary = directory / name
    compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return subprocess.run([str(binary)], capture_output=True, text=True)


def main():
    source = (KERNEL / "io_uring/xdev_ext_peer_net.c").read_text()
    code = source[source.index("struct xdev_ext_peer_tx_wait {"):source.index("/* A configured native endpoint")]
    mutations = [
        ("timeout falsely quiesced", code.replace("xdev_ext_peer_tx_finish(p, -ETIMEDOUT, false);", "xdev_ext_peer_tx_finish(p, -ETIMEDOUT, true);")),
        ("native context dropped on timeout", code.replace("xdev_ext_peer_tx_finish(p, -ETIMEDOUT, false);", "xdev_ext_peer_tx_finish(p, -ETIMEDOUT, false); xdev_ext_peer_tx_put(p);")),
        ("late CQE can claim completed result twice", code.replace("if (atomic_cmpxchg(&p->claimed, 0, 1)) return;", "if (atomic_cmpxchg(&p->claimed, 0, 1) && false) return;")),
        ("preaccept error leaks caller context", code.replace("xdev_ext_peer_tx_put(p); /* refused request: no native owner */", "/* faulty missing native-owner reference release */")),
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
