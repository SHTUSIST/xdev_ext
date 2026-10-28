#!/usr/bin/env python3
"""Execute the fixture's real worker with simulated OS/native completion edges."""
import pathlib, re, subprocess, tempfile, unittest
HERE=pathlib.Path(__file__).resolve().parent
SOURCE=HERE/'xdev_ext_dma_provider_sim.c'
def function(text,name):
    m=re.search(r'^static [^;{}]*\b'+name+r'\([^;{}]*\)\n\{\n.*?^\}',text,re.M|re.S)
    if not m: raise AssertionError('missing fixture worker '+name)
    return m[0]
class Worker(unittest.TestCase):
    def test_actual_worker_faults(self):
        code=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
typedef uint64_t u64; typedef uint32_t u32;
#define XDEV_EXT_MECH_DIR_FROM_DEVICE 1
#define XDEV_EXT_MECH_DIR_TO_DEVICE 2
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define READ_ONCE(x) (x)
#define min(a,b) ((a)<(b)?(a):(b))
#define spin_lock(x) ((void)(x))
#define spin_unlock(x) ((void)(x))
#define kfree(p) free(p)
struct work_struct { int unused; };
struct stats { u64 completed,bytes,from_device,to_device,pending,peak_pending,stale_callbacks,polled_completed; };
struct sim_device { void *window; int lock; struct stats stats; };
struct sim_region { struct sim_device *dev; u64 base; };
struct sim_host { void *addr; u64 bytes; struct sim_device *dev; };
struct xdev_ext_dma_cookie { int unused; };
struct xdev_ext_dma_xfer { u64 host_byte_off,device_off; u32 len,flags; };
struct sim_request { struct work_struct work; struct xdev_ext_dma_cookie *cookie; u64 ticket,old_ticket;
 struct sim_region *region; struct sim_host *host; u32 direction,n; struct xdev_ext_dma_xfer x[]; };
static unsigned fail_mode,delay_us,stale_replays,delayed,calls;
static u64 tickets[8],counts[8]; static int statuses[8];
static void usleep_range(unsigned a,unsigned b) { (void)b; delayed+=a; }
static void xdev_ext_dma_complete(struct xdev_ext_dma_cookie *c,u64 ticket,int status,bool submitted,u64 bytes) {
 (void)c; if(!submitted || calls>=8) abort(); tickets[calls]=ticket; statuses[calls]=status;counts[calls++]=bytes;
}
/* WORKER */
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1; } } while(0)
int main(void) {
 for(unsigned mode=0;mode<4;mode++) for(unsigned replay=0;replay<=2;replay++) {
  unsigned char dev[64],host[64];memset(dev,0xa6,sizeof(dev));memset(host,0x97,sizeof(host));
  for(unsigned i=0;i<16;i++)dev[8+i]=(unsigned char)(i*17+3);
  struct sim_device d={.window=dev,.stats={.pending=1}};
  struct sim_region region={.dev=&d};struct sim_host h={.addr=host};struct xdev_ext_dma_cookie ck={0};
  struct sim_request *r=calloc(1,sizeof(*r)+sizeof(r->x[0]));
  r->cookie=&ck;r->ticket=41;r->old_ticket=40;r->region=&region;r->host=&h;r->n=1;r->direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;
  r->x[0]=(struct xdev_ext_dma_xfer){.device_off=8,.host_byte_off=16,.len=16};
  fail_mode=mode;delay_us=123;stale_replays=replay;delayed=calls=0;
  sim_work(&r->work);
  CHECK(delayed==123);CHECK(calls==replay+1);CHECK(d.stats.pending==0);CHECK(d.stats.completed==1);
  for(unsigned i=0;i<replay;i++){CHECK(tickets[i]==40);CHECK(statuses[i]==-ESTALE);}
  CHECK(tickets[replay]==41);CHECK(statuses[replay]==(mode==3?-EIO:0));
  CHECK(counts[replay]==(mode==2?15:16));CHECK(d.stats.stale_callbacks==replay);
  CHECK(d.stats.polled_completed==0); /* the worker thread is not a poll completion */
  CHECK(!memcmp(host+16,dev+8,16));for(unsigned i=0;i<64;i++)if(i<16||i>=32)CHECK(host[i]==0x97);
 }
 puts("PASS actual simulator worker delay, short, ambiguous, stale/replay-before-final, guards");return 0;
}
'''.replace('/* WORKER */',function(SOURCE.read_text(),'sim_finish')+'\n'+function(SOURCE.read_text(),'sim_work'))
        with tempfile.TemporaryDirectory(prefix='xdev-ext-sim-work-') as d:
            source=pathlib.Path(d)/'test.c';source.write_text(code);exe=pathlib.Path(d)/'test'
            p=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=undefined',str(source),'-o',str(exe)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            p=subprocess.run([str(exe)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stdout+p.stderr)
            print(p.stdout.strip())
if __name__=='__main__':unittest.main(verbosity=2)
