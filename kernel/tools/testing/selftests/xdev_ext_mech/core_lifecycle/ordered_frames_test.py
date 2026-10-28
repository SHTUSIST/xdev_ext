#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Ordered START requirements against unchanged real START/custody functions.

Expectations come from the frozen message contract: selected indices stay HELD,
never visit allocator K_FREE, and failed preparation restores the whole pool.
KERNEL_SRC selects a fixed baseline for RED; no production allocator is replaced.
The existing recycle fixture supplies OS boundaries and the real IOU FIFO only.
"""
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('KERNEL_SRC', HERE.parents[4]))
sys.path.insert(0, str(HERE.parent))
from xdev_ext_mech_recycle_tail_test import function

SCENARIO = r'''
#ifndef XDEV_EXT_MECH_START_F_ORDERED_FRAMES
#define XDEV_EXT_MECH_START_F_ORDERED_FRAMES (1U << 3)
#endif
static int ordered_scenario(const char *mode) {
 struct xdev_ext_mech_session s;
 struct io_xdev_ext_umem_mech m;
 __u8 states[12], before[12];struct xdev_ext_mech_life life_before[12];
 const u32 ordered= XDEV_EXT_MECH_START_F_ORDERED_FRAMES | XDEV_EXT_MECH_START_F_USER_FRAMES;
 u32 indices[4]={7,3,9,1};
 struct io_ring_ctx ctx={0};
 setup_n(&s,&m,states,0,2,12);
 s.pool.kind=XDEV_EXT_MECH_POOL_IOU_UMEM;
 s.frames=2;s.depth=2;s.start_left=0;s.start_recycle=false;s.start_return_pending=false;
 s.layout=(struct xdev_ext_mech_layout){.frame_size=1,.group_bytes=2,.seg_len=1};
 s.plan[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 struct xdev_ext_mech_start req={.session_id=1,.nr_batches=2,.first_seq=101,
  .flags=ordered,.nr_user_frames=4,.user_frames=(uintptr_t)indices};
 int want=0,bad=0;
 if(!strcmp(mode,"peer") || !strcmp(mode,"peer_mixed") || !strncmp(mode,"peer_busy",9)) {
  s.pool.kind=XDEV_EXT_MECH_POOL_PEER;
  memset(states,XDEV_EXT_MECH_F_K_FREE,sizeof(states));
  if(strcmp(mode,"peer")){states[3]=XDEV_EXT_MECH_F_USER;states[1]=XDEV_EXT_MECH_F_USER;}
  if(!strncmp(mode,"peer_busy",9)){unsigned pos=(unsigned)(mode[9]-'0');assert(pos<4);states[indices[pos]]=XDEV_EXT_MECH_F_HELD;want=-EBUSY;}
 } else if(!strcmp(mode,"legacy")) req.flags=XDEV_EXT_MECH_START_F_USER_FRAMES;
 else if(!strcmp(mode,"missing_user")){req.flags=XDEV_EXT_MECH_START_F_ORDERED_FRAMES;want=-EINVAL;}
 else if(!strcmp(mode,"unknown")){req.flags|=1U<<31;want=-EINVAL;}
 else if(!strcmp(mode,"xsk")){s.pool.kind=XDEV_EXT_MECH_POOL_XSK;want=-EOPNOTSUPP;}
 else if(!strcmp(mode,"peer_legacy")){s.pool.kind=XDEV_EXT_MECH_POOL_PEER;req.flags=XDEV_EXT_MECH_START_F_USER_FRAMES;want=-EOPNOTSUPP;}
 else if(!strcmp(mode,"duplicate")){indices[2]=7;want=-EINVAL;}
 else if(!strcmp(mode,"range")){indices[3]=12;want=-EINVAL;}
 else if(!strncmp(mode,"busy",4)) {
  unsigned pos=(unsigned)(mode[4]-'0');assert(pos<4);
  states[indices[pos]]=XDEV_EXT_MECH_F_INFLIGHT;want=-EBUSY;
 } else if(!strcmp(mode,"iou_free")){states[9]=XDEV_EXT_MECH_F_K_FREE;want=-EBUSY;}
 else if(!strncmp(mode,"blocked_",8)) {
  unsigned pool,pos,phase;assert(sscanf(mode,"blocked_%u_%u_%u",&pool,&phase,&pos)==3&&pos<4&&phase<4);
  const u32 blocked[]={XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_INFLIGHT,XDEV_EXT_MECH_F_SEQUESTERED,XDEV_EXT_MECH_F_NIC_RX};
  if(pool){s.pool.kind=XDEV_EXT_MECH_POOL_PEER;states[7]=XDEV_EXT_MECH_F_K_FREE;states[9]=XDEV_EXT_MECH_F_K_FREE;}
  states[indices[pos]]=blocked[phase];s.life[indices[pos]].ctrl=19ULL<<XDEV_EXT_MECH_L_GEN_SHIFT;
  s.life[indices[pos]].valid_len=73;want=-EBUSY;
 }
 else if(!strcmp(mode,"ordered_spans")){req.flags|=XDEV_EXT_MECH_START_F_USER_SPANS;want=-EOPNOTSUPP;}
 else if(!strcmp(mode,"user_varlen")){s.plan[0].class_id=XDEV_EXT_MECH_CLASS_USER;s.plan[0].flags=XDEV_EXT_USER_F_VARLEN;want=-EOPNOTSUPP;}
 else if(!strcmp(mode,"user_delta")){s.plan[0].class_id=XDEV_EXT_MECH_CLASS_USER;s.plan[0].arg1=4;want=-EOPNOTSUPP;}
 else if(!strcmp(mode,"count")){req.nr_user_frames=3;want=-EINVAL;}
 else if(!strcmp(mode,"recycle")){req.nr_batches=6;req.flags|=XDEV_EXT_MECH_START_F_RECYCLE;}
 else if(!strcmp(mode,"recycle_count")){req.nr_batches=6;req.flags|=XDEV_EXT_MECH_START_F_RECYCLE;req.nr_user_frames=2;want=-EINVAL;}
 else if(!strcmp(mode,"stop_copy")){stop_during_copy=true;want=-ESHUTDOWN;}
 memcpy(before,states,sizeof(states));memcpy(life_before,s.life,sizeof(life_before));
 int ret=xdev_ext_mech_start(&ctx,&req);
 if(ret!=want){fprintf(stderr,"FAIL %s: START returned %d, expected %d\n",mode,ret,want);return 1;}
 if(want) {
  bad|=check(!memcmp(states,before,sizeof(states)),"failed START changed pool ownership");
  bad|=check(!memcmp(life_before,s.life,sizeof(life_before)),"failed START changed another lifecycle or generation");
  bad|=check(!m.nr,"failed START queued a frame");
  bad|=check(!s.start_left,"failed START installed batches");
  bad|=check(!s.start_preparing,"failed START retained preparation gate");
 } else if(!strcmp(mode,"legacy")) {
  bad|=check(m.nr==4,"old UMEM USER_FRAMES stopped publishing its FIFO");
  for(unsigned i=0;i<4;i++)bad|=check(states[indices[i]]==XDEV_EXT_MECH_F_K_FREE,"old UMEM selected frame custody changed");
 } else {
  bad|=check(!m.nr,"ordered START published selected frames to allocator FIFO");
  for(unsigned i=0;i<12;i++) {
   bool listed=i==7||i==3||i==9||i==1;
   bad|=check(states[i]==(listed?XDEV_EXT_MECH_F_HELD:before[i]),"ordered START claimed wrong frame or wrong ownership");
   bad|=check(!s.life[i].ctrl,"START prepare published frame before batch binding");
  }
  bad|=check(s.start_left==req.nr_batches&&s.start_seq==101,"START lost count or first message key");
  struct xdev_ext_mech_start again=req;
  bad|=check(xdev_ext_mech_start(&ctx,&again)==-EBUSY,"overlapping ordered START admitted");
 }
 if(!bad)printf("PASS ordered START %s\n",mode);
 return bad;
}
'''


def build(directory, transform=None):
    core = Path(os.environ.get('XDEV_EXT_RECYCLE_SOURCE', ROOT / 'io_uring/xdev_ext_mech.c')).read_text()
    umem = (ROOT / 'io_uring/xdev_ext_umem.c').read_text()
    names = {'POOL': '\n'.join(function(umem, n) for n in
               ('io_xdev_ext_umem_mech_alloc', 'io_xdev_ext_umem_mech_recycle')),
             'NOTIFY': function(core, 'xdev_ext_mech_notify_locked'),
             'COUNT': function(core, 'xdev_ext_mech_count'),
             'MOVE': function(core, 'xdev_ext_mech_frames_move'),
             'RELEASE': function(core, 'xdev_ext_mech_frames_release'),
             'STOP': function(core, 'xdev_ext_mech_session_stop'),
             'SETTLED': function(core, 'xdev_ext_mech_settled'),
             'SETTLE': function(core, 'xdev_ext_mech_settle_locked'),
             'RETURN_IDLE': function(core, 'xdev_ext_mech_return_idle', optional=True),
             'END': function(core, 'xdev_ext_mech_end'),
             'STOP_WORK': function(core, 'xdev_ext_mech_stop_work'),
             'TAKE': function(core, 'xdev_ext_mech_take_user_frames'),
             'START': function(core, 'xdev_ext_mech_start')}
    fixture = (HERE.parent / 'xdev_ext_mech_recycle_tail_fixture.c').read_text()
    fixture = '#define smp_load_acquire(p) (*(p))\n#define GENMASK_ULL(h,l) (((~0ULL) << (l)) & ((~0ULL) >> (63-(h))))\n' + fixture
    fixture=fixture.replace('#define WARN_ON_ONCE(x) (!!(x))','static bool test_warn(bool x){return x;}\n#define WARN_ON_ONCE(x) test_warn(!!(x))')
    fixture = fixture.replace('typedef __u64 u64;', 'typedef __u64 u64;\nstatic u64 ktime_get_boottime_ns(void){return 0;}')
    fixture = fixture.replace('int lock,worker,evfd,stop_err,last_err; bool worker_gone;',
      'int lock,worker,evfd,stop_err,last_err; bool worker_gone,progress_ready;u64 stop_started_ns;')
    fixture=fixture.replace('struct xdev_ext_mech_frame { u32 index; };', 'struct xdev_ext_mech_frame { u32 index,data_off,data_len;u64 umem_addr; };')
    fixture=fixture.replace('struct xdev_ext_mech_pool { u32 kind;', 'struct xdev_ext_mech_pool { u32 frame_size,kind;')
    fixture=fixture.replace('void (*recycle)(struct xdev_ext_mech_pool *,struct xdev_ext_mech_frame *);', 'void (*recycle)(struct xdev_ext_mech_pool *,struct xdev_ext_mech_frame *);int (*resolve)(struct xdev_ext_mech_pool *,struct xdev_ext_mech_frame *);')
    fixture=fixture.replace('struct xdev_ext_mech_batch {', 'struct xdev_ext_mech_batch {\nstruct xdev_ext_mech_session *s;u64 key;u32 bytes;int status;bool sequester;')
    fixture=fixture.replace(' struct {u32 state;} bs;', ' struct xdev_ext_mech_bstate bs;')
    fixture=fixture.replace('static const struct xdev_ext_mech_pool_ops ops={io_xdev_ext_umem_mech_alloc,hook_recycle};', 'static const struct xdev_ext_mech_pool_ops ops={.alloc=io_xdev_ext_umem_mech_alloc,.recycle=hook_recycle};')
    queue_header=ROOT/'io_uring/xdev_ext_mech_start_queue.h'
    if queue_header.exists():
        fixture=fixture.replace('typedef __u64 u64;', 'typedef __u64 u64;\n#include "io_uring/xdev_ext_mech_start_queue.h"')
        fixture=fixture.replace('struct xdev_ext_mech_session {', 'struct xdev_ext_mech_session {\nstruct xdev_ext_mech_start_queue *start_queue;bool start_ordered;')
        fixture=fixture.replace(' bool to_user; u32 nr_frames,present;', ' bool ordered_loan;u32 start_template;u64 start_ordinal;bool to_user; u32 nr_frames,present;')
        queue_names=list(dict.fromkeys(re.findall(r'^\w[^;{}]*\b(xdev_ext_mech_start_queue_\w+)\([^;{}]*\)\n\{',core,re.M)))
        queue_bodies=[function(core,n) for n in queue_names]
        prototypes='\n'.join(b[:b.index('\n{')]+';' for b in queue_bodies)
        publication=function(core,'xdev_ext_mech_start_publication')
        prototypes+='\n'+publication[:publication.index('\n{')]+';' 
        fixture=fixture.replace('/* PRODUCTION_RELEASE */',prototypes+'\n/* PRODUCTION_RELEASE */')
        fixture=fixture.replace('/* PRODUCTION_START */',publication+'\n'+'\n'.join(queue_bodies)+'\n/* PRODUCTION_START */')
        fixture=fixture.replace('#define kfree(x) free(x)', '#define kfree(x) free(x)\n#define kvcalloc(n,s,gfp) calloc(n,s)\n#define bitmap_free(p) free(p)\nstatic unsigned long *bitmap_zalloc(unsigned n,int g){(void)g;return calloc((n+63)/64,sizeof(unsigned long));}\nstatic bool test_and_set_bit(unsigned n,unsigned long *p){unsigned long mask=1UL<<(n%64);bool old=!!(p[n/64]&mask);p[n/64]|=mask;return old;}\n#define kzalloc(n,gfp) calloc(1,n)\n#define kcalloc(n,s,gfp) calloc(n,s)\n#define kvmalloc_array(n,s,gfp) calloc(n,s)\n#define kvfree(p) free(p)')
    for marker, body in names.items():
        fixture = fixture.replace('/* PRODUCTION_' + marker + ' */', body)
    fixture = fixture.replace('int main(int argc,char **argv) {', SCENARIO+'\nint main(int argc,char **argv) {',1)
    fixture = fixture.replace(' assert(argc==2);\n',' assert(argc==2);\n return ordered_scenario(argv[1]);\n',1)
    if transform is not None:
        fixture=transform(fixture,core)
    directory=Path(directory)
    source=directory/'ordered.c';source.write_text(fixture)
    binary=directory/'ordered'
    command=[os.environ.get('CC','gcc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
      '-Wno-unused-function','-fsanitize=undefined','-fno-sanitize-recover=undefined',
      '-I'+str(ROOT),str(source),'-o',str(binary)]
    result=subprocess.run(command,capture_output=True,text=True)
    if result.returncode: raise RuntimeError(result.stdout+result.stderr)
    return binary

class OrderedFrames(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='xdev-ordered-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.binary=build(cls.tmp.name)
    def probe(self,mode):
        result=subprocess.run([str(self.binary),mode],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

for name in ('iou','peer','peer_mixed','legacy','missing_user','unknown','xsk','peer_legacy',
             'duplicate','range','busy0','busy1','busy2','busy3','peer_busy0','peer_busy1','peer_busy2','peer_busy3','iou_free','count',
             'recycle','recycle_count','stop_copy','ordered_spans','user_varlen','user_delta'):
    setattr(OrderedFrames,'test_'+name,lambda self,mode=name:self.probe(mode))
for pool in range(2):
    for phase in range(4):
        for pos in range(4):
            mode=f'blocked_{pool}_{phase}_{pos}'
            setattr(OrderedFrames,'test_'+mode,lambda self,mode=mode:self.probe(mode))
if __name__=='__main__': unittest.main(verbosity=2)
