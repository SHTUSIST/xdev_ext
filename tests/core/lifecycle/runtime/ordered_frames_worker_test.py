#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Freeze queue ordering/last-use oracles around real START/start_more/end.

Only batch-object slots, work queues, and pool resolve are OS boundaries.
The IOU frame allocator is production code, instrumented so any ordered-path
fallback is a failure. Lifecycle claims/puts are the unchanged core rules.
The native stage boundary holds each whole batch until the test completes it.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from ordered_frames_test import build, function, ROOT

BOUNDARY = r'''
#define GENMASK_ULL(h,l) (((~0ULL) << (l)) & ((~0ULL) >> (63-(h))))
#define ERR_PTR(x) ((void *)(intptr_t)(x))
static struct xdev_ext_mech_batch worker_batches[2];
static bool worker_used[2];
static unsigned admitted,allocator_calls;
static struct xdev_ext_mech_batch *observed[8];
static u32 observed_index[8][2];
static u64 observed_key[8],lease[2][2];
static int counted_alloc(struct xdev_ext_mech_pool*p,struct xdev_ext_mech_frame*f,u32 n){
 allocator_calls++;return io_xdev_ext_umem_mech_alloc(p,f,n);
}
static int resolve_frame(struct xdev_ext_mech_pool*p,struct xdev_ext_mech_frame*f){
 if(f->index>=p->nr_frames)return -EINVAL;
 f->umem_addr=(u64)f->index*p->frame_size;return 0;
}
static const struct xdev_ext_mech_pool_ops worker_ops={counted_alloc,hook_recycle,resolve_frame};
static const struct xdev_ext_mech_class_ops quiet_cls={0};
static struct xdev_ext_mech_batch*xdev_ext_mech_batch_get_locked(struct xdev_ext_mech_session*s){
 if(!xdev_ext_mech_session_admits(s))return ERR_PTR(-ESHUTDOWN);
 for(unsigned j=0;j<2;j++)if(!worker_used[j]){
  struct xdev_ext_mech_batch*b=&worker_batches[j];memset(b,0,sizeof(*b));
  if(xdev_ext_mech_sess_batch_begin(&s->ss))abort();
  worker_used[j]=true;b->s=s;xdev_ext_mech_bstate_init(&b->bs,s->nr_stages);return b;
 }
 return ERR_PTR(-ENOSPC);
}
static void xdev_ext_mech_batch_run(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b){
 unsigned slot=(unsigned)(b-worker_batches);assert(slot<2&&admitted<8);
 observed[admitted]=b;observed_key[admitted]=b->key;
 for(unsigned i=0;i<2;i++){
  observed_index[admitted][i]=b->f[i].index;
  assert(!xdev_ext_mech_life_acquire(&s->life[b->f[i].index],0,XDEV_EXT_MECH_L_ACQ_EXCLUSIVE,&lease[slot][i]));
  assert(!xdev_ext_mech_pool_frame_move(&s->pool,b->f[i].index,XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_INFLIGHT));
 }
 admitted++;
}
'''

SCENARIO = r'''
static void finish_message(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b){
 unsigned slot=(unsigned)(b-worker_batches);assert(slot<2);
 for(unsigned i=0;i<2;i++){
  assert(!xdev_ext_mech_life_republish(&s->life[b->f[i].index],lease[slot][i],0,b->f[i].data_len));
  assert(!xdev_ext_mech_pool_frame_move(&s->pool,b->f[i].index,XDEV_EXT_MECH_F_INFLIGHT,XDEV_EXT_MECH_F_HELD));
 }
 b->bs.state=XDEV_EXT_MECH_B_DONE;
 xdev_ext_mech_end(s,b,XDEV_EXT_MECH_END_DONE,0);
}
/* The existing native boundary certifies quiescence before actual END. No
 * publisher or native-error latch is reimplemented by this terminal test. */
static void finish_failed_message(struct xdev_ext_mech_session*s,struct xdev_ext_mech_batch*b,int err){
 unsigned slot=(unsigned)(b-worker_batches);assert(slot<2);
 for(unsigned i=0;i<2;i++){
  assert(!xdev_ext_mech_life_republish(&s->life[b->f[i].index],lease[slot][i],0,b->f[i].data_len));
  assert(!xdev_ext_mech_pool_frame_move(&s->pool,b->f[i].index,XDEV_EXT_MECH_F_INFLIGHT,XDEV_EXT_MECH_F_HELD));
 }
 b->bs.state=XDEV_EXT_MECH_B_ABORT;
 xdev_ext_mech_end(s,b,XDEV_EXT_MECH_END_ABORT,err);
}
static int worker_scenario(const char*mode){
 struct xdev_ext_mech_session s;struct io_xdev_ext_umem_mech m;__u8 state[12];
 u32 selected[]={7,3,9,1};int bad=0;
 const u32 expected[6][2]={{7,3},{9,1},{7,3},{9,1},{7,3},{9,1}};
 bool stop_unbound=!strcmp(mode,"stop_unbound");
 bool recycle=strcmp(mode,"one_pass")!=0;
 setup_n(&s,&m,state,0,recycle?6:2,12);
 s.pool.kind=XDEV_EXT_MECH_POOL_IOU_UMEM;s.pool.frame_size=4096;s.pool.ops=&worker_ops;
 s.frames=2;s.depth=2;s.start_left=0;s.start_recycle=false;s.start_return_pending=false;
 if(stop_unbound){s.pool.kind=XDEV_EXT_MECH_POOL_PEER;memset(state,XDEV_EXT_MECH_F_K_FREE,sizeof(state));state[3]=XDEV_EXT_MECH_F_USER;state[1]=XDEV_EXT_MECH_F_USER;}
 s.st[0].cls=&quiet_cls;
 s.plan[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_USER,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 s.layout=(struct xdev_ext_mech_layout){.frame_size=4096,.seg_len=4096,.group_bytes=8192};
 struct xdev_ext_mech_start req={.session_id=1,.nr_batches=recycle?6:2,.first_seq=101,
  .flags=XDEV_EXT_MECH_START_F_ORDERED_FRAMES|XDEV_EXT_MECH_START_F_USER_FRAMES|(recycle?XDEV_EXT_MECH_START_F_RECYCLE:0),
  .nr_user_frames=4,.user_frames=(uintptr_t)selected};
 struct io_ring_ctx ctx={0};
 int ret=xdev_ext_mech_start(&ctx,&req);
 if(ret){fprintf(stderr,"FAIL %s: ordered START rejected (%d)\n",mode,ret);return 1;}
 if(stop_unbound){
  xdev_ext_mech_session_stop(&s,-ESHUTDOWN);xdev_ext_mech_stop_work(&s.stop_work);
  for(unsigned i=0;i<12;i++){
   bool selected_frame=i==7||i==3||i==9||i==1;
   bad|=check(state[i]==(selected_frame?XDEV_EXT_MECH_F_USER:XDEV_EXT_MECH_F_K_FREE),"STOP touched unlisted frame or lost loan");
  }
  bad|=check(s.cnt[XDEV_EXT_MECH_CNT_PUBLISHED]==4,"STOP returned a loan multiple times");
  xdev_ext_mech_stop_work(&s.stop_work);
  bad|=check(s.cnt[XDEV_EXT_MECH_CNT_PUBLISHED]==4,"repeated STOP drain returned loans again");
  bad|=check(!allocator_calls,"STOP drain called arbitrary allocator");
  return bad;
 }
 xdev_ext_mech_start_more(&s);
 if(admitted!=2){fprintf(stderr,"FAIL initial admission count %u, expected 2\n",admitted);return 1;}
 for(unsigned i=0;i<2;i++)for(unsigned j=0;j<2;j++)
  bad|=check(observed_index[i][j]==expected[i][j],"worker bound a different frame/order");
 bad|=check(observed_key[0]==101&&observed_key[1]==102,"worker changed initial message keys");
 if(!strcmp(mode,"clean_stop_cancel")||!strcmp(mode,"active_error")||!strcmp(mode,"stop_error")){
  bool active_error=!strcmp(mode,"active_error"),real_error=active_error||!strcmp(mode,"stop_error");
  int expected=real_error?-EIO:0;
  if(!active_error){
   xdev_ext_mech_session_stop(&s,0);
   bad|=check(!s.last_err&&!s.stop_err,"clean STOP invented an error before END");
   /* Model the documented already-latched native error precondition through
    * the real fatal-stop latch. Prior origin tests cover real publication. */
   if(real_error)xdev_ext_mech_session_stop(&s,-EIO);
  }
  finish_failed_message(&s,observed[0],real_error?-EIO:-ESHUTDOWN);
  bad|=check(s.last_err==expected&&s.stop_err==expected,"ordered END replaced clean STOP or the first real error");
  bad|=check(!xdev_ext_mech_session_admits(&s),"failed ordered work allowed a later ordinal");
  finish_message(&s,observed[1]);xdev_ext_mech_stop_work(&s.stop_work);xdev_ext_mech_start_more(&s);
  bad|=check(s.last_err==expected&&s.stop_err==expected,"loan return or later DONE changed terminal error origin");
  for(unsigned i=0;i<12;i++)bad|=check(state[i]==XDEV_EXT_MECH_F_USER,"quiesced terminal path lost or reclaimed an ordered loan");
  bad|=check(s.cnt[XDEV_EXT_MECH_CNT_PUBLISHED]==4,"terminal cancellation did not return each selected loan exactly once");
  bad|=check(!allocator_calls&&admitted==2&&!s.ss.inflight&&!s.start_left,"terminal cancellation allocated or restarted work");
  printf("ORDERED_END_ORIGIN %s last_err=%d stop_err=%d published=%llu admitted=%u failures=%d\n",
         mode,s.last_err,s.stop_err,(unsigned long long)s.cnt[XDEV_EXT_MECH_CNT_PUBLISHED],admitted,bad);
  return bad;
 }
 if(!strcmp(mode,"unknown")||!strcmp(mode,"stop_unknown")){
  if(!strcmp(mode,"stop_unknown")){
   xdev_ext_mech_session_stop(&s,0);
   /* Real UNKNOWN completion has already recorded its fatal status before
    * terminal custody is landed. This fixture begins at that END boundary. */
   xdev_ext_mech_session_stop(&s,-ETIMEDOUT);
  }
  struct xdev_ext_mech_batch *uncertain=observed[0];
  u64 word[2]={s.life[7].ctrl,s.life[3].ctrl};
  for(unsigned i=0;i<2;i++)assert(!xdev_ext_mech_pool_frame_move(&s.pool,uncertain->f[i].index,XDEV_EXT_MECH_F_INFLIGHT,XDEV_EXT_MECH_F_SEQUESTERED));
  uncertain->sequester=true;uncertain->bs.state=XDEV_EXT_MECH_B_SEQUESTERED;
  xdev_ext_mech_end(&s,uncertain,XDEV_EXT_MECH_END_SEQUESTER,-ETIMEDOUT);
  bad|=check(state[7]==XDEV_EXT_MECH_F_SEQUESTERED&&state[3]==XDEV_EXT_MECH_F_SEQUESTERED,"UNKNOWN reclaimed device-owned template");
  bad|=check(s.life[7].ctrl==word[0]&&s.life[3].ctrl==word[1],"UNKNOWN dropped held refs or advanced generation");
  finish_message(&s,observed[1]);xdev_ext_mech_stop_work(&s.stop_work);xdev_ext_mech_start_more(&s);
  bad|=check(admitted==2,"UNKNOWN allowed another template cycle");
  bad|=check(state[9]==XDEV_EXT_MECH_F_USER&&state[1]==XDEV_EXT_MECH_F_USER,"safe template was not returned during UNKNOWN drain");
  bad|=check(state[7]==XDEV_EXT_MECH_F_SEQUESTERED&&s.life[7].ctrl==word[0]&&s.life[3].ctrl==word[1],"subsequent drain revived UNKNOWN template");
  bad|=check(worker_used[uncertain-worker_batches],"UNKNOWN discarded retained batch storage");
  bad|=check(s.cnt[XDEV_EXT_MECH_CNT_PUBLISHED]==2&&!allocator_calls,"UNKNOWN return count includes retained frames or allocator used");
  bad|=check(s.last_err==-ETIMEDOUT&&s.stop_err==-ETIMEDOUT,"UNKNOWN terminal path lost its recorded error");
  return bad;
 }
 if(recycle){
  /* Hold ordinal0, retire ordinal1. Its free template cannot bypass ordinal2. */
  u64 generation=xdev_ext_mech_life_gen(&s.life[7]);
  finish_message(&s,observed[1]);
  xdev_ext_mech_start_more(&s);
  bad|=check(admitted==2,"busy template0 was skipped in favour of free template1");
  bad|=check(state[7]==XDEV_EXT_MECH_F_INFLIGHT&&state[3]==XDEV_EXT_MECH_F_INFLIGHT,"held first message lost custody");
  bad|=check(xdev_ext_mech_life_phase(&s.life[7])==XDEV_EXT_MECH_L_OUT_PENDING&&xdev_ext_mech_life_gen(&s.life[7])==generation,"waiting message advanced lifecycle generation");
  finish_message(&s,observed[0]);xdev_ext_mech_start_more(&s);
  bad|=check(admitted==4,"released templates did not resume in order");
  if(admitted!=4)return 1;
  finish_message(&s,observed[2]);finish_message(&s,observed[3]);xdev_ext_mech_start_more(&s);
  bad|=check(admitted==6,"last two cycles were lost");
  if(admitted!=6)return 1;
  finish_message(&s,observed[4]);finish_message(&s,observed[5]);
 }else {finish_message(&s,observed[0]);finish_message(&s,observed[1]);}
 for(unsigned i=0;i<admitted;i++){
  bad|=check(observed_key[i]==101+i,"worker consumed wrong ordinal/key");
  for(unsigned j=0;j<2;j++)bad|=check(observed_index[i][j]==expected[i][j],"cycle changed exact index order");
 }
 for(unsigned i=0;i<12;i++)bad|=check(state[i]==XDEV_EXT_MECH_F_USER,"last cycle failed to return exact loan set");
 bad|=check(s.cnt[XDEV_EXT_MECH_CNT_PUBLISHED]==4,"loan returned more than once or lost at final cycle");
 bad|=check(!allocator_calls,"ordered route invoked arbitrary pool allocator");
 bad|=check(!s.ss.inflight&&!s.start_left,"final message left outstanding work");
 if(!bad)printf("PASS ordered worker %s (%u messages)\n",mode,admitted);
 return bad;
}
'''

def adapt(fixture, core):
    fixture=fixture.replace('#define WARN_ON_ONCE(x) (!!(x))', 'static bool test_warn(bool x){return x;}\n#define WARN_ON_ONCE(x) test_warn(!!(x))')
    # END must use the actual state-sensitive core latch. The legacy recycle
    # boundary's simplified latch otherwise creates a second false error.
    old='static void xdev_ext_mech_set_err_locked(struct xdev_ext_mech_session *s,int err) {if(err&&!s->stop_err)s->last_err=err;}'
    if fixture.count(old)!=1:raise RuntimeError('ordered worker error-latch boundary changed')
    fixture=fixture.replace(old,function(core,'xdev_ext_mech_set_err_locked'),1)
    # The boundary allocates batch storage only, never frame indices.
    marker='static bool xdev_ext_mech_batch_put_locked('
    at=fixture.index(marker)
    boundary=BOUNDARY
    boundary=boundary.replace('static const struct xdev_ext_mech_pool_ops worker_ops={counted_alloc,hook_recycle,resolve_frame};',
      'static const struct xdev_ext_mech_pool_ops worker_ops={.alloc=counted_alloc,.recycle=hook_recycle,.resolve=resolve_frame};')
    fixture=fixture[:at]+boundary+fixture[at:]
    fixture=fixture.replace('(void)b; bool last=xdev_ext_mech_sess_batch_end',
      'if(!seq){worker_used[b-worker_batches]=false;}bool last=xdev_ext_mech_sess_batch_end')
    fixture=fixture.replace('static const struct xdev_ext_mech_pool_ops ops={io_xdev_ext_umem_mech_alloc,hook_recycle};',
      'static const struct xdev_ext_mech_pool_ops ops={.alloc=io_xdev_ext_umem_mech_alloc,.recycle=hook_recycle};')
    # Bodies are compiled verbatim; no source-shape assertions determine success.
    worker_names=('xdev_ext_mech_start_more',) if (ROOT/'io_uring/xdev_ext_mech_start_queue.h').exists() else ('xdev_ext_mech_start_publication','xdev_ext_mech_start_more')
    worker='\n'.join(function(core,n) for n in worker_names)
    fixture=fixture.replace('static int ordered_scenario(',worker+'\n'+SCENARIO+'\nstatic int ordered_scenario(',1)
    fixture=fixture.replace('return ordered_scenario(argv[1]);','return worker_scenario(argv[1]);',1)
    return fixture

class OrderedWorker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='xdev-ordered-worker-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.binary=build(cls.tmp.name,adapt)
    def test_stop_before_worker_returns_only_selected_loans_once(self):self.probe('stop_unbound')
    def test_unknown_template_retains_custody_refs_and_generation(self):self.probe('unknown')
    def test_exact_nonlowest_frames_one_pass(self):self.probe('one_pass')
    def test_busy_template_cannot_be_skipped_or_reused_before_last_use(self):self.probe('recycle')
    def test_clean_stop_quiesced_cancel_returns_loans_without_latching_error(self):self.probe('clean_stop_cancel')
    def test_first_active_ordered_failure_still_closes_admission(self):self.probe('active_error')
    def test_real_error_already_latched_after_stop_survives_end(self):self.probe('stop_error')
    def test_unknown_after_stop_retains_custody_and_error(self):self.probe('stop_unknown')
    def probe(self,mode):
        run=subprocess.run([str(self.binary),mode],capture_output=True,text=True,timeout=10)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
