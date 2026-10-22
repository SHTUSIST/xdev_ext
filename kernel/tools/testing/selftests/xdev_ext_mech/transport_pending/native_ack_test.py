#!/usr/bin/env python3
"""Execute actual journal/count-completion/native-done pipeline.

Use real portable FIFO/protocol functions; shims supply list, lock and external
kernel APIs. RX-only has no TX socket stage. Locked stage_dead is an error.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
ROOT=Path(os.environ.get('KERNEL_DIR',str(next(p for p in Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech.c').is_file()))))
HERE=Path(__file__).resolve().parent
def function(source,name):
 match=re.search(r'^(?:static )?(?:void|int) '+re.escape(name)+r'\([^)]*\)\s*\{.*?^\}',source,re.M|re.S)
 if not match: raise RuntimeError('missing production '+name)
 return match[0]
LIST=r'''
struct list_head { struct list_head *next,*prev; };
#define LIST_HEAD(n) struct list_head n={&n,&n}
static void list_add_tail(struct list_head *n,struct list_head *h) { n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n; }
static void list_del_init(struct list_head *n) { n->prev->next=n->next;n->next->prev=n->prev;n->next=n->prev=n; }
#define list_entry(p,t,m) container_of(p,t,m)
#define list_for_each_entry_safe(p,n,h,m) for(p=list_entry((h)->next,__typeof__(*p),m),n=list_entry(p->m.next,__typeof__(*p),m); &p->m!=(h); p=n,n=list_entry(n->m.next,__typeof__(*n),m))
'''
EXTERNAL=r'''
#define READ_ONCE(x) (x)
#define rcu_read_lock() do {} while(0)
#define rcu_read_unlock() do {} while(0)
#define rcu_dereference(x) (x)
static int wrong_locked_dead,dead_calls;
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int err)
{ dead_calls++; wrong_locked_dead+=st->s->pool.priv->tx_lock!=0; st->s->last_err=err; st->priv->dead=true; }
static void xdev_ext_mech_batch_sequester(struct xdev_ext_mech_batch *b,u64 ticket,int err) { (void)b;(void)ticket;(void)err; }
static void xdev_ext_mech_batch_complete(struct xdev_ext_mech_batch *b,u64 ticket,int err) { (void)b;(void)ticket;(void)err; }
static void xdev_ext_mech_batch_complete_cancelled(struct xdev_ext_mech_batch *b,u64 ticket,int err) { (void)b;(void)ticket;(void)err; }
static void xsk_mech_zc_stop(struct xsk_xdev_ext_mech_provider *p,int err) { (void)err;p->stopped=true; }
'''
MAIN=r'''
int main(int argc,char **argv)
{
 int result=argc>1 ? atoi(argv[1]) : 0;
 bool rx_only=argc>2 && !strcmp(argv[2],"rx-only");
 bool uncertain=argc>3 && !strcmp(argv[3],"uncertain");
 bool cancelled=argc>4 && !strcmp(argv[4],"cancelled");
 bool data=argc>5 && !strcmp(argv[5],"data");
 struct fake_xp xp={.dev=(void *)1,.dma_pages=(void *)1};
 struct xdp_sock xs={0};
 struct xsk_mech_zc_slot slots[4]={0};
 struct xsk_xdev_ext_mech_provider p={.xp=&xp,.xs=&xs,.slots=slots,.ring={.capacity=4}};
 struct fake_session s={.pool={.priv=&p},.native_controls=1};
 struct xsk_mech_reliable r={0};
 struct xsk_xdev_ext_mech_stage xst={.rel=&r};
 struct xdev_ext_mech_stage st={.priv=&xst,.s=&s};
 struct xsk_rel_control c={.busy=true,.frame={.index=20,.data_off=384}};
 struct xsk_buff_pool pool={.xdev_ext_mech_tx=&p};
 struct xdev_ext_rel_cfg cfg={.session=17,.first_group=1,.timeout_ns=10,.window=1,.max_attempts=3,.group_bytes=16,.seg_len=16};
 xdev_ext_rel_tx_init(&r.tx,&cfg);
 c.tb.reliable_stage=&st;c.tb.control=true;c.tb.completion.pending=1;
 c.tb.completion.uncertain=uncertain;
 struct xdev_ext_mech_batch batch={.group=1};
 c.tb.control=!data;c.tb.batch=&batch;
 c.tb.done.next=c.tb.done.prev=&c.tb.done;
 struct fake_session other_s={.pool={.priv=&p}};
 struct xsk_xdev_ext_mech_stage other_xst={.rel=&r};
 struct xdev_ext_mech_stage other_st={.priv=&other_xst,.s=&other_s};
 xs.xdev_ext_mech_rx=&st; if(!rx_only) xs.xdev_ext_mech_tx=&st;
 if(argc>2 && !strcmp(argv[2],"foreign-tx")) xs.xdev_ext_mech_tx=&other_st;
 p.ring.prod=1;slots[0].batch=&c.tb;slots[0].state=XSK_MECH_ZC_PENDING;
 int ret=0;
 if(cancelled) xsk_mech_zc_cancel_pending(&p,result);
 else { xsk_mech_zc_peek(&p.ring,slots);ret=xsk_xdev_ext_mech_tx_complete(&pool,1,result,false,false); }
 printf("ret=%d last_err=%d locked_dead=%d dead_calls=%d controls=%d uncertain=%d busy=%d invalid_map_reads=%d syncs=%d\n",ret,s.last_err,wrong_locked_dead,dead_calls,s.native_controls,c.uncertain,c.busy,invalid_map_reads,syncs);
 return 0;
}
'''
class NativeAck(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  rel=(ROOT/'net/xdp/xsk_xdev_ext_mech_reliable.inc').read_text()
  driver=(ROOT/'net/xdp/xsk_xdev_ext_mech.c').read_text()
  src=(HERE/'native_ack_fixture.c').read_text()
  src=src.replace('#include <errno.h>','#include <errno.h>\n#include <stdlib.h>\n#include "net/xdp/xsk_xdev_ext_mech_zc_core.h"')
  src=src.replace('typedef uint64_t __u64;','')
  src=src.replace('struct xdp_desc { u64 addr; u32 len; };','')
  src=src.replace('struct xsk_mech_zc_batch { bool uncertain; int status; };','')
  src=src.replace('struct xdev_ext_mech_stage;','struct xdev_ext_mech_stage;\n'+LIST)
  src=src.replace('struct xdev_ext_mech_stage *reliable_stage;','struct xdev_ext_mech_stage *reliable_stage;\n struct list_head done; u64 ticket; __s32 err[32];')
  src=src.replace('struct xsk_xdev_ext_mech_provider { struct fake_xp *xp; bool stopped; int tx_lock; };',
   'struct xdp_sock { struct xdev_ext_mech_stage *xdev_ext_mech_rx,*xdev_ext_mech_tx; };\nstruct xsk_xdev_ext_mech_provider { struct fake_xp *xp; bool stopped; int tx_lock; struct xdp_sock *xs; struct xsk_mech_zc_ring ring; struct xsk_mech_zc_slot *slots; };\nstruct xsk_buff_pool { struct xsk_xdev_ext_mech_provider *xdev_ext_mech_tx; };')
  src=src.replace('int native_controls;','int native_controls,last_err;')
  src=src.replace('(void)(p); (f)=0;','++*(p); (f)=0;').replace('(void)(p); (void)(f);','--*(p); (void)(f);')
  bodies='\n'.join(function(rel if name=='xsk_rel_native_done' else driver,name) for name in ('xsk_rel_native_done','xsk_mech_zc_done','xsk_mech_zc_retire','xsk_mech_zc_cancel_pending','xsk_xdev_ext_mech_tx_complete'))
  src=src.replace('/* PRODUCTION_NATIVE_DONE */',EXTERNAL+'\n'+bodies)+MAIN
  cls.tmp=tempfile.TemporaryDirectory(prefix='transport-native-');cls.addClassCleanup(cls.tmp.cleanup)
  path=Path(cls.tmp.name);(path/'probe.c').write_text(src);cls.bin=path/'probe'
  subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=undefined','-I',str(ROOT),str(path/'probe.c'),'-o',str(cls.bin)],check=True)
 def run_case(self,result,rx=True,uncertain=False,cancelled=False,data=False):
  p=subprocess.run([str(self.bin),str(result),'foreign-tx' if rx=='foreign' else ('rx-only' if rx else 'duplex'),'uncertain' if uncertain else 'definite','cancelled' if cancelled else 'native','data' if data else 'control'],check=True,capture_output=True,text=True)
  return {k:int(v) for k,v in (word.split('=') for word in p.stdout.split())}
 def test_final_ack_success(self):
  r=self.run_case(0);self.assertEqual((r['last_err'],r['controls'],r['busy'],r['uncertain']),(0,0,0,0),r)
 def test_rx_only_final_ack_definite_error_is_visible_outside_lock(self):
  r=self.run_case(-5);self.assertEqual(r['last_err'],-5,r);self.assertEqual(r['locked_dead'],0,r)
  self.assertEqual((r['controls'],r['busy'],r['uncertain']),(0,0,0),r)
 def test_duplex_final_ack_error_does_not_claim_uncertain_dma(self):
  r=self.run_case(-5,False);self.assertEqual(r['last_err'],-5,r)
  self.assertEqual((r['controls'],r['busy'],r['uncertain'],r['locked_dead']),(0,0,0,0),r)
 def test_ack_error_routes_to_its_journal_owner(self):
  r=self.run_case(-5,'foreign');self.assertEqual(r['last_err'],-5,r);self.assertEqual(r['locked_dead'],0,r)
 def test_local_pending_cancel_is_not_native_fatal(self):
  r=self.run_case(-125,cancelled=True);self.assertEqual((r['last_err'],r['controls']),(0,0),r)
 def test_local_pending_data_cancel_is_not_native_fatal(self):
  r=self.run_case(-125,cancelled=True,data=True);self.assertEqual((r['last_err'],r['dead_calls']),(0,0),r)
 def test_actual_native_data_ecanceled_is_fatal(self):
  r=self.run_case(-125,data=True);self.assertEqual(r['last_err'],-125,r)
 def test_actual_native_ecanceled_is_fatal(self):
  r=self.run_case(-125);self.assertEqual(r['last_err'],-125,r)
 def test_uncertain_final_ack_keeps_native_owner(self):
  r=self.run_case(-5,True,True);self.assertEqual((r['controls'],r['busy'],r['uncertain']),(1,1,1),r)
if __name__=='__main__': unittest.main(verbosity=2)
