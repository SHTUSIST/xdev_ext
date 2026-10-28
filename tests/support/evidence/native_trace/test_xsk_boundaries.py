# SPDX-License-Identifier: GPL-2.0
"""Run actual common XSK success paths, including fast batch and fallback."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
SOURCE=Path(os.environ.get('NATIVE_TRACE_XSK_SOURCE',ROOT/'kernel/net/xdp/xsk.c'))
def body(text, name):
 marker=name+'('; start=text.index(marker)
 start=text.rfind('\n',0,start)+1; a=text.index('{',start); n=1; end=a+1
 while n:
  n+=(text[end]=='{')-(text[end]=='}'); end+=1
 return text[start:end]
PREFIX=r'''
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
typedef uint32_t u32;
#define MAX_PER_SOCKET_BUDGET 16
struct xdp_desc { uint64_t addr; u32 len; };
struct xdp_sock { u32 tx_budget_spent; int *tx; struct { struct { void (*sk_write_space)(void *); } sk; }; };
struct xsk_buff_pool { struct xdp_desc *tx_descs; int xsk_tx_list,cq_lock; int *cq; };
static int queue;
static void space(void *p) { (void)p; }
static struct xdp_sock one={.tx=&queue,.sk={.sk_write_space=space}};
static int mode,remaining,traces,calls;
#define rcu_read_lock() do {} while(0)
#define rcu_read_unlock() do {} while(0)
#define list_for_each_entry_rcu(xs,l,m) for((xs)=&one;(xs);(xs)=0)
#define list_first_or_null_rcu(l,t,m) (&one)
#define list_is_singular(l) (mode!=7)
#define spin_lock_irqsave(l,f) do { (void)(l); (f)=0; } while(0)
#define spin_unlock_irqrestore(l,f) do { (void)(l); (void)(f); } while(0)
static int xsk_xdev_ext_mech_tx_peek(struct xsk_buff_pool *p,struct xdp_desc *d)
{ (void)p; if(mode!=1 && mode!=7) return -EOPNOTSUPP; if(!remaining) return 0; remaining--; d->addr=4096+remaining; d->len=64; return 1; }
static int xsk_xdev_ext_zc_tx_peek_desc(struct xsk_buff_pool *p,struct xdp_desc *d)
{ (void)p; if(mode!=2) return -EOPNOTSUPP; d->addr=8192; d->len=128; return 1; }
static int xsk_xdev_ext_mech_tx_batch(struct xsk_buff_pool *p,u32 n)
{ (void)p; (void)n; return mode==4 ? 3 : -EOPNOTSUPP; }
static int xsk_xdev_ext_zc_tx_peek_release_desc_batch(struct xsk_buff_pool *p,u32 n)
{ (void)p; (void)n; return mode==5 ? 3 : -EOPNOTSUPP; }
static bool xsk_xdev_ext_mech_tx_active(struct xsk_buff_pool *p) { (void)p; return false; }
static bool xskq_cons_peek_desc(int *q,struct xdp_desc *d,struct xsk_buff_pool *p)
{ (void)q;(void)p;d->addr=12288;d->len=256;return mode==3; }
static bool xskq_has_descs(int *q) { (void)q;return false; }
static void xskq_cons_release(int *q) { (void)q; }
static void __xskq_cons_release(int *q) { (void)q; }
static int xsk_cq_reserve_addr_locked(struct xsk_buff_pool *p,uint64_t a) { (void)p;(void)a;return 0; }
static u32 xskq_cons_nb_entries(int *q,u32 n) { (void)q;return n; }
static u32 xskq_prod_nb_free(int *q,u32 n) { (void)q;return n; }
static u32 xskq_cons_read_desc_batch(int *q,struct xsk_buff_pool *p,u32 n) { (void)q;(void)p;return n; }
static void xskq_prod_write_addr_batch(int *q,struct xdp_desc *d,u32 n) { (void)q;(void)d;(void)n; }
static void xsk_tx_release(struct xsk_buff_pool *p) { (void)p; }
static void __attribute__((unused)) xsk_native_trace_submit(struct xsk_buff_pool *p,const struct xdp_desc *d,u32 n)
{ (void)p;(void)d;traces+=n;calls++; }
'''
# xskq access needs real field names, with the rest of the dependency empty.
PREFIX=PREFIX.replace('int *tx;', 'struct queue *tx;').replace('int *cq;', 'struct queue *cq;').replace('static int queue;', 'struct queue { int queue_empty_descs; };\nstatic struct queue queue;').replace('int *q','struct queue *q')
SUFFIX=r'''
int main(void) {
 struct xdp_desc descs[8]={{0}}; struct xsk_buff_pool p={.tx_descs=descs,.cq=&queue};
 for(mode=1;mode<=3;mode++) {
  traces=calls=0; remaining=1;
  if(!xsk_tx_peek_desc(&p,descs) || traces!=1 || calls!=1) return mode;
 }
 for(mode=4;mode<=6;mode++) {
  traces=calls=0;
  if(xsk_tx_peek_release_desc_batch(&p,3)!=3 || traces!=3 || calls!=1) return mode;
 }
 mode=7; remaining=3; traces=calls=0;
 if(xsk_tx_peek_release_desc_batch(&p,4)!=3 || traces!=3 || calls!=3) return 7;
 remaining=0; traces=calls=0;
 if(xsk_tx_peek_desc(&p,descs) || traces || calls) return 8;
 return 0;
}
'''
class XSKBoundaries(unittest.TestCase):
 def test_single_batch_and_fallback_emit_each_consumed_descriptor_once(self):
  text=SOURCE.read_text()
  functions='\n'.join(body(text,name) for name in ['xsk_tx_peek_desc','xsk_tx_peek_release_fallback','xsk_tx_peek_release_desc_batch'])
  with tempfile.TemporaryDirectory() as tmp:
   c=Path(tmp)/'test.c';c.write_text(PREFIX+functions+SUFFIX);binary=Path(tmp)/'test'
   result=subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],capture_output=True,text=True)
   self.assertEqual(result.returncode,0,result.stderr)
   self.assertEqual(subprocess.run([str(binary)]).returncode,0,'driver consumed descriptor missing or double counted')
if __name__=='__main__': unittest.main()
