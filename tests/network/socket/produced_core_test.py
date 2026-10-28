#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the actual producer completion and trim over real lifecycle rules.

The custody allocator is a bounded host boundary, not a device or DMA model.
Tests stale/duplicate tickets, invalid lengths, short spans, unused tail return,
and retention when a tail cannot safely leave its producer lifecycle.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[5]

def function(text, name):
    match = re.search(r'(?:static )?(?:void|int|u32)\s+' + name + r'\([^;]*?\)\s*\{.*?\n\}', text, re.S)
    if not match:
        raise AssertionError('missing production function ' + name)
    return match.group()

PREAMBLE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_produced.h"
#include "io_uring/xdev_ext_mech_lifecycle.h"
typedef __u32 u32; typedef __u64 u64;
#define BIT(i) (1U << (i))
struct xdev_ext_mech_frame {u32 index, data_len;};
struct xdev_ext_mech_pool;
struct ops {void (*recycle)(struct xdev_ext_mech_pool *, struct xdev_ext_mech_frame *);};
struct xdev_ext_mech_pool {const struct ops *ops; u32 state[32], returned;};
struct xdev_ext_mech_session {bool start_recycle;u32 transform_owner[32];struct xdev_ext_mech_pool pool; struct xdev_ext_mech_life life[32];u32 recycled;};
struct xdev_ext_mech_batch {u32 nr_frames,bytes,present,produced,produced_used,life_active;bool produced_set,producing,to_user,ordered_loan;struct xdev_ext_mech_frame f[32];u64 life_token[32];struct xdev_ext_mech_completion completion;int status,publishes;};
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 t)
{return xdev_ext_mech_completion_claim(&b->completion,t);}
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 t,int e,bool seq)
{assert(!seq);assert(!xdev_ext_mech_completion_publish_begin(&b->completion,t));b->status=e;b->publishes++;xdev_ext_mech_completion_publish_end(&b->completion,t,e);}
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *p,u32 i,u32 from,u32 to)
{if(p->state[i]!=from)return -EBUSY;p->state[i]=to;return 0;}
static void recycle(struct xdev_ext_mech_pool *p,struct xdev_ext_mech_frame *f)
{assert(p->state[f->index]==XDEV_EXT_MECH_F_K_FREE);assert(!(p->returned&BIT(f->index)));p->returned|=BIT(f->index);}
static void xdev_ext_mech_count(struct xdev_ext_mech_session *s,enum xdev_ext_mech_counter c,u64 n)
{assert(c==XDEV_EXT_MECH_CNT_RECYCLED);s->recycled+=n;}
'''
MAIN = r'''
/* L separates native lifecycle trim from worker-only provider tail recycle. */
static int trim_and_retire(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b)
{int rc=xdev_ext_mech_trim_produced(s,b);return rc?rc:xdev_ext_mech_recycle_produced_tail(s,b);}
static void setup(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,u64 *ticket)
{
 static const struct ops ops={.recycle=recycle};u32 i;
 memset(s,0,sizeof(*s));memset(b,0,sizeof(*b));s->pool.ops=&ops;
 b->nr_frames=4;b->present=15;b->bytes=3500;b->producing=true;b->life_active=15;
 xdev_ext_mech_completion_init(&b->completion);
 assert(!xdev_ext_mech_completion_begin(&b->completion,ticket));
 for(i=0;i<4;i++){b->f[i]=(struct xdev_ext_mech_frame){i,i==3?500:1000};s->pool.state[i]=XDEV_EXT_MECH_F_HELD;xdev_ext_mech_life_init(&s->life[i]);assert(!xdev_ext_mech_life_claim(&s->life[i],0,&b->life_token[i]));}
}
int main(void)
{
 struct xdev_ext_mech_session s;struct xdev_ext_mech_batch b;u64 t;u32 i;
 setup(&s,&b,&t);
 xdev_ext_mech_batch_complete_produced(&b,t+1,0,1500);
 assert(!b.publishes&&!b.produced_set);
 xdev_ext_mech_batch_complete_produced(&b,t,0,1500);
 assert(b.publishes==1&&!b.status&&xdev_ext_mech_batch_produced(&b)==1500);
 xdev_ext_mech_batch_complete_produced(&b,t,-EIO,0);
 assert(b.publishes==1&&b.produced==1500);
 assert(!trim_and_retire(&s,&b));
 assert(b.bytes==1500&&b.nr_frames==2&&b.present==3&&b.f[0].data_len==1000&&b.f[1].data_len==500);
 assert(s.recycled==2&&s.pool.returned==12);
 for(i=0;i<4;i++)assert(xdev_ext_mech_life_phase(&s.life[i])==(i<2?XDEV_EXT_MECH_L_IO_PENDING:XDEV_EXT_MECH_L_FREE));
 setup(&s,&b,&t);xdev_ext_mech_batch_complete_produced(&b,t,0,3500);
 assert(!trim_and_retire(&s,&b)&&b.nr_frames==4&&!s.recycled&&b.bytes==3500);
 for(i=0;i<3;i++){
  setup(&s,&b,&t);xdev_ext_mech_batch_complete_produced(&b,t,i==2?-EIO:0,i==0?0:3501);
  assert(b.status==(i==2?-EIO:-EOVERFLOW)&&b.produced==0&&b.produced_set&&b.publishes==1);
 }
 setup(&s,&b,&t);b.produced=500;b.life_token[1]++;
 assert(xdev_ext_mech_trim_produced(&s,&b)<0&&s.recycled==0&&b.present==15);
 setup(&s,&b,&t);b.produced=500;b.life_token[2]++;
 assert(xdev_ext_mech_trim_produced(&s,&b)<0&&s.recycled==0&&b.present==15&&s.pool.returned==0);
 assert(xdev_ext_mech_life_phase(&s.life[1])==XDEV_EXT_MECH_L_FREE); /* invalidated tail waits for safe worker custody */
 puts("PASS actual producer completion: ticket claim, valid bytes, tail release and uncertainty retention");
}
'''
class ProducedCore(unittest.TestCase):
    def test_actual_core(self):
        source = (ROOT/'io_uring/xdev_ext_mech.c').read_text()
        body = '\n'.join(function(source, name) for name in
                         ('xdev_ext_mech_batch_complete_produced','xdev_ext_mech_batch_produced','xdev_ext_mech_trim_produced','xdev_ext_mech_recycle_produced_tail'))
        with tempfile.TemporaryDirectory() as tmp:
            c=Path(tmp)/'test.c';exe=Path(tmp)/'test'
            c.write_text(PREAMBLE+body+MAIN)
            p=subprocess.run([os.environ.get('CC','gcc'),'-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined','-I'+str(ROOT),str(c),'-o',str(exe)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stdout+p.stderr)
            p=subprocess.run([str(exe)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stdout+p.stderr)
            print(p.stdout,end='')
if __name__=='__main__':unittest.main(verbosity=2)
