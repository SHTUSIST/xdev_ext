#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production initial reliable submit after one core BPF build."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[4]
source = (root / 'net/xdp/xsk_xdev_ext_mech_reliable.inc').read_text()
function = re.search(r'^static int xsk_rel_submit\([^;]*?\)\s*\{.*?^}', source, re.M | re.S)
assert function is not None
fixture = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <linux/types.h>
#include "include/linux/xdev_ext_mech_reliable_core.h"
typedef uint32_t u32;
typedef uint64_t u64;
#define WARN_ON_ONCE(x) warn_on(x)
static int warn_on(bool value) { if(value)abort();return value; }
#define spin_lock_irqsave(l,f) ((void)(l),(void)((f)=0))
#define spin_unlock_irqrestore(l,f) ((void)(l),(void)(f))
struct xdp_desc { u64 addr; u32 len,options; };
struct xsk_xdev_ext_mech_tx_batch { void *batch;u64 ticket;bool control;u32 attempt; };
struct xdev_ext_mech_batch { struct xsk_xdev_ext_mech_tx_batch priv; };
struct xsk_rel_data { struct xdev_ext_mech_batch *batch;u64 ticket;u32 count;struct xdp_desc desc[32]; };
struct xsk_mech_reliable { struct xdev_ext_rel_tx tx;struct xsk_rel_data data[32];struct xdp_desc scratch[32];bool initial_unchecked; };
struct xsk_xdev_ext_mech_provider { int tx_lock; };
struct xdev_ext_mech_pool { struct xsk_xdev_ext_mech_provider *priv; };
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel;u32 tx_n;struct xdp_desc tx_desc[32]; };
struct xdev_ext_mech_stage { struct xsk_xdev_ext_mech_stage *priv;struct xdev_ext_mech_session *s; };
static unsigned int builds=1,enqueues,kicks;
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) { return &b->priv; }
static u64 xdev_ext_mech_batch_key(struct xdev_ext_mech_batch *b) { (void)b;return 1; }
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b) { (void)b;return 7; }
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { (void)b;return 1024; }
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b) { (void)b;return 2; }
static int xsk_rel_build(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b,void *c,u64 g,u32 a,u64 credit)
{ (void)b;(void)c;(void)g;(void)a;(void)credit;builds++;memcpy(st->priv->rel->scratch,st->priv->tx_desc,sizeof(st->priv->tx_desc));return 0; }
static u64 ktime_get_ns(void) { return 1; }
static int xsk_rel_enqueue(struct xdev_ext_mech_stage *st,struct xsk_xdev_ext_mech_tx_batch *tb,const struct xdp_desc *d,u32 count)
{ (void)st;(void)tb;if(count!=2 || d[0].addr!=4096 || d[1].addr!=8192)abort();enqueues++;return 0; }
static void xsk_rel_wakeup(struct xdev_ext_mech_stage *st) { (void)st; }
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) { (void)st;kicks++; }
/* PRODUCTION */
int main(void)
{
 struct xsk_mech_reliable r={};
 struct xsk_xdev_ext_mech_provider p={};
 struct xdev_ext_mech_session session={.pool={.priv=&p}};
 struct xsk_xdev_ext_mech_stage xst={.rel=&r,.tx_n=2,.tx_desc={{.addr=4096},{.addr=8192}}};
 struct xdev_ext_mech_stage st={.priv=&xst,.s=&session};
 struct xdev_ext_mech_batch b={};
 struct xdev_ext_rel_cfg cfg={.session=7,.first_group=1,.timeout_ns=100,.window=2,.max_attempts=3,.group_bytes=1024,.seg_len=512};
 int rc=xdev_ext_rel_tx_init(&r.tx,&cfg);
 if(!rc)rc=xsk_rel_submit(&st,&b);
 printf("rc=%d builds=%u enqueues=%u kicks=%u\n",rc,builds,enqueues,kicks);
 return rc || builds!=1 || enqueues!=1 || kicks!=1;
}
'''
with tempfile.TemporaryDirectory(prefix='xdev_ext-reliable-submit-') as temp:
    path = Path(temp)
    (path/'probe.c').write_text(fixture.replace('/* PRODUCTION */',function[0]))
    subprocess.run([os.environ.get('CC','cc'),'-O1','-g','-Wall','-Wextra','-Werror',
                    '-Wno-unused-function','-I'+str(root),str(path/'probe.c'),
                    '-o',str(path/'probe')],check=True)
    subprocess.run([str(path/'probe')],check=True)
