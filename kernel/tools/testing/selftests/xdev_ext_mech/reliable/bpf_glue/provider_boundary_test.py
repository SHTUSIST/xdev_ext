#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the production hold boundary against a hostile repeated HOLD.

Only the downstream custody sink is a recording stub. Production C must
refuse before reaching it. This does not model DMA or assert a current
end-to-end exploit: 75b51c2's upstream C classifier currently protects it.
The new boundary must remain safe when classification moves into BPF.
"""
import unittest
import glue_common as G

FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#define XDEV_EXT_REL_C_GLUE
#include "include/linux/xdev_ext_mech_reliable_core.h"
typedef __u64 u64; typedef __u32 u32; typedef __u8 u8;
struct xsk_rel_rx_intent { __u64 group; __u32 index, attempt; __u8 calls, valid; };
struct xsk_mech_reliable { struct xdev_ext_rel_rx rx; struct xsk_rel_rx_intent rx_intent; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel; };
struct xsk_xdev_ext_mech_provider { int tx_lock; };
struct xdev_ext_mech_pool { void *priv; };
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; };
struct xdev_ext_mech_stage { void *priv; struct xdev_ext_mech_session *s; };
struct xdev_ext_mech_hold_intent { __u64 key; __u32 pos,count,span_off,span_len; };
struct xdev_ext_mech_frame { __u32 data_off,data_len; };
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
#define spin_lock_irqsave(lock, flags) do { (void)(lock); (flags)=0; } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(lock); (void)(flags); } while (0)
#define WARN_ON_ONCE(c) ((void)(c))
static unsigned delivered;
static int xdev_ext_mech_hold_commit(struct xdev_ext_mech_stage *s,
 const struct xdev_ext_mech_hold_intent *h,const struct xdev_ext_mech_frame *f)
{ (void)s;(void)h;(void)f; delivered++;return 0; }
/* PRODUCTION */
static unsigned checks,failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr,"FAIL line %d %s\n",__LINE__,#c); } } while (0)
int main(void)
{
 struct xdev_ext_rel_cfg cfg={.session=9,.first_group=1,.timeout_ns=100,.window=4,
  .max_attempts=3,.group_bytes=1024,.seg_len=512};
 struct xsk_mech_reliable rel={0};
 struct xsk_xdev_ext_mech_stage xst={.rel=&rel};
 struct xsk_xdev_ext_mech_provider provider={0};
 struct xdev_ext_mech_session session={.pool={.priv=&provider}};
 struct xdev_ext_mech_stage st={.priv=&xst,.s=&session};
 struct xdev_ext_mech_hold_intent hold={.key=1,.pos=0,.count=2,.span_off=384,.span_len=512};
 struct xdev_ext_mech_frame frame={.data_off=278,.data_len=618};
 struct xdev_ext_rel_msg msg={.session=9,.group=1,.attempt=1,.type=XDEV_EXT_REL_DATA,
  .total_len=1024,.count=2,.payload_len=512};
 int rc; unsigned bad;
 CHECK(!xdev_ext_rel_rx_init(&rel.rx,&cfg));
 rel.rx_intent=(struct xsk_rel_rx_intent){.group=1,.index=0,.attempt=1,.valid=1};
 rc=CALL;
 CHECK(rc==0 && delivered==1);
 /* BPF lies: request the same group/index with a fresh frame again. */
 rel.rx_intent=(struct xsk_rel_rx_intent){.group=1,.index=0,.attempt=2,.valid=1};
 msg.attempt=2;
 rc=CALL;
 CHECK(rc==-EEXIST); CHECK(delivered==1); CHECK(rel.rx.entry[1].present==1);
 /* Validate all intent/custody coordinates before any downstream call. */
 for (bad=0;bad<8;bad++) {
  struct xdev_ext_rel_rx before;
  CHECK(!xdev_ext_rel_rx_init(&rel.rx,&cfg)); delivered=0;
  hold=(struct xdev_ext_mech_hold_intent){.key=1,.pos=0,.count=2,.span_off=384,.span_len=512};
  rel.rx_intent=(struct xsk_rel_rx_intent){.group=1,.index=0,.attempt=1,.valid=1};
  msg.group=1; msg.index=0; msg.attempt=1;
  switch(bad) {
  case 0: hold.key=2; break;
  case 1: hold.pos=1; break;
  case 2: hold.count=3; break;
  case 3: hold.span_off++; break;
  case 4: hold.span_len++; break;
  case 5: rel.rx_intent.valid=0; break;
  case 6: msg.group=hold.key=rel.rx_intent.group=5; break;
  case 7: msg.index=hold.pos=rel.rx_intent.index=2; break;
  }
  before=rel.rx; rc=CALL;
  CHECK(rc<0); CHECK(delivered==0); CHECK(!memcmp(&before,&rel.rx,sizeof(before)));
 }
 printf("provider repeated HOLD: %u checks, %u failures\n",checks,failures);
 return failures!=0;
}
'''

class ProviderBoundary(unittest.TestCase):
    def test_repeated_hold_refused_before_downstream(self):
        body = G.require(G.default_text(G.INC), 'xsk_rel_hold_commit', str(G.INC))
        old_signature = 'const struct xdev_ext_rel_msg *' in body.split('{', 1)[0]
        call = 'xsk_rel_hold_commit(&st,&msg,&hold,&frame)' if old_signature else \
               'xsk_rel_hold_commit(&st,&hold,&frame)'
        G.build_and_run(self, FIXTURE.replace('/* PRODUCTION */', body).replace('CALL', call),
                        name='provider-boundary')

if __name__ == '__main__':
    unittest.main(verbosity=2)
