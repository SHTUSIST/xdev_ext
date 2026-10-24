// SPDX-License-Identifier: GPL-2.0
/* Production policy and enforcement headers, no reference implementation. */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#include "io_uring/xdev_ext_policy.h"
static unsigned checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr,"FAIL %s:%d %s\n",__func__,__LINE__,#c); } } while (0)
#define BAD(field, mutation) do { xdev_ext_rel_policy_defaults(&p); mutation; before=p; f=999; CHECK(xdev_ext_rel_policy_validate(&p,&f)==-EINVAL); CHECK(f==XDEV_EXT_POLICY_F_##field); CHECK(!memcmp(&p,&before,sizeof(p))); CHECK(xdev_ext_rel_policy_validate(&p,NULL)==-EINVAL); } while (0)
static void defaults_and_boundaries(void)
{
 struct xdev_ext_rel_policy p, before;
 __u32 f;
 unsigned i;
 memset(&p,0xa5,sizeof(p)); xdev_ext_rel_policy_defaults(&p);
 CHECK(sizeof(struct xdev_ext_afxdp_reliable_policy_config)==152);
 CHECK(sizeof(struct xdev_ext_mech_transport_stats)==32);
 CHECK(sizeof(struct xdev_ext_mech_transport_stats_v2)==64);
 CHECK(sizeof(struct xdev_ext_mech_transport_stats_v3)==96);
 CHECK(sizeof(struct xdev_ext_mech_transport_stats_v4)==216);
 CHECK(offsetof(struct xdev_ext_mech_transport_stats_v4,rel_policy)==96);
 CHECK(sizeof(p)==120); CHECK(p.version==1); CHECK(p.size==120);
 CHECK(p.window==4 && p.initial_credit==4); CHECK(p.rto_ns==100000000ULL);
 CHECK(p.backoff==XDEV_EXT_REL_BACKOFF_FIXED && p.rto_max_ns==0);
 CHECK(p.max_attempts==8 && p.ack_rule==XDEV_EXT_REL_ACK_EACH);
 CHECK(p.ack_every==1 && !p.ack_delay_ns && p.resend_order==XDEV_EXT_REL_RESEND_SLOT);
 CHECK(!p.flags && !p.bad_field && !p.rsvd0);
 for (i=0;i<6;i++) CHECK(!p.rsvd[i]);
 f=999; CHECK(!xdev_ext_rel_policy_validate(&p,&f)); CHECK(!f);
 p.bad_field=999; before=p; CHECK(!xdev_ext_rel_policy_validate(&p,&f)); CHECK(!f);
 CHECK(!memcmp(&p,&before,sizeof(p)));
 BAD(VERSION,p.version=0); BAD(VERSION,p.version=2);
 BAD(SIZE,p.size=119); BAD(SIZE,p.size=121);
 BAD(FLAGS,p.flags=1); BAD(RSVD,p.rsvd0=1);
 for(i=0;i<6;i++) { BAD(RSVD,p.rsvd[i]=1); }
 BAD(WINDOW,p.window=0); BAD(WINDOW,p.window=33); BAD(WINDOW,p.window=~0U);
 BAD(INITIAL_CREDIT,p.initial_credit=0); BAD(INITIAL_CREDIT,p.initial_credit=5);
 BAD(RTO,p.rto_ns=999); BAD(RTO,p.rto_ns=86400000000001ULL);
 BAD(BACKOFF,p.backoff=2); BAD(BACKOFF,p.backoff=~0U);
 BAD(RTO_MAX,p.rto_max_ns=p.rto_ns); /* fixed must have cap zero */
 BAD(RTO_MAX,p.backoff=XDEV_EXT_REL_BACKOFF_EXPONENTIAL; p.rto_max_ns=0);
 BAD(RTO_MAX,p.backoff=XDEV_EXT_REL_BACKOFF_EXPONENTIAL; p.rto_max_ns=p.rto_ns);
 BAD(RTO_MAX,p.backoff=XDEV_EXT_REL_BACKOFF_EXPONENTIAL; p.rto_max_ns=86400000000001ULL);
 BAD(MAX_ATTEMPTS,p.max_attempts=0); BAD(MAX_ATTEMPTS,p.max_attempts=65536);
 BAD(ACK_RULE,p.ack_rule=3); BAD(ACK_RULE,p.ack_rule=~0U);
 BAD(ACK_EVERY,p.ack_every=0); BAD(ACK_EVERY,p.ack_every=2);
 BAD(ACK_EVERY,p.ack_rule=XDEV_EXT_REL_ACK_EVERY_N; p.ack_every=1; p.ack_delay_ns=1);
 BAD(ACK_EVERY,p.ack_rule=XDEV_EXT_REL_ACK_EVERY_N; p.ack_every=5; p.ack_delay_ns=1);
 BAD(ACK_EVERY,p.ack_rule=XDEV_EXT_REL_ACK_EVERY_N; p.initial_credit=2; p.ack_every=3; p.ack_delay_ns=1);
 BAD(ACK_EVERY,p.ack_rule=XDEV_EXT_REL_ACK_DELAYED; p.ack_every=1; p.ack_delay_ns=1);
 BAD(ACK_DELAY,p.ack_delay_ns=1);
 BAD(ACK_DELAY,p.ack_rule=XDEV_EXT_REL_ACK_EVERY_N; p.ack_every=2);
 BAD(ACK_DELAY,p.ack_rule=XDEV_EXT_REL_ACK_EVERY_N; p.ack_every=2; p.ack_delay_ns=p.rto_ns);
 BAD(ACK_DELAY,p.ack_rule=XDEV_EXT_REL_ACK_DELAYED; p.ack_every=0);
 BAD(ACK_DELAY,p.ack_rule=XDEV_EXT_REL_ACK_DELAYED; p.ack_every=0; p.ack_delay_ns=~0ULL);
 BAD(RESEND_ORDER,p.resend_order=3); BAD(RESEND_ORDER,p.resend_order=~0U);
 /* First-error attribution must be deterministic. */
 BAD(VERSION,p.version=0; p.window=0; p.flags=1);
 xdev_ext_rel_policy_defaults(&p); p.rto_ns=1000; p.max_attempts=1;
 p.window=p.initial_credit=1; CHECK(!xdev_ext_rel_policy_validate(&p,&f));
 p.rto_ns=86400000000000ULL; p.max_attempts=65535;
 p.window=p.initial_credit=32; CHECK(!xdev_ext_rel_policy_validate(&p,&f));
 p.rto_ns=1000; p.rto_max_ns=1001; p.backoff=XDEV_EXT_REL_BACKOFF_EXPONENTIAL;
 p.ack_rule=XDEV_EXT_REL_ACK_EVERY_N; p.ack_every=32; p.ack_delay_ns=999;
 p.resend_order=XDEV_EXT_REL_RESEND_ROUND_ROBIN; CHECK(!xdev_ext_rel_policy_validate(&p,&f));
 p.ack_rule=XDEV_EXT_REL_ACK_DELAYED; p.ack_every=0;
 p.resend_order=XDEV_EXT_REL_RESEND_OLDEST; CHECK(!xdev_ext_rel_policy_validate(&p,&f));
}
static void legacy_default_equivalence(void)
{
 struct xdev_ext_rel_policy p;
 unsigned w,a;
 const __u64 times[]={1,1000,100000000ULL,86400000000000ULL};
 for(w=1;w<=32;w++) for(a=0;a<4;a++) {
  struct xdev_ext_rel_cfg want={.session=9,.first_group=17,.timeout_ns=times[a],
    .window=w,.max_attempts=7,.group_bytes=1024,.seg_len=512}, got=want;
  xdev_ext_rel_policy_from_legacy(&p,w,times[a],7);
  xdev_ext_rel_policy_cfg(&p,&got);
  CHECK(!memcmp(&got,&want,sizeof(got)));
 }
}
static void policies_never_disable_custody_or_window(void)
{
 unsigned w,rule,order;
 for(w=1;w<=8;w*=8) for(rule=0;rule<3;rule++) for(order=0;order<3;order++) {
  struct xdev_ext_rel_policy p;
  struct xdev_ext_rel_cfg c={.session=9,.first_group=1,.group_bytes=1024,.seg_len=512};
  struct xdev_ext_rel_rx r,before;
  __u64 owed=0;
  if(w==1 && rule==XDEV_EXT_REL_ACK_EVERY_N) continue;
  xdev_ext_rel_policy_defaults(&p); p.window=p.initial_credit=w; p.ack_rule=rule;
  p.ack_every=rule==XDEV_EXT_REL_ACK_EACH?1:rule==XDEV_EXT_REL_ACK_EVERY_N?2:0;
  p.ack_delay_ns=rule==XDEV_EXT_REL_ACK_EACH?0:10; p.resend_order=order;
  CHECK(!xdev_ext_rel_policy_validate(&p,NULL)); xdev_ext_rel_policy_cfg(&p,&c);
  CHECK(!xdev_ext_rel_rx_init(&r,&c));
  CHECK(xdev_ext_rel_rx_claim(&r,1,0,1)==XDEV_EXT_REL_HOLD);
  before=r;
  CHECK(xdev_ext_rel_rx_verdict(&r,&owed,1,0,2,XDEV_EXT_REL_HOLD)==-EEXIST);
  CHECK(xdev_ext_rel_rx_claim(&r,1,0,2)==-EEXIST);
  CHECK(xdev_ext_rel_rx_claim(&r,1+w,0,1)==-ERANGE);
  CHECK(!memcmp(&r,&before,sizeof(r)) && !owed);
  CHECK(xdev_ext_rel_rx_claim(&r,1,1,1)==XDEV_EXT_REL_SUBMIT);
  before=r;
  CHECK(xdev_ext_rel_rx_claim(&r,1,1,2)==-EEXIST);
  CHECK(!memcmp(&r,&before,sizeof(r)));
 }
}
static void backoff_timer_and_budget(void)
{
 struct xdev_ext_rel_policy p;
 struct xdev_ext_rel_cfg c={.session=9,.first_group=1,.group_bytes=1024,.seg_len=512};
 struct xdev_ext_rel_tx t,before;
 xdev_ext_rel_policy_defaults(&p); p.rto_ns=1000; p.rto_max_ns=5000;
 p.backoff=XDEV_EXT_REL_BACKOFF_EXPONENTIAL; p.max_attempts=3;
 CHECK(!xdev_ext_rel_policy_validate(&p,NULL)); xdev_ext_rel_policy_cfg(&p,&c);
 CHECK(xdev_ext_rel_rto(&c,0)==1000); CHECK(xdev_ext_rel_rto(&c,1)==1000);
 CHECK(xdev_ext_rel_rto(&c,2)==2000); CHECK(xdev_ext_rel_rto(&c,3)==4000);
 CHECK(xdev_ext_rel_rto(&c,4)==5000); CHECK(xdev_ext_rel_rto(&c,~0U)==5000);
 CHECK(!xdev_ext_rel_tx_init(&t,&c));
 CHECK(xdev_ext_rel_tx_open(&t,1,1024,2)==XDEV_EXT_REL_SEND);
 CHECK(xdev_ext_rel_tx_native_begin(&t,1,0)==XDEV_EXT_REL_SEND);
 CHECK(xdev_ext_rel_tx_native_done(&t,1,1,0,false,10)==XDEV_EXT_REL_NONE);
 CHECK(t.entry[1].deadline_ns==1010);
 CHECK(xdev_ext_rel_tx_poll(&t,1,1009)==XDEV_EXT_REL_NONE);
 before=t; CHECK(xdev_ext_rel_tx_decline(&t,1,1009)==XDEV_EXT_REL_STALE);
 CHECK(!memcmp(&t,&before,sizeof(t)));
 CHECK(xdev_ext_rel_tx_poll(&t,1,1010)==XDEV_EXT_REL_SEND);
 CHECK(xdev_ext_rel_tx_native_begin(&t,1,1010)==XDEV_EXT_REL_SEND);
 CHECK(xdev_ext_rel_tx_native_done(&t,1,2,0,false,1020)==XDEV_EXT_REL_NONE);
 CHECK(t.entry[1].deadline_ns==3020);
 CHECK(xdev_ext_rel_tx_decline(&t,1,3020)==XDEV_EXT_REL_UNKNOWN);
 CHECK(t.entry[1].attempt==2 && t.entry[1].declined==1);
 CHECK(xdev_ext_rel_tx_native_begin(&t,1,3020)==XDEV_EXT_REL_BAD);
 /* Uncertain native ownership survives even an accepted ACK. */
 CHECK(!xdev_ext_rel_tx_init(&t,&c));
 CHECK(xdev_ext_rel_tx_open(&t,1,1024,2)==XDEV_EXT_REL_SEND);
 CHECK(xdev_ext_rel_tx_native_begin(&t,1,0)==XDEV_EXT_REL_SEND);
 CHECK(xdev_ext_rel_tx_native_done(&t,1,1,-EIO,true,0)==XDEV_EXT_REL_UNKNOWN);
 before=t; CHECK(xdev_ext_rel_tx_retire(&t,1)==-EBUSY);
 CHECK(xdev_ext_rel_tx_control(&t,1,1,5,XDEV_EXT_REL_ACK)==-ESTALE);
 CHECK(!memcmp(&t,&before,sizeof(t)) && t.entry[1].native_pending);
 /* Saturating deadline and cap, without overflow or undefined shifts. */
 CHECK(!xdev_ext_rel_tx_init(&t,&c));
 CHECK(xdev_ext_rel_tx_open(&t,1,1024,2)==XDEV_EXT_REL_SEND);
 CHECK(xdev_ext_rel_tx_native_begin(&t,1,0)==XDEV_EXT_REL_SEND);
 CHECK(xdev_ext_rel_tx_native_done(&t,1,1,0,false,~0ULL-10)==XDEV_EXT_REL_NONE);
 CHECK(t.entry[1].deadline_ns==~0ULL);
}
int main(void)
{
 defaults_and_boundaries(); legacy_default_equivalence();
 policies_never_disable_custody_or_window(); backoff_timer_and_budget();
 printf("policy: %u checks, %u failures\n",checks,failures);
 return failures!=0;
}
