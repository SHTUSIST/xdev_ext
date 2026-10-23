// SPDX-License-Identifier: GPL-2.0
#define main ctl_main
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl.c"
#undef main
static unsigned checks,failures;
#define CHECK(c) do { checks++; if(!(c)) { failures++; fprintf(stderr,"FAIL %d %s\n",__LINE__,#c); } } while(0)
int main(void)
{
 struct ctl_opts o={.reliable=true,.remote_window=4,.depth=8,.retry_timeout_ms=100,.max_attempts=8,
  .first_group=17,.groups=32,.wire_session=9};
 struct xdev_ext_afxdp_reliable_policy_config cfg;
 struct xdev_ext_mech_create c={.nr_stages=1,.st={{.class_id=XDEV_EXT_MECH_CLASS_AFXDP}}};
 unsigned i;
 const struct {int opt; const char *value;} args[]={
  {OPT_REL_WINDOW,"8"},{OPT_REL_INITIAL_CREDIT,"4"},{OPT_REL_RTO_US,"10000"},
  {OPT_REL_RTO_MAX_US,"40000"},{OPT_REL_BACKOFF,"exponential"},{OPT_REL_MAX_ATTEMPTS,"3"},
  {OPT_REL_ACK_EVERY,"4"},{OPT_REL_ACK_DELAY_US,"3000"},{OPT_REL_ACK_RULE,"every-n"},
  {OPT_REL_RESEND_ORDER,"round-robin"}};
 memset(&cfg,0xa5,sizeof(cfg));
 CHECK(!ctl_rel_policy_finish(&o));ctl_reliable_config(&o,&c,&cfg);
 CHECK(c.st[0].flags==(XDEV_EXT_AFXDP_F_RELIABLE|XDEV_EXT_AFXDP_F_FINITE));
 CHECK(cfg.finite.base.first_group==17 && cfg.finite.base.window==4);
 CHECK(cfg.finite.base.timeout_ns==100000000ULL && cfg.finite.base.max_attempts==8 && cfg.finite.nr_groups==32);
 CHECK(((unsigned char *)&cfg.policy)[0]==0xa5);
 for(i=0;i<sizeof(args)/sizeof(args[0]);i++) CHECK(!ctl_rel_policy_option(&o,args[i].opt,args[i].value));
 CHECK(!ctl_rel_policy_finish(&o)); ctl_reliable_config(&o,&c,&cfg);
 CHECK(c.st[0].flags==(XDEV_EXT_AFXDP_F_RELIABLE|XDEV_EXT_AFXDP_F_FINITE|XDEV_EXT_AFXDP_F_POLICY));
 CHECK(!cfg.finite.base.window && !cfg.finite.base.timeout_ns && !cfg.finite.base.max_attempts);
 CHECK(cfg.finite.base.first_group==17 && cfg.finite.nr_groups==32);
 CHECK(cfg.policy.window==8 && cfg.policy.initial_credit==4 && cfg.policy.rto_ns==10000000ULL);
 CHECK(cfg.policy.rto_max_ns==40000000ULL && cfg.policy.max_attempts==3 && cfg.policy.backoff==1);
 CHECK(cfg.policy.ack_every==4 && cfg.policy.ack_delay_ns==3000000ULL && cfg.policy.ack_rule==1);
 CHECK(cfg.policy.resend_order==2);
 CHECK(ctl_rel_policy_option(&o,OPT_REL_WINDOW,"4294967296")==-EINVAL);
 CHECK(ctl_rel_policy_option(&o,OPT_REL_RTO_US,"18446744073709551615")==-EINVAL);
 CHECK(ctl_rel_policy_option(&o,OPT_REL_BACKOFF,"other")==-EINVAL);
 CHECK(ctl_rel_policy_option(&o,OPT_REL_ACK_RULE,"other")==-EINVAL);
 CHECK(ctl_rel_policy_option(&o,OPT_REL_RESEND_ORDER,"other")==-EINVAL);
 CHECK(ctl_rel_policy_option(&o,OPT_GROUPS,"5")==-ENOENT);
 CHECK(!ctl_rel_policy_option(&o,OPT_REL_ACK_EVERY,"5"));
 CHECK(ctl_rel_policy_finish(&o)==-EINVAL);
 printf("ctl policy: %u checks, %u failures\n",checks,failures);return failures!=0;
}
