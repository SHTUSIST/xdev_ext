// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#c); return 1; } } while(0)
static struct xdev_ext_mech_stats good(void)
{
 struct xdev_ext_mech_stats s={.session_id=7,.state=XDEV_EXT_MECH_SESSION_ACTIVE,
  .batches_done=2,.held=6,.recycled=6};
 s.submitted[1]=s.completed[1]=2;
 return s;
}
int main(int argc,char **argv)
{
 struct xdev_ext_mech_stats s=good(); char line[1024];
 CHECK(argc==2);
 if (!strcmp(argv[1],"abi")) {
  CHECK(sizeof(s)==168); CHECK(offsetof(struct xdev_ext_mech_stats,session_id)==0);
  CHECK(offsetof(struct xdev_ext_mech_stats,submitted)==96);
  CHECK(offsetof(struct xdev_ext_mech_stats,completed)==128);
  CHECK(offsetof(struct xdev_ext_mech_stats,last_err)==160);
  CHECK(offsetof(struct xdev_ext_mech_stats,state)==164);
 } else if (!strcmp(argv[1],"legacy-error")) {
  CHECK(xdev_ext_mech_ctl_nic_nvme_ok(&s,2,3));
  s.last_err=-EIO;
  CHECK(!xdev_ext_mech_ctl_nic_nvme_ok(&s,2,3));
  CHECK(!xdev_ext_mech_ctl_report_nic_nvme(line,sizeof(line),&s,2,3));
  CHECK(strstr(line,"=FAIL"));
 } else if (!strcmp(argv[1],"legacy-state")) {
  unsigned int state;
  for(state=0;state<=6;state++) {
   s.state=state;
   CHECK(xdev_ext_mech_ctl_nic_nvme_ok(&s,2,3)==(state==XDEV_EXT_MECH_SESSION_ACTIVE));
  }
 } else if (!strcmp(argv[1],"ce-state")) {
  for (int i=0;i<4;i++) { s.submitted[i]=i ? 2 : 0; s.completed[i]=2; }
  CHECK(xdev_ext_mech_ctl_report_nic_ce_nvme(line,sizeof(line),&s,2,3));
  s.state=XDEV_EXT_MECH_SESSION_STOPPING;
  CHECK(!xdev_ext_mech_ctl_report_nic_ce_nvme(line,sizeof(line),&s,2,3));
 } else if (!strcmp(argv[1],"transport")) {
#ifdef XDEV_EXT_MECH_TRANSPORT_STATS_VERSION
  struct xdev_ext_mech_transport_stats t={.size=sizeof(t),.version=1,.session_id=7};
  CHECK(XDEV_EXT_MECH_OP_TRANSPORT_STATS==6);
  CHECK(sizeof(t)==32); CHECK(offsetof(struct xdev_ext_mech_transport_stats,session_id)==8);
  CHECK(offsetof(struct xdev_ext_mech_transport_stats,native_controls)==16);
  CHECK(offsetof(struct xdev_ext_mech_transport_stats,pending_acks)==20);
  CHECK(offsetof(struct xdev_ext_mech_transport_stats,uncertain_controls)==24);
  CHECK(offsetof(struct xdev_ext_mech_transport_stats,rsvd)==28);
  CHECK(xdev_ext_mech_ctl_transport_ok(&t));
  t.native_controls=1; CHECK(!xdev_ext_mech_ctl_transport_ok(&t)); t.native_controls=0;
  t.pending_acks=1; CHECK(!xdev_ext_mech_ctl_transport_ok(&t)); t.pending_acks=0;
  t.uncertain_controls=1; CHECK(!xdev_ext_mech_ctl_transport_ok(&t)); t.uncertain_controls=0;
  t.rsvd=1; CHECK(!xdev_ext_mech_ctl_transport_ok(&t)); t.rsvd=0;
  t.session_id=0; CHECK(!xdev_ext_mech_ctl_transport_ok(&t)); t.session_id=7;
  t.version=2; CHECK(!xdev_ext_mech_ctl_transport_ok(&t)); t.version=1;
  t.size=31; CHECK(!xdev_ext_mech_ctl_transport_ok(&t));
#else
  fputs("FAIL: public transport ABI/helper absent (feature-absence RED)\n",stderr);
  return 1;
#endif
 } else return 2;
 puts("PASS"); return 0;
}
