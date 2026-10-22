// SPDX-License-Identifier: GPL-2.0
/* Finite campaigns lease one distinct device group slot per batch. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"
static unsigned int checks, failures;
#define EXPECT(c,msg) do { checks++; if (!(c)) { failures++; \
 fprintf(stderr,"FAIL: %s\n",msg); } } while (0)
int main(void)
{
 __u64 off;
 /* More than one window size catches both a constant and a modulo lease. */
 for (__u64 slots=1;slots<=8;slots++) {
  for (__u64 index=0;index<slots;index++) {
   off=UINT64_MAX;
   EXPECT(xdev_ext_mp_ce_base(index,8192,slots*8192+17,&off)==0 && off==index*8192,
          "in-window campaign group has its unique exact offset");
  }
  const __u64 bad[]={slots,slots+1,slots*2,UINT64_MAX};
  for (unsigned int j=0;j<sizeof(bad)/sizeof(bad[0]);j++) {
   off=UINT64_MAX;
   EXPECT(xdev_ext_mp_ce_base(bad[j],8192,slots*8192+17,&off)==-ERANGE,
          "out-of-window campaign index must reject rather than wrap");
   EXPECT(off==UINT64_MAX,"out-of-window index must not publish a reusable offset");
  }
 }
 off=UINT64_MAX;
 EXPECT(xdev_ext_mp_ce_base(0,0,8192,&off)==-ERANGE,"zero group bytes is invalid");
 EXPECT(xdev_ext_mp_ce_base(0,8192,8191,&off)==-ERANGE,"short device window is invalid");
 EXPECT(xdev_ext_mp_ce_base(UINT64_MAX/8192-1,8192,UINT64_MAX,&off)==0 &&
        off==(UINT64_MAX/8192-1)*8192,"large valid index cannot overflow offset");
 EXPECT(xdev_ext_mp_ce_base(UINT64_MAX/8192,8192,UINT64_MAX,&off)==-ERANGE,
        "large index at exact slot count is rejected");
#ifdef XDEV_EXT_TEST_HAS_CE_WINDOW
 EXPECT(xdev_ext_mech_ctl_ce_window_ok(1,8192,8192),"one exact slot is valid");
 EXPECT(xdev_ext_mech_ctl_ce_window_ok(8,8192,65536),"eight exact slots are valid");
 EXPECT(xdev_ext_mech_ctl_ce_window_ok(8,8192,65553),"trailing partial slot may be unused");
 EXPECT(!xdev_ext_mech_ctl_ce_window_ok(9,8192,65553),"partial last slot cannot cover another group");
 EXPECT(!xdev_ext_mech_ctl_ce_window_ok(0,8192,65536),"zero groups is invalid");
 EXPECT(!xdev_ext_mech_ctl_ce_window_ok(1,0,65536),"zero group size is invalid");
 EXPECT(!xdev_ext_mech_ctl_ce_window_ok(1,8192,0),"zero CE window is invalid");
 EXPECT(!xdev_ext_mech_ctl_ce_window_ok(UINT64_MAX,8192,65536),"group multiplication overflow must not bypass guard");
 EXPECT(xdev_ext_mech_ctl_ce_window_ok(UINT64_MAX/8192,8192,UINT64_MAX),"maximum representable full slot count is valid");
 EXPECT(!xdev_ext_mech_ctl_ce_window_ok(UINT64_MAX/8192+1,8192,UINT64_MAX),"one past maximum full slots is invalid");
#else
 EXPECT(0,"production finite-campaign CE window guard is missing");
#endif
 printf("CE exclusive window: %u checks, %u failures\n",checks,failures);
 return !!failures;
}
