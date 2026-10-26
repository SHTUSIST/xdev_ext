/* SPDX-License-Identifier: MIT */
/* Provider facts must distinguish BAR, page-backed and coherent memory;
 * RAW_BUS applies only to BAR memory and EXTERNAL is never lost. */
#include <stdbool.h>
#include <stdio.h>
#if !__has_include("../kernel-open/nvidia/nv-xdev_ext-peer-backing.h")
int main(void) { puts("not ok 1 - NVIDIA provider cannot describe its backing"); return 1; }
#else
#include "../kernel-open/nvidia/nv-xdev_ext-peer-backing.h"
int main(void)
{
 /* Literal expected UAPI flags, independently enumerated with input bits
  * page=1, coherent=2, external=4, raw=8. */
 static const unsigned expected[16] = { 1, 2, 4, 2, 9, 10, 12, 10,
                                       17, 2, 4, 2, 25, 10, 12, 10 };
 unsigned i, failures = 0;
 for (i = 0; i < 16; i++) {
  unsigned got = nv_xdev_ext_peer_backing_flags(!!(i & 1), !!(i & 2), !!(i & 4), !!(i & 8));
  if (got != expected[i]) {
   fprintf(stderr, "input %u: flags %u expected %u\n", i, got, expected[i]); failures++;
  }
 }
 printf("%s 1 - NVIDIA backing preserves memory kind, external ownership and requester-specific raw BAR address (16 cases)\n", failures ? "not ok" : "ok");
 return failures != 0;
}
#endif
