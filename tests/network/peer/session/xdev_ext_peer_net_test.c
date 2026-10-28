// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#if !__has_include("../../../../io_uring/xdev_ext_peer_net_core.h")
int main(void) { puts("not ok 1 - CPU-header/peer-payload native TX bounds and RX capability admission unavailable"); return 1; }
#else
#include <assert.h>
#include "../../../../io_uring/xdev_ext_peer_net_core.h"
int main(void)
{
 assert(xdev_ext_peer_net_check(1500, 82, 1024, 0) == 0);
 assert(xdev_ext_peer_net_check(1500, 14, 1, 0) == -EINVAL);
 assert(xdev_ext_peer_net_check(1500, 13, 1024, 0) == -EINVAL);
 assert(xdev_ext_peer_net_check(1500, 129, 1024, 0) == -EINVAL);
 assert(xdev_ext_peer_net_check(1500, 82, 0, 0) == -EINVAL);
 assert(xdev_ext_peer_net_check(1500, 82, 1500, 0) == -EMSGSIZE);
 assert(xdev_ext_peer_net_check(1500, 82, 1024, 1) == -EOPNOTSUPP);
 puts("ok 1 - bounded inline CPU header and peer payload admission; RX split unsupported");
 return 0;
}
#endif
