// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#if !__has_include("../../../../drivers/nvme/host/xdev_ext_peer_nvme_core.h")
int main(void) { puts("not ok 1 - peer NVMe read/write admission and native SGL command unavailable"); return 1; }
#else
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include "../../../../drivers/nvme/host/xdev_ext_peer_nvme_core.h"
int main(void)
{
 struct xdev_ext_peer_nvme_plan p;
 assert(xdev_ext_peer_nvme_plan(9, 1000, 0, 0, 10, 4096, 0, &p) == 0);
 assert(p.opcode == 2 && p.slba == 10 && p.nlb == 7 && p.bytes == 4096);
 assert(xdev_ext_peer_nvme_plan(12, 1000, 0, 0, 999, 4096, 1, &p) == 0 && p.opcode == 1 && p.nlb == 0);
 assert(xdev_ext_peer_nvme_plan(9, 1000, 1, 0, 10, 4096, 0, &p) == -EOPNOTSUPP);
 assert(xdev_ext_peer_nvme_plan(9, 1000, 0, 1, 10, 4096, 0, &p) == -EOPNOTSUPP);
 assert(xdev_ext_peer_nvme_plan(9, 1000, 0, 0, 999, 1024, 0, &p) == -ERANGE);
 assert(xdev_ext_peer_nvme_plan(9, 1000, 0, 0, UINT64_MAX, 512, 0, &p) == -ERANGE);
 assert(xdev_ext_peer_nvme_plan(9, 1000, 0, 0, 1, 511, 0, &p) == -EINVAL);
 assert(xdev_ext_peer_nvme_plan(9, 1000, 0, 0, 1, 0, 0, &p) == -EINVAL);
 assert(xdev_ext_peer_nvme_plan(9, 100000, 0, 0, 1, 33554944, 0, &p) == -E2BIG);
 puts("ok 1 - peer NVMe read/write bounds, metadata, namespace and NLB admission");
 return 0;
}
#endif
