/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_LIFE_POOL_H
#define XDEV_EXT_MECH_LIFE_POOL_H
#include "xdev_ext_mech_lifecycle.h"

/* One authoritative packed lifecycle per registered UMEM frame. Provider custody
 * controls allocator admission separately; it is not another data-plane state. */
struct xdev_ext_mech_life_pool {
 __u32 nr_frames;
 struct xdev_ext_mech_life *frames;
};
static inline void xdev_ext_mech_life_pool_init(struct xdev_ext_mech_life_pool *pool,
 struct xdev_ext_mech_life *frames, __u32 nr)
{
 __u32 i;

 pool->nr_frames = nr;
 pool->frames = frames;
 for (i = 0; i < nr; i++)
  xdev_ext_mech_life_init(&frames[i]);
}
#endif
