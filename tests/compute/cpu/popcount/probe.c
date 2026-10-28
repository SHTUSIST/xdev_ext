// SPDX-License-Identifier: GPL-2.0
#include "lifecycle.h"

int xdev_ext_popcount_acquire(struct xdev_ext_mech_life *life, __u32 stage,
			    __u32 flags, __u64 *claim);
int xdev_ext_popcount_drop(struct xdev_ext_mech_life *life, __u64 claim,
			 bool failed);

int xdev_ext_popcount_acquire(struct xdev_ext_mech_life *life, __u32 stage,
			    __u32 flags, __u64 *claim)
{
	return xdev_ext_mech_life_acquire(life, stage, flags, claim);
}

int xdev_ext_popcount_drop(struct xdev_ext_mech_life *life, __u64 claim,
			 bool failed)
{
	return xdev_ext_mech_life_drop(life, claim, failed);
}
