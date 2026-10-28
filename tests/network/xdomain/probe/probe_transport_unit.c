/* SPDX-License-Identifier: GPL-2.0 */
#include "probe_extra_compat.h"
#include "stack_nhi_api.h"
#define tb_ring_tx stack_ring_tx
#define tb_ring_rx stack_ring_rx
#include "xdev_ext_xdomain_probe.c"
