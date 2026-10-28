/* SPDX-License-Identifier: GPL-2.0 */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"
int native_progress_more(struct tb_ring *, struct ring_frame *);
#define tb_ring_tx_more native_progress_more
#define tb_ring_rx_more native_progress_more
#include "stack_x4.c"
