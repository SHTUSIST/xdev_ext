/* SPDX-License-Identifier: GPL-2.0 */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"
#include "stack_batch_session_source.inc"
#include "../../../../../io_uring/family/xdev_ext_netfam.c"
/* One actual backing definition for all X4/probe users in this program. */
#include "../../../../../io_uring/family/xdev_ext_requester_backing.c"
struct pci_dev *stack_backing_requester(struct xdev_ext_requester_backing *b, size_t *bytes)
{
	*bytes = b->bytes;
	return b->pdev;
}
