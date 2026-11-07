/* SPDX-License-Identifier: GPL-2.0 */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"

#ifdef STACK_REAL_NHI
#include "stack_nhi_api.h"
/* Observe the real API calls and supply explicitly selected host adapters.
 * The production source and its callbacks are included without body edits. */
#define tb_ring_alloc_tx stack_ring_alloc_tx
#define tb_ring_alloc_rx stack_ring_alloc_rx
#define tb_ring_start stack_ring_start
#define tb_ring_stop stack_ring_stop
#define tb_ring_free stack_ring_free
#define tb_ring_free_quarantined stack_ring_free_quarantined
#define tb_ring_tx stack_ring_tx
#define tb_ring_rx stack_ring_rx
#ifndef tb_ring_tx_more
#define tb_ring_tx_more stack_ring_tx_more
#endif
#ifndef tb_ring_rx_more
#define tb_ring_rx_more stack_ring_rx_more
#endif
#else
int tb_ring_tx_more(struct tb_ring *, struct ring_frame *);
int tb_ring_rx_more(struct tb_ring *, struct ring_frame *);
void tb_ring_notify(struct tb_ring *);
#endif
#define xdev_ext_xd_class_ctl stack_record_dispatch
/* Observe X4 control-allocation retirement at the actual core boundary. */
#define xdev_ext_requester_backing_retire stack_x4_backing_retire
#include "../../../../../io_uring/xdomain/xdev_ext_xdomain_ring.c"
#undef xdev_ext_requester_backing_retire
u64 xdev_ext_requester_backing_retire(struct xdev_ext_requester_backing **, bool);
u64 stack_x4_backing_retire(struct xdev_ext_requester_backing **bp, bool unknown){
	struct xdev_ext_xd_ctl_allocation *a=container_of(bp,struct xdev_ext_xd_ctl_allocation,backing);
	size_t bytes=0;
	struct pci_dev *pdev=*bp?stack_backing_requester(*bp,&bytes):NULL;
	u64 retained=xdev_ext_requester_backing_retire(bp,unknown);
	if(pdev&&unknown)stack_record((struct stack_event){
		.kind=STACK_EV_RETAIN,.endpoint=pdev->dev.endpoint,.control=1,.owner=(uintptr_t)a,.address=(uintptr_t)pdev,.length=bytes,.generation=a->generation,.status=-ENOLINK
	});
	return retained;
}

void stack_x4_control_pressure(struct xdev_ext_xd_link*x,bool full){
	unsigned long f;
	spin_lock_irqsave(&x->lock,f);
	bitmap_zero(x->ctl_tx_free,XDEV_EXT_XD_CTL_RING);
	if(!full&&x->ctl_tx_alloc&&!x->ctl_tx_alloc->unknown)   for(unsigned i=0;i<XDEV_EXT_XD_CTL_RING;i++)if(!x->ctl_tx_alloc->pending[i])__set_bit(i,x->ctl_tx_free);
	spin_unlock_irqrestore(&x->lock,f);
}
