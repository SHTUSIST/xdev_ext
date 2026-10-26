/* SPDX-License-Identifier: GPL-2.0 */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"
#define xdev_ext_xd_class_ctl stack_record_dispatch
#include "../../../../../io_uring/xdomain/xdev_ext_xdomain_ring.c"
void stack_x4_control_pressure(struct xdev_ext_xd_link*x,bool full){
	unsigned long f;
	spin_lock_irqsave(&x->lock,f);
	bitmap_zero(x->ctl_tx_free,XDEV_EXT_XD_CTL_RING);
	if(!full&&x->ctl_tx_alloc&&!x->ctl_tx_alloc->unknown)   for(unsigned i=0;i<XDEV_EXT_XD_CTL_RING;i++)if(!x->ctl_tx_alloc->pending[i])__set_bit(i,x->ctl_tx_free);
	spin_unlock_irqrestore(&x->lock,f);
}
void stack_x4_quarantine_records(void){
	struct xdev_ext_xd_ctl_allocation*a;
	static void*seen[1024];
	static unsigned count;
	list_for_each_entry(a,&xdev_ext_xd_ctl_quarantine,node){
		bool known=false;
		for(unsigned i=0;i<count;i++)if(seen[i]==a)known=true;
		if(known)continue;
		assert(count<ARRAY_SIZE(seen));
		seen[count++]=a;
		stack_record((struct stack_event){
			.kind=STACK_EV_RETAIN,.endpoint=a->pdev->dev.endpoint,.control=1,.owner=(uintptr_t)a,.address=(uintptr_t)a->pdev,.length=a->bytes,.generation=a->generation,.status=-ENOLINK
		}
		);
	}
}
