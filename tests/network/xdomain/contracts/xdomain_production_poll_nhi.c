/* SPDX-License-Identifier: GPL-2.0 */
#include "stack_nhi.c"
void production_poll_return(struct tb_ring *, struct ring_frame *);
struct ring_frame *production_poll_ring(struct tb_ring *ring)
{
 struct ring_frame *frame=tb_ring_poll(ring);
 /* The caller, not this observer, must execute the actual callback. */
 if(frame)callback_origin=2;
 production_poll_return(ring,frame);
 return frame;
}

void production_poll_complete(struct tb_ring *ring)
{
 if(ring->flags&RING_FLAG_NO_INTERRUPT){fprintf(stderr,"STACK_ASSERT no-interrupt: pure production polling must never rearm IRQ\n");exit(1);}
 tb_ring_poll_complete(ring);
}
