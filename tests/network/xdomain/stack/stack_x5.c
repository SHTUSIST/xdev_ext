/* SPDX-License-Identifier: GPL-2.0 */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"
#include "../../../../../io_uring/xdomain/xdev_ext_xdomain_class.c"
const struct xdev_ext_mech_class_ops*stack_x5_ops(void){
	return &xdev_ext_xd_class;
}

/* Observation only. Do not call xd_snapshot: it advances the protocol cursor,
 * event identity and current authority. These are guarded raw storage reads. */
int stack_x5_stage_facts(struct xdev_ext_mech_stage *stage, unsigned index,
                         struct stack_stage_facts *out)
{
 struct xdev_ext_xd_stage *xs=stage->priv;
 unsigned long flags;
 if(!xs||!out||index>=xs->ns.depth)return -ERANGE;
 memset(out,0,sizeof(*out));
 spin_lock_irqsave(&stage->s->lock,flags);
 out->session_id=stage->s->id;
 out->generation=stage->s->generation;
 out->native_controls=stage->s->native_controls;
 out->inflight=stage->s->ss.inflight;
 out->sequestered=stage->s->ss.sequestered;
 spin_unlock_irqrestore(&stage->s->lock,flags);
 spin_lock_irqsave(&xs->ns.lock,flags);
 struct xdev_ext_net_slot *slot=&xs->ns.slots[index];
 struct xdev_ext_xd_fact *fact=&xs->facts[index];
 struct xdev_ext_xd_reply *reply=fact->reply;
 out->stage_owner=(uintptr_t)stage;
 out->slot_owner=(uintptr_t)slot;
 out->slot_group=slot->group;
 out->slot_ticket=slot->ticket;
 out->slot_state=slot->state;
 out->slot_remote=slot->remote;
 out->slot_busy=slot->busy;
 out->slot_nr=slot->nr;
 out->slot_local_known=slot->local_known;
 out->slot_local_quiesced=slot->local_quiesced;
 out->slot_withdrawn=slot->withdrawn;
 out->slot_sequestered=slot->sequestered;
 out->stage_dead=xs->ns.dead;
 out->pending=xdev_ext_net_read(&slot->track.pending);
 out->uncertain=xdev_ext_net_read(&slot->track.uncertain);
 out->fact_reserved=fact->reserved;
 out->fact_accepted=fact->accepted;
 out->fact_cts_received=fact->cts_received;
 if(reply){
  out->reply_used=reply->used;
  out->reply_admission=reply->admission;
  out->reply_chain_done=reply->chain_done;
  out->reply_closed=reply->closed;
  out->reply_native_posted=reply->native_posted;
  out->reply_cts=reply->cts;
  out->reply_final=reply->final;
 }
 for(unsigned i=0;i<XD_REPLIES;i++)out->reply_admissions+=xs->replies[i].admission;
 for(unsigned i=0;i<xs->rts_count;i++)out->rts_admissions+=xs->rts[i].admission;
 spin_unlock_irqrestore(&xs->ns.lock,flags);
 return 0;
}
