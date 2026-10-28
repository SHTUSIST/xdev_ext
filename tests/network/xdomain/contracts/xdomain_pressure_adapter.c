/* SPDX-License-Identifier: GPL-2.0 */
/* Test-only legitimate full-queue precondition, using actual class storage.
 * No enqueue, capacity decision, coalescing or overflow policy is implemented. */
void pressure_seed_full(struct side *side,struct xdev_ext_xd_msg *one_more)
{
 struct xdev_ext_xd_stage *xs=stage_of(side)->priv;
 struct xdev_ext_xd_ep *ep=xdev_ext_xd_ep_of(xs);
 assert(!xs->ns.rx&&!held_spinlocks&&!held_mutexes);
 assert(sizeof(xs->ctl)<=sizeof(((struct pressure_observation *)0)->queue));
 for(unsigned i=0;i<XD_EVENTS;i++)
  xs->ctl[i]=(struct xdev_ext_xd_msg){.type=XDEV_EXT_XD_CTS,
   .src_inc=xs->remote_inc,.dst_inc=xs->local_inc,.channel=ep->chan,
   .stream=xs->stream,.group=(u64)i+1,.credit=(u64)i+1+XDEV_EXT_REL_MAX_WINDOW};
 xs->ctl_count=XD_EVENTS;
 *one_more=(struct xdev_ext_xd_msg){.type=XDEV_EXT_XD_CTS,
  .src_inc=xs->remote_inc,.dst_inc=xs->local_inc,.channel=ep->chan,
  .stream=xs->stream,.group=(u64)XD_EVENTS+1,.credit=(u64)XD_EVENTS+1+XDEV_EXT_REL_MAX_WINDOW};
}
void pressure_capture(struct side *side,struct pressure_observation *out)
{
 struct xdev_ext_xd_stage *xs=stage_of(side)->priv;
 assert(sizeof(xs->ctl)<=sizeof(out->queue));
 *out=(struct pressure_observation){.bytes=sizeof(xs->ctl),.used=xs->ctl_count,
  /* STOP is authoritative at core admission closure, before class worker. */
  .stop_pending=xs->stop_latched||xdev_ext_mech_session_state(&side->session)==XDEV_EXT_MECH_SESSION_STOPPING,
  .link_down_pending=xs->down_latched,.stop_observed=xs->stop_latched};
 memcpy(out->queue,xs->ctl,sizeof(xs->ctl));
}
