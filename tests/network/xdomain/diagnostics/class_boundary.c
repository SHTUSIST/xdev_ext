/* SPDX-License-Identifier: GPL-2.0 */
/* Explicit link-observation boundary for class-only protocol tests. */
static unsigned diag_link_calls;
int xdev_ext_xd_link_diag(struct xdev_ext_xd_ep *ep,struct xdev_ext_mech_stage_diag *out)
{
 assert(ep && ep->xl && !held_spinlocks && held_mutexes==1);
 diag_link_calls++;
 out->token=ep->xl->token;out->local_inc=ep->xl->local_inc;out->remote_inc=ep->xl->remote_inc;
 out->valid|=1U;out->readiness|=16U;return 0;
}
