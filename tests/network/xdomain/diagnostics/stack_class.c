/* SPDX-License-Identifier: GPL-2.0 */
/* Included after the qualified full class TU. Only calls true registered hook. */
bool stack_diag_parallel(void);
int stack_diag_class(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_stage_diag *d)
{
 struct xdev_ext_xd_stage *xs=st->priv,saved=*xs;
 struct xdev_ext_net_slot slots[xs->ns.depth];
 struct xdev_ext_xd_fact facts[xs->ns.depth];
 memcpy(slots,xs->ns.slots,sizeof(slots));memcpy(facts,xs->facts,sizeof(facts));
 int rc=xdev_ext_xd_class.stage_diag(st,d);
 if(stack_diag_parallel())return rc;
 assert(!memcmp(xs,&saved,sizeof(saved)));
 assert(!memcmp(slots,xs->ns.slots,sizeof(slots)));
 assert(!memcmp(facts,xs->facts,sizeof(facts)));
 return rc;
}
