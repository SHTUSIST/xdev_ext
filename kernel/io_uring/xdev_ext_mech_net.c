// SPDX-License-Identifier: GPL-2.0
/* Generic native NIC TX over an authoritative device-memory pool. All
 * producers use this same class and native endpoint, independent of device
 * pairs. BPF writes CPU headers and bounded offsets; C owns DMA and CQEs.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_peer.h>
#include <uapi/linux/xdev_ext_peer.h>
#include "xdev_ext_mech_net_core.h"
struct xdev_ext_net_stage {
 struct xdev_ext_peer_net_endpoint *endpoint;
 /* Worker only. A group refused after a completed prefix resumes at the
  * refused descriptor; NET is ordered, so at most one group is pending.
  */
 struct {
  u64 batch; /* xdev_ext_mech_batch_id(); nr == 0 when none */
  u32 nr, entries_done, bytes_sent;
  struct xdev_ext_net_send_desc desc[XDEV_EXT_NET_MAX_ENTRIES];
 } resume;
 bool dead;
};
struct xdev_ext_net_batch {
 struct xdev_ext_net_send_desc desc[XDEV_EXT_NET_MAX_ENTRIES];
 struct xdev_ext_net_mech_cqe cqe;
 u32 nr;
};
/* NETDEV_UNREGISTER of the bound device, under RTNL: never blocks. */
static void xdev_ext_net_endpoint_dead(void *arg)
{ xdev_ext_mech_stage_dead(arg, -ENXIO); }
static bool xdev_ext_net_stopped(void *arg)
{ return !xdev_ext_mech_session_admits(((struct xdev_ext_mech_stage *)arg)->s); }
static int xdev_ext_net_bind(struct xdev_ext_mech_stage *st,
                             const struct xdev_ext_mech_stage_uapi *u)
{
 struct xdev_ext_net_stage *ns;
 if (xdev_ext_mech_session_pool(st->s)->kind != XDEV_EXT_MECH_POOL_PEER ||
     st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE) return -EOPNOTSUPP;
 if (!xdev_ext_peer_control_file(st->file) || u->flags || !u->arg0 ||
     u->arg0 > U32_MAX || u->arg1 > U32_MAX) return -EINVAL;
 ns = kzalloc(sizeof(*ns), GFP_KERNEL);
 if (!ns) return -ENOMEM;
 /* Published first: removal may report the stage dead before bind returns. */
 st->priv = ns;
 ns->endpoint = xdev_ext_peer_net_bind_stage(u->arg0, u->arg1, xdev_ext_net_endpoint_dead, st);
 if (IS_ERR(ns->endpoint)) {
  int ret = PTR_ERR(ns->endpoint); st->priv = NULL; kfree(ns); return ret;
 }
 return 0;
}
static void xdev_ext_net_unbind(struct xdev_ext_mech_stage *st)
{
 struct xdev_ext_net_stage *ns = st->priv;
 xdev_ext_peer_net_unbind(ns->endpoint); kfree(ns); st->priv = NULL;
}
static void xdev_ext_net_fill_info(struct xdev_ext_mech_stage *st,
                                  struct xdev_ext_mech_batch *b, void *out)
{
 struct xdev_ext_net_stage *ns = st->priv;
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 struct xdev_ext_net_mech_info *info = out;
 struct xdev_ext_mech_frame f;
 *info = (struct xdev_ext_net_mech_info){
   .l = *xdev_ext_mech_session_layout(st->s),
   .generation = xdev_ext_peer_mech_pool_generation(pool),
   .mtu = xdev_ext_peer_net_mtu(ns->endpoint),
   .peer = *xdev_ext_mech_session_peer(st->s),
 };
 if (b && xdev_ext_mech_batch_nr_frames(b) == 1 && !xdev_ext_mech_batch_frame(b, 0, &f)) {
  info->nr_frames = 1;
  info->f[0] = (struct xdev_ext_mech_frame_info){
    .umem_addr = f.umem_addr, .data_off = f.data_off, .data_len = f.data_len };
 }
}
static int xdev_ext_net_validate(struct xdev_ext_mech_stage *st,
                                 struct xdev_ext_mech_batch *b, const u8 *scratch, u32 nr)
{
 struct xdev_ext_net_stage *ns = st->priv;
 struct xdev_ext_net_mech_info info;
 struct xdev_ext_net_batch *bp = xdev_ext_mech_batch_priv(b);
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 struct xdev_ext_mech_frame f;
 int ret;
 if (xdev_ext_mech_batch_frame(b, 0, &f) || f.kaddr || f.index >= pool->nr_frames ||
     f.umem_addr != (u64)f.index * pool->frame_size ||
     f.data_off > pool->frame_size || f.data_len > pool->frame_size - f.data_off)
  ret = -EPROTO;
 else {
  xdev_ext_net_fill_info(st, b, &info);
  ret = xdev_ext_net_plan_check(&info, (const void *)scratch, nr);
 }
 if (!ret) { memcpy(bp->desc, scratch, nr * sizeof(bp->desc[0])); bp->nr = nr; }
 /* The core rebuilt a refused batch; any other batch ends a stale record. */
 if (ns->resume.nr && ns->resume.batch != xdev_ext_mech_batch_id(b)) ns->resume.nr = 0;
 if (!ns->resume.nr) return ret;
 bp->cqe.entries_done = ns->resume.entries_done; bp->cqe.bytes_sent = ns->resume.bytes_sent;
 if (!ret && (ns->resume.nr != nr ||
              memcmp(ns->resume.desc, bp->desc, nr * sizeof(bp->desc[0]))))
  ret = -EPROTO;
 if (ret) {
  /* The sent prefix belongs to the old plan: never complete it differently. */
  ns->resume.nr = 0; bp->cqe.status = ret; bp->cqe.outcome = 1;
 }
 return ret;
}
static int xdev_ext_net_submit(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b)
{
 struct xdev_ext_net_stage *ns = st->priv;
 struct xdev_ext_net_batch *bp = xdev_ext_mech_batch_priv(b);
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 struct xdev_ext_mech_frame f;
 struct xdev_ext_peer_net_desc d;
 bool accepted;
 u32 i;
 int ret;
 if (READ_ONCE(ns->dead) || !xdev_ext_mech_session_admits(st->s)) return -ESHUTDOWN;
 if (!bp->nr || bp->nr > XDEV_EXT_NET_MAX_ENTRIES || xdev_ext_mech_batch_frame(b, 0, &f))
  return -EPROTO;
 for (i = bp->cqe.entries_done; i < bp->nr; i++) {
  d = (struct xdev_ext_peer_net_desc){ .offset = f.umem_addr + bp->desc[i].frame_off,
         .bytes = bp->desc[i].len, .header_len = bp->desc[i].header_len };
  memcpy(d.header, bp->desc[i].header, d.header_len);
  accepted = false;
  if (!xdev_ext_mech_session_admits(st->s)) ret = -ESHUTDOWN;
  else ret = xdev_ext_peer_net_send_stoppable(ns->endpoint, xdev_ext_peer_mech_pool_file(pool),
                    xdev_ext_peer_mech_pool_generation(pool), &d, &accepted,
                    xdev_ext_net_stopped, st);
  if (ret) {
   /* Refusal before native acceptance can be retried. Transient refusal
    * after a completed prefix is retried from descriptor i, so the prefix
    * (each entry already completed and quiesced) is never resent.
    */
   if (!accepted && (!i || ret == -EAGAIN)) {
    if (i) {
     ns->resume.batch = xdev_ext_mech_batch_id(b); ns->resume.nr = bp->nr;
     ns->resume.entries_done = i; ns->resume.bytes_sent = bp->cqe.bytes_sent;
     memcpy(ns->resume.desc, bp->desc, bp->nr * sizeof(bp->desc[0]));
     /* Kept in the batch area for consistency only: an aborted batch
      * gets no class CQE (the core reports just the session error), and a
      * retry that fails in the core before ->validate loses this area.
      */
     bp->cqe.status = ret; bp->cqe.outcome = 1;
    }
    return ret;
   }
   ns->resume.nr = 0;
   bp->cqe.status = ret; bp->cqe.outcome = accepted ? 2 : 1;
   if (accepted) xdev_ext_mech_batch_sequester(b, xdev_ext_mech_batch_ticket(b), ret);
   else xdev_ext_mech_batch_complete(b, xdev_ext_mech_batch_ticket(b), ret);
   return 0;
  }
  bp->cqe.bytes_sent += d.bytes; bp->cqe.entries_done++;
 }
 ns->resume.nr = 0;
 xdev_ext_mech_batch_complete(b, xdev_ext_mech_batch_ticket(b), 0);
 return 0;
}
static void xdev_ext_net_fill_cqe(struct xdev_ext_mech_stage *st,
                                 struct xdev_ext_mech_batch *b, void *out)
{ (void)st; *(struct xdev_ext_net_mech_cqe *)out = ((struct xdev_ext_net_batch *)xdev_ext_mech_batch_priv(b))->cqe; }
static void xdev_ext_net_dead(struct xdev_ext_mech_stage *st)
{ WRITE_ONCE(((struct xdev_ext_net_stage *)st->priv)->dead, true); }
static const struct xdev_ext_mech_class_ops xdev_ext_net_class = {
 .class_id = XDEV_EXT_MECH_CLASS_NET, .flags = XDEV_EXT_MECH_CLASS_F_ORDERED,
 .desc_size = sizeof(struct xdev_ext_net_send_desc), .desc_cap = XDEV_EXT_NET_MAX_ENTRIES,
 .info_size = sizeof(struct xdev_ext_net_mech_info),
 .cqe_size = sizeof(struct xdev_ext_net_mech_cqe), .cqe_cap = 1,
 .batch_priv_size = sizeof(struct xdev_ext_net_batch), .owner = THIS_MODULE,
 .bind = xdev_ext_net_bind, .unbind = xdev_ext_net_unbind, .fill_info = xdev_ext_net_fill_info,
 .validate = xdev_ext_net_validate, .submit = xdev_ext_net_submit,
 .fill_cqe = xdev_ext_net_fill_cqe, .mark_dead = xdev_ext_net_dead,
};
static int __init xdev_ext_net_init(void) { return xdev_ext_mech_class_register(&xdev_ext_net_class); }
late_initcall_sync(xdev_ext_net_init);
