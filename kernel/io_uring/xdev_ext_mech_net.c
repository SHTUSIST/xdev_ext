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
#ifdef XDEV_EXT_PEER_NET_SYNC_ONE
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
  ns->resume.nr = 0; bp->cqe.status = ret;
  bp->cqe.outcome = XDEV_EXT_MECH_OUTCOME_PRE_SUBMIT_FAILED;
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
     bp->cqe.status = ret; bp->cqe.outcome = XDEV_EXT_MECH_OUTCOME_PRE_SUBMIT_FAILED;
    }
    return ret;
   }
   ns->resume.nr = 0;
   bp->cqe.status = ret; bp->cqe.outcome = xdev_ext_mech_classify(false, accepted);
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

#else
/* Completion-driven NET: native contexts outlive uncertain callbacks. */
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include "xdev_ext_peer_net_track.h"
#include "xdev_ext_peer_net_core.h"
struct xdev_ext_net_slot;
struct xdev_ext_net_element {
 struct xdev_ext_peer_tx tx;
 struct xdev_ext_peer_rx rx;
 struct xdev_ext_peer_fd_lease lease;
 struct xdev_ext_net_slot *slot;
 u32 bytes, header_len;
 u8 header[XDEV_EXT_NET_HEADER_MAX];
};
struct xdev_ext_net_slot {
 struct xdev_ext_peer_net_track track;
 struct xdev_ext_net_element element[XDEV_EXT_NET_MAX_ENTRIES];
 struct xdev_ext_mech_batch *batch;
 u64 ticket, posted_ms;
 u32 nr;
 bool busy;
};
struct xdev_ext_net_stage {
 struct xdev_ext_peer_net_endpoint *endpoint;
 struct xdev_ext_net_slot *slots;
 u32 depth, header_room;
 u64 stop_ms;
 bool rx, dead, flushed;
};
struct xdev_ext_net_batch {
 struct xdev_ext_net_send_desc desc[XDEV_EXT_NET_MAX_ENTRIES];
 struct xdev_ext_net_rx_mech_cqe cqe;
 struct xdev_ext_net_slot *slot;
 u32 nr;
};
static void xdev_ext_net_endpoint_dead(void *arg)
{ xdev_ext_mech_stage_dead(arg, -ENXIO); }
static int xdev_ext_net_bind(struct xdev_ext_mech_stage *st,
                             const struct xdev_ext_mech_stage_uapi *u)
{
 const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
 struct xdev_ext_net_stage *ns;
 bool rx = st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE;
 u32 frames, span, header_room = u->arg1 >> 32;
 int ret;
 if (xdev_ext_mech_session_pool(st->s)->kind != XDEV_EXT_MECH_POOL_PEER)
  return -EOPNOTSUPP;
 if (!rx && st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE) return -EINVAL;
 if (!xdev_ext_peer_control_file(st->file) || u->flags || !u->arg0 ||
     u->arg0 > U32_MAX || (!rx && header_room) ||
     (rx && (header_room < 14 || header_room > 128))) return -EINVAL;
 frames = DIV_ROUND_UP(l->group_bytes, l->seg_len);
 if (rx && frames > XDEV_EXT_NET_MAX_ENTRIES) return -EINVAL;
 ns = kzalloc(sizeof(*ns), GFP_KERNEL);
 if (!ns) return -ENOMEM;
 ns->depth = xdev_ext_mech_session_depth(st->s);
 ns->rx = rx; ns->header_room = header_room;
 ns->slots = kvcalloc(ns->depth, sizeof(*ns->slots), GFP_KERNEL);
 if (!ns->slots) { kfree(ns); return -ENOMEM; }
 st->priv = ns;
 ns->endpoint = xdev_ext_peer_net_bind_dir(u->arg0, (u32)u->arg1, rx,
                                         xdev_ext_net_endpoint_dead, st);
 if (IS_ERR(ns->endpoint)) { ret = PTR_ERR(ns->endpoint); goto fail; }
 if (rx) {
  span = min(l->seg_len, l->group_bytes);
  ret = xdev_ext_peer_net_rx_check(xdev_ext_peer_net_mtu(ns->endpoint), header_room, span, 0);
  if (!ret) {
   span = l->group_bytes - (frames - 1) * l->seg_len;
   ret = xdev_ext_peer_net_rx_check(xdev_ext_peer_net_mtu(ns->endpoint), header_room, span, 0);
  }
  if (ret) { xdev_ext_peer_net_unbind(ns->endpoint); goto fail; }
 }
 return 0;
fail:
 st->priv = NULL; kvfree(ns->slots); kfree(ns); return ret;
}
static void xdev_ext_net_unbind(struct xdev_ext_mech_stage *st)
{
 struct xdev_ext_net_stage *ns = st->priv;
 u32 i;
 for (i = 0; i < ns->depth; i++)
  if (WARN_ON_ONCE(ns->slots[i].busy)) return;
 xdev_ext_peer_net_unbind(ns->endpoint);
 kvfree(ns->slots); kfree(ns); st->priv = NULL;
}
static void xdev_ext_net_fill_info(struct xdev_ext_mech_stage *st,
                                  struct xdev_ext_mech_batch *b, void *out)
{
 struct xdev_ext_net_stage *ns = st->priv;
 struct xdev_ext_net_mech_info *info = out;
 struct xdev_ext_mech_frame f;
 u32 i;
 *info = (struct xdev_ext_net_mech_info){
  .l = *xdev_ext_mech_session_layout(st->s),
  .generation = xdev_ext_peer_mech_pool_generation(xdev_ext_mech_session_pool(st->s)),
  .mtu = xdev_ext_peer_net_mtu(ns->endpoint), .peer = *xdev_ext_mech_session_peer(st->s),
  .direction = st->direction, .header_room = ns->header_room,
 };
 if (!b) return;
 info->nr_frames = xdev_ext_mech_batch_nr_frames(b);
 for (i = 0; i < info->nr_frames; i++) {
  if (xdev_ext_mech_batch_frame(b, i, &f)) { info->nr_frames = 0; return; }
  info->f[i] = (struct xdev_ext_mech_frame_info){
   .umem_addr = f.umem_addr, .data_off = f.data_off, .data_len = f.data_len };
 }
}
static int xdev_ext_net_default_build(struct xdev_ext_mech_stage *st,
                                     struct xdev_ext_mech_batch *b, u8 *scratch)
{
 struct xdev_ext_net_stage *ns = st->priv;
 struct xdev_ext_net_send_desc *d = (void *)scratch;
 struct xdev_ext_mech_frame f;
 u32 i, nr = xdev_ext_mech_batch_nr_frames(b);
 if (!ns->rx || !nr || nr > XDEV_EXT_NET_MAX_ENTRIES) return -EOPNOTSUPP;
 for (i = 0; i < nr; i++) {
  if (xdev_ext_mech_batch_frame(b, i, &f)) return -EPROTO;
  d[i] = (struct xdev_ext_net_send_desc){ .frame_pos = i, .frame_off = f.data_off,
   .len = f.data_len, .header_len = ns->header_room };
 }
 return nr;
}
static int xdev_ext_net_validate(struct xdev_ext_mech_stage *st,
                                 struct xdev_ext_mech_batch *b, const u8 *scratch, u32 nr)
{
 struct xdev_ext_net_stage *ns = st->priv;
 struct xdev_ext_net_batch *bp = xdev_ext_mech_batch_priv(b);
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 const struct xdev_ext_net_send_desc *d = (const void *)scratch;
 struct xdev_ext_net_mech_info info;
 struct xdev_ext_mech_frame f;
 u32 i, frames = xdev_ext_mech_batch_nr_frames(b);
 int ret;
 if (!nr || nr > XDEV_EXT_NET_MAX_ENTRIES || !frames) return -EINVAL;
 if (ns->rx && nr != frames) return -EINVAL;
 for (i = 0; i < frames; i++) {
  if (xdev_ext_mech_batch_frame(b, i, &f) || f.kaddr || f.index >= pool->nr_frames ||
      f.umem_addr != (u64)f.index * pool->frame_size ||
      f.data_off > pool->frame_size || !f.data_len || f.data_len > pool->frame_size - f.data_off)
   return -EPROTO;
  if (!ns->rx) continue;
  if (d[i].frame_pos != i || d[i].frame_off != f.data_off || d[i].len != f.data_len ||
      d[i].header_len != ns->header_room || d[i].flags || d[i].reserved) return -EINVAL;
  ret = xdev_ext_peer_net_rx_check(xdev_ext_peer_net_mtu(ns->endpoint), ns->header_room, f.data_len, 0);
  if (ret) return ret;
 }
 if (!ns->rx) {
  xdev_ext_net_fill_info(st, b, &info);
  ret = xdev_ext_net_plan_check(&info, d, nr);
  if (ret) return ret;
 }
 memcpy(bp->desc, d, nr * sizeof(*d)); bp->nr = nr;
 return 0;
}
/* Only the tracker winner touches batch state, using its immutable ticket. */
static void xdev_ext_net_handoff(struct xdev_ext_net_slot *slot)
{
 struct xdev_ext_mech_batch *b = slot->batch;
 struct xdev_ext_net_batch *bp;
 bool sequester;
 int status = xdev_ext_peer_net_track_result(&slot->track, &sequester);
 u32 i;
 if (xdev_ext_mech_batch_completion_claim(b, slot->ticket)) return;
 bp = xdev_ext_mech_batch_priv(b);
 bp->cqe.base.status = status;
 bp->cqe.base.outcome = xdev_ext_mech_classify(!status && !sequester, sequester);
 /* Abandon can race callbacks: it must not read their mutable records. */
 if (!sequester) {
  for (i = 0; i < slot->nr; i++) {
   bp->cqe.base.bytes_sent += slot->element[i].bytes;
   bp->cqe.base.entries_done++;
   bp->cqe.rx[i].payload_len = slot->element[i].bytes;
   bp->cqe.rx[i].header_len = slot->element[i].header_len;
   memcpy(bp->cqe.rx[i].header, slot->element[i].header, slot->element[i].header_len);
  }
 }
 xdev_ext_mech_batch_completion_publish(b, slot->ticket, status, sequester);
}
static void xdev_ext_net_tx_complete(struct xdev_ext_peer_tx *tx, int status, bool quiesced)
{
 struct xdev_ext_net_element *e = container_of(tx, struct xdev_ext_net_element, tx);
 e->bytes = status ? 0 : tx->len;
 if (xdev_ext_peer_net_track_complete(&e->slot->track, status, quiesced) == XDEV_EXT_PEER_NET_TRACK_HANDOFF)
  xdev_ext_net_handoff(e->slot);
}
static void xdev_ext_net_rx_complete(struct xdev_ext_peer_rx *rx, int status,
                                     u32 header_len, u32 payload_len, bool quiesced)
{
 struct xdev_ext_net_element *e = container_of(rx, struct xdev_ext_net_element, rx);
 bool sequester;
 status = xdev_ext_peer_net_rx_result(status, quiesced, rx->header_room, header_len,
                                      payload_len, rx->len, &sequester);
 e->bytes = status ? 0 : payload_len;
 e->header_len = status ? 0 : header_len;
 /* A fixed-layout consumer must never observe an unwritten frame tail.
  * Preserve the valid native lengths above for completion BPF/diagnostics,
  * but fail production before the core publishes READY or builds a consumer.
  */
 if (!status && payload_len != rx->len) status = -EMSGSIZE;
 if (xdev_ext_peer_net_track_complete(&e->slot->track, status, !sequester) == XDEV_EXT_PEER_NET_TRACK_HANDOFF)
  xdev_ext_net_handoff(e->slot);
}
static void xdev_ext_net_release(struct xdev_ext_net_slot *slot, bool quiesced)
{
 u32 i;
 for (i = 0; i < slot->nr; i++) xdev_ext_peer_fd_release(&slot->element[i].lease, quiesced);
 if (quiesced) slot->busy = false;
}
static int xdev_ext_net_submit(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b)
{
 struct xdev_ext_net_stage *ns = st->priv;
 struct xdev_ext_net_batch *bp = xdev_ext_mech_batch_priv(b);
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 struct xdev_ext_net_slot *slot = NULL;
 struct xdev_ext_mech_frame f;
 u32 i;
 int ret;
 if (READ_ONCE(ns->dead) || !xdev_ext_mech_session_admits(st->s)) return -ESHUTDOWN;
 if (!bp->nr || bp->nr > XDEV_EXT_NET_MAX_ENTRIES) return -EPROTO;
 for (i = 0; i < ns->depth; i++) if (!ns->slots[i].busy) { slot = &ns->slots[i]; break; }
 if (!slot) return -EAGAIN;
 memset(slot, 0, sizeof(*slot)); slot->busy = true;
 slot->nr = bp->nr; slot->batch = b; slot->ticket = xdev_ext_mech_batch_ticket(b);
 slot->posted_ms = ktime_get_boottime_ns() / NSEC_PER_MSEC;
 for (i = 0; i < bp->nr; i++) {
  struct xdev_ext_net_element *e = &slot->element[i];
  const struct xdev_ext_net_send_desc *d = &bp->desc[i];
  ret = xdev_ext_mech_batch_frame(b, d->frame_pos, &f);
  if (ret) goto refuse;
  ret = xdev_ext_peer_file_acquire(xdev_ext_peer_mech_pool_file(pool),
    xdev_ext_peer_net_peer(ns->endpoint), xdev_ext_peer_mech_pool_generation(pool),
    f.umem_addr + d->frame_off, d->len, ns->rx ? DMA_FROM_DEVICE : DMA_TO_DEVICE, &e->lease);
  if (ret) goto refuse;
  e->slot = slot;
  if (ns->rx) {
   e->rx = (struct xdev_ext_peer_rx){ .dma_address = e->lease.lease.dma_address,
    .len = d->len, .header_room = ns->header_room, .header = e->header,
    .complete = xdev_ext_net_rx_complete, .next = i + 1 < bp->nr ? &slot->element[i + 1].rx : NULL };
  } else {
   memcpy(e->header, d->header, d->header_len);
   e->tx = (struct xdev_ext_peer_tx){ .dma_address = e->lease.lease.dma_address,
    .len = d->len, .header_len = d->header_len, .header = e->header,
    .complete = xdev_ext_net_tx_complete, .next = i + 1 < bp->nr ? &slot->element[i + 1].tx : NULL };
  }
 }
 ret = xdev_ext_peer_net_track_init(&slot->track, bp->nr);
 if (ret) goto refuse;
 bp->slot = slot;
 ret = ns->rx ? xdev_ext_peer_net_post_rx(ns->endpoint, &slot->element[0].rx) :
                xdev_ext_peer_net_post_tx(ns->endpoint, &slot->element[0].tx);
 if (!ret) return 0;
 bp->slot = NULL;
refuse:
 xdev_ext_net_release(slot, true);
 return ret;
}
static void xdev_ext_net_fill_cqe(struct xdev_ext_mech_stage *st,
                                 struct xdev_ext_mech_batch *b, void *out)
{
 struct xdev_ext_net_batch *bp = xdev_ext_mech_batch_priv(b);
 bool sequester;
 (void)st;
 if (bp->slot) {
  xdev_ext_peer_net_track_result(&bp->slot->track, &sequester);
  xdev_ext_net_release(bp->slot, !sequester);
  bp->slot = NULL;
 }
 memcpy(out, &bp->cqe, sizeof(bp->cqe));
}
static void xdev_ext_net_dead(struct xdev_ext_mech_stage *st)
{ WRITE_ONCE(((struct xdev_ext_net_stage *)st->priv)->dead, true); }
static unsigned long xdev_ext_net_progress(struct xdev_ext_mech_stage *st)
{
 struct xdev_ext_net_stage *ns = st->priv;
 u64 now = ktime_get_boottime_ns() / NSEC_PER_MSEC;
 bool stopping = READ_ONCE(ns->dead) || !xdev_ext_mech_session_admits(st->s);
 u32 i;
 if (stopping && !ns->stop_ms) ns->stop_ms = now ? now : 1;
 if (ns->rx && !ns->flushed) {
  bool flush = stopping;
  for (i = 0; i < ns->depth && !flush; i++)
   flush = ns->slots[i].busy && xdev_ext_peer_net_track_expired(now,
             ns->slots[i].posted_ms, ns->stop_ms);
  if (flush) {
   xdev_ext_peer_net_rx_flush(ns->endpoint);
   ns->flushed = true;
  }
 }
 for (i = 0; i < ns->depth; i++) {
  struct xdev_ext_net_slot *slot = &ns->slots[i];
  if (!slot->busy || !xdev_ext_peer_net_track_expired(now, slot->posted_ms, ns->stop_ms)) continue;
  if (xdev_ext_peer_net_track_abandon(&slot->track, stopping ? -ECANCELED : -ETIMEDOUT))
   xdev_ext_net_handoff(slot);
 }
 return msecs_to_jiffies(20);
}
static const struct xdev_ext_mech_class_ops xdev_ext_net_class = {
 .class_id = XDEV_EXT_MECH_CLASS_NET, .flags = XDEV_EXT_MECH_CLASS_F_ORDERED | XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE,
 .desc_size = sizeof(struct xdev_ext_net_send_desc), .desc_cap = XDEV_EXT_NET_MAX_ENTRIES,
 .info_size = sizeof(struct xdev_ext_net_mech_info),
 .cqe_size = sizeof(struct xdev_ext_net_rx_mech_cqe), .cqe_cap = 1,
 .batch_priv_size = sizeof(struct xdev_ext_net_batch), .owner = THIS_MODULE,
 .bind = xdev_ext_net_bind, .unbind = xdev_ext_net_unbind, .fill_info = xdev_ext_net_fill_info,
 .default_build = xdev_ext_net_default_build, .validate = xdev_ext_net_validate,
 .submit = xdev_ext_net_submit, .fill_cqe = xdev_ext_net_fill_cqe,
 .mark_dead = xdev_ext_net_dead, .progress = xdev_ext_net_progress,
};
static int __init xdev_ext_net_init(void) { return xdev_ext_mech_class_register(&xdev_ext_net_class); }
late_initcall_sync(xdev_ext_net_init);

#endif
