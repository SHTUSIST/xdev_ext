// SPDX-License-Identifier: GPL-2.0
/* Variable-length CryptoAPI transforms over independently leased pool pages.
 * No payload bounce or user progress calls. Software is explicitly selected.
 *
 * deflate-iaa maps each side with dma_map_sg() and fails with -EIO unless it
 * gets exactly one DMA segment (iaa_comp_acompress/adecompress), and only its
 * async_irq sync_mode returns -EINPROGRESS; sync and async modes poll inside
 * ->submit, so depth then gives no overlap. A hardware stage is admitted at
 * CREATE only when every source and destination it can be given is one
 * physically contiguous range; IOMMU merging is not relied upon.
 */
#include <crypto/acompress.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/xdev_ext_mech.h>

#define XDEV_EXT_IAA_SG_MAX 128
struct xdev_ext_iaa_request {
 struct xdev_ext_mech_batch *b;
 struct acomp_req *req;
 u64 ticket;
 struct scatterlist src[XDEV_EXT_IAA_SG_MAX], dst[XDEV_EXT_IAA_SG_MAX];
 struct xdev_ext_mech_frame output[XDEV_EXT_MECH_MAX_FRAMES];
};
struct xdev_ext_iaa_stage {
 struct crypto_acomp *tfm;
 struct xdev_ext_iaa_request *requests;
 u32 first, nr, capacity, depth;
 bool dead;
};

/* Request storage is depth-bounded and reused only after its terminal result.
 * CryptoAPI finishes one operation per request (acompress.h); the IAA driver
 * unmaps DMA before its terminal callback (iaa_desc_complete). Duplicate/stale
 * immutable core tickets are rejected, but a provider violating CryptoAPI by
 * calling a previous operation after request reuse is outside this adapter's
 * contract: callback data alone cannot identify that previous operation.
 */
static void xdev_ext_iaa_crypto_done(void *opaque, int err)
{
 struct xdev_ext_iaa_request *r = opaque;
 u32 produced;
 if (err == -EINPROGRESS) return; /* backlog promotion is not terminal */
 if (err > 0 || err < -4095) err = -EIO;
 produced = err ? 0 : READ_ONCE(r->req->dlen);
 /* The core claims the immutable native ticket before publishing metadata. */
 xdev_ext_mech_batch_transform_complete(r->b, r->ticket, err, produced, false);
}

/* Truthful page scatterlists; frame boundaries need not be page boundaries.
 * Physically adjacent pieces extend one entry. Returns the entry count.
 */
static int xdev_ext_iaa_sg(struct xdev_ext_mech_pool *p,
              struct scatterlist *sg, const struct xdev_ext_mech_frame *f, u32 nr)
{
 u32 i, off, po, len, n = 0;
 struct page *page;
 sg_init_table(sg, XDEV_EXT_IAA_SG_MAX);
 for (i = 0; i < nr; i++) {
  off = 0;
  while (off < f[i].data_len) {
   page = xdev_ext_mech_frame_page(p, &f[i], f[i].data_off + off, &po, &len);
   if (!page) return -EFAULT;
   len = min(len, f[i].data_len - off);
   if (n && sg_phys(&sg[n - 1]) + sg[n - 1].length == page_to_phys(page) + po) {
    sg[n - 1].length += len;
   } else {
    if (n >= XDEV_EXT_IAA_SG_MAX) return -E2BIG;
    sg_set_page(&sg[n++], page, len, po);
   }
   off += len;
  }
 }
 if (!n) return -EINVAL;
 sg_mark_end(&sg[n - 1]);
 return n;
}

/* Output window of request slot @slot: its reserved frames, capacity in order. */
static void xdev_ext_iaa_output(const struct xdev_ext_iaa_stage *cs,
                               const struct xdev_ext_mech_layout *l, u32 slot,
                               struct xdev_ext_mech_frame *out)
{
 u32 i, left = cs->capacity;
 for (i = 0; i < cs->nr; i++) {
  out[i] = (struct xdev_ext_mech_frame) {
   .index = cs->first + slot * cs->nr + i,
   .data_off = l->hdr_room, .data_len = min(l->seg_len, left),
  };
  left -= out[i].data_len;
 }
}

/* CREATE: sources are single frames ([hdr_room, hdr_room + seg_len) of any
 * pool frame) and each slot's whole output window is one segment. A source
 * from a preceding multi-frame transform is refused per batch at submit.
 */
static int xdev_ext_iaa_hw_admit(struct xdev_ext_mech_stage *st,
                                struct xdev_ext_iaa_stage *cs)
{
 const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 struct xdev_ext_iaa_request *r = &cs->requests[0];
 u32 i;
 if (DIV_ROUND_UP(l->group_bytes, l->seg_len) != 1) return -EOPNOTSUPP;
 for (i = 0; i < pool->nr_frames; i++) {
  struct xdev_ext_mech_frame f = {
   .index = i, .data_off = l->hdr_room, .data_len = l->seg_len,
  };
  if (xdev_ext_iaa_sg(pool, r->src, &f, 1) != 1) return -EOPNOTSUPP;
 }
 for (i = 0; i < cs->depth; i++) {
  xdev_ext_iaa_output(cs, l, i, r->output);
  if (xdev_ext_iaa_sg(pool, r->dst, r->output, cs->nr) != 1) return -EOPNOTSUPP;
 }
 return 0;
}

static int xdev_ext_iaa_bind(struct xdev_ext_mech_stage *st,
                            const struct xdev_ext_mech_stage_uapi *u)
{
 const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
 struct xdev_ext_iaa_stage *cs;
 u32 i;
 int err;
 if ((u->flags & ~XDEV_EXT_IAA_F_SOFTWARE) || u->arg0 > U32_MAX ||
     !u->arg1 || u->arg1 > CRYPTO_ACOMP_DST_MAX)
  return -EINVAL;
 cs = kzalloc(sizeof(*cs), GFP_KERNEL);
 if (!cs) return -ENOMEM;
 cs->first = u->arg0;
 cs->capacity = u->arg1;
 cs->nr = DIV_ROUND_UP(cs->capacity, l->seg_len);
 cs->depth = xdev_ext_mech_session_depth(st->s);
 if (cs->nr > XDEV_EXT_MECH_MAX_FRAMES) { err = -E2BIG; goto free; }
 cs->tfm = crypto_alloc_acomp(u->flags & XDEV_EXT_IAA_F_SOFTWARE ?
                              "deflate-generic" : "deflate-iaa", 0, 0);
 if (IS_ERR(cs->tfm)) { err = PTR_ERR(cs->tfm); goto free; }
 cs->requests = kvcalloc(cs->depth, sizeof(*cs->requests), GFP_KERNEL);
 if (!cs->requests) { err = -ENOMEM; goto tfm; }
 for (i = 0; i < cs->depth; i++) {
  cs->requests[i].req = acomp_request_alloc(cs->tfm, GFP_KERNEL);
  if (!cs->requests[i].req) { err = -ENOMEM; goto requests; }
 }
 err = xdev_ext_mech_transform_reserve(st, cs->first, cs->depth * cs->nr);
 if (err) goto requests;
 if (!(u->flags & XDEV_EXT_IAA_F_SOFTWARE)) {
  err = xdev_ext_iaa_hw_admit(st, cs);
  if (err) {
   xdev_ext_mech_transform_unreserve(st, cs->first, cs->depth * cs->nr);
   goto requests;
  }
 }
 st->priv = cs;
 return 0;
requests:
 for (i = 0; i < cs->depth; i++) acomp_request_free(cs->requests[i].req);
 kvfree(cs->requests);
tfm:
 crypto_free_acomp(cs->tfm);
free:
 kfree(cs);
 return err;
}

static void xdev_ext_iaa_unbind(struct xdev_ext_mech_stage *st)
{
 struct xdev_ext_iaa_stage *cs = st->priv;
 u32 i;
 /* The core never unbinds a quarantined session with possible native use. */
 xdev_ext_mech_transform_unreserve(st, cs->first, cs->depth * cs->nr);
 for (i = 0; i < cs->depth; i++) acomp_request_free(cs->requests[i].req);
 kvfree(cs->requests);
 crypto_free_acomp(cs->tfm);
 kfree(cs);
 st->priv = NULL;
}

static void xdev_ext_iaa_fill_info(struct xdev_ext_mech_stage *st,
                                  struct xdev_ext_mech_batch *b, void *info)
{
 struct xdev_ext_iaa_stage *cs = st->priv;
 struct xdev_ext_iaa_mech_info *out = info;
 struct xdev_ext_mech_frame f;
 u32 i;
 *out = (struct xdev_ext_iaa_mech_info) {
  .l = *xdev_ext_mech_session_layout(st->s),
  .nr_frames = b ? xdev_ext_mech_batch_nr_frames(b) : 0,
  .dst_frames = cs->nr, .dst_capacity = cs->capacity,
  .software = !!(st->flags & XDEV_EXT_IAA_F_SOFTWARE),
 };
 for (i = 0; i < out->nr_frames; i++) {
  if (xdev_ext_mech_batch_frame(b, i, &f)) { out->nr_frames = 0; break; }
  out->f[i] = (struct xdev_ext_mech_frame_info) {
   .umem_addr = f.umem_addr, .data_off = f.data_off, .data_len = f.data_len,
  };
 }
}

static int xdev_ext_iaa_validate(struct xdev_ext_mech_stage *st,
                struct xdev_ext_mech_batch *b, const u8 *scratch, u32 n)
{
 const struct xdev_ext_iaa_stage *cs = st->priv;
 const struct xdev_ext_iaa_desc *d = (const void *)scratch;
 if (n != 1 || d->flags || d->reserved || !d->src_len ||
     d->src_len != xdev_ext_mech_batch_bytes(b) ||
     d->src_len > CRYPTO_ACOMP_DST_MAX || d->dst_capacity != cs->capacity)
  return -EINVAL;
 return 0;
}

static int xdev_ext_iaa_submit(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b)
{
 struct xdev_ext_iaa_stage *cs = st->priv;
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
 struct xdev_ext_mech_frame src[XDEV_EXT_MECH_MAX_FRAMES];
 struct xdev_ext_iaa_request *r = &cs->requests[xdev_ext_mech_batch_slot(b)];
 u32 i, nr = xdev_ext_mech_batch_nr_frames(b);
 int err, nsrc, ndst;
 if (READ_ONCE(cs->dead)) return -ENODEV;
 for (i = 0; i < nr; i++) {
  err = xdev_ext_mech_batch_frame(b, i, &src[i]);
  if (err) return err;
 }
 xdev_ext_iaa_output(cs, l, xdev_ext_mech_batch_slot(b), r->output);
 nsrc = xdev_ext_iaa_sg(pool, r->src, src, nr);
 if (nsrc < 0) return nsrc;
 ndst = xdev_ext_iaa_sg(pool, r->dst, r->output, cs->nr);
 if (ndst < 0) return ndst;
 /* Outside the CREATE-admitted shape deflate-iaa would fail with -EIO. */
 if (!(st->flags & XDEV_EXT_IAA_F_SOFTWARE) && (nsrc != 1 || ndst != 1))
  return -EOPNOTSUPP;
 err = xdev_ext_mech_batch_transform_begin(b, r->output, cs->nr);
 if (err) return err;
 r->b = b;
 r->ticket = xdev_ext_mech_batch_ticket(b);
 acomp_request_set_params(r->req, r->src, r->dst, xdev_ext_mech_batch_bytes(b), cs->capacity);
 acomp_request_set_callback(r->req, CRYPTO_TFM_REQ_MAY_BACKLOG, xdev_ext_iaa_crypto_done, r);
 err = st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE ?
       crypto_acomp_decompress(r->req) : crypto_acomp_compress(r->req);
 /* A synchronous -EAGAIN is final, callback-free and returned before the
  * provider accepted anything (idxd_submit_desc() could not enqueue on a
  * shared work queue; the IAA driver has already unmapped both sides). The
  * destination is unpublished and the source read-only, so the core restores
  * both leases and resubmits later: scheduling backpressure, not a failure.
  */
 if (err == -EAGAIN) return -EAGAIN;
 if (err != -EINPROGRESS && err != -EBUSY)
  xdev_ext_iaa_crypto_done(r, err);
 /* Entered CryptoAPI: terminal failure is completed, never resubmitted. */
 return 0;
}

static void xdev_ext_iaa_fill_cqe(struct xdev_ext_mech_stage *st,
                               struct xdev_ext_mech_batch *b, void *out)
{
 struct xdev_ext_iaa_stage *cs = st->priv;
 *(struct xdev_ext_iaa_mech_cqe *)out = (struct xdev_ext_iaa_mech_cqe) {
  .status = xdev_ext_mech_batch_status(b),
  .produced = xdev_ext_mech_batch_transform_produced(b), .capacity = cs->capacity,
 };
}
static void xdev_ext_iaa_mark_dead(struct xdev_ext_mech_stage *st)
{
 struct xdev_ext_iaa_stage *cs = st->priv;
 WRITE_ONCE(cs->dead, true);
}
static const struct xdev_ext_mech_class_ops xdev_ext_iaa_class = {
 .class_id = XDEV_EXT_MECH_CLASS_IAA, .flags = XDEV_EXT_MECH_CLASS_F_TRANSFORM,
 .desc_size = sizeof(struct xdev_ext_iaa_desc), .desc_cap = 1,
 .info_size = sizeof(struct xdev_ext_iaa_mech_info),
 .cqe_size = sizeof(struct xdev_ext_iaa_mech_cqe), .cqe_cap = 1,
 .owner = THIS_MODULE, .bind = xdev_ext_iaa_bind, .unbind = xdev_ext_iaa_unbind,
 .fill_info = xdev_ext_iaa_fill_info, .validate = xdev_ext_iaa_validate,
 .submit = xdev_ext_iaa_submit, .fill_cqe = xdev_ext_iaa_fill_cqe,
 .mark_dead = xdev_ext_iaa_mark_dead,
};
static int __init xdev_ext_mech_iaa_init(void)
{
 return xdev_ext_mech_class_register(&xdev_ext_iaa_class);
}
late_initcall_sync(xdev_ext_mech_iaa_init);
