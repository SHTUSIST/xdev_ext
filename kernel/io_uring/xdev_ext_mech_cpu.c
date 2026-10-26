// SPDX-License-Identifier: GPL-2.0
/* Fixed kernel transforms over the registered CPU mapping. Variable output
 * uses separate, CREATE-reserved frames of the same pool and its producer lease.
 * XDEV_EXT_CPU_XFORM_BPF runs the verified compute member of the pinned CPU
 * struct_ops generation instead (Documentation/userspace-api/xdev_ext-compute.rst).
 * No user function pointers, payload staging allocation, or per-request allocation.
 */
#include <crypto/acompress.h>
#include <crypto/sha2.h>
#include <linux/crc32.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/xdev_ext_compfam.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xxhash.h>
#include "xdev_ext_mech_cpu_core.h"

#define XDEV_EXT_CPU_SG_MAX 128
struct xdev_ext_cpu_request {
 struct acomp_req *req;
 struct scatterlist src[XDEV_EXT_CPU_SG_MAX], dst[XDEV_EXT_CPU_SG_MAX];
 struct xdev_ext_mech_frame output[XDEV_EXT_MECH_MAX_FRAMES];
};
struct xdev_ext_cpu_stage {
 struct crypto_acomp *tfm;
 struct xdev_ext_cpu_request *requests;
 struct xdev_ext_cpu_desc selected;
 struct xdev_ext_mech_batch *staged;
 u32 first, nr, depth, capacity;
 bool dead;
};

static u32 xdev_ext_cpu_crc(u32 crc, const void *p, size_t len)
{
 return crc32c(crc, p, len);
}
static u64 xdev_ext_cpu_hash(const void *p, size_t len, u64 seed)
{
 return xxh64(p, len, seed);
}
static void xdev_ext_cpu_digest(const void *p, size_t len, u8 out[32])
{
 sha256(p, len, out);
}
static const struct xdev_ext_mech_cpu_prims xdev_ext_cpu_prims = {
 .crc32c = xdev_ext_cpu_crc, .xxh64 = xdev_ext_cpu_hash, .sha256 = xdev_ext_cpu_digest,
};

static int xdev_ext_cpu_sg(struct xdev_ext_mech_pool *pool, struct scatterlist *sg,
                          const struct xdev_ext_mech_frame *f, u32 nr)
{
 u32 i, n = 0;

 sg_init_table(sg, XDEV_EXT_CPU_SG_MAX);
 for (i = 0; i < nr; i++) {
  u32 done = 0;

  while (done < f[i].data_len) {
   u32 off, len;
   struct page *page = xdev_ext_mech_frame_page(pool, &f[i], f[i].data_off + done, &off, &len);

   if (!page || n == XDEV_EXT_CPU_SG_MAX)
    return -E2BIG;
   len = min(len, f[i].data_len - done);
   sg_set_page(&sg[n++], page, len, off);
   done += len;
  }
 }
 if (!n)
  return -EINVAL;
 sg_mark_end(&sg[n - 1]);
 return 0;
}

static int xdev_ext_cpu_bind(struct xdev_ext_mech_stage *st,
                            const struct xdev_ext_mech_stage_uapi *u)
{
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
 struct xdev_ext_cpu_stage *cs;
 u32 i, total;
 int err;

 if (!pool->vaddr || u->fd != -1 || u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE)
  return -EOPNOTSUPP;
 cs = kzalloc(sizeof(*cs), GFP_KERNEL);
 if (!cs)
  return -ENOMEM;
 cs->depth = xdev_ext_mech_session_depth(st->s);
 /* No silent C path: BPF compute needs a compute program at CREATE. */
 if (xdev_ext_mech_cpu_xform_bpf(u->arg0) &&
     !xdev_ext_mech_stage_has_member(st, XDEV_EXT_MECH_MEMBER_COMPUTE)) {
  kfree(cs);
  return -EOPNOTSUPP;
 }
 if (xdev_ext_mech_cpu_xform_fixed(u->arg0) || xdev_ext_mech_cpu_xform_bpf(u->arg0)) {
  st->priv = cs;
  return 0;
 }
 cs->capacity = u->arg1;
 cs->nr = DIV_ROUND_UP(cs->capacity, l->seg_len);
 total = cs->nr * cs->depth;
 if (!cs->nr || cs->nr > XDEV_EXT_MECH_MAX_FRAMES || total > pool->nr_frames) {
  err = -ENOSPC;
  goto free;
 }
 /* Select the synchronous generic CPU implementation explicitly. */
 cs->tfm = crypto_alloc_acomp("deflate-generic", 0, CRYPTO_ALG_ASYNC);
 if (IS_ERR(cs->tfm)) {
  err = PTR_ERR(cs->tfm);
  goto free;
 }
 cs->requests = kvcalloc(cs->depth, sizeof(*cs->requests), GFP_KERNEL);
 if (!cs->requests) {
  err = -ENOMEM;
  goto tfm;
 }
 for (i = 0; i < cs->depth; i++) {
  cs->requests[i].req = acomp_request_alloc(cs->tfm, GFP_KERNEL);
  if (!cs->requests[i].req) {
   err = -ENOMEM;
   goto requests;
  }
 }
 /* Explicit reserved destination windows: no source can acquire these frames.
  * Search at CREATE only; the bounded pool owns their mapping until teardown. */
 cs->first = pool->nr_frames - total;
 for (;;) {
  err = xdev_ext_mech_transform_reserve(st, cs->first, total);
  if (!err)
   break;
  if (!cs->first)
   goto requests;
  cs->first--;
 }
 st->priv = cs;
 return 0;
requests:
 for (i = 0; i < cs->depth; i++)
  acomp_request_free(cs->requests[i].req);
 kvfree(cs->requests);
tfm:
 crypto_free_acomp(cs->tfm);
free:
 kfree(cs);
 return err;
}

static void xdev_ext_cpu_unbind(struct xdev_ext_mech_stage *st)
{
 struct xdev_ext_cpu_stage *cs = st->priv;
 u32 i;

 if (cs->tfm) {
  xdev_ext_mech_transform_unreserve(st, cs->first, cs->depth * cs->nr);
  for (i = 0; i < cs->depth; i++)
   acomp_request_free(cs->requests[i].req);
  kvfree(cs->requests);
  crypto_free_acomp(cs->tfm);
 }
 kfree(cs);
 st->priv = NULL;
}

static int xdev_ext_cpu_default_build(struct xdev_ext_mech_stage *st,
                                     struct xdev_ext_mech_batch *b, u8 *scratch)
{
 *(struct xdev_ext_cpu_desc *)scratch = (struct xdev_ext_cpu_desc) {
  .xform = st->arg0, .param = st->arg1,
 };
 return 0;
}

static int xdev_ext_cpu_validate(struct xdev_ext_mech_stage *st,
                                struct xdev_ext_mech_batch *b, const u8 *scratch, u32 n)
{
 struct xdev_ext_cpu_stage *cs = st->priv;
 const struct xdev_ext_cpu_desc *d = (const void *)scratch;
 int err;

 cs->staged = NULL;
 if (n != 1)
  return -EINVAL;
 err = xdev_ext_mech_cpu_desc_check(d, st->arg0, st->arg1);
 if (err)
  return err;
 /* A program may pick BPF compute only when its generation has one. */
 if (xdev_ext_mech_cpu_xform_bpf(d->xform) &&
     !xdev_ext_mech_stage_has_member(st, XDEV_EXT_MECH_MEMBER_COMPUTE))
  return -EOPNOTSUPP;
 cs->selected = *d;
 cs->staged = b;
 return 0;
}

static int xdev_ext_cpu_submit(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b)
{
 struct xdev_ext_cpu_stage *cs = st->priv;
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
 struct xdev_ext_mech_frame src[XDEV_EXT_MECH_MAX_FRAMES];
 struct xdev_ext_cpu_request *r;
 u32 i, nr = xdev_ext_mech_batch_nr_frames(b), produced = 0, left;
 u64 ticket = xdev_ext_mech_batch_ticket(b);
 int err;

 if (READ_ONCE(cs->dead))
  return -ENODEV;
 if (cs->staged != b)
  return -EPROTO;
 cs->staged = NULL;
 if (xdev_ext_mech_cpu_xform_bpf(cs->selected.xform)) {
  __s64 delta;

  /* Once per batch; a failure is terminal, the payload may be half changed. */
  err = xdev_ext_mech_cpu_len_delta(cs->selected.xform, cs->selected.param, &delta);
  if (!err)
   err = xdev_ext_mech_batch_compute(b, (s32)delta);
  xdev_ext_mech_batch_complete(b, ticket, err);
  return 0;
 }
 for (i = 0; i < nr; i++) {
  err = xdev_ext_mech_batch_frame(b, i, &src[i]);
  if (err)
   return err;
 }
 if (xdev_ext_mech_cpu_xform_fixed(cs->selected.xform)) {
  for (i = 0; i < nr; i++) {
   u32 len;

   err = xdev_ext_mech_cpu_apply(&xdev_ext_cpu_prims, cs->selected.xform,
     cs->selected.param, (u8 *)src[i].kaddr + src[i].data_off, src[i].data_len,
     pool->frame_size - src[i].data_off, &len);
   if (err)
    break;
   err = xdev_ext_mech_batch_cpu_length(b, i, len);
   if (err)
    break;
  }
  /* Even a transform error has a terminal native return; never retry mutation. */
  xdev_ext_mech_batch_complete(b, ticket, err);
  return 0;
 }
 r = &cs->requests[xdev_ext_mech_batch_slot(b)];
 left = cs->capacity;
 for (i = 0; i < cs->nr; i++) {
  r->output[i] = (struct xdev_ext_mech_frame) {
   .index = cs->first + xdev_ext_mech_batch_slot(b) * cs->nr + i,
   .data_off = l->hdr_room, .data_len = min(l->seg_len, left),
  };
  left -= r->output[i].data_len;
 }
 err = xdev_ext_cpu_sg(pool, r->src, src, nr);
 if (!err)
  err = xdev_ext_cpu_sg(pool, r->dst, r->output, cs->nr);
 if (!err)
  err = xdev_ext_mech_batch_transform_begin(b, r->output, cs->nr);
 if (err)
  return err;
 acomp_request_set_params(r->req, r->src, r->dst, xdev_ext_mech_batch_bytes(b), cs->capacity);
 err = cs->selected.xform == XDEV_EXT_CPU_XFORM_DEFLATE ?
  crypto_acomp_compress(r->req) : crypto_acomp_decompress(r->req);
 err = xdev_ext_mech_cpu_var_result(err, r->req->dlen, cs->capacity, &produced);
 xdev_ext_mech_batch_transform_complete(b, ticket, err, produced, false);
 return 0;
}

static void xdev_ext_cpu_mark_dead(struct xdev_ext_mech_stage *st)
{
 struct xdev_ext_cpu_stage *cs = st->priv;
 WRITE_ONCE(cs->dead, true);
}
static const struct xdev_ext_comp_hooks xdev_ext_cpu_comp_hooks = {
 .hdr = { .family = XDEV_EXT_FAMILY_COMPUTE },
 .kinds = (1U << XDEV_EXT_COMP_INPLACE) | (1U << XDEV_EXT_COMP_TRANSFORM),
 .producer_visibility = XDEV_EXT_CAP_NOT_APPLICABLE,
};
static const struct xdev_ext_mech_class_ops xdev_ext_cpu_class = {
 .class_id = XDEV_EXT_MECH_CLASS_CPU, .flags = XDEV_EXT_MECH_CLASS_F_TRANSFORM,
 .desc_size = sizeof(struct xdev_ext_cpu_desc), .desc_cap = 1,
 .owner = THIS_MODULE, .bind = xdev_ext_cpu_bind, .unbind = xdev_ext_cpu_unbind,
 .default_build = xdev_ext_cpu_default_build, .validate = xdev_ext_cpu_validate,
 .submit = xdev_ext_cpu_submit, .mark_dead = xdev_ext_cpu_mark_dead,
 .fam.comp = &xdev_ext_cpu_comp_hooks,
};
static int __init xdev_ext_mech_cpu_init(void)
{
 return xdev_ext_mech_class_register(&xdev_ext_cpu_class);
}
late_initcall_sync(xdev_ext_mech_cpu_init);
