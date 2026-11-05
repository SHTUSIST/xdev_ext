// SPDX-License-Identifier: GPL-2.0
/* Transform execution over storage and lifecycle authority borrowed from core. */
#include <linux/bitops.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xdev_ext_mech.h>

#include "xdev_ext_mech_core.h"
#include "xdev_ext_mech_lifecycle.h"
#include "xdev_ext_mech_cpu_core.h"
#include "xdev_ext_mech_step.h"
#include "xdev_ext_mech_compute_internal.h"
#include "xdev_ext_compfam_transform.h"

static bool xdev_ext_mech_transform_alias(struct xdev_ext_mech_pool *p,
                    const struct xdev_ext_mech_frame *a,
                    const struct xdev_ext_mech_frame *b);

/*
 * CREATE: a table of the page bytes of reserved frames [@first, @first + @nr),
 * sorted, then one walk of every other frame: O((pool + table) log table).
 */
static int xdev_ext_mech_transform_alias_free(struct xdev_ext_mech_session *s,
                        u32 first, u32 nr)
{
 struct xdev_ext_mech_compute_session_access a;
 struct xdev_ext_mech_alias_seg *table;
 u32 i, j, off, po, len, fs;
 size_t n = 0, cap = 0;
 struct page *page;
 int err = 0;

 xdev_ext_mech_compute_session_access(s, &a);
 fs = a.pool->frame_size;
 for (i = 0; i < nr; i++) {
  struct xdev_ext_mech_frame out = { .index = first + i };
  for (off = 0; off < fs; off += len) {
   if (!xdev_ext_mech_frame_page(a.pool, &out, off, &po, &len))
    return -EINVAL;
   len = min(len, fs - off);
   cap++;
  }
 }
 table = kvmalloc_array(cap, sizeof(*table), GFP_KERNEL);
 if (!table)
  return -ENOMEM;
 for (i = 0; i < nr; i++) {
  struct xdev_ext_mech_frame out = { .index = first + i };
  for (off = 0; off < fs && n < cap; off += len, n++) {
   page = xdev_ext_mech_frame_page(a.pool, &out, off, &po, &len);
   len = min(len, fs - off);
   table[n] = (struct xdev_ext_mech_alias_seg){ .page = page, .off = po, .len = len };
  }
 }
 xdev_ext_mech_alias_sort(table, n);
 /* Two reserved outputs, or two pages of one, share bytes. */
 if (xdev_ext_mech_alias_overlapping(table, n))
  err = -EINVAL;
 for (j = 0; !err && j < a.pool->nr_frames; j++) {
  struct xdev_ext_mech_frame other = { .index = j };
  if (j >= first && j - first < nr)
   continue;
  for (off = 0; off < fs; off += len) {
   page = xdev_ext_mech_frame_page(a.pool, &other, off, &po, &len);
   if (!page) { err = -EINVAL; break; }
   len = min(len, fs - off);
   if (xdev_ext_mech_alias_hits(table, n, page, po, len)) { err = -EINVAL; break; }
  }
  cond_resched(); /* uring_lock is a mutex; a 1 GiB pool is many frames */
 }
 kvfree(table);
 return err;
}

/*
 * CREATE owns these output frames until unbind; START cannot lend them.
 * The pool's pages are pinned at registration and fixed while the session
 * holds it, so this one proof covers every later batch: a reserved output
 * shares no page byte with any other frame, START sources included.
 */
int xdev_ext_mech_transform_reserve(struct xdev_ext_mech_stage *st, u32 first, u32 nr)
{
 struct xdev_ext_mech_session *s = st->s;
 struct xdev_ext_mech_compute_session_access a;
 u32 i;
 int err;

 xdev_ext_mech_compute_session_access(s, &a);
 if (a.pool->kind != XDEV_EXT_MECH_POOL_IOU_UMEM || !nr ||
     first >= a.pool->nr_frames || nr > a.pool->nr_frames - first)
  return -EINVAL;
 err = xdev_ext_mech_transform_alias_free(s, first, nr);
 if (err)
  return err;
 for (i = 0; i < nr; i++) {
  if (a.transform_owner[first + i]) { err = -EBUSY; goto undo; }
  err = xdev_ext_mech_pool_frame_move(a.pool, first + i,
                         XDEV_EXT_MECH_F_USER, XDEV_EXT_MECH_F_HELD);
  if (err) goto undo;
  a.transform_owner[first + i] = st->index + 1;
 }
 return 0;
undo:
 while (i--) {
  a.transform_owner[first + i] = 0;
  xdev_ext_mech_pool_frame_move(a.pool, first + i,
                         XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_USER);
 }
 return err;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_transform_reserve);

void xdev_ext_mech_transform_unreserve(struct xdev_ext_mech_stage *st, u32 first, u32 nr)
{
 struct xdev_ext_mech_session *s = st->s;
 struct xdev_ext_mech_compute_session_access a;
 u32 i;

 xdev_ext_mech_compute_session_access(s, &a);
 for (i = 0; i < nr; i++) {
  u32 idx = first + i;
  if (WARN_ON_ONCE(idx >= a.pool->nr_frames ||
      a.transform_owner[idx] != st->index + 1 ||
      xdev_ext_mech_life_phase(&a.life[idx]) != XDEV_EXT_MECH_L_FREE ||
      xdev_ext_mech_pool_frame_state(a.pool, idx) != XDEV_EXT_MECH_F_HELD))
   continue;
  if (!xdev_ext_mech_pool_frame_move(a.pool, idx,
                       XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_USER))
   a.transform_owner[idx] = 0;
 }
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_transform_unreserve);

/* Compare real page intervals, including distinct indices aliasing one page. */
static bool xdev_ext_mech_transform_alias(struct xdev_ext_mech_pool *p,
                    const struct xdev_ext_mech_frame *a,
                    const struct xdev_ext_mech_frame *b)
{
 u32 ai = 0, bi, ao, bo, al, bl;
 struct page *ap, *bp;
 while (ai < a->data_len) {
  ap = xdev_ext_mech_frame_page(p, a, a->data_off + ai, &ao, &al);
  if (!ap) return true;
  al = min(al, a->data_len - ai);
  bi = 0;
  while (bi < b->data_len) {
   bp = xdev_ext_mech_frame_page(p, b, b->data_off + bi, &bo, &bl);
   if (!bp) return true;
   bl = min(bl, b->data_len - bi);
   if (ap == bp && ao < bo + bl && bo < ao + al) return true;
   bi += bl;
  }
  ai += al;
 }
 return false;
}

int xdev_ext_mech_batch_transform_begin(struct xdev_ext_mech_batch *b,
                        const struct xdev_ext_mech_frame *dst, u32 nr)
{
 struct xdev_ext_mech_session *s = xdev_ext_mech_batch_session(b);
 struct xdev_ext_mech_stage *st = xdev_ext_mech_batch_stage(b);
 struct xdev_ext_mech_compute_session_access a;
 struct xdev_ext_mech_compute_batch_access v;
 u32 i, j, begun = 0, moved = 0;
 int err = -EINVAL;

 xdev_ext_mech_compute_session_access(s, &a);
 xdev_ext_mech_compute_batch_access(b, &v);
 if (!(st->cls->flags & XDEV_EXT_MECH_CLASS_F_TRANSFORM) ||
     v.transform->active || !nr || nr > XDEV_EXT_MECH_MAX_FRAMES)
  return -EINVAL;
 for (i = 0; i < *v.nr_frames; i++) {
  const struct xdev_ext_mech_frame *f = &v.f[i];
  if (xdev_ext_mech_life_phase(&a.life[f->index]) != XDEV_EXT_MECH_L_OUT_PENDING ||
      a.life[f->index].valid_len < f->data_len)
   return -ENODATA;
 }
 for (i = 0; i < nr; i++) {
  if (dst[i].index >= a.pool->nr_frames || !dst[i].data_len ||
      dst[i].data_off >= a.pool->frame_size ||
      dst[i].data_len > a.pool->frame_size - dst[i].data_off ||
      a.transform_owner[dst[i].index] != st->index + 1 ||
      xdev_ext_mech_pool_frame_state(a.pool, dst[i].index) != XDEV_EXT_MECH_F_HELD)
   return -EINVAL;
  for (j = 0; j < *v.nr_frames; j++)
   if (xdev_ext_mech_transform_alias(a.pool, &dst[i], &v.f[j])) return -EINVAL;
  /* Reserved windows of other slots/stages are independent leases too;
   * reserve proved at CREATE that no two reserved chunks share a page
   * byte, so only the index, owner and state checks above run per batch.
   */
  for (j = 0; j < i; j++)
   if (dst[i].index == dst[j].index ||
       xdev_ext_mech_transform_alias(a.pool, &dst[i], &dst[j])) return -EINVAL;
 }
 for (i = 0; i < nr; i++) {
  v.transform->dst[i] = dst[i];
  err = a.pool->ops->resolve(a.pool, &v.transform->dst[i]);
  if (err) goto undo;
  err = xdev_ext_mech_life_claim(&a.life[dst[i].index], st->index,
                                        &v.transform->token[i]);
  if (err) goto undo;
  begun++;
  err = xdev_ext_mech_pool_frame_move(a.pool, dst[i].index,
                        XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_INFLIGHT);
  if (err) goto undo;
  moved++;
 }
 v.transform->nr = nr;
 v.transform->produced = 0;
 v.transform->active = true;
 return 0;
undo:
 for (i = 0; i < moved; i++)
  xdev_ext_mech_pool_frame_move(a.pool, dst[i].index,
                        XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD);
 for (i = 0; i < begun; i++)
  WARN_ON_ONCE(xdev_ext_mech_life_rollback(&a.life[dst[i].index],
                        v.transform->token[i]));
 return err;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_transform_begin);

void xdev_ext_mech_batch_transform_complete(struct xdev_ext_mech_batch *b, u64 ticket,
                                          int err, u32 produced, bool sequester)
{
 struct xdev_ext_mech_compute_batch_access v;
 u64 cap = 0;
 u32 i;
 if (xdev_ext_mech_batch_completion_claim(b, ticket)) return;
 xdev_ext_mech_compute_batch_access(b, &v);
 if (!v.transform->active) { err = -EPROTO; sequester = true; }
 for (i = 0; i < v.transform->nr; i++) cap += v.transform->dst[i].data_len;
 if (!err && (!produced || produced > cap)) err = -EOVERFLOW;
 v.transform->produced = err ? 0 : produced;
 xdev_ext_mech_batch_completion_publish(b, ticket, err, sequester);
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_transform_complete);

u32 xdev_ext_mech_batch_transform_produced(const struct xdev_ext_mech_batch *b)
{
 return xdev_ext_mech_compute_transform_state(b)->produced;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_transform_produced);

/* Submit refusal has proven no native owner; restore the entire dst lease. */
void xdev_ext_mech_transform_undo(struct xdev_ext_mech_session *s,
                                       struct xdev_ext_mech_batch *b)
{
 struct xdev_ext_mech_compute_session_access a;
 struct xdev_ext_mech_compute_batch_access v;
 u32 i;

 xdev_ext_mech_compute_session_access(s, &a);
 xdev_ext_mech_compute_batch_access(b, &v);
 if (!v.transform->active) return;
 for (i = 0; i < v.transform->nr; i++) {
  struct xdev_ext_mech_frame *f = &v.transform->dst[i];
  WARN_ON_ONCE(xdev_ext_mech_life_rollback(&a.life[f->index],
                    v.transform->token[i]));
  WARN_ON_ONCE(xdev_ext_mech_pool_frame_move(a.pool, f->index,
                    XDEV_EXT_MECH_F_INFLIGHT, XDEV_EXT_MECH_F_HELD));
 }
 v.transform->active = false;
}

/* Native callback: core has already handed off every source claim. */
int xdev_ext_mech_transform_handoff(struct xdev_ext_mech_batch *b,
                                   u32 refs, int err, bool *sequester)
{
 struct xdev_ext_mech_session *s = xdev_ext_mech_batch_session(b);
 struct xdev_ext_mech_compute_session_access a;
 struct xdev_ext_mech_compute_batch_access v;
 u32 i, left;
 int rc;

 xdev_ext_mech_compute_session_access(s, &a);
 xdev_ext_mech_compute_batch_access(b, &v);
 left = v.transform->produced;
 if (!v.transform->active)
  return err;
 for (i = 0; i < v.transform->nr; i++) {
  struct xdev_ext_mech_frame *f = &v.transform->dst[i];
  struct xdev_ext_mech_life *l = &a.life[f->index];

  if (err || !left) {
   rc = xdev_ext_mech_life_fail_produce(l, v.transform->token[i]);
   f->data_len = 0;
  } else {
   f->data_len = min(f->data_len, left);
   left -= f->data_len;
   if (a.pool->ops->sync_for_cpu)
    a.pool->ops->sync_for_cpu(a.pool, f);
   rc = xdev_ext_mech_life_publish(l, v.transform->token[i], refs, f->data_len);
  }
  if (rc < 0) {
   *sequester = true;
   return -EIO;
  }
 }
 return err;
}

/* Worker only, after source consume is complete. Unknown retains both leases. */
bool xdev_ext_mech_transform_landed(struct xdev_ext_mech_session *s,
                                         struct xdev_ext_mech_batch *b, bool seq)
{
 struct xdev_ext_mech_compute_session_access a;
 struct xdev_ext_mech_compute_batch_access v;
 u32 i, left, used = 0;

 xdev_ext_mech_compute_session_access(s, &a);
 xdev_ext_mech_compute_batch_access(b, &v);
 left = v.transform->produced;
 for (i = 0; i < v.transform->nr; i++) {
  struct xdev_ext_mech_frame *f = &v.transform->dst[i];
  if (xdev_ext_mech_pool_frame_move(a.pool, f->index, XDEV_EXT_MECH_F_INFLIGHT,
                    seq ? XDEV_EXT_MECH_F_SEQUESTERED : XDEV_EXT_MECH_F_HELD))
   seq = true;
  if (seq) {
   xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_SEQUESTERED, 1);
   continue;
  }
  if (!xdev_ext_mech_batch_status(b) && left) {
   left -= f->data_len;
   used++;
  }
 }
 if (seq) {
quarantine:
  /* A partial ownership failure cannot authorize either lease's reuse. */
  for (i = 0; i < v.transform->nr; i++)
   xdev_ext_mech_pool_frame_move(a.pool, v.transform->dst[i].index,
                    XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_SEQUESTERED);
  xdev_ext_mech_frames_move(s, b, XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_SEQUESTERED);
  return true;
 }
 if (!xdev_ext_mech_batch_status(b)) {
  if (WARN_ON_ONCE(left || !used) || xdev_ext_mech_frames_release(s, b))
   goto quarantine;
  memcpy(v.f, v.transform->dst, used * sizeof(v.f[0]));
  *v.nr_frames = used;
  *v.present = (u32)GENMASK_ULL(used - 1, 0);
  *v.bytes = v.transform->produced;
 }
 v.transform->active = false;
 return false;
}

int xdev_ext_mech_batch_cpu_length(struct xdev_ext_mech_batch *b, u32 pos, u32 len)
{
 struct xdev_ext_mech_compute_session_access a;
 struct xdev_ext_mech_compute_batch_access v;
 struct xdev_ext_mech_frame *f;
 u64 claim;

 xdev_ext_mech_compute_batch_access(b, &v);
 if (pos >= *v.nr_frames || !(v.life_active & BIT(pos)))
  return -EINVAL;
 f = &v.f[pos];
 claim = v.life_token[pos];
 xdev_ext_mech_compute_session_access(xdev_ext_mech_batch_session(b), &a);
 if ((claim & XDEV_EXT_MECH_L_STATE_MASK) != XDEV_EXT_MECH_L_CLAIM_EXCLUSIVE ||
     !xdev_ext_mech_life_matches(smp_load_acquire(&a.life[f->index].ctrl), claim))
  return -ESTALE;
 if (len > a.pool->frame_size - f->data_off)
  return -EMSGSIZE;
 *v.bytes = *v.bytes - f->data_len + len;
 f->data_len = len;
 return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_cpu_length);

/*
 * Worker, inside a CPU stage's ->submit: the frames are INFLIGHT and their
 * lifecycle claims exclusive, exactly as for a fixed transform.  The program
 * runs once over the whole batch; C checks every length before and after it
 * and applies the lengths only when all of them are data_len + @delta.
 */
int xdev_ext_mech_batch_compute(struct xdev_ext_mech_batch *b, s32 delta)
{
	struct xdev_ext_mech_session *s = xdev_ext_mech_batch_session(b);
	struct xdev_ext_mech_stage *st = xdev_ext_mech_batch_stage(b);
	struct xdev_ext_binding_ctx_v2 base = xdev_ext_mech_base(st, xdev_ext_mech_batch_bytes(b));
	struct xdev_ext_mech_compute_session_access access;
	struct xdev_ext_mech_compute_batch_access v;
	u32 out[XDEV_EXT_MECH_MAX_FRAMES], want, i;
	struct xdev_ext_mech_call_args a;
	s32 ret = -EPROTO;
	bool illegal;
	int err;

	xdev_ext_mech_compute_session_access(s, &access);
	xdev_ext_mech_compute_batch_access(b, &v);
	if (!st->cls->decl->compute_worker || !*v.nr_frames ||
	    *v.nr_frames > XDEV_EXT_MECH_MAX_FRAMES)
		return -EINVAL;
	/* Every frame can take exactly L + D bytes before any byte changes. */
	for (i = 0; i < *v.nr_frames; i++) {
		if (v.f[i].data_off > access.pool->frame_size)
			return -EINVAL;
		err = xdev_ext_mech_cpu_out_len(XDEV_EXT_CPU_XFORM_BPF, (u64)(s64)delta,
					   v.f[i].data_len,
					   access.pool->frame_size - v.f[i].data_off, &want);
		if (err)
			return err;
		out[i] = v.f[i].data_len;
	}
	xdev_ext_mech_worker_args(s, st, b, XDEV_EXT_MECH_MEMBER_COMPUTE, &base, &a);
	a.out_len = out;
	a.len_delta = delta;
	err = xdev_ext_mech_call(st, &a, &ret, NULL);
	if (err) {
		xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
		return err == -ENOENT ? -EOPNOTSUPP : err;
	}
	ret = xdev_ext_mech_ret_resolve_desc(st->cls->decl, XDEV_EXT_MECH_MEMBER_COMPUTE,
				   XDEV_EXT_MECH_SITE_WORKER, ret, &illegal);
	if (illegal)
		xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
	if (ret)
		return ret;
	for (i = 0; i < *v.nr_frames; i++)
		if ((s64)out[i] != (s64)v.f[i].data_len + delta) {
			xdev_ext_mech_count(s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
			return -EPROTO;
		}
	for (i = 0; i < *v.nr_frames; i++) {
		err = xdev_ext_mech_batch_cpu_length(b, i, out[i]);
		if (err)
			return err;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_compute);
