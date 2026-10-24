// SPDX-License-Identifier: GPL-2.0
/* Device-memory custody for ordinary mechanism batches. The frames contain
 * allocation offsets only: no CPU address, struct page, or host DMA mapping.
 */
#include <linux/file.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_peer.h>
#include "xdev_ext_mech_step.h"
struct xdev_ext_peer_mech_pool {
 struct file *authority;
 u64 generation;
};
/* Undo the takes of one alloc call; only this call moved them to HELD, so
 * each move back cannot fail.
 */
static void xdev_ext_peer_pool_unwind(struct xdev_ext_mech_pool *pool,
                                      struct xdev_ext_mech_frame *f, u32 n)
{
 while (n--)
  xdev_ext_mech_pool_frame_move(pool, f[n].index, XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_K_FREE);
}
/* Worker: @nr frames for one batch.  The lowest run of @nr consecutive free
 * frames keeps a multi-frame NVMe command on one contiguous allocation span;
 * otherwise the @nr lowest free frames in ascending order.  Each take is the
 * ownership-word compare-and-exchange, so a concurrent taker never gets the
 * same frame; -ENOSPC returns everything this call took.
 */
static int xdev_ext_peer_pool_alloc(struct xdev_ext_mech_pool *pool,
                                   struct xdev_ext_mech_frame *f, u32 nr)
{
 u32 i, n = 0;
 if (!nr || nr > XDEV_EXT_MECH_MAX_FRAMES) return -EINVAL;
 for (i = 0; i < pool->nr_frames && n < nr; i++) {
  if (xdev_ext_mech_pool_frame_move(pool, i, XDEV_EXT_MECH_F_K_FREE, XDEV_EXT_MECH_F_HELD)) {
   /* A taken or busy frame breaks the run. */
   xdev_ext_peer_pool_unwind(pool, f, n);
   n = 0;
   continue;
  }
  f[n++] = (struct xdev_ext_mech_frame){ .index = i };
 }
 if (n == nr) return 0;
 xdev_ext_peer_pool_unwind(pool, f, n);
 /* No run: the lowest free frames, ascending. */
 for (i = 0, n = 0; i < pool->nr_frames && n < nr; i++)
  if (!xdev_ext_mech_pool_frame_move(pool, i, XDEV_EXT_MECH_F_K_FREE, XDEV_EXT_MECH_F_HELD))
   f[n++] = (struct xdev_ext_mech_frame){ .index = i };
 if (n == nr) return 0;
 xdev_ext_peer_pool_unwind(pool, f, n);
 return -ENOSPC;
}
static int xdev_ext_peer_pool_resolve(struct xdev_ext_mech_pool *pool,
                                     struct xdev_ext_mech_frame *f)
{
 if (f->index >= pool->nr_frames) return -ERANGE;
 f->kaddr = NULL; f->pool_priv = NULL;
 f->umem_addr = (u64)f->index * pool->frame_size;
 return 0;
}
static void xdev_ext_peer_pool_recycle(struct xdev_ext_mech_pool *pool,
                                      struct xdev_ext_mech_frame *f)
{ (void)pool; (void)f; /* Core already returned the ownership word to K_FREE. */ }
static void xdev_ext_peer_pool_release(struct xdev_ext_mech_pool *pool)
{
 struct xdev_ext_peer_mech_pool *p = pool->priv;
 fput(p->authority);
 kvfree(pool->state); kfree(p);
}
static const struct xdev_ext_mech_pool_ops xdev_ext_peer_pool_ops = {
 .alloc = xdev_ext_peer_pool_alloc, .resolve = xdev_ext_peer_pool_resolve,
 .recycle = xdev_ext_peer_pool_recycle, .release = xdev_ext_peer_pool_release,
};
int xdev_ext_peer_mech_pool_bind(struct xdev_ext_mech_pool *pool, struct file *file,
                                const struct xdev_ext_mech_layout *layout)
{
 struct xdev_ext_peer_mech_pool *p;
 u64 len, generation, frames;
 struct file *authority;
 int nr;
 if (!pool || !layout) return -EINVAL;
 /* Geometry is exactly the CREATE capability rule; several frames per batch. */
 if (xdev_ext_mech_peer_layout_check(layout)) return -EOPNOTSUPP;
 nr = xdev_ext_mech_layout_frames(layout);
 if (nr < 0) return nr;
 p = kzalloc(sizeof(*p), GFP_KERNEL);
 if (!p) return -ENOMEM;
 authority = xdev_ext_peer_file_claim(file, &len, &generation);
 if (IS_ERR(authority)) { kfree(p); return PTR_ERR(authority); }
 frames = len / layout->frame_size;
 if (!frames || frames > U32_MAX || len % layout->frame_size) {
  fput(authority); kfree(p); return -EINVAL;
 }
 pool->state = kvmalloc_array(frames, sizeof(*pool->state), GFP_KERNEL);
 if (!pool->state) { fput(authority); kfree(p); return -ENOMEM; }
 memset(pool->state, XDEV_EXT_MECH_F_K_FREE, frames);
 p->authority = authority; p->generation = generation;
 *pool = (struct xdev_ext_mech_pool){ .ops = &xdev_ext_peer_pool_ops, .priv = p,
   .state = pool->state, .size = len, .kind = XDEV_EXT_MECH_POOL_PEER,
   .capabilities = XDEV_EXT_BINDING_CAP_ZERO_COPY,
   .frame_size = layout->frame_size, .nr_frames = frames };
 return 0;
}
struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *pool)
{
 struct xdev_ext_peer_mech_pool *p;
 if (!pool || pool->kind != XDEV_EXT_MECH_POOL_PEER || pool->ops != &xdev_ext_peer_pool_ops)
  return NULL;
 p = pool->priv; return p->authority;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_mech_pool_file);
u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *pool)
{
 struct xdev_ext_peer_mech_pool *p;
 if (!xdev_ext_peer_mech_pool_file(pool)) return 0;
 p = pool->priv; return p->generation;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_mech_pool_generation);
