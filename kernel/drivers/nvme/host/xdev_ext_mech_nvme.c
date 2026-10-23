// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe class of the XDEV_EXT mechanism layer.
 *
 * A stage binds one NVMe generic namespace (/dev/ngXnY), captures its
 * identity once and fixes an LBA window inside it.  For each batch the
 * session worker runs the NVMe program's build into a one-slot scratch SQE;
 * ->validate admits that SQE with nvme_xdev_ext_mech_validate() and keeps the
 * admitted bytes with the batch; ->submit rechecks the namespace identity,
 * builds a passthrough request whose bio carries the batch frames page by
 * page, and executes it.  The completion records the native status and
 * result for the program's complete.  The program never sees a page, a DMA
 * address, a queue slot or a doorbell; nvme-pci maps the bio and writes the
 * SQ entry and doorbell as for any passthrough command.
 *
 * On a GPU-memory pool (XDEV_EXT_MECH_POOL_PEER) the frames are allocation
 * offsets.  ->submit leases the controller's DMA address of each GPU page
 * from the provider and issues one bio-less command whose SGL already names
 * those addresses.  It completes through end_io like the host-page command;
 * the worker releases the leases in ->fill_cqe, quiesced only on success.
 */

#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/dma-mapping.h>
#include <linux/highmem.h>
#include <linux/moduleparam.h>
#include <linux/nvme_xdev_ext_passthru.h>
#include <linux/pci.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_peer.h>
#include <uapi/linux/xdev_ext_peer.h>
#include <linux/capability.h>
#include "nvme.h"
#include "xdev_ext_peer_nvme_core.h"

struct nvme_xdev_ext_mech_slot;
struct nvme_xdev_ext_peer_slot;
struct nvme_xdev_ext_peer_res;

struct nvme_xdev_ext_mech_stage {
	struct nvme_ns *ns;		/* pinned by the stage file */
	struct nvme_xdev_ext_identity identity;
	const struct nvme_ns_head *head;
	const struct gendisk *disk;
	const struct request_queue *queue;
	bool write;
	atomic_t dead;
	/* Only this session's worker mutates the free list. End_io records a
  * terminal outcome; fill_cqe returns a definitively drained slot. */
	struct nvme_xdev_ext_mech_slot *slots, *free;
	u32 nr_slots;
	u16 nr_vecs;
	struct nvme_xdev_ext_peer_res *peer;	/* GPU-memory pool only */
};

/* xdev_ext_mech_batch_priv(): ->validate fills it for ->submit of the same batch. */
struct nvme_xdev_ext_mech_batch {
	u8 sqe[NVME_XDEV_EXT_SQE_SIZE];	/* the SQE ->validate admitted */
	u64 batch_id;
	bool validated;
	struct bio *bio;
	struct nvme_xdev_ext_mech_slot *slot;
	struct page **bounce;
	u32 nr_bounce;
	struct xdev_ext_nvme_mech_cqe cqe;	/* written by end_io */
	struct nvme_xdev_ext_peer_slot *peer_slot;
};

/* Owned by one native request until end_io; never re-read a reused batch ticket. */
struct nvme_xdev_ext_mech_completion {
	struct xdev_ext_mech_batch *b;
	u64 ticket;
	bool uncertain;
};

/*
 * One bounded lease per possible live batch, allocated at CREATE. A native
 * request retains this context and bio until end_io and worker consumption.
 */
struct nvme_xdev_ext_mech_slot {
	struct nvme_xdev_ext_mech_completion done;
	struct nvme_xdev_ext_mech_slot *next;
	struct bio *bio;
	struct page **bounce;
	u32 nr_bounce;
	bool busy, bio_live;
};

/* Process context: only after drain, or unwinding a failed CREATE. */
static bool nvme_xdev_ext_class_resources_free(struct nvme_xdev_ext_mech_stage *p)
{
	u32 i;

	if (!p->slots)
		return true;
	for (i = 0; i < p->nr_slots; i++)
		if (WARN_ON_ONCE(p->slots[i].busy))
			return false; /* Accepted or quarantined leases remain pinned. */
	for (i = 0; i < p->nr_slots; i++) {
		struct nvme_xdev_ext_mech_slot *slot = &p->slots[i];

		if (slot->bio_live)
			bio_uninit(slot->bio);
#if !defined(CONFIG_XDEV_EXT_MECH_ZEROCOPY) && defined(CONFIG_XDEV_EXT_MECH_KVM_BOUNCE)
		{
			u32 j;

			for (j = 0; j < slot->nr_bounce; j++)
				if (slot->bounce[j])
					__free_page(slot->bounce[j]);
			kfree(slot->bounce);
		}
#endif
		kfree(slot->bio);
	}
	kfree(p->slots);
	p->slots = p->free = NULL;
	p->nr_slots = 0;
	return true;
}

/*
 * CREATE: reserve metadata by depth, never native request tags or DMA state.
 * A frame may start at the last byte of a physical page. The conservative
 * page bound is capped at the same bio limit enforced by map admission.
 */
static int nvme_xdev_ext_class_resources_init(struct xdev_ext_mech_stage *st)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
	u64 pieces;
	u32 i;

	if (xdev_ext_mech_session_pool(st->s)->kind == XDEV_EXT_MECH_POOL_PEER)
		return 0;
	p->nr_slots = xdev_ext_mech_session_depth(st->s);
	if (!p->nr_slots || !l->seg_len || !l->group_bytes || !l->frame_size)
		return -EINVAL;
	pieces = DIV_ROUND_UP((u64)l->group_bytes, l->seg_len) *
          DIV_ROUND_UP((u64)l->frame_size + PAGE_SIZE - 1, PAGE_SIZE);
	if (!pieces)
		return -EINVAL;
	p->nr_vecs = min_t(u64, pieces, BIO_MAX_INLINE_VECS);
	p->slots = kcalloc(p->nr_slots, sizeof(*p->slots), GFP_KERNEL);
	if (!p->slots)
		return -ENOMEM;
	for (i = 0; i < p->nr_slots; i++) {
		struct nvme_xdev_ext_mech_slot *slot = &p->slots[i];

		slot->bio = bio_kmalloc(p->nr_vecs, GFP_KERNEL);
		if (!slot->bio)
			goto fail;
#if !defined(CONFIG_XDEV_EXT_MECH_ZEROCOPY) && defined(CONFIG_XDEV_EXT_MECH_KVM_BOUNCE)
		{
			u32 j, nr = DIV_ROUND_UP(l->group_bytes, PAGE_SIZE);

			/* This explicitly marked compatibility build may copy CPU payloads. */
			if (nr && nr <= BIO_MAX_INLINE_VECS) {
				slot->bounce = kcalloc(nr, sizeof(*slot->bounce), GFP_KERNEL);
				if (!slot->bounce)
					goto fail;
				slot->nr_bounce = nr;
				for (j = 0; j < nr; j++) {
					slot->bounce[j] = alloc_page(GFP_KERNEL);
					if (!slot->bounce[j])
						goto fail;
				}
			}
		}
#endif
		slot->next = p->free;
		p->free = slot;
	}
	return 0;
fail:
	nvme_xdev_ext_class_resources_free(p);
	return -ENOMEM;
}

/* Worker: no accepted command can share a bio or completion context. */
static struct nvme_xdev_ext_mech_slot *
nvme_xdev_ext_class_slot_get(struct xdev_ext_mech_stage *st,
                        struct nvme_xdev_ext_mech_batch *bp)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct nvme_xdev_ext_mech_slot *slot;

	if (bp->slot)
		return ERR_PTR(-EBUSY);
	slot = p->free;
	if (!slot)
		return ERR_PTR(-EAGAIN);
	p->free = slot->next;
	slot->next = NULL;
	slot->busy = true;
	slot->done.uncertain = false;
	bp->slot = slot;
	return slot;
}

/* Worker: preaccept unwind, or native completion consumed by fill_cqe. */
static void nvme_xdev_ext_class_slot_put(struct xdev_ext_mech_stage *st,
                                   struct nvme_xdev_ext_mech_batch *bp)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct nvme_xdev_ext_mech_slot *slot = bp->slot;

	if (!slot || slot->done.uncertain)
		return;
	if (slot->bio_live) {
		bio_uninit(slot->bio);
		slot->bio_live = false;
	}
	bp->bio = NULL;
	bp->bounce = NULL;
	bp->nr_bounce = 0;
	bp->slot = NULL;
	slot->busy = false;
	slot->next = p->free;
	p->free = slot;
}

/* At most one 4 KiB descriptor list per command, the size of an nvme-pci
 * "nvme descriptor page" (NVME_CTRL_PAGE_SIZE / 16 SGL descriptors). */
#define NVME_XDEV_EXT_PEER_MAX_PIECES	256U
/* xdev_ext_peer_map() accepts no provider page smaller than 4 KiB. */
#define NVME_XDEV_EXT_PEER_MIN_PAGE_SHIFT	12
/* nvme-pci aligns its lists to 256 bytes, 512 under NVME_QUIRK_DMAPOOL_ALIGN_512. */
#define NVME_XDEV_EXT_PEER_SGL_ALIGN	512U

/*
 * GPU-memory command context, one per possible live batch, allocated at
 * CREATE like the host slots.  It holds the provider leases and the
 * descriptor list from ->submit until the worker consumed the completion.
 */
struct nvme_xdev_ext_peer_slot {
	struct xdev_ext_peer_nvme_seg spans[NVME_XDEV_EXT_PEER_MAX_PIECES];
	struct nvme_xdev_ext_mech_completion done;
	struct nvme_xdev_ext_peer_slot *next;
	struct xdev_ext_peer_fd_lease *leases;	/* max_pieces, in payload order */
	struct nvme_sgl_desc *sgl;		/* max_pieces, controller-readable */
	dma_addr_t sgl_dma;
	u32 nr_leases;
	bool busy;
};

struct nvme_xdev_ext_peer_res {
	struct device *dma_dev;			/* the controller's PCI function */
	struct nvme_xdev_ext_peer_slot *slots, *free;	/* free: worker only */
	struct xdev_ext_peer_fd_lease *leases;
	struct nvme_sgl_desc *sgl;
	dma_addr_t sgl_dma;
	size_t sgl_bytes;
	u32 nr_slots, max_pieces;
};

/* Process context: only after drain, or unwinding a failed CREATE. */
static bool nvme_xdev_ext_peer_resources_free(struct nvme_xdev_ext_mech_stage *p)
{
	struct nvme_xdev_ext_peer_res *res = p->peer;
	u32 i;

	if (!res)
		return true;
	for (i = 0; i < res->nr_slots; i++)
		if (WARN_ON_ONCE(res->slots[i].busy))
			return false; /* The controller may still read the list. */
	if (res->sgl)
		dma_free_coherent(res->dma_dev, res->sgl_bytes, res->sgl,
				  res->sgl_dma);
	kvfree(res->leases);
	kvfree(res->slots);
	kfree(res);
	p->peer = NULL;
	return true;
}

/*
 * CREATE, process context: slots, lease records and descriptor lists bounded
 * by depth.  A frame of frame_size bytes spans at most frame_size / 4 KiB + 1
 * provider pages.
 */
static int nvme_xdev_ext_peer_resources_init(struct xdev_ext_mech_stage *st)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
	u32 i, stride, depth = xdev_ext_mech_session_depth(st->s);
	struct device *dev = p->ns->ctrl->dev;
	struct nvme_xdev_ext_peer_res *res;
	u64 pieces;

	if (xdev_ext_mech_session_pool(st->s)->kind != XDEV_EXT_MECH_POOL_PEER)
		return 0;
	if (!dev || !dev_is_pci(dev))
		return -EOPNOTSUPP;
	if (!depth || !l->seg_len || !l->group_bytes || !l->frame_size)
		return -EINVAL;
	pieces = DIV_ROUND_UP((u64)l->group_bytes, l->seg_len) *
		 (DIV_ROUND_UP((u64)l->frame_size, SZ_4K) + 1);
	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;
	p->peer = res;
	res->dma_dev = dev;
	res->max_pieces = min_t(u64, pieces, NVME_XDEV_EXT_PEER_MAX_PIECES);
	res->slots = kvcalloc(depth, sizeof(*res->slots), GFP_KERNEL);
	res->leases = kvcalloc((size_t)depth * res->max_pieces,
			       sizeof(*res->leases), GFP_KERNEL);
	/* Each slot's list starts on the alignment nvme-pci gives its lists. */
	/* A PRP list must not cross a controller page, even for small batches. */
	stride = SZ_4K / sizeof(*res->sgl);
	res->sgl_bytes = (size_t)depth * stride * sizeof(*res->sgl);
	if (res->slots && res->leases)
		res->sgl = dma_alloc_coherent(dev, res->sgl_bytes, &res->sgl_dma,
					      GFP_KERNEL);
	if (!res->sgl) {
		nvme_xdev_ext_peer_resources_free(p);
		return -ENOMEM;
	}
	res->nr_slots = depth;
	for (i = 0; i < depth; i++) {
		struct nvme_xdev_ext_peer_slot *slot = &res->slots[i];

		slot->leases = &res->leases[(size_t)i * res->max_pieces];
		slot->sgl = &res->sgl[(size_t)i * stride];
		slot->sgl_dma = res->sgl_dma +
			(dma_addr_t)i * stride * sizeof(*slot->sgl);
		slot->next = res->free;
		res->free = slot;
	}
	return 0;
}

#ifndef CONFIG_XDEV_EXT_MECH_ZEROCOPY
#ifdef CONFIG_XDEV_EXT_MECH_KVM_BOUNCE
#define NVME_XDEV_EXT_MECH_BOUNCE_AVAILABLE
static atomic64_t nvme_xdev_ext_mech_bounces;

static int nvme_xdev_ext_mech_bounces_get(char *buffer,
				     const struct kernel_param *kp)
{
	return sysfs_emit(buffer, "%lld\n",
			  (long long)atomic64_read(&nvme_xdev_ext_mech_bounces));
}

static int nvme_xdev_ext_mech_bounces_set(const char *value,
				     const struct kernel_param *kp)
{
	return -EPERM;
}

static const struct kernel_param_ops nvme_xdev_ext_mech_bounces_ops = {
	.set = nvme_xdev_ext_mech_bounces_set,
	.get = nvme_xdev_ext_mech_bounces_get,
};
module_param_cb(xdev_ext_mech_bounces, &nvme_xdev_ext_mech_bounces_ops, NULL, 0444);
MODULE_PARM_DESC(xdev_ext_mech_bounces,
		 "XDEV_EXT mechanism NVMe batches copied through kernel pages (KVM test builds)");

/* Worker: the batch payload, in frame order, to or from the bounce pages. */
static void nvme_xdev_ext_class_bounce_copy(struct xdev_ext_mech_batch *b,
				       struct nvme_xdev_ext_mech_batch *bp,
				       bool to_pages)
{
	u32 pos, nr = xdev_ext_mech_batch_nr_frames(b), done = 0;
	struct xdev_ext_mech_frame f;

	for (pos = 0; pos < nr && !xdev_ext_mech_batch_frame(b, pos, &f); pos++) {
		u8 *data = (u8 *)f.kaddr + f.data_off;
		u32 off, len;

		for (off = 0; off < f.data_len; off += len, done += len) {
			struct page *page = bp->bounce[done >> PAGE_SHIFT];

			len = min_t(u32, f.data_len - off,
				    PAGE_SIZE - offset_in_page(done));
			if (to_pages)
				memcpy_to_page(page, offset_in_page(done),
					       data + off, len);
			else
				memcpy_from_page(data + off, page,
						 offset_in_page(done), len);
		}
	}
}

/*
 * KVM test builds only (plan section 4.1, failure branch 3): when the
 * emulated controller cannot take the frames as they are, copy the payload
 * into whole kernel pages and count it.
 */
static int nvme_xdev_ext_class_bounce(struct xdev_ext_mech_stage *st,
				 struct xdev_ext_mech_batch *b, struct request *req,
				 struct nvme_xdev_ext_mech_batch *bp)
{
	const struct nvme_xdev_ext_mech_stage *p = st->priv;
	u32 bytes = xdev_ext_mech_batch_bytes(b);
	u32 i, len, nr = DIV_ROUND_UP(bytes, PAGE_SIZE);
	struct nvme_xdev_ext_mech_slot *slot = bp->slot;
	struct bio *bio;
	int ret = -ENOMEM;

	if (!nr || nr > BIO_MAX_INLINE_VECS)
		return -EREMOTEIO;
	if (!slot || nr > slot->nr_bounce)
		return -EREMOTEIO;
	bp->bounce = slot->bounce;
	bp->nr_bounce = nr;
	if (p->write)
		nvme_xdev_ext_class_bounce_copy(b, bp, true);

	bio = slot->bio;
	bio_init(bio, NULL, bio->bi_inline_vecs,
          ((struct nvme_xdev_ext_mech_stage *)st->priv)->nr_vecs, req->cmd_flags);
	slot->bio_live = true;
	for (i = 0; i < nr; i++) {
		len = min_t(u32, bytes - i * PAGE_SIZE, PAGE_SIZE);
		if (bio_add_page(bio, bp->bounce[i], len, 0) != len) {
			ret = -EREMOTEIO;
			goto out_bio;
		}
	}
	ret = blk_rq_append_bio(req, bio);
	if (ret)
		goto out_bio;
	bp->bio = bio;
	atomic64_inc(&nvme_xdev_ext_mech_bounces);
	pr_warn_once("nvme: XDEV_EXT mechanism batches are bounced (CONFIG_XDEV_EXT_MECH_KVM_BOUNCE)\n");
	return 0;

out_bio:
	bio_uninit(bio);
	slot->bio_live = false;
	bp->bounce = NULL;
	bp->nr_bounce = 0;
	return ret;
}

/* Worker: a READ's payload goes back into the frames only on success. */
static void nvme_xdev_ext_class_bounce_release(struct xdev_ext_mech_batch *b,
					  struct nvme_xdev_ext_mech_batch *bp,
					  bool copy_back)
{
	if (!bp->bounce)
		return;
	if (copy_back)
		nvme_xdev_ext_class_bounce_copy(b, bp, false);
	bp->bounce = NULL;
	bp->nr_bounce = 0;
}
#endif /* CONFIG_XDEV_EXT_MECH_KVM_BOUNCE */
#endif /* !CONFIG_XDEV_EXT_MECH_ZEROCOPY */

#ifndef NVME_XDEV_EXT_MECH_BOUNCE_AVAILABLE
static int nvme_xdev_ext_class_bounce(struct xdev_ext_mech_stage *st,
				 struct xdev_ext_mech_batch *b, struct request *req,
				 struct nvme_xdev_ext_mech_batch *bp)
{
	return -EREMOTEIO;
}

static void nvme_xdev_ext_class_bounce_release(struct xdev_ext_mech_batch *b,
					  struct nvme_xdev_ext_mech_batch *bp,
					  bool copy_back)
{
}
#endif /* !NVME_XDEV_EXT_MECH_BOUNCE_AVAILABLE */

/*
 * CREATE: only a non-multipath /dev/ngXnY (the one whose uring_cmd is
 * nvme_ns_chr_uring_cmd) binds; its open pins the namespace.
 */
static struct nvme_ns *nvme_xdev_ext_class_ns(struct file *file)
{
	if (!file->f_op || file->f_op->uring_cmd != nvme_ns_chr_uring_cmd)
		return NULL;
	return container_of(file_inode(file)->i_cdev, struct nvme_ns, cdev);
}

static int nvme_xdev_ext_class_bind(struct xdev_ext_mech_stage *st,
			       const struct xdev_ext_mech_stage_uapi *u)
{
	const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
	bool write = st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE;
	struct nvme_xdev_ext_mech_stage *p;
	struct nvme_ns *ns;
	int ret;

	if (u->flags || (!write && st->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE))
		return -EINVAL;
	ns = nvme_xdev_ext_class_ns(st->file);
	if (!ns)
		return -EOPNOTSUPP;
#ifdef CONFIG_XDEV_EXT_MECH_ZEROCOPY
	/* Only PCI has the strict SGL/no-bounce transport contract below. */
	if (xdev_ext_mech_session_pool(st->s)->kind != XDEV_EXT_MECH_POOL_PEER &&
	    (strcmp(ns->ctrl->ops->name, "pcie") ||
	     !nvme_ctrl_sgl_supported(ns->ctrl) || queue_virt_boundary(ns->queue)))
		return -EOPNOTSUPP;
#endif
 if (xdev_ext_mech_session_pool(st->s)->kind == XDEV_EXT_MECH_POOL_PEER) {
  if (!capable(CAP_SYS_RAWIO)) return -EPERM;
  if (!ns->ctrl->ops->peer_rw || strcmp(ns->ctrl->ops->name, "pcie")) return -EOPNOTSUPP;
  if (!write && !(st->file->f_mode & FMODE_READ)) return -EBADF;
 }
	if (write && !(st->file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!nvme_xdev_ext_mech_cmd_allowed(ns, st->file, write))
		return -EACCES;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	p->ns = ns;
	p->write = write;
	ret = nvme_xdev_ext_capture_identity(ns, &p->identity, &p->head, &p->disk,
					&p->queue);
	if (!ret)
		ret = nvme_xdev_ext_mech_bind_check(&p->identity, write, st->arg0,
					       st->arg1, l->group_bytes);
	if (ret) {
		kfree(p);
		return ret;
	}
	st->priv = p;
	ret = nvme_xdev_ext_class_resources_init(st);
	if (!ret)
		ret = nvme_xdev_ext_peer_resources_init(st);
	if (ret) {
		st->priv = NULL;
		kfree(p);
	}
	return ret;
}

static void nvme_xdev_ext_class_unbind(struct xdev_ext_mech_stage *st)
{
	if (!nvme_xdev_ext_peer_resources_free(st->priv) ||
	    !nvme_xdev_ext_class_resources_free(st->priv))
		return;
	kfree(st->priv);
	st->priv = NULL;
}

/* Any context: the stage's class information; @b NULL for a uring_cmd. */
void nvme_xdev_ext_mech_fill_info(struct xdev_ext_mech_stage *st,
			     struct xdev_ext_mech_batch *b, void *out)
{
	const struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct xdev_ext_nvme_mech_info *info = out;
	struct xdev_ext_mech_frame f;
	u32 i, nr;

	memset(info, 0, sizeof(*info));
	info->l = *xdev_ext_mech_session_layout(st->s);
	info->lba_shift = p->identity.lba_shift;
	info->max_nlb = min_t(u32, NVME_XDEV_EXT_MAX_NLB,
			      queue_max_hw_sectors(p->ns->queue) >>
			      (p->identity.lba_shift - SECTOR_SHIFT));
	info->window_slba = st->arg0;
	info->window_nlb = st->arg1;
	info->capacity_lbas = p->identity.capacity_lbas;
	info->sgl = nvme_ctrl_sgl_supported(p->ns->ctrl);
	if (!b)
		return;
	nr = min_t(u32, xdev_ext_mech_batch_nr_frames(b), XDEV_EXT_MECH_MAX_FRAMES);
	for (i = 0; i < nr && !xdev_ext_mech_batch_frame(b, i, &f); i++)
		info->f[i] = (struct xdev_ext_mech_frame_info) {
			.umem_addr = f.umem_addr,
			.data_off = f.data_off,
			.data_len = f.data_len,
		};
	info->nr_frames = i;
}

/*
 * F_XDEV_EXT_BUILD uring_cmd: the stage is alive, the command targets the bound
 * namespace, and that namespace is still what CREATE captured.
 */
int nvme_xdev_ext_mech_stage_matches(struct xdev_ext_mech_stage *st, struct nvme_ns *ns,
				const struct nvme_xdev_ext_identity *identity)
{
	const struct nvme_xdev_ext_mech_stage *p = st->priv;

	if (!p || atomic_read(&p->dead))
		return -ENODEV;
	if (p->ns != ns)
		return -EXDEV;
	if (!nvme_xdev_ext_identity_equal(&p->identity, identity))
		return -ESTALE;
	return 0;
}

static int nvme_xdev_ext_class_validate(struct xdev_ext_mech_stage *st,
				   struct xdev_ext_mech_batch *b, const u8 *scratch,
				   u32 n)
{
	const struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);
	struct nvme_xdev_ext_mech_bounds bounds = {
		.window_slba = st->arg0,
		.window_nlb = st->arg1,
		.capacity_lbas = p->identity.capacity_lbas,
		.data_len = xdev_ext_mech_batch_bytes(b),
		.lba_shift = p->identity.lba_shift,
		.write = p->write,
	};
	struct nvme_xdev_ext_decoded decoded;
	int ret;

	bp->validated = false;
	if (n != 1)
		return -EPROTO;
	ret = nvme_xdev_ext_mech_validate(scratch, &bounds, &decoded);
	if (ret)
		return ret;
	memcpy(bp->sqe, scratch, NVME_XDEV_EXT_SQE_SIZE);
	bp->batch_id = xdev_ext_mech_batch_id(b);
	bp->validated = true;
	return 0;
}

/* Worker: the namespace is still the one CREATE bound; else the stage dies. */
static int nvme_xdev_ext_class_recheck(struct xdev_ext_mech_stage *st)
{
	const struct nvme_xdev_ext_mech_stage *p = st->priv;
	const struct request_queue *queue;
	const struct nvme_ns_head *head;
	struct nvme_xdev_ext_identity id;
	const struct gendisk *disk;
	int ret;

	ret = nvme_xdev_ext_capture_identity(p->ns, &id, &head, &disk, &queue);
	if (!ret && (head != p->head || disk != p->disk || queue != p->queue ||
		     !nvme_xdev_ext_identity_equal(&p->identity, &id)))
		ret = -ESTALE;
	if (ret)
		xdev_ext_mech_stage_dead(st, ret);
	return ret;
}

static struct nvme_xdev_ext_queue_caps
nvme_xdev_ext_class_caps(const struct nvme_xdev_ext_mech_stage *p)
{
	struct request_queue *q = p->ns->queue;

	return (struct nvme_xdev_ext_queue_caps) {
		.virt_boundary_mask = queue_virt_boundary(q),
		.page_size = PAGE_SIZE,
		.dma_align_mask = blk_lim_dma_alignment_and_pad(&q->limits),
		.max_segments = queue_max_segments(q),
		.max_segment_size = queue_max_segment_size(q),
		.max_bytes = queue_max_hw_sectors(q) << SECTOR_SHIFT,
		.lba_size = 1U << p->identity.lba_shift,
	};
}

/*
 * Worker: visit the batch payload page by page in frame order, checking
 * each piece against the queue (@bio NULL) or adding it to @bio.  Returns
 * the number of pieces or -errno.
 */
static int nvme_xdev_ext_class_walk(struct xdev_ext_mech_stage *st,
			       struct xdev_ext_mech_batch *b,
			       struct nvme_xdev_ext_seg_walk *walk, struct bio *bio)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	u32 pos, nr = xdev_ext_mech_batch_nr_frames(b);
	struct page *prev = NULL;
	int pieces = 0, ret;

	for (pos = 0; pos < nr; pos++) {
		struct xdev_ext_mech_frame f;
		u32 off, left, page_off, len;
		struct page *page;

		ret = xdev_ext_mech_batch_frame(b, pos, &f);
		if (ret)
			return ret;
		for (off = f.data_off, left = f.data_len; left;
		     off += len, left -= len) {
			page = xdev_ext_mech_frame_page(pool, &f, off, &page_off,
						   &len);
			if (!page)
				return -EFAULT;
			len = min(len, left);
			if (bio) {
				if (bio_add_page(bio, page, len, page_off) != len)
					return -EREMOTEIO;
			} else {
				ret = nvme_xdev_ext_seg_add(walk, page_off, len,
						       page == prev);
				if (ret)
					return ret;
			}
			prev = page;
			pieces++;
		}
	}
	return pieces;
}

/*
 * Worker: the batch payload as the request's bio, built from the frame
 * pages with bio_add_page() (CHK.8).  Fails closed with -EREMOTEIO when the
 * queue cannot take the pieces as they are: DMA alignment, a gap under the
 * virtual boundary, too many segments, or a split that blk_rq_append_bio()
 * refuses.  Only a CONFIG_XDEV_EXT_MECH_KVM_BOUNCE build copies instead.
 */
static int nvme_xdev_ext_class_map(struct xdev_ext_mech_stage *st,
			      struct xdev_ext_mech_batch *b, struct request *req,
			      struct nvme_xdev_ext_mech_batch *bp)
{
	struct nvme_xdev_ext_queue_caps caps = nvme_xdev_ext_class_caps(st->priv);
	struct nvme_xdev_ext_seg_walk walk;
	struct bio *bio;
	int pieces, ret;

	nvme_xdev_ext_seg_walk_init(&walk, &caps);
	pieces = nvme_xdev_ext_class_walk(st, b, &walk, NULL);
	ret = pieces < 0 ? pieces : nvme_xdev_ext_seg_done(&walk);
	if (!ret && walk.bytes != xdev_ext_mech_batch_bytes(b))
		ret = -EPROTO;
	if (!ret && pieces > BIO_MAX_INLINE_VECS)
		ret = -EREMOTEIO;
	if (!ret) {
		struct nvme_xdev_ext_mech_stage *p = st->priv;

		if (!bp->slot || pieces > p->nr_vecs)
			return -EREMOTEIO;
		bio = bp->slot->bio;
		bio_init(bio, NULL, bio->bi_inline_vecs, p->nr_vecs, req->cmd_flags);
		bp->slot->bio_live = true;
		ret = nvme_xdev_ext_class_walk(st, b, NULL, bio);
		if (ret >= 0)
			ret = blk_rq_append_bio(req, bio);
		if (!ret) {
			bp->bio = bio;
			return 0;
		}
		bio_uninit(bio);
		bp->slot->bio_live = false;
	}
	if (ret != -EREMOTEIO)
		return ret;
	return nvme_xdev_ext_class_bounce(st, b, req, bp);
}

/* Any context: the native completion, kept for the worker's fill_cqe. */
static enum rq_end_io_ret nvme_xdev_ext_class_end_io(struct request *req,
						 blk_status_t err)
{
	struct nvme_xdev_ext_mech_completion *done = req->end_io_data;
	struct xdev_ext_mech_batch *b = done->b;
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);
	u64 ticket = done->ticket;
	bool uncertain, full_batch;
	int status;

	if (xdev_ext_mech_batch_completion_claim(b, ticket))
		return RQ_END_IO_FREE;
	/* The uring_cmd convention: NVMe status > 0, -errno without one. */
	if (nvme_req(req)->flags & NVME_REQ_CANCELLED)
		status = -EINTR;
	else
		status = nvme_req(req)->status ?: blk_status_to_errno(err);
	/* The block batch completion loop already ends every bio in the optimized NVMe
	 * completion batch, but deliberately preserves bio/__data_len for a
	 * passthrough request's end_io. That exact owned bio and original length
	 * are bookkeeping, not evidence of a short DMA. A successful CQE is also
	 * required; a short, foreign or missing bio retains the conservative
	 * residual handling below. The PCI transport has unmapped before end_io. */
	full_batch = !status && bp->bio && req->bio == bp->bio &&
		blk_rq_bytes(req) == xdev_ext_mech_batch_bytes(b);
	uncertain = blk_rq_bytes(req) != 0 && !full_batch;
	if (uncertain && !status)
		status = -EIO;
	done->uncertain = uncertain;
	nvme_xdev_ext_mech_cqe(status, le64_to_cpu(nvme_req(req)->result.u64),
			  &bp->cqe);
	xdev_ext_mech_batch_completion_publish(b, ticket, status, uncertain);
	return RQ_END_IO_FREE;
}

/* Worker: a free GPU-memory slot, or preaccept backpressure. */
static struct nvme_xdev_ext_peer_slot *
nvme_xdev_ext_peer_slot_get(struct nvme_xdev_ext_peer_res *res,
			    struct nvme_xdev_ext_mech_batch *bp)
{
	struct nvme_xdev_ext_peer_slot *slot = res->free;

	if (bp->peer_slot)
		return ERR_PTR(-EBUSY);
	if (!slot)
		return ERR_PTR(-EAGAIN);
	res->free = slot->next;
	slot->next = NULL;
	slot->busy = true;
	slot->nr_leases = 0;
	slot->done.uncertain = false;
	bp->peer_slot = slot;
	return slot;
}

/*
 * Worker, process context: return the leases of a command that was never
 * issued or whose completion the worker consumed.  After an uncertain
 * outcome the controller may still access the GPU memory or the descriptor
 * list: the leases retire unquiesced, which quarantines the allocation and
 * its mapping for good (xdev_ext_peer_release()), and the slot stays busy.
 */
static void nvme_xdev_ext_peer_slot_put(struct nvme_xdev_ext_peer_res *res,
					struct nvme_xdev_ext_mech_batch *bp)
{
	struct nvme_xdev_ext_peer_slot *slot = bp->peer_slot;
	bool quiesced;
	u32 i;

	if (!slot)
		return;
	quiesced = !slot->done.uncertain;
	for (i = 0; i < slot->nr_leases; i++)
		xdev_ext_peer_fd_release(&slot->leases[i], quiesced);
	slot->nr_leases = 0;
	bp->peer_slot = NULL;
	if (!quiesced)
		return;
	slot->busy = false;
	slot->next = res->free;
	res->free = slot;
}

/*
 * Worker: lease GPU memory from @off, at most @left bytes, inside one
 * provider page.  The page size is private to the provider mapping and at
 * least 4 KiB; a span the provider refuses with -ERANGE is cut at the next
 * smaller power-of-two boundary until it fits.
 */
static int nvme_xdev_ext_peer_lease(struct file *file, struct pci_dev *pdev,
				    u64 generation, u64 off, u32 left,
				    enum dma_data_direction dir,
				    struct xdev_ext_peer_fd_lease *l)
{
	u32 shift = 31, len = left;
	int ret;

	for (;;) {
		ret = xdev_ext_peer_file_acquire(file, pdev, generation, off, len,
						 dir, l);
		if (ret != -ERANGE)
			return ret;
		while (shift >= NVME_XDEV_EXT_PEER_MIN_PAGE_SHIFT &&
		       ALIGN_DOWN(off, 1ULL << shift) + (1ULL << shift) - off >= len)
			shift--;
		if (shift < NVME_XDEV_EXT_PEER_MIN_PAGE_SHIFT)
			return ret;
		len = ALIGN_DOWN(off, 1ULL << shift) + (1ULL << shift) - off;
	}
}

/*
 * Worker: lease the batch payload page by page in frame order and describe
 * it to the controller: one inline SGL data block when the leased pages are
 * DMA-contiguous, else a last-segment list in the slot, the layout that
 * nvme_pci_setup_sgls() builds for host pages.  Any error is before native
 * acceptance; the caller returns what was leased.
 */
static int nvme_xdev_ext_peer_map(struct xdev_ext_mech_stage *st,
				  struct xdev_ext_mech_batch *b,
				  struct nvme_xdev_ext_peer_slot *slot, u32 bytes,
				  struct nvme_command *cmd)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct nvme_xdev_ext_peer_res *res = p->peer;
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	struct file *authority = xdev_ext_peer_mech_pool_file(pool);
	u64 generation = xdev_ext_peer_mech_pool_generation(pool);
	enum dma_data_direction dir = p->write ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
	u32 pos, n = 0, total = 0;
	u32 nr = xdev_ext_mech_batch_nr_frames(b);
	u64 prp1, prp2;
	int ret;

	if (!authority || !nr)
		return -EINVAL;
	for (pos = 0; pos < nr; pos++) {
		struct xdev_ext_mech_frame f;
		u32 left, len;
		u64 off;

		ret = xdev_ext_mech_batch_frame(b, pos, &f);
		if (ret)
			return ret;
		if (f.kaddr || !f.data_len || f.data_off > pool->frame_size ||
		    f.data_len > pool->frame_size - f.data_off ||
		    f.umem_addr != (u64)f.index * pool->frame_size)
			return -EPROTO;
		for (off = f.umem_addr + f.data_off, left = f.data_len; left;
		     off += len, left -= len) {
			struct xdev_ext_peer_fd_lease *l;

			if (slot->nr_leases == res->max_pieces)
				return -EREMOTEIO;
			l = &slot->leases[slot->nr_leases];
			ret = nvme_xdev_ext_peer_lease(authority,
						       to_pci_dev(res->dma_dev),
						       generation, off, left, dir, l);
			if (ret)
				return ret;
			slot->nr_leases++;
			len = l->lease.len;
			if (!len || len > left || total > bytes || len > bytes - total)
				return -EPROTO;
			slot->spans[slot->nr_leases - 1] =
				(struct xdev_ext_peer_nvme_seg){ l->lease.dma_address, len };
			total += len;
		}
	}
	if (total != bytes)
		return -EINVAL;
	if (nvme_ctrl_sgl_supported(p->ns->ctrl)) {
		ret = xdev_ext_peer_nvme_sgl_build(slot->spans, slot->nr_leases,
				slot->spans, res->max_pieces, &n);
		if (ret)
			return ret;
		for (pos = 0; pos < n; pos++)
			slot->sgl[pos] = (struct nvme_sgl_desc) {
				.addr = cpu_to_le64(slot->spans[pos].addr),
				.length = cpu_to_le32(slot->spans[pos].len),
				.type = NVME_SGL_FMT_DATA_DESC << 4,
			};
		if (n == 1)
			cmd->rw.dptr.sgl = slot->sgl[0];
		else
			cmd->rw.dptr.sgl = (struct nvme_sgl_desc) {
				.addr = cpu_to_le64(slot->sgl_dma),
				.length = cpu_to_le32(n * sizeof(*slot->sgl)),
				.type = NVME_SGL_FMT_LAST_SEG_DESC << 4,
			};
	} else {
		u64 *list = (u64 *)slot->sgl;

		ret = xdev_ext_peer_nvme_prp_build(slot->spans, slot->nr_leases,
				NVME_XDEV_EXT_PEER_MIN_PAGE_SHIFT, slot->sgl_dma,
				list, SZ_4K / sizeof(*list), &prp1, &prp2, &n);
		if (ret)
			return ret;
		for (pos = 0; pos < n; pos++)
			list[pos] = cpu_to_le64(list[pos]);
		cmd->rw.dptr.prp1 = cpu_to_le64(prp1);
		cmd->rw.dptr.prp2 = cpu_to_le64(prp2);
	}
	return 0;
}

/* Any context: the native completion, kept for the worker's fill_cqe. */
static enum rq_end_io_ret nvme_xdev_ext_peer_end_io(struct request *req,
						    blk_status_t err)
{
	struct nvme_xdev_ext_mech_completion *done = req->end_io_data;
	struct xdev_ext_mech_batch *b = done->b;
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);
	u64 ticket = done->ticket;
	int status;

	if (xdev_ext_mech_batch_completion_claim(b, ticket))
		return RQ_END_IO_FREE;
	if (nvme_req(req)->flags & NVME_REQ_CANCELLED)
		status = -EINTR;
	else
		status = nvme_req(req)->status ?: blk_status_to_errno(err);
	/* An error or a cancellation does not prove that peer DMA stopped. */
	done->uncertain = status != 0;
	nvme_xdev_ext_mech_cqe(status, le64_to_cpu(nvme_req(req)->result.u64),
			       &bp->cqe);
	xdev_ext_mech_batch_completion_publish(b, ticket, status, done->uncertain);
	return RQ_END_IO_FREE;
}

/*
 * Worker: one native command for the whole batch, issued like the host-page
 * command.  The admission of nvme_pci_peer_rw() precedes acceptance; once
 * blk_execute_rq_nowait() has the request only end_io and the worker's
 * fill_cqe touch the slot, so up to depth commands are outstanding.
 */
static int nvme_xdev_ext_peer_submit(struct xdev_ext_mech_stage *st,
				     struct xdev_ext_mech_batch *b)
{
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct nvme_xdev_ext_peer_slot *slot;
	struct xdev_ext_peer_nvme_plan plan;
	struct nvme_command cmd = {};
	struct nvme_ns *ns = p->ns;
	struct request *req;
	u64 slba;
	int ret;

	if (!p->peer)
		return -EINVAL;
	if (nvme_ctrl_state(ns->ctrl) != NVME_CTRL_LIVE ||
	    !test_bit(NVME_NS_READY, &ns->flags) ||
	    test_bit(NVME_NS_REMOVING, &ns->flags))
		return -ENODEV;
	if (ns->head->lba_shift < SECTOR_SHIFT || ns->head->lba_shift > 31)
		return -EINVAL;
	if (p->write && get_disk_ro(ns->disk))
		return -EROFS;
	slba = (u64)nvme_xdev_ext_sqe_dw(bp->sqe, 10) |
	       (u64)nvme_xdev_ext_sqe_dw(bp->sqe, 11) << 32;
	ret = xdev_ext_peer_nvme_plan(ns->head->lba_shift,
			get_capacity(ns->disk) >> (ns->head->lba_shift - SECTOR_SHIFT),
			ns->head->ms, ns->head->ids.csi, slba,
			xdev_ext_mech_batch_bytes(b), p->write, &plan);
	if (ret)
		return ret;
	if (plan.bytes > (u64)queue_max_hw_sectors(ns->queue) << SECTOR_SHIFT)
		return -E2BIG;
	cmd.rw.opcode = plan.opcode;
	cmd.rw.nsid = cpu_to_le32(p->identity.nsid);
	cmd.rw.slba = cpu_to_le64(plan.slba);
	cmd.rw.length = cpu_to_le16(plan.nlb);

	/* Tag pressure is preaccept backpressure, as for host pages. */
	req = blk_mq_alloc_request(ns->queue, nvme_req_op(&cmd),
				   BLK_MQ_REQ_NOWAIT);
	if (IS_ERR(req))
		return PTR_ERR(req);
	slot = nvme_xdev_ext_peer_slot_get(p->peer, bp);
	if (IS_ERR(slot)) {
		blk_mq_free_request(req);
		return PTR_ERR(slot);
	}
	ret = nvme_xdev_ext_peer_map(st, b, slot, plan.bytes, &cmd);
	if (ret) {
		nvme_xdev_ext_peer_slot_put(p->peer, bp);
		blk_mq_free_request(req);
		return ret;
	}
	nvme_init_request(req, &cmd);
	/*
	 * nvme_init_request() clears the SGL bits of ordinary passthrough. These
	 * descriptors are already mapped for this PCI function, as in
	 * nvme_pci_peer_rw(); without a bio nvme-pci neither maps nor unmaps.
	 */
	if (nvme_ctrl_sgl_supported(ns->ctrl))
		nvme_req(req)->cmd->common.flags |= NVME_CMD_SGL_METABUF;
	req->cmd_flags |= REQ_FAILFAST_MASK;
	nvme_req(req)->flags |= NVME_REQ_USERCMD;
	slot->done.b = b;
	slot->done.ticket = xdev_ext_mech_batch_ticket(b);
	req->end_io = nvme_xdev_ext_peer_end_io;
	req->end_io_data = &slot->done;
	/* As for host pages, end_io may run before this returns. */
	blk_execute_rq_nowait(req, false);
	return 0;
}

static int nvme_xdev_ext_class_submit(struct xdev_ext_mech_stage *st,
				 struct xdev_ext_mech_batch *b)
{
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct nvme_command cmd = {};
	struct request *req;
	struct nvme_xdev_ext_mech_completion *done;
	struct nvme_xdev_ext_mech_slot *slot;
	int ret;

	if (atomic_read(&p->dead))
		return -ENODEV;
	if (!bp->validated || bp->batch_id != xdev_ext_mech_batch_id(b))
		return -EPROTO;
	ret = nvme_xdev_ext_class_recheck(st);
	if (ret)
		return ret;

 if (xdev_ext_mech_session_pool(st->s)->kind == XDEV_EXT_MECH_POOL_PEER)
  return nvme_xdev_ext_peer_submit(st, b);
	/* Only the admitted opcode, SLBA and NLB; C owns every other field. */
	cmd.rw.opcode = bp->sqe[0];
	cmd.rw.nsid = cpu_to_le32(p->identity.nsid);
	cmd.common.cdw10 = cpu_to_le32(nvme_xdev_ext_sqe_dw(bp->sqe, 10));
	cmd.common.cdw11 = cpu_to_le32(nvme_xdev_ext_sqe_dw(bp->sqe, 11));
	cmd.common.cdw12 = cpu_to_le32(nvme_xdev_ext_sqe_dw(bp->sqe, 12));

	/*
	 * Tag pressure is preaccept backpressure: -EWOULDBLOCK is -EAGAIN,
	 * which the core rolls back and retries after a delay.
	 */
	req = blk_mq_alloc_request(p->ns->queue, nvme_req_op(&cmd),
				   BLK_MQ_REQ_NOWAIT);
	if (IS_ERR(req))
		return PTR_ERR(req);
	nvme_init_request(req, &cmd);
	nvme_req(req)->flags |= NVME_REQ_USERCMD;
#ifdef CONFIG_XDEV_EXT_MECH_ZEROCOPY
	nvme_req(req)->flags |= NVME_REQ_XDEV_EXT_ZC;
#endif
	slot = nvme_xdev_ext_class_slot_get(st, bp);
	if (IS_ERR(slot)) {
		blk_mq_free_request(req);
		return PTR_ERR(slot);
	}
	done = &slot->done;
	done->b = b;
	done->ticket = xdev_ext_mech_batch_ticket(b);
	ret = nvme_xdev_ext_class_map(st, b, req, bp);
	if (ret) {
		nvme_xdev_ext_class_slot_put(st, bp);
		blk_mq_free_request(req);
		return ret;
	}
	req->end_io = nvme_xdev_ext_class_end_io;
	req->end_io_data = done;
	/*
	 * The core marked the batch IN_FLIGHT before ->submit: end_io may
	 * run before this returns, even from here when the queue is dead.
	 */
	blk_execute_rq_nowait(req, false);
	return 0;
}

static void nvme_xdev_ext_class_fill_cqe(struct xdev_ext_mech_stage *st,
				    struct xdev_ext_mech_batch *b, void *cqe)
{
	const struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);

	nvme_xdev_ext_class_bounce_release(b, bp, !p->write && !bp->cqe.status &&
					     !bp->cqe.err &&
		xdev_ext_mech_session_state(st->s) != XDEV_EXT_MECH_SESSION_ZOMBIE);
	if (xdev_ext_mech_session_state(st->s) != XDEV_EXT_MECH_SESSION_ZOMBIE)
		nvme_xdev_ext_class_slot_put(st, bp);
	memcpy(cqe, &bp->cqe, sizeof(bp->cqe));
	bp->validated = false;
}

/* Worker: a GPU-memory completion; its leases go back here, never in end_io. */
static void nvme_xdev_ext_peer_fill_cqe(struct xdev_ext_mech_stage *st,
					struct xdev_ext_mech_batch *b, void *cqe)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);

	/* After the drain timed out every lease stays with the session. */
	if (xdev_ext_mech_session_state(st->s) != XDEV_EXT_MECH_SESSION_ZOMBIE)
		nvme_xdev_ext_peer_slot_put(p->peer, bp);
	memcpy(cqe, &bp->cqe, sizeof(bp->cqe));
	bp->validated = false;
}

/* Worker: ->fill_cqe for either pool kind. */
static void nvme_xdev_ext_stage_fill_cqe(struct xdev_ext_mech_stage *st,
					 struct xdev_ext_mech_batch *b, void *cqe)
{
	if (xdev_ext_mech_session_pool(st->s)->kind == XDEV_EXT_MECH_POOL_PEER)
		nvme_xdev_ext_peer_fill_cqe(st, b, cqe);
	else
		nvme_xdev_ext_class_fill_cqe(st, b, cqe);
}

static void nvme_xdev_ext_class_mark_dead(struct xdev_ext_mech_stage *st)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;

	if (p)
		atomic_set(&p->dead, 1);
}

static const struct xdev_ext_mech_class_ops nvme_xdev_ext_mech_class = {
	.class_id = XDEV_EXT_MECH_CLASS_NVME,
	.desc_size = NVME_XDEV_EXT_SQE_SIZE,
	.desc_cap = 1,
	.info_size = sizeof(struct xdev_ext_nvme_mech_info),
	.cqe_size = sizeof(struct xdev_ext_nvme_mech_cqe),
	.cqe_cap = 1,
	.batch_priv_size = sizeof(struct nvme_xdev_ext_mech_batch),
	.owner = THIS_MODULE,
	.bind = nvme_xdev_ext_class_bind,
	.unbind = nvme_xdev_ext_class_unbind,
	.fill_info = nvme_xdev_ext_mech_fill_info,
	.validate = nvme_xdev_ext_class_validate,
	.submit = nvme_xdev_ext_class_submit,
	.fill_cqe = nvme_xdev_ext_stage_fill_cqe,
	.mark_dead = nvme_xdev_ext_class_mark_dead,
};

static bool nvme_xdev_ext_mech_registered;

/* nvme-core init: NVMe keeps working when the class cannot register. */
void nvme_xdev_ext_mech_init(void)
{
	int ret = xdev_ext_mech_class_register(&nvme_xdev_ext_mech_class);

	if (ret)
		pr_warn("nvme: XDEV_EXT mechanism class not registered: %d\n", ret);
	nvme_xdev_ext_mech_registered = !ret;
}

void nvme_xdev_ext_mech_exit(void)
{
	if (nvme_xdev_ext_mech_registered)
		xdev_ext_mech_class_unregister(&nvme_xdev_ext_mech_class);
	nvme_xdev_ext_mech_registered = false;
}
