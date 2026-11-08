// SPDX-License-Identifier: GPL-2.0
/* Storage-family block resources, payload mapping and async issue/consume. */
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/export.h>
#include <linux/dma-mapping.h>
#include <linux/highmem.h>
#include <linux/pci.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_requester.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_storfam_block.h>
#include <linux/xdev_ext_storfam_runtime.h>

struct xdev_ext_stor_queue_caps
xdev_ext_stor_block_caps(struct request_queue *queue, __u8 lba_shift)
{
	return (struct xdev_ext_stor_queue_caps) {
		.virt_boundary_mask = queue_virt_boundary(queue),
		.page_size = PAGE_SIZE,
		.dma_align_mask = blk_lim_dma_alignment_and_pad(&queue->limits),
		.max_segments = queue_max_segments(queue),
		.max_segment_size = queue_max_segment_size(queue),
		.max_bytes = queue_max_hw_sectors(queue) << SECTOR_SHIFT,
		.lba_size = 1U << lba_shift,
	};
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_block_caps);

/* Visit the actual batch payload in frame/page order. With no bio, qualify
 * each piece; otherwise append it to the caller's already initialized bio.
 */
static int xdev_ext_stor_block_walk(struct xdev_ext_mech_pool *pool,
		struct xdev_ext_mech_batch *batch,
		struct xdev_ext_stor_seg_walk *walk, struct bio *bio)
{
	u32 pos, nr = xdev_ext_mech_batch_nr_frames(batch);
	struct page *prev = NULL;
	int pieces = 0, ret;

	for (pos = 0; pos < nr; pos++) {
		struct xdev_ext_mech_frame frame;
		u32 off, left, page_off, len;
		struct page *page;

		ret = xdev_ext_mech_batch_frame(batch, pos, &frame);
		if (ret)
			return ret;
		for (off = frame.data_off, left = frame.data_len; left;
		     off += len, left -= len) {
			page = xdev_ext_mech_frame_page(pool, &frame, off,
						   &page_off, &len);
			if (!page)
				return -EFAULT;
			len = min(len, left);
			if (bio) {
				if (bio_add_page(bio, page, len, page_off) != len)
					return -EREMOTEIO;
			} else {
				ret = xdev_ext_stor_seg_add(walk, page_off, len,
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

int xdev_ext_stor_block_preflight(struct xdev_ext_mech_pool *pool,
		struct xdev_ext_mech_batch *batch,
		const struct xdev_ext_stor_queue_caps *caps)
{
	struct xdev_ext_stor_seg_walk walk;
	int pieces, ret;

	xdev_ext_stor_seg_walk_init(&walk, caps);
	pieces = xdev_ext_stor_block_walk(pool, batch, &walk, NULL);
	ret = pieces < 0 ? pieces : xdev_ext_stor_seg_done(&walk);
	if (!ret && walk.bytes != xdev_ext_mech_batch_bytes(batch))
		ret = -EPROTO;
	if (!ret && pieces > BIO_MAX_INLINE_VECS)
		ret = -EREMOTEIO;
	return ret ? ret : pieces;
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_block_preflight);

static int xdev_ext_stor_block_fill(struct xdev_ext_mech_pool *pool,
		struct xdev_ext_mech_batch *batch, struct bio *bio)
{
	return xdev_ext_stor_block_walk(pool, batch, NULL, bio);
}

int xdev_ext_stor_block_append(struct xdev_ext_mech_pool *pool,
		struct xdev_ext_mech_batch *batch, struct request *request,
		struct bio *bio)
{
	int ret = xdev_ext_stor_block_fill(pool, batch, bio);

	if (ret < 0)
		return ret;
	return blk_rq_append_bio(request, bio);
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_block_append);

bool xdev_ext_stor_block_poll_capable(const struct request_queue *queue)
{
	return (queue->limits.features & BLK_FEAT_POLL) && queue->tag_set &&
	       queue->tag_set->nr_maps > HCTX_TYPE_POLL &&
	       queue->tag_set->map[HCTX_TYPE_POLL].nr_queues;
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_block_poll_capable);

int xdev_ext_stor_block_poll_check(bool poll, struct request *request)
{
	return poll && !blk_rq_is_poll(request) ? -EOPNOTSUPP : 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_block_poll_check);

void xdev_ext_stor_block_poll_arm(bool poll, struct request *request,
		struct xdev_ext_stor_completion *done)
{
	if (!poll) {
		WRITE_ONCE(done->poll_live, false);
		return;
	}
	done->poll_queue = request->mq_hctx->queue_num;
	WRITE_ONCE(done->poll_live, true);
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_block_poll_arm);

int xdev_ext_stor_block_poll(struct request_queue *queue,
		const struct xdev_ext_stor_poll_view *views, __u32 nr_views)
{
	u32 seen[64], nr_seen = 0, i, j, k;
	int found = 0;

	for (i = 0; i < nr_views; i++) {
		for (j = 0; j < views[i].count; j++) {
			const struct xdev_ext_stor_completion *done =
				(const void *)((const char *)views[i].first +
					       (size_t)j * views[i].stride);
			u32 queue_num;
			int ret;

			if (!READ_ONCE(done->poll_live))
				continue;
			queue_num = done->poll_queue;
			for (k = 0; k < nr_seen && seen[k] != queue_num; k++)
				;
			if (k < nr_seen)
				continue;
			/* Past 64 recorded queues, keep polling unrecorded keys. */
			if (nr_seen < ARRAY_SIZE(seen))
				seen[nr_seen++] = queue_num;
			ret = blk_mq_poll_hw_queue(queue, queue_num, NULL);
			if (ret > 0)
				found += ret;
		}
	}
	return found;
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_block_poll);

/* Process context: only after drain, or unwinding a failed CREATE. */
static bool xdev_ext_storfam_host_resources_free(struct xdev_ext_stor_stage *p)
{
	u32 i;

	if (!p->slots)
		return true;
	for (i = 0; i < p->nr_slots; i++)
		if (WARN_ON_ONCE(p->slots[i].runtime.busy))
			return false; /* Accepted or quarantined leases remain pinned. */
	p->poll_views[0] = (struct xdev_ext_stor_poll_view) {};
	for (i = 0; i < p->nr_slots; i++) {
		struct xdev_ext_stor_io *slot = &p->slots[i];

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
	p->slots = NULL;
	p->pool.free = NULL;
	p->nr_slots = 0;
	return true;
}

/*
 * CREATE: reserve metadata by depth, never native request tags or DMA state.
 * A frame may start at the last byte of a physical page. The conservative
 * page bound is capped at the same bio limit enforced by map admission.
 */
static int xdev_ext_storfam_host_resources_init(struct xdev_ext_stor_stage *p)
{
	const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(p->st->s);
	u64 pieces;
	u32 i;

	if (xdev_ext_mech_session_pool(p->st->s)->kind == XDEV_EXT_MECH_POOL_PEER)
		return 0;
	p->nr_slots = xdev_ext_mech_session_depth(p->st->s);
	if (!p->nr_slots || !l->seg_len || !l->group_bytes || !l->frame_size)
		return -EINVAL;
	pieces = DIV_ROUND_UP((u64)l->group_bytes, l->seg_len) *
		 DIV_ROUND_UP((u64)l->frame_size + PAGE_SIZE - 1, PAGE_SIZE);
	if (!pieces)
		return -EINVAL;
	p->nr_vecs = min_t(u64, pieces, BIO_MAX_INLINE_VECS);
	/* One allocation: the slots, then each slot's member state (its
	 * per-command DMA-stop record, read by dev->peer_evidence). */
	p->slots = kcalloc(p->nr_slots, sizeof(*p->slots) + p->dev->host_native_bytes,
			   GFP_KERNEL);
	if (!p->slots)
		return -ENOMEM;
	for (i = 0; i < p->nr_slots; i++) {
		struct xdev_ext_stor_io *slot = &p->slots[i];

		if (p->dev->host_native_bytes)
			slot->peer_native = (char *)&p->slots[p->nr_slots] +
					    (size_t)i * p->dev->host_native_bytes;
		slot->bio = bio_kmalloc(p->nr_vecs, GFP_KERNEL);
		if (!slot->bio)
			goto fail;
#if !defined(CONFIG_XDEV_EXT_MECH_ZEROCOPY) && defined(CONFIG_XDEV_EXT_MECH_KVM_BOUNCE)
		if (p->dev->host_path == XDEV_EXT_STOR_HOST_NATIVE_RQ) {
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
		xdev_ext_stor_slot_add(&p->pool, &slot->runtime);
	}
	p->poll_views[0] = (struct xdev_ext_stor_poll_view) {
		.first = &p->slots[0].done,
		.stride = sizeof(*p->slots),
		.count = p->nr_slots,
	};
	return 0;
fail:
	xdev_ext_storfam_host_resources_free(p);
	return -ENOMEM;
}

/* Worker: no accepted command can share a bio or completion context. */
static struct xdev_ext_stor_io *
xdev_ext_storfam_host_get(struct xdev_ext_stor_stage *p,
		struct xdev_ext_stor_batch *bp)
{
	struct xdev_ext_stor_io *slot;
	struct xdev_ext_stor_slot *node;

	node = xdev_ext_stor_slot_get(&p->pool, bp->host_io != NULL);
	if (IS_ERR(node))
		return ERR_CAST(node);
	slot = container_of(node, struct xdev_ext_stor_io, runtime);
	slot->done.uncertain = false;
	bp->host_io = slot;
	return slot;
}

/* Worker: preaccept unwind, or native completion consumed by fill_cqe. */
static void xdev_ext_storfam_host_put(struct xdev_ext_stor_stage *p,
		struct xdev_ext_stor_batch *bp)
{
	struct xdev_ext_stor_io *slot = bp->host_io;

	if (!slot || slot->done.uncertain)
		return;
	if (slot->bio_live) {
		bio_uninit(slot->bio);
		slot->bio_live = false;
	}
	bp->bio = NULL;
	bp->bounce = NULL;
	bp->nr_bounce = 0;
	bp->host_io = NULL;
	xdev_ext_stor_slot_put(&p->pool, &slot->runtime, false);
}

/* One descriptor page and one inline-span container per possible command. */
#define XDEV_EXT_STOR_PEER_MAX_SPANS 512U
struct xdev_ext_stor_peer_resources {
	struct device *dma_dev;
	void *slots;
	struct xdev_ext_stor_pool pool;
	struct xdev_ext_peer_fd_lease *leases;
	void *list_cpu;
	dma_addr_t list_dma;
	size_t list_bytes;
	u32 nr_slots, max_pieces;
};

static struct xdev_ext_stor_io *
xdev_ext_storfam_peer_io(struct xdev_ext_stor_stage *ss, u32 index)
{
	return (void *)((char *)ss->peer->slots +
		(size_t)index * ss->dev->peer_slot_bytes);
}

static bool xdev_ext_storfam_peer_resources_free(struct xdev_ext_stor_stage *ss)
{
	struct xdev_ext_stor_peer_resources *res = ss->peer;
	u32 i;

	if (!res)
		return true;
	for (i = 0; i < res->nr_slots; i++)
		if (WARN_ON_ONCE(xdev_ext_storfam_peer_io(ss, i)->runtime.busy))
			return false;
	ss->poll_views[1] = (struct xdev_ext_stor_poll_view) {};
	if (res->list_cpu)
		dma_free_coherent(res->dma_dev, res->list_bytes, res->list_cpu,
				  res->list_dma);
	kvfree(res->leases);
	kvfree(res->slots);
	kfree(res);
	ss->peer = NULL;
	return true;
}

static int xdev_ext_storfam_peer_resources_init(struct xdev_ext_stor_stage *ss)
{
	struct xdev_ext_mech_stage *st = ss->st;
	const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
	u32 i, depth = xdev_ext_mech_session_depth(st->s);
	struct pci_dev *requester;
	struct device *dev;
	struct xdev_ext_stor_peer_resources *res;
	u64 pieces;

	if (xdev_ext_mech_session_pool(st->s)->kind != XDEV_EXT_MECH_POOL_PEER)
		return 0;
	requester = ss->requester.pdev;
	if (!requester)
		return -EOPNOTSUPP;
	dev = &requester->dev;
	if (!depth || !l->seg_len || !l->group_bytes || !l->frame_size)
		return -EINVAL;
	pieces = DIV_ROUND_UP((u64)l->group_bytes, l->seg_len) *
		 (DIV_ROUND_UP((u64)l->frame_size, SZ_4K) + 1);
	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;
	ss->peer = res;
	res->dma_dev = dev;
	res->max_pieces = min_t(u64, pieces, XDEV_EXT_STOR_PEER_MAX_SPANS);
	res->slots = kvcalloc(depth, ss->dev->peer_slot_bytes, GFP_KERNEL);
	res->leases = kvcalloc((size_t)depth * res->max_pieces,
			       sizeof(*res->leases), GFP_KERNEL);
	res->list_bytes = (size_t)depth * SZ_4K;
	if (res->slots && res->leases)
		res->list_cpu = dma_alloc_coherent(dev, res->list_bytes,
						  &res->list_dma, GFP_KERNEL);
	if (!res->list_cpu) {
		xdev_ext_storfam_peer_resources_free(ss);
		return -ENOMEM;
	}
	res->nr_slots = depth;
	for (i = 0; i < depth; i++) {
		struct xdev_ext_stor_io *io = xdev_ext_storfam_peer_io(ss, i);
		struct xdev_ext_stor_peer_io *prefix = (void *)io;

		io->leases = &res->leases[(size_t)i * res->max_pieces];
		io->spans = prefix->spans;
		io->list_cpu = (char *)res->list_cpu + (size_t)i * SZ_4K;
		io->list_dma = res->list_dma + (dma_addr_t)i * SZ_4K;
		io->peer_native = (char *)io + ss->dev->peer_native_offset;
		xdev_ext_stor_slot_add(&res->pool, &io->runtime);
	}
	ss->poll_views[1] = (struct xdev_ext_stor_poll_view) {
		.first = &xdev_ext_storfam_peer_io(ss, 0)->done,
		.stride = ss->dev->peer_slot_bytes,
		.count = res->nr_slots,
	};
	return 0;
}

static struct xdev_ext_stor_io *
xdev_ext_storfam_peer_get(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_stor_batch *sb)
{
	struct xdev_ext_stor_io *io;
	struct xdev_ext_stor_slot *node;

	node = xdev_ext_stor_slot_get(&ss->peer->pool, sb->peer_io != NULL);
	if (IS_ERR(node))
		return ERR_CAST(node);
	io = container_of(node, struct xdev_ext_stor_io, runtime);
	io->nr_leases = 0;
	io->done.uncertain = false;
	sb->peer_io = io;
	return io;
}

/* The requester record and submission epoch of a consumed peer command. */
static void xdev_ext_storfam_peer_evidence(struct xdev_ext_stor_stage *ss,
		const struct xdev_ext_stor_io *io,
		struct xdev_ext_peer_requester **rq, u64 *epoch)
{
	*rq = NULL;
	*epoch = XDEV_EXT_PEER_EPOCH_NONE;
	if (ss->dev->peer_evidence && io->peer_native)
		ss->dev->peer_evidence(ss->member, io, rq, epoch);
}

/*
 * Worker.  An UNKNOWN command's leases are retired bound to the requester
 * epoch it was submitted in; its slot (and SGL list page) stays retained
 * until that requester proves a later DMA stop, unless one already did.
 */
static void xdev_ext_storfam_peer_put(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_stor_batch *sb)
{
	struct xdev_ext_stor_io *io = sb->peer_io;
	struct xdev_ext_peer_requester *rq;
	bool quiesced;
	u64 epoch;

	if (!io)
		return;
	quiesced = !io->done.uncertain;
	if (quiesced) {
		xdev_ext_stor_leases_retire(io->leases, io->nr_leases, true);
	} else {
		xdev_ext_storfam_peer_evidence(ss, io, &rq, &epoch);
		quiesced = xdev_ext_stor_leases_retire_unknown(io->leases,
				io->nr_leases, rq, epoch);
	}
	ss->dev->retire_peer(ss->member, io, quiesced);
	io->nr_leases = 0;
	sb->peer_io = NULL;
	if (!quiesced)
		return;
	xdev_ext_stor_slot_put(&ss->peer->pool, &io->runtime, false);
}

int xdev_ext_storfam_evidence(struct xdev_ext_stor_stage *ss)
{
	struct xdev_ext_stor_peer_resources *res = ss->peer;
	int worst = XDEV_EXT_PEER_EVIDENCE_COVERED, e;
	struct xdev_ext_peer_requester *rq;
	u64 epoch;
	u32 i;

	/*
	 * A host-page slot retained after an UNKNOWN outcome is bound like a
	 * peer command: to the controller that received it and the epoch it was
	 * prepared in.  One kept after a definite completion (a ZOMBIE session's
	 * consumption keeps it) needs no proof.
	 */
	for (i = 0; ss->slots && i < ss->nr_slots; i++) {
		struct xdev_ext_stor_io *slot = &ss->slots[i];

		if (!slot->runtime.busy || !slot->done.uncertain)
			continue;
		xdev_ext_storfam_peer_evidence(ss, slot, &rq, &epoch);
		e = xdev_ext_peer_requester_evidence(rq, epoch);
		if (e > worst)
			worst = e;
	}
	for (i = 0; res && i < res->nr_slots; i++) {
		struct xdev_ext_stor_io *io = xdev_ext_storfam_peer_io(ss, i);

		if (!io->runtime.busy)
			continue;
		/* Completed definitely; a ZOMBIE session kept its leases. */
		if (io->nr_leases && !io->done.uncertain)
			continue;
		xdev_ext_storfam_peer_evidence(ss, io, &rq, &epoch);
		e = xdev_ext_peer_requester_evidence(rq, epoch);
		if (e > worst)
			worst = e;
	}
	return worst;
}
EXPORT_SYMBOL_GPL(xdev_ext_storfam_evidence);

int xdev_ext_storfam_evidence_release(struct xdev_ext_stor_stage *ss)
{
	struct xdev_ext_stor_peer_resources *res = ss->peer;
	struct xdev_ext_peer_requester *rq;
	int ret = 0;
	u64 epoch;
	u32 i;

	if (xdev_ext_storfam_evidence(ss) != XDEV_EXT_PEER_EVIDENCE_COVERED)
		return -EBUSY;
	/* The proven stop includes every retained host-page command. */
	for (i = 0; ss->slots && i < ss->nr_slots; i++) {
		struct xdev_ext_stor_io *slot = &ss->slots[i];

		if (!slot->runtime.busy)
			continue;
		if (slot->bio_live) {
			bio_uninit(slot->bio);
			slot->bio_live = false;
		}
		slot->done.uncertain = false;
		xdev_ext_stor_slot_put(&ss->pool, &slot->runtime, false);
	}
	for (i = 0; res && i < res->nr_slots; i++) {
		struct xdev_ext_stor_io *io = xdev_ext_storfam_peer_io(ss, i);
		bool quiesced = true;

		if (!io->runtime.busy)
			continue;
		if (io->nr_leases) {
			if (io->done.uncertain) {
				xdev_ext_storfam_peer_evidence(ss, io, &rq, &epoch);
				quiesced = xdev_ext_stor_leases_retire_unknown(io->leases,
						io->nr_leases, rq, epoch);
			} else {
				xdev_ext_stor_leases_retire(io->leases, io->nr_leases, true);
			}
			ss->dev->retire_peer(ss->member, io, quiesced);
			io->nr_leases = 0;
		}
		if (!quiesced) {
			ret = -EIO;
			continue;
		}
		xdev_ext_stor_slot_put(&res->pool, &io->runtime, false);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_storfam_evidence_release);

static int xdev_ext_storfam_peer_map(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *b, struct xdev_ext_stor_io *io,
		u32 bytes)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(ss->st->s);
	struct xdev_ext_requester *requester = &ss->requester;
	enum dma_data_direction dir = ss->window.write ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
	u32 pos, total = 0, nr = xdev_ext_mech_batch_nr_frames(b);
	int ret;

	if (!requester->authority || !nr)
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

			if (io->nr_leases == ss->peer->max_pieces)
				return -EREMOTEIO;
			l = &io->leases[io->nr_leases];
			ret = xdev_ext_peer_lease_split(requester->authority,
					requester->pdev, requester->generation,
					off, left, dir, l);
			if (ret)
				return ret;
			io->nr_leases++;
			len = l->lease.len;
			if (!len || len > left || total > bytes || len > bytes - total)
				return -EPROTO;
			io->spans[io->nr_leases - 1] =
				(struct xdev_ext_stor_extent){ l->lease.dma_address, len };
			total += len;
		}
	}
	return total == bytes ? 0 : -EINVAL;
}
#if !defined(CONFIG_XDEV_EXT_MECH_ZEROCOPY) && defined(CONFIG_XDEV_EXT_MECH_KVM_BOUNCE)
#define XDEV_EXT_STOR_BOUNCE_AVAILABLE
/* Worker: the batch payload, in frame order, to or from the bounce pages. */
static void xdev_ext_storfam_bounce_copy(struct xdev_ext_mech_batch *b,
				       struct xdev_ext_stor_batch *bp,
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
 * into whole kernel pages. The native member observes successful bounce posts.
 */
static int xdev_ext_storfam_bounce(struct xdev_ext_stor_stage *p,
				 struct xdev_ext_mech_batch *b, struct request *req,
				 struct xdev_ext_stor_batch *bp)
{
	u32 bytes = xdev_ext_mech_batch_bytes(b);
	u32 i, len, nr = DIV_ROUND_UP(bytes, PAGE_SIZE);
	struct xdev_ext_stor_io *slot = bp->host_io;
	struct bio *bio;
	int ret = -ENOMEM;

	if (!nr || nr > BIO_MAX_INLINE_VECS)
		return -EREMOTEIO;
	if (!slot || nr > slot->nr_bounce)
		return -EREMOTEIO;
	bp->bounce = slot->bounce;
	bp->nr_bounce = nr;
	if (p->window.write)
		xdev_ext_storfam_bounce_copy(b, bp, true);

	bio = slot->bio;
	bio_init(bio, NULL, bio->bi_inline_vecs,
		 p->nr_vecs, req->cmd_flags);
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
	return 0;

out_bio:
	bio_uninit(bio);
	slot->bio_live = false;
	bp->bounce = NULL;
	bp->nr_bounce = 0;
	return ret;
}

/* Worker: a READ's payload goes back into the frames only on success. */
static void xdev_ext_storfam_bounce_release(struct xdev_ext_mech_batch *b,
					  struct xdev_ext_stor_batch *bp,
					  bool copy_back)
{
	if (!bp->bounce)
		return;
	if (copy_back)
		xdev_ext_storfam_bounce_copy(b, bp, false);
	bp->bounce = NULL;
	bp->nr_bounce = 0;
}
#endif /* compatibility bounce */

#ifndef XDEV_EXT_STOR_BOUNCE_AVAILABLE
static int xdev_ext_storfam_bounce(struct xdev_ext_stor_stage *p,
				 struct xdev_ext_mech_batch *b, struct request *req,
				 struct xdev_ext_stor_batch *bp)
{
	return -EREMOTEIO;
}

static void xdev_ext_storfam_bounce_release(struct xdev_ext_mech_batch *b,
					  struct xdev_ext_stor_batch *bp,
					  bool copy_back)
{
}
#endif /* !XDEV_EXT_STOR_BOUNCE_AVAILABLE */

/*
 * Worker: the batch payload as the request's bio, built from the frame
 * pages with bio_add_page() (CHK.8).  Fails closed with -EREMOTEIO when the
 * queue cannot take the pieces as they are: DMA alignment, a gap under the
 * virtual boundary, too many segments, or a split that blk_rq_append_bio()
 * refuses.  Only a CONFIG_XDEV_EXT_MECH_KVM_BOUNCE build copies instead.
 */
static int xdev_ext_storfam_host_map(struct xdev_ext_stor_stage *p,
			      struct xdev_ext_mech_batch *b, struct request *req,
			      struct xdev_ext_stor_batch *bp)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(p->st->s);
	struct xdev_ext_stor_queue_caps caps =
		xdev_ext_stor_block_caps(p->dev->queue(p->member),
				 p->geometry.lba_shift);
	struct bio *bio;
	int pieces, ret;

	pieces = xdev_ext_stor_block_preflight(pool, b, &caps);
	ret = pieces < 0 ? pieces : 0;
	if (!ret) {
		if (!bp->host_io || pieces > p->nr_vecs)
			return -EREMOTEIO;
		bio = bp->host_io->bio;
		bio_init(bio, NULL, bio->bi_inline_vecs, p->nr_vecs, req->cmd_flags);
		bp->host_io->bio_live = true;
		ret = xdev_ext_stor_block_append(pool, b, req, bio);
		if (!ret) {
			bp->bio = bio;
			return 0;
		}
		bio_uninit(bio);
		bp->host_io->bio_live = false;
	}
	if (ret != -EREMOTEIO)
		return ret;
	return xdev_ext_storfam_bounce(p, b, req, bp);
}

/* CREATE: native authorization precedes identity admission and window binding. */
int xdev_ext_storfam_bind(struct xdev_ext_mech_stage *st,
		const struct xdev_ext_mech_stage_uapi *u,
		const struct xdev_ext_stor_dev_ops *dev)
{
	struct xdev_ext_stor_stage *ss;
	void *member;
	int ret;

	if (!dev || !dev->bind || !dev->unbind || !dev->identity ||
	    !dev->queue || !dev->decode || !dev->post)
		return -EINVAL;
	switch (dev->host_path) {
	case XDEV_EXT_STOR_HOST_NATIVE_RQ:
		if (!dev->requester || !dev->poll || !dev->encode ||
		    !dev->encode_dptr || !dev->request_init || !dev->retire_peer ||
		    dev->peer_slot_bytes < sizeof(struct xdev_ext_stor_peer_io) ||
		    dev->peer_native_offset < sizeof(struct xdev_ext_stor_peer_io) ||
		    dev->peer_native_offset >= dev->peer_slot_bytes)
			return -EINVAL;
		break;
	case XDEV_EXT_STOR_HOST_BIO:
		if (!dev->bdev)
			return -EINVAL;
		if (xdev_ext_mech_session_pool(st->s)->kind == XDEV_EXT_MECH_POOL_PEER)
			return -EOPNOTSUPP;
		break;
	default:
		return -EINVAL;
	}
	ret = dev->bind(st, u, &ss, &member);
	if (ret)
		return ret;
	ss->st = st;
	ss->dev = dev;
	ss->member = member;
	ss->requester = (struct xdev_ext_requester) {};
	memset(ss->poll_views, 0, sizeof(ss->poll_views));
	ss->slots = NULL;
	ss->pool.free = NULL;
	ss->nr_slots = 0;
	ss->nr_vecs = 0;
	ss->peer = NULL;
	atomic_set(&ss->dead, 0);
	ret = dev->identity(member, false, &ss->geometry);
	if (!ret)
		ret = xdev_ext_stor_window_bind(&ss->window,
			ss->geometry.capacity_lbas, ss->geometry.lba_shift,
			st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE,
			st->arg0, st->arg1,
			xdev_ext_mech_session_layout(st->s)->group_bytes);
	if (!ret && xdev_ext_mech_session_pool(st->s)->kind == XDEV_EXT_MECH_POOL_PEER) {
		struct pci_dev *requester = dev->requester(member);

		ret = requester ? xdev_ext_requester_bind(&ss->requester, st,
							requester, 0) : -EOPNOTSUPP;
	}
	if (ret) {
		dev->unbind(member);
		return ret;
	}
	st->priv = member;
	ret = xdev_ext_storfam_host_resources_init(ss);
	if (!ret)
		ret = xdev_ext_storfam_peer_resources_init(ss);
	if (ret) {
		xdev_ext_storfam_peer_resources_free(ss);
		xdev_ext_storfam_host_resources_free(ss);
		if (ss->requester.pdev)
			xdev_ext_requester_unbind(&ss->requester);
		st->priv = NULL;
		dev->unbind(member);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_storfam_bind);

int xdev_ext_storfam_validate(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *batch, struct xdev_ext_stor_batch *sb,
		const __u8 scratch[64], __u32 nr_slots)
{
	struct xdev_ext_stor_rw rw;
	int ret;

	sb->validated = false;
	if (nr_slots != 1)
		return -EPROTO;
	ret = ss->dev->decode(ss->member, batch, scratch, &ss->window,
			      xdev_ext_mech_batch_bytes(batch), &rw);
	if (ret)
		return ret;
	memcpy(sb->sqe, scratch, sizeof(sb->sqe));
	sb->rw = rw;
	sb->batch_id = xdev_ext_mech_batch_id(batch);
	sb->validated = true;
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_storfam_validate);

int xdev_ext_storfam_submit_check(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *batch, struct xdev_ext_stor_batch *sb)
{
	if (atomic_read(&ss->dead))
		return -ENODEV;
	if (!sb->validated || sb->batch_id != xdev_ext_mech_batch_id(batch))
		return -EPROTO;
	return ss->dev->identity(ss->member, true, &ss->geometry);
}
EXPORT_SYMBOL_GPL(xdev_ext_storfam_submit_check);

int xdev_ext_storfam_poll(struct xdev_ext_stor_stage *ss)
{
	return ss->dev->poll(ss->member, ss->poll_views,
			     ARRAY_SIZE(ss->poll_views));
}
EXPORT_SYMBOL_GPL(xdev_ext_storfam_poll);

void xdev_ext_storfam_mark_dead(struct xdev_ext_stor_stage *ss)
{
	atomic_set(&ss->dead, 1);
}
EXPORT_SYMBOL_GPL(xdev_ext_storfam_mark_dead);

/* Process context: leave the member and all pins intact on retained resources. */
bool xdev_ext_storfam_unbind(struct xdev_ext_stor_stage *ss)
{
	if (!xdev_ext_storfam_peer_resources_free(ss) ||
	    !xdev_ext_storfam_host_resources_free(ss))
		return false;
	if (ss->requester.pdev)
		xdev_ext_requester_unbind(&ss->requester);
	return true;
}
EXPORT_SYMBOL_GPL(xdev_ext_storfam_unbind);

/* Worker: ordinary root BIO, sharing the existing host slots and page walk. */
static int xdev_ext_storfam_submit_bio(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *b, struct xdev_ext_stor_batch *sb)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(ss->st->s);
	struct xdev_ext_stor_queue_caps caps;
	struct xdev_ext_stor_io *io;
	struct bio *bio;
	int pieces, ret;

	sb->posting = sb->rw;
	io = xdev_ext_storfam_host_get(ss, sb);
	if (IS_ERR(io))
		return PTR_ERR(io);
	io->done.b = b;
	io->done.ticket = xdev_ext_mech_batch_ticket(b);
	WRITE_ONCE(io->done.poll_live, false);
	caps = xdev_ext_stor_block_caps(ss->dev->queue(ss->member),
					ss->geometry.lba_shift);
	pieces = xdev_ext_stor_block_preflight(pool, b, &caps);
	if (pieces < 0) {
		ret = pieces;
		goto put;
	}
	if (pieces > ss->nr_vecs) {
		ret = -EREMOTEIO;
		goto put;
	}
	bio = io->bio;
	bio_init(bio, ss->dev->bdev(ss->member), bio->bi_inline_vecs,
		 ss->nr_vecs, sb->posting.write ? REQ_OP_WRITE : REQ_OP_READ);
	io->bio_live = true;
	bio->bi_iter.bi_sector = sb->posting.byte_offset >> SECTOR_SHIFT;
	ret = xdev_ext_stor_block_fill(pool, b, bio);
	if (ret < 0)
		goto put;
	if (bio->bi_iter.bi_size != sb->posting.byte_length ||
	    bio->bi_iter.bi_size != xdev_ext_mech_batch_bytes(b)) {
		ret = -EMSGSIZE;
		goto put;
	}
	sb->bio = bio;
	/* The post can complete inline. Do not access any context after it. */
	ss->dev->post(ss->member, NULL, io, b, NULL, false);
	return 0;
put:
	xdev_ext_storfam_host_put(ss, sb);
	return ret;
}

int xdev_ext_storfam_submit(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *b, struct xdev_ext_stor_batch *sb)
{
	bool peer;
	struct xdev_ext_stor_io *io;
	struct request *req;
	int ret;

	ret = xdev_ext_storfam_submit_check(ss, b, sb);
	if (ret)
		return ret;
	if (ss->dev->host_path == XDEV_EXT_STOR_HOST_BIO)
		return xdev_ext_storfam_submit_bio(ss, b, sb);
	peer = xdev_ext_mech_session_pool(ss->st->s)->kind == XDEV_EXT_MECH_POOL_PEER;
	if (peer && !ss->peer)
		return -EINVAL;
	ret = ss->dev->encode(ss->member, &sb->rw, sb->sqe,
			xdev_ext_mech_batch_bytes(b), peer, &sb->posting, &sb->command);
	if (ret)
		return ret;
	req = blk_mq_alloc_request(ss->dev->queue(ss->member),
		xdev_ext_stor_block_poll_opf(ss->st->poll,
			sb->posting.write ? REQ_OP_DRV_OUT : REQ_OP_DRV_IN),
		BLK_MQ_REQ_NOWAIT);
	if (IS_ERR(req))
		return PTR_ERR(req);
	ret = xdev_ext_stor_block_poll_check(ss->st->poll, req);
	if (ret)
		goto free_request;
	if (!peer)
		ss->dev->request_init(ss->member, req, &sb->command, false);
	io = peer ? xdev_ext_storfam_peer_get(ss, sb) :
		xdev_ext_storfam_host_get(ss, sb);
	if (IS_ERR(io)) {
		ret = PTR_ERR(io);
		goto free_request;
	}
	if (peer) {
		ret = xdev_ext_storfam_peer_map(ss, b, io, sb->posting.byte_length);
		if (!ret)
			ret = ss->dev->encode_dptr(ss->member, &sb->command,
				io->spans, io->nr_leases, io->spans,
				XDEV_EXT_STOR_PEER_MAX_SPANS, io->list_cpu,
				io->list_dma, SZ_4K);
		if (!ret && (sb->rw.byte_length != sb->posting.byte_length ||
			     sb->rw.nlb != sb->posting.nlb))
			ret = -EPROTO;
		if (ret) {
			xdev_ext_storfam_peer_put(ss, sb);
			goto free_request;
		}
		ss->dev->request_init(ss->member, req, &sb->command, true);
	} else {
		io->done.b = b;
		io->done.ticket = xdev_ext_mech_batch_ticket(b);
		ret = xdev_ext_storfam_host_map(ss, b, req, sb);
		if (ret) {
			xdev_ext_storfam_host_put(ss, sb);
			goto free_request;
		}
	}
	if (peer) {
		io->done.b = b;
		io->done.ticket = xdev_ext_mech_batch_ticket(b);
	}
	ss->dev->post(ss->member, req, io, b, &sb->command, peer);
	return 0;

free_request:
	blk_mq_free_request(req);
	return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_storfam_submit);

void xdev_ext_storfam_host_ready(struct xdev_ext_mech_batch *b,
		int status, bool uncertain)
{
#ifdef XDEV_EXT_STOR_BOUNCE_AVAILABLE
	struct xdev_ext_stor_batch *sb = xdev_ext_mech_batch_priv(b);
	struct xdev_ext_mech_stage *st = xdev_ext_mech_batch_stage(b);

	if (!status && !uncertain && sb->bounce &&
	    st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE &&
	    xdev_ext_mech_session_state(st->s) != XDEV_EXT_MECH_SESSION_ZOMBIE)
		xdev_ext_storfam_bounce_copy(b, sb, false);
#endif
}
EXPORT_SYMBOL_GPL(xdev_ext_storfam_host_ready);

void xdev_ext_storfam_consume(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *b, struct xdev_ext_stor_batch *sb)
{
	if (xdev_ext_mech_session_pool(ss->st->s)->kind == XDEV_EXT_MECH_POOL_PEER) {
		/* ZOMBIE retains even the handle records and native trace. */
		if (xdev_ext_mech_session_state(ss->st->s) != XDEV_EXT_MECH_SESSION_ZOMBIE)
			xdev_ext_storfam_peer_put(ss, sb);
	} else {
		/* Active bounce references are cleared even when the slot is retained. */
		xdev_ext_storfam_bounce_release(b, sb, false);
		if (xdev_ext_mech_session_state(ss->st->s) != XDEV_EXT_MECH_SESSION_ZOMBIE)
			xdev_ext_storfam_host_put(ss, sb);
	}
	sb->validated = false;
}
EXPORT_SYMBOL_GPL(xdev_ext_storfam_consume);
