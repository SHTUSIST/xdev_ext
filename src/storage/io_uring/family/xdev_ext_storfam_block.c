// SPDX-License-Identifier: GPL-2.0
/* Storage-family block payload qualification and bio assembly. */
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/export.h>
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

int xdev_ext_stor_block_append(struct xdev_ext_mech_pool *pool,
		struct xdev_ext_mech_batch *batch, struct request *request,
		struct bio *bio)
{
	int ret = xdev_ext_stor_block_walk(pool, batch, NULL, bio);

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

/* CREATE: native authorization precedes identity admission and window binding. */
int xdev_ext_storfam_bind(struct xdev_ext_mech_stage *st,
		const struct xdev_ext_mech_stage_uapi *u,
		const struct xdev_ext_stor_dev_ops *dev)
{
	struct xdev_ext_stor_stage *ss;
	void *member;
	int ret;

	if (!dev || !dev->bind || !dev->unbind || !dev->identity ||
	    !dev->requester || !dev->queue || !dev->decode || !dev->poll)
		return -EINVAL;
	ret = dev->bind(st, u, &ss, &member);
	if (ret)
		return ret;
	ss->st = st;
	ss->dev = dev;
	ss->member = member;
	memset(ss->poll_views, 0, sizeof(ss->poll_views));
	atomic_set(&ss->dead, 0);
	ret = dev->identity(member, false, &ss->geometry);
	if (!ret)
		ret = xdev_ext_stor_window_bind(&ss->window,
			ss->geometry.capacity_lbas, ss->geometry.lba_shift,
			st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE,
			st->arg0, st->arg1,
			xdev_ext_mech_session_layout(st->s)->group_bytes);
	if (ret) {
		dev->unbind(member);
		return ret;
	}
	st->priv = member;
	return 0;
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
