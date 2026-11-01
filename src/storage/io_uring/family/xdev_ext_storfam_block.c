// SPDX-License-Identifier: GPL-2.0
/* Storage-family block payload qualification and bio assembly. */
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/export.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_storfam_block.h>

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
