// SPDX-License-Identifier: GPL-2.0
/* Ordinary host-page block RW member of the shared storage family. */
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/build_bug.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/xdev_ext_desc_schema.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_storfam_block.h>

/* All pointers are borrowed from the same core-pinned opened block file. */
struct xdev_ext_block_identity {
	struct block_device *bdev;
	struct gendisk *disk;
	struct request_queue *queue;
	u64 diskseq;
	sector_t sectors, start;
	u32 logical_size;
	struct xdev_ext_stor_geometry geometry;
};

struct xdev_ext_block_stage {
	struct xdev_ext_stor_stage family;
	struct file *file;
	struct xdev_ext_block_identity identity;
	bool write;
};

struct xdev_ext_block_batch {
	struct xdev_ext_stor_batch family;
	struct xdev_ext_block_mech_cqe cqe;
};

static_assert(offsetof(struct xdev_ext_block_stage, family) == 0);
static_assert(offsetof(struct xdev_ext_block_batch, family) == 0);
static_assert(sizeof(struct xdev_ext_block_rw_desc) == 64);
static_assert(sizeof(struct xdev_ext_block_mech_info) == 576);
static_assert(sizeof(struct xdev_ext_block_mech_cqe) == 16);
static_assert(sizeof(struct xdev_ext_block_batch) < 4096);

/* CREATE/worker: open_mutex precedes the target's holder mutex, as in open. */
static int xdev_ext_block_capture(struct file *file, bool write,
		struct xdev_ext_block_identity *id)
{
	struct block_device *bdev;
	struct request_queue *queue;
	struct gendisk *disk;
	u32 logical_size, shift;
	u64 capacity;
	int ret = 0;

	if (!S_ISBLK(file_inode(file)->i_mode))
		return -ENOTBLK;
	if (!(file->f_mode & (write ? FMODE_WRITE : FMODE_READ)))
		return -EBADF;
	bdev = file_bdev(file);
	/* VFS clears O_EXCL after open; the holder must be this same file. */
	if (file->private_data != file)
		return -EBUSY;
	disk = bdev->bd_disk;
	queue = bdev_get_queue(bdev);
	mutex_lock(&disk->open_mutex);
	mutex_lock(&bdev->bd_holder_lock);
	if (bdev->bd_holder != file) {
		ret = -EBUSY;
		goto out;
	}
	if (!disk_live(disk)) {
		ret = -ENODEV;
		goto out;
	}
	if (!queue_is_mq(queue) || bdev_test_flag(bdev, BD_HAS_SUBMIT_BIO) ||
	    bdev_is_zoned(bdev) ||
	    queue->limits.integrity.csum_type != BLK_INTEGRITY_CSUM_NONE) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	if (write && bdev_read_only(bdev)) {
		ret = -EROFS;
		goto out;
	}
	logical_size = bdev_logical_block_size(bdev);
	if (logical_size < 512 || !is_power_of_2(logical_size)) {
		ret = -EINVAL;
		goto out;
	}
	shift = ilog2(logical_size);
	if (shift >= 32) {
		ret = -EOVERFLOW;
		goto out;
	}
	capacity = bdev_nr_sectors(bdev) >> (shift - SECTOR_SHIFT);
	if (!capacity) {
		ret = -ENODEV;
		goto out;
	}
	*id = (struct xdev_ext_block_identity) {
		.bdev = bdev, .disk = disk, .queue = queue,
		.diskseq = disk->diskseq,
		.sectors = bdev_nr_sectors(bdev), .start = get_start_sect(bdev),
		.logical_size = logical_size,
		.geometry = { .capacity_lbas = capacity, .lba_shift = shift },
	};
out:
	mutex_unlock(&bdev->bd_holder_lock);
	mutex_unlock(&disk->open_mutex);
	return ret;
}

static bool xdev_ext_block_identity_equal(const struct xdev_ext_block_identity *a,
		const struct xdev_ext_block_identity *b)
{
	return a->bdev == b->bdev && a->disk == b->disk && a->queue == b->queue &&
		a->diskseq == b->diskseq && a->sectors == b->sectors &&
		a->start == b->start && a->logical_size == b->logical_size &&
		a->geometry.capacity_lbas == b->geometry.capacity_lbas &&
		a->geometry.lba_shift == b->geometry.lba_shift;
}

static int xdev_ext_block_member_bind(struct xdev_ext_mech_stage *st,
		const struct xdev_ext_mech_stage_uapi *u,
		struct xdev_ext_stor_stage **family, void **member)
{
	struct xdev_ext_block_identity id;
	struct xdev_ext_block_stage *p;
	bool write = st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE;
	int ret;

	/* Generic CREATE has already admitted flags and direction. */
	(void)u;
	ret = xdev_ext_block_capture(st->file, write, &id);
	if (ret)
		return ret;
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	p->file = st->file;
	p->write = write;
	p->identity = id;
	*family = &p->family;
	*member = p;
	return 0;
}

static void xdev_ext_block_member_unbind(void *member)
{
	kfree(member);
}

static int xdev_ext_block_member_identity(void *member, bool final,
		struct xdev_ext_stor_geometry *geometry)
{
	struct xdev_ext_block_stage *p = member;
	struct xdev_ext_block_identity id;
	int ret = xdev_ext_block_capture(p->file, p->write, &id);

	if (final && ret && ret != -ENODEV && ret != -EROFS)
		ret = -ESTALE;
	if (!ret && !xdev_ext_block_identity_equal(&p->identity, &id))
		ret = -ESTALE;
	if (ret) {
		if (final)
			xdev_ext_mech_stage_dead(p->family.st, ret);
		return ret;
	}
	*geometry = p->identity.geometry;
	return 0;
}

static struct request_queue *xdev_ext_block_member_queue(void *member)
{
	struct xdev_ext_block_stage *p = member;

	return p->identity.queue;
}

static struct block_device *xdev_ext_block_member_bdev(void *member)
{
	struct xdev_ext_block_stage *p = member;

	return p->identity.bdev;
}

static int xdev_ext_block_member_decode(void *member,
		struct xdev_ext_mech_batch *b, const u8 scratch[64],
		const struct xdev_ext_stor_window *window, u32 bytes,
		struct xdev_ext_stor_rw *rw)
{
	static const struct xdev_ext_desc_schema16 schema = {
		.writable = { [0] = 0xffU, [2] = ~0U, [3] = ~0U, [4] = ~0U },
	};
	u64 slba;
	u32 nlb;
	int ret;

	(void)member;
	ret = xdev_ext_desc_schema16_check(scratch, &schema,
		window->write ? XDEV_EXT_BLOCK_OP_WRITE : XDEV_EXT_BLOCK_OP_READ);
	if (ret)
		return ret;
	nlb = get_unaligned_le32(scratch + 16);
	if (!nlb)
		return -EINVAL;
	slba = get_unaligned_le64(scratch + 8);
	ret = xdev_ext_stor_window_check(window->slba, window->nlb, slba, nlb);
	if (ret)
		return ret;
	if (nlb > 65536U)
		return -E2BIG;
	ret = xdev_ext_stor_window_admit(window, slba, nlb, bytes, rw);
	if (b)
		xdev_ext_mech_trace_plan(b, slba, bytes, scratch[0], ret);
	return ret;
}

/* Called only after the family has claimed this slot's captured ticket. */
static int xdev_ext_block_complete(struct xdev_ext_mech_batch *b,
		void *native, int status, bool *uncertain)
{
	struct xdev_ext_block_batch *bp = xdev_ext_mech_batch_priv(b);
	struct xdev_ext_stor_io *io = bp->family.host_io;
	struct bio *bio = native;
	struct xdev_ext_block_mech_cqe *cqe = &bp->cqe;

	*cqe = (struct xdev_ext_block_mech_cqe) {
		.submitted_bytes = bp->family.posting.byte_length,
	};
	*uncertain = !bio || !io || bp->family.bio != bio || io->bio != bio ||
		!io->bio_live || !io->runtime.busy || bio->bi_private != &io->done;
	if (*uncertain) {
		cqe->err = -EIO;
		return -EIO;
	}
	cqe->residual_bytes = bio->bi_iter.bi_size;
	cqe->blk_status = bio->bi_status;
	/*
	 * Owned ordinary root endio is terminal, including error with residual.
	 * Success with residual is not a full completion of this batch.
	 */
	if (!status && cqe->residual_bytes) {
		*uncertain = true;
		status = -EIO;
	}
	cqe->err = status;
	return status;
}

static void xdev_ext_block_end_io(struct bio *bio)
{
	xdev_ext_stor_done(bio->bi_private, blk_status_to_errno(bio->bi_status),
			   bio, xdev_ext_block_complete, NULL);
}

static void xdev_ext_block_member_post(void *member, struct request *request,
		struct xdev_ext_stor_io *io, struct xdev_ext_mech_batch *b,
		const struct xdev_ext_stor_command *command, bool peer)
{
	struct xdev_ext_block_batch *bp = xdev_ext_mech_batch_priv(b);
	struct bio *bio = io->bio;

	/* The BIO route supplies no native request or command. */
	(void)member;
	(void)request;
	(void)command;
	(void)peer;
	bio->bi_private = &io->done;
	bio->bi_end_io = xdev_ext_block_end_io;
	xdev_ext_mech_trace_native_submit(b, (u64)(unsigned long)bio,
		bp->family.posting.slba, bp->family.posting.byte_length, bio_op(bio));
	/* Native handoff may invoke endio inline; no context access follows. */
	submit_bio(bio);
}

static const struct xdev_ext_stor_dev_ops xdev_ext_block_member_ops = {
	.host_path = XDEV_EXT_STOR_HOST_BIO,
	.bdev = xdev_ext_block_member_bdev,
	.bind = xdev_ext_block_member_bind,
	.unbind = xdev_ext_block_member_unbind,
	.identity = xdev_ext_block_member_identity,
	.queue = xdev_ext_block_member_queue,
	.decode = xdev_ext_block_member_decode,
	.post = xdev_ext_block_member_post,
};

static int xdev_ext_block_bind(struct xdev_ext_mech_stage *st,
		const struct xdev_ext_mech_stage_uapi *u)
{
	int ret = xdev_ext_storfam_bind(st, u, &xdev_ext_block_member_ops);

	if (!ret)
		st->caps.native_queue = XDEV_EXT_CAP_ESTABLISHED;
	return ret;
}

static int xdev_ext_block_unbind_checked(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_block_stage *p = st->priv;

	return !p || xdev_ext_storfam_unbind(&p->family) ? 0 : -EBUSY;
}

static void xdev_ext_block_unbind(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_block_stage *p = st->priv;

	if (!p || !xdev_ext_storfam_unbind(&p->family))
		return;
	st->priv = NULL;
	xdev_ext_block_member_unbind(p);
}

static void xdev_ext_block_fill_info(struct xdev_ext_mech_stage *st,
		struct xdev_ext_mech_batch *b, void *out)
{
	const struct xdev_ext_block_stage *p = st->priv;
	struct xdev_ext_block_mech_info *info = out;
	struct xdev_ext_mech_frame f;
	u32 i, nr;

	memset(info, 0, sizeof(*info));
	info->l = *xdev_ext_mech_session_layout(st->s);
	info->lba_shift = p->identity.geometry.lba_shift;
	info->max_nlb = 65536U;
	info->window_slba = p->family.window.slba;
	info->window_nlb = p->family.window.nlb;
	info->capacity_lbas = p->identity.geometry.capacity_lbas;
	info->diskseq = p->identity.diskseq;
	if (!b)
		return;
	nr = min_t(u32, xdev_ext_mech_batch_nr_frames(b), XDEV_EXT_MECH_MAX_FRAMES);
	for (i = 0; i < nr && !xdev_ext_mech_batch_frame(b, i, &f); i++)
		info->f[i] = (struct xdev_ext_mech_frame_info) {
			.umem_addr = f.umem_addr, .data_off = f.data_off, .data_len = f.data_len,
		};
	info->nr_frames = i;
}

static int xdev_ext_block_validate(struct xdev_ext_mech_stage *st,
		struct xdev_ext_mech_batch *b, const u8 *scratch, u32 n)
{
	struct xdev_ext_block_stage *p = st->priv;
	struct xdev_ext_block_batch *bp = xdev_ext_mech_batch_priv(b);

	return xdev_ext_storfam_validate(&p->family, b, &bp->family, scratch, n);
}

static int xdev_ext_block_submit(struct xdev_ext_mech_stage *st,
		struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_block_stage *p = st->priv;
	struct xdev_ext_block_batch *bp = xdev_ext_mech_batch_priv(b);

	return xdev_ext_storfam_submit(&p->family, b, &bp->family);
}

static void xdev_ext_block_fill_cqe(struct xdev_ext_mech_stage *st,
		struct xdev_ext_mech_batch *b, void *out)
{
	struct xdev_ext_block_stage *p = st->priv;
	struct xdev_ext_block_batch *bp = xdev_ext_mech_batch_priv(b);

	xdev_ext_storfam_consume(&p->family, b, &bp->family);
	memcpy(out, &bp->cqe, sizeof(bp->cqe));
}

static void xdev_ext_block_mark_dead(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_block_stage *p = st->priv;

	if (p)
		xdev_ext_storfam_mark_dead(&p->family);
}

static const struct xdev_ext_mech_class_ops xdev_ext_block_class = {
	.decl = &xdev_ext_mech_class_decls[XDEV_EXT_MECH_CLASS_BLOCK],
	.class_id = XDEV_EXT_MECH_CLASS_BLOCK,
	.desc_size = XDEV_EXT_BLOCK_MECH_DESC_SIZE, .desc_cap = 1,
	.info_size = sizeof(struct xdev_ext_block_mech_info),
	.cqe_size = sizeof(struct xdev_ext_block_mech_cqe), .cqe_cap = 1,
	.batch_priv_size = sizeof(struct xdev_ext_block_batch),
	.owner = THIS_MODULE,
	.bind = xdev_ext_block_bind, .unbind = xdev_ext_block_unbind,
	.unbind_checked = xdev_ext_block_unbind_checked,
	.fill_info = xdev_ext_block_fill_info, .validate = xdev_ext_block_validate,
	.submit = xdev_ext_block_submit, .fill_cqe = xdev_ext_block_fill_cqe,
	.mark_dead = xdev_ext_block_mark_dead,
};

static int __init xdev_ext_block_init(void)
{
	return xdev_ext_mech_class_register(&xdev_ext_block_class);
}
late_initcall_sync(xdev_ext_block_init);
