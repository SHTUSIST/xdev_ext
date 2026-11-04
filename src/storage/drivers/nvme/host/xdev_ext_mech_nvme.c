// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe class of the XDEV_EXT mechanism layer.
 *
 * A stage binds one NVMe generic namespace (/dev/ngXnY), captures its
 * identity once and fixes an LBA window inside it.  For each batch the
 * session worker runs the NVMe program's build into a one-slot scratch SQE;
 * ->validate admits that SQE with nvme_xdev_ext_mech_validate() and keeps the
 * admitted bytes with the batch; ->submit rechecks the namespace identity,
 * asks the block family to build and issue the mapped passthrough request.  The completion records the native status and
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

#include <linux/blk-mq.h>
#include <linux/build_bug.h>
#include <linux/moduleparam.h>
#include <linux/nvme_xdev_ext_passthru.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_storfam.h>
#include <linux/xdev_ext_storfam_block.h>
#include <uapi/linux/xdev_ext_peer.h>
#include <linux/capability.h>
#include "nvme.h"
#include "xdev_ext_peer_nvme_core.h"
#include "xdev_ext_native_peer_trace.h"

struct nvme_xdev_ext_mech_stage {
	struct xdev_ext_stor_stage family;
	struct nvme_ns *ns; /* pinned by the stage file */
	struct nvme_xdev_ext_identity identity;
	const struct nvme_ns_head *head;
	const struct gendisk *disk;
	const struct request_queue *queue;
	bool write;
};

struct nvme_xdev_ext_mech_batch {
	struct xdev_ext_stor_batch family;
	struct xdev_ext_nvme_mech_cqe cqe;
};

struct nvme_xdev_ext_peer_slot {
	struct xdev_ext_stor_peer_io common;
	struct nvme_xdev_ext_peer_trace trace;
};

static_assert(sizeof(struct xdev_ext_stor_command) == sizeof(struct nvme_command));
static_assert(sizeof(struct xdev_ext_stor_command) == 64);
static_assert(__alignof__(struct xdev_ext_stor_command) >= 8);
static_assert(offsetof(struct nvme_xdev_ext_mech_stage, family) == 0);
static_assert(offsetof(struct nvme_xdev_ext_mech_batch, family) == 0);
static_assert(offsetof(struct nvme_xdev_ext_peer_slot, common) == 0);
static_assert(offsetof(struct xdev_ext_stor_peer_io, io) == 0);
static_assert(offsetof(struct xdev_ext_stor_io, done) == 0);
static_assert(sizeof(((struct xdev_ext_stor_peer_io *)0)->spans) ==
	512 * sizeof(struct xdev_ext_stor_extent));
static_assert(offsetof(struct nvme_xdev_ext_peer_slot, trace) ==
	sizeof(struct xdev_ext_stor_peer_io));
static_assert(offsetof(struct nvme_xdev_ext_peer_slot, trace) %
	__alignof__(struct nvme_xdev_ext_peer_trace) == 0);
static_assert(sizeof(struct nvme_xdev_ext_peer_slot) ==
	sizeof(struct xdev_ext_stor_peer_io) + sizeof(struct nvme_xdev_ext_peer_trace));
static_assert(sizeof(struct nvme_xdev_ext_peer_slot) %
	__alignof__(struct nvme_xdev_ext_peer_trace) == 0);

#define NVME_XDEV_EXT_PEER_MAX_PIECES 256U
#define NVME_XDEV_EXT_PEER_MIN_PAGE_SHIFT 12

static const struct xdev_ext_stor_hooks nvme_xdev_ext_stor_hooks = {
	.hdr = { .family = XDEV_EXT_FAMILY_STORAGE },
	.extent_align_mask = 3,
	.max_extents = NVME_XDEV_EXT_PEER_MAX_PIECES,
};

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

#endif
#endif

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

static int nvme_xdev_ext_member_bind(struct xdev_ext_mech_stage *st,
		const struct xdev_ext_mech_stage_uapi *u,
		struct xdev_ext_stor_stage **family, void **member)
{
	bool write = st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE;
	struct nvme_xdev_ext_mech_stage *p;
	struct nvme_ns *ns;

	if (u->flags || (!write && st->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE))
		return -EINVAL;
	ns = nvme_xdev_ext_class_ns(st->file);
	if (!ns)
		return -EOPNOTSUPP;
	/* No interrupt fallback: polling needs this namespace's poll queues. */
	if (st->poll && !xdev_ext_stor_block_poll_capable(ns->queue))
		return -EOPNOTSUPP;
#ifdef CONFIG_XDEV_EXT_MECH_ZEROCOPY
	/* Only PCI has the strict SGL/no-bounce transport contract below. */
	if (xdev_ext_mech_session_pool(st->s)->kind != XDEV_EXT_MECH_POOL_PEER &&
	    (strcmp(ns->ctrl->ops->name, "pcie") ||
	     !nvme_ctrl_sgl_supported(ns->ctrl) || queue_virt_boundary(ns->queue)))
		return -EOPNOTSUPP;
#endif
 if (xdev_ext_mech_session_pool(st->s)->kind == XDEV_EXT_MECH_POOL_PEER) {
  /* The allocation authority seals DMA memory. Namespace fd modes and the
   * native command-effects check below authorize storage access for PEER too.
   */
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
	*family = &p->family;
	*member = p;
	return 0;
}

static void nvme_xdev_ext_member_unbind(void *member)
{
	kfree(member);
}

static struct pci_dev *nvme_xdev_ext_member_requester(void *member)
{
	struct nvme_xdev_ext_mech_stage *p = member;
	struct device *dev = p->ns->ctrl->dev;

	return dev && dev_is_pci(dev) ? to_pci_dev(dev) : NULL;
}

static struct request_queue *nvme_xdev_ext_member_queue(void *member)
{
	struct nvme_xdev_ext_mech_stage *p = member;

	return p->ns->queue;
}

static const struct xdev_ext_stor_dev_ops nvme_xdev_ext_member_ops;

static int nvme_xdev_ext_class_bind(struct xdev_ext_mech_stage *st,
		const struct xdev_ext_mech_stage_uapi *u)
{
	return xdev_ext_storfam_bind(st, u, &nvme_xdev_ext_member_ops);
}

static void nvme_xdev_ext_class_unbind(struct xdev_ext_mech_stage *st)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	const struct xdev_ext_stor_dev_ops *dev = p->family.dev;
	void *member = p->family.member;

	if (!xdev_ext_storfam_unbind(&p->family))
		return;
	dev->unbind(member);
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
	info->lba_shift = p->family.window.lba_shift;
	info->max_nlb = min_t(u32, NVME_XDEV_EXT_MAX_NLB,
			      queue_max_hw_sectors(
			      p->family.dev->queue(p->family.member)) >>
			      (p->family.window.lba_shift - SECTOR_SHIFT));
	info->window_slba = p->family.window.slba;
	info->window_nlb = p->family.window.nlb;
	info->capacity_lbas = p->family.window.capacity_lbas;
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

	if (!p || atomic_read(&p->family.dead))
		return -ENODEV;
	if (p->ns != ns)
		return -EXDEV;
	if (!nvme_xdev_ext_identity_equal(&p->identity, identity))
		return -ESTALE;
	return 0;
}

static int nvme_xdev_ext_member_decode(void *member,
		struct xdev_ext_mech_batch *b, const u8 scratch[64],
		const struct xdev_ext_stor_window *window, u32 bytes,
		struct xdev_ext_stor_rw *rw)
{
	struct nvme_xdev_ext_mech_bounds bounds = {
		.window_slba = window->slba,
		.window_nlb = window->nlb,
		.capacity_lbas = window->capacity_lbas,
		.data_len = bytes,
		.lba_shift = window->lba_shift,
		.write = window->write,
	};
	struct nvme_xdev_ext_decoded decoded;
	int ret;

	ret = nvme_xdev_ext_mech_validate(scratch, &bounds, &decoded);
	if (b)
		xdev_ext_mech_trace_plan(b,
			(u64)nvme_xdev_ext_sqe_dw(scratch, 10) |
			(u64)nvme_xdev_ext_sqe_dw(scratch, 11) << 32,
			bounds.data_len, scratch[0] |
			(nvme_xdev_ext_sqe_dw(scratch, 12) & 0xffff) << 8, ret);
	if (ret)
		return ret;
	*rw = (struct xdev_ext_stor_rw) {
		.slba = decoded.slba, .nlb = decoded.nlb,
		.byte_offset = decoded.byte_offset, .byte_length = decoded.byte_length,
		.write = decoded.write,
	};
	return 0;
}

static int nvme_xdev_ext_class_validate(struct xdev_ext_mech_stage *st,
		struct xdev_ext_mech_batch *b, const u8 *scratch, u32 n)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);

	return xdev_ext_storfam_validate(&p->family, b, &bp->family, scratch, n);
}

/* Native identity admission at CREATE, or the original worker recheck. */
static int nvme_xdev_ext_member_identity(void *member, bool final,
		struct xdev_ext_stor_geometry *geometry)
{
	struct nvme_xdev_ext_mech_stage *p = member;
	const struct request_queue *queue;
	const struct nvme_ns_head *head;
	struct nvme_xdev_ext_identity id;
	const struct gendisk *disk;
	int ret;

	if (!final) {
		ret = nvme_xdev_ext_capture_identity(p->ns, &p->identity,
					&p->head, &p->disk, &p->queue);
		if (!ret)
			ret = nvme_xdev_ext_mech_bind_identity(&p->identity, p->write,
				xdev_ext_mech_session_layout(p->family.st->s)->group_bytes);
		if (!ret)
			*geometry = (struct xdev_ext_stor_geometry) {
				.capacity_lbas = p->identity.capacity_lbas,
				.lba_shift = p->identity.lba_shift,
			};
		return ret;
	}
	ret = nvme_xdev_ext_capture_identity(p->ns, &id, &head, &disk, &queue);
	if (!ret && (head != p->head || disk != p->disk || queue != p->queue ||
		     !nvme_xdev_ext_identity_equal(&p->identity, &id)))
		ret = -ESTALE;
	if (ret)
		xdev_ext_mech_stage_dead(p->family.st, ret);
	return ret;
}

/* Member mapping runs only after the family has claimed the captured ticket. */
static int nvme_xdev_ext_class_complete(struct xdev_ext_mech_batch *b,
				       void *native, int transport_status,
				       bool *is_uncertain)
{
	struct request *req = native;
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);
	bool uncertain, full_batch;
	int status;

	/* The uring_cmd convention: NVMe status > 0, -errno without one. */
	if (nvme_req(req)->flags & NVME_REQ_CANCELLED)
		status = -EINTR;
	else
		status = nvme_req(req)->status ?: transport_status;
	/* The block batch completion loop already ends every bio in the optimized NVMe
	 * completion batch, but deliberately preserves bio/__data_len for a
	 * passthrough request's end_io. That exact owned bio and original length
	 * are bookkeeping, not evidence of a short DMA. A successful CQE is also
	 * required; a short, foreign or missing bio retains the conservative
	 * residual handling below. The PCI transport has unmapped before end_io. */
	full_batch = !status && bp->family.bio && req->bio == bp->family.bio &&
		blk_rq_bytes(req) == xdev_ext_mech_batch_bytes(b);
	uncertain = blk_rq_bytes(req) != 0 && !full_batch;
	if (uncertain && !status)
		status = -EIO;
	*is_uncertain = uncertain;
	nvme_xdev_ext_mech_cqe(status, le64_to_cpu(nvme_req(req)->result.u64),
			  &bp->cqe);
	return status;
}

static enum rq_end_io_ret nvme_xdev_ext_class_end_io(struct request *req,
						 blk_status_t err)
{
	xdev_ext_stor_done(req->end_io_data, blk_status_to_errno(err), req,
			   nvme_xdev_ext_class_complete, xdev_ext_storfam_host_ready);
	return RQ_END_IO_FREE;
}

static int nvme_xdev_ext_peer_complete(struct xdev_ext_mech_batch *b,
				      void *native, int transport_status,
				      bool *uncertain)
{
	struct request *req = native;
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);
	int status;

	if (nvme_req(req)->flags & NVME_REQ_CANCELLED)
		status = -EINTR;
	else
		status = nvme_req(req)->status ?: transport_status;
	/* An error or a cancellation does not prove that peer DMA stopped. */
	*uncertain = status != 0;
	nvme_xdev_ext_mech_cqe(status, le64_to_cpu(nvme_req(req)->result.u64),
			       &bp->cqe);
	return status;
}

static enum rq_end_io_ret nvme_xdev_ext_peer_end_io(struct request *req,
						    blk_status_t err)
{
	nvme_req(req)->flags &= ~NVME_REQ_XDEV_EXT_PEER;
	nvme_req(req)->peer_trace = NULL;
	xdev_ext_stor_done(req->end_io_data, blk_status_to_errno(err), req,
			   nvme_xdev_ext_peer_complete, NULL);
	return RQ_END_IO_FREE;
}

/* Encode only native RW policy and format; common owns issue and mapping. */
static int nvme_xdev_ext_member_encode(void *member,
		const struct xdev_ext_stor_rw *admitted, const u8 admitted_sqe[64],
		u32 batch_bytes, bool peer, struct xdev_ext_stor_rw *posting,
		struct xdev_ext_stor_command *command)
{
	struct nvme_xdev_ext_mech_stage *p = member;
	struct nvme_command *cmd = (void *)command->bytes;
	struct nvme_ns *ns = p->ns;
	struct xdev_ext_peer_nvme_plan plan;
	int ret;

	memset(command, 0, sizeof(*command));
	if (!peer) {
		*posting = *admitted;
		cmd->rw.opcode = admitted->write ?
			NVME_XDEV_EXT_NVM_WRITE : NVME_XDEV_EXT_NVM_READ;
		cmd->rw.nsid = cpu_to_le32(p->identity.nsid);
		cmd->rw.slba = cpu_to_le64(admitted->slba);
		cmd->common.cdw12 = cpu_to_le32(
			(nvme_xdev_ext_sqe_dw(admitted_sqe, 12) & 0xffff0000U) |
			(u32)(admitted->nlb - 1));
		return 0;
	}
	if (nvme_ctrl_state(ns->ctrl) != NVME_CTRL_LIVE ||
	    !test_bit(NVME_NS_READY, &ns->flags) ||
	    test_bit(NVME_NS_REMOVING, &ns->flags))
		return -ENODEV;
	if (ns->head->lba_shift < SECTOR_SHIFT || ns->head->lba_shift > 31)
		return -EINVAL;
	if (p->write && get_disk_ro(ns->disk))
		return -EROFS;
	ret = xdev_ext_peer_nvme_plan(ns->head->lba_shift,
			get_capacity(ns->disk) >> (ns->head->lba_shift - SECTOR_SHIFT),
			ns->head->ms, ns->head->ids.csi, admitted->slba,
			batch_bytes, p->write, &plan);
	if (ret)
		return ret;
	if (plan.bytes > (u64)queue_max_hw_sectors(
			p->family.dev->queue(p->family.member)) << SECTOR_SHIFT)
		return -E2BIG;
	*posting = (struct xdev_ext_stor_rw) {
		.slba = plan.slba, .nlb = (u64)plan.nlb + 1,
		.byte_offset = plan.slba << ns->head->lba_shift,
		.byte_length = plan.bytes, .write = p->write,
	};
	cmd->rw.opcode = plan.opcode;
	cmd->rw.nsid = cpu_to_le32(p->identity.nsid);
	cmd->rw.slba = cpu_to_le64(plan.slba);
	cmd->rw.length = cpu_to_le16(plan.nlb);
	return 0;
}

static int nvme_xdev_ext_member_encode_dptr(void *member,
		struct xdev_ext_stor_command *command,
		const struct xdev_ext_stor_extent *spans, u32 nr,
		struct xdev_ext_stor_extent *work, u32 capacity,
		void *list_cpu, u64 list_dma, u32 list_bytes)
{
	struct nvme_xdev_ext_mech_stage *p = member;
	struct nvme_command *cmd = (void *)command->bytes;
	struct nvme_sgl_desc *sgl = list_cpu;
	u32 pos, n = 0;
	u64 prp1, prp2;
	int ret;

	if (nvme_ctrl_sgl_supported(p->ns->ctrl)) {
		ret = xdev_ext_peer_nvme_sgl_build(spans, nr, work,
			min(capacity, nvme_xdev_ext_stor_hooks.max_extents),
			nvme_xdev_ext_stor_hooks.extent_align_mask, &n);
		if (ret)
			return ret;
		for (pos = 0; pos < n; pos++)
			sgl[pos] = (struct nvme_sgl_desc) {
				.addr = cpu_to_le64(work[pos].addr),
				.length = cpu_to_le32(work[pos].len),
				.type = NVME_SGL_FMT_DATA_DESC << 4,
			};
		if (n == 1)
			cmd->rw.dptr.sgl = sgl[0];
		else
			cmd->rw.dptr.sgl = (struct nvme_sgl_desc) {
				.addr = cpu_to_le64(list_dma),
				.length = cpu_to_le32(n * sizeof(*sgl)),
				.type = NVME_SGL_FMT_LAST_SEG_DESC << 4,
			};
	} else {
		u64 *list = list_cpu;

		ret = xdev_ext_peer_nvme_prp_build(spans, nr,
			NVME_XDEV_EXT_PEER_MIN_PAGE_SHIFT, list_dma,
			list, list_bytes / sizeof(*list), &prp1, &prp2, &n);
		if (ret)
			return ret;
		for (pos = 0; pos < n; pos++)
			list[pos] = cpu_to_le64(list[pos]);
		cmd->rw.dptr.prp1 = cpu_to_le64(prp1);
		cmd->rw.dptr.prp2 = cpu_to_le64(prp2);
	}
	return 0;
}

static void nvme_xdev_ext_member_request_init(void *member, struct request *req,
		struct xdev_ext_stor_command *command, bool peer)
{
	struct nvme_xdev_ext_mech_stage *p = member;
	struct nvme_command *cmd = (void *)command->bytes;

	nvme_init_request(req, cmd);
	if (peer) {
		/* init clears template SGL bits; this is already-mapped peer DMA. */
		if (nvme_ctrl_sgl_supported(p->ns->ctrl))
			nvme_req(req)->cmd->common.flags |= NVME_CMD_SGL_METABUF;
		req->cmd_flags |= REQ_FAILFAST_MASK;
	} else {
		nvme_req(req)->flags |= NVME_REQ_USERCMD;
#ifdef CONFIG_XDEV_EXT_MECH_ZEROCOPY
		nvme_req(req)->flags |= NVME_REQ_XDEV_EXT_ZC;
#endif
	}
}

static void nvme_xdev_ext_member_post(void *member, struct request *req,
		struct xdev_ext_stor_io *io, struct xdev_ext_mech_batch *b,
		const struct xdev_ext_stor_command *command, bool peer)
{
	struct nvme_xdev_ext_mech_stage *p = member;
	const struct nvme_command *cmd = (const void *)command->bytes;
	struct xdev_ext_stor_batch *sb = xdev_ext_mech_batch_priv(b);

	if (peer) {
		struct nvme_xdev_ext_peer_trace *trace = io->peer_native;

		*trace = (struct nvme_xdev_ext_peer_trace) {
			.leases = io->leases, .nr_leases = io->nr_leases,
			.bytes = sb->posting.byte_length, .origin = "K",
			.cookie = (u64)(unsigned long)req,
		};
		nvme_req(req)->peer_trace = trace;
		nvme_req(req)->flags |= NVME_REQ_USERCMD | NVME_REQ_XDEV_EXT_PEER;
		req->end_io = nvme_xdev_ext_peer_end_io;
	} else {
#ifdef NVME_XDEV_EXT_MECH_BOUNCE_AVAILABLE
		if (sb->bounce) {
			atomic64_inc(&nvme_xdev_ext_mech_bounces);
			pr_warn_once("nvme: XDEV_EXT mechanism batches are bounced (CONFIG_XDEV_EXT_MECH_KVM_BOUNCE)\n");
		}
#endif
		req->end_io = nvme_xdev_ext_class_end_io;
	}
	req->end_io_data = &io->done;
	xdev_ext_stor_block_poll_arm(p->family.st->poll, req, &io->done);
	xdev_ext_mech_trace_native_submit(b, (u64)(unsigned long)req,
		le64_to_cpu(cmd->rw.slba), xdev_ext_mech_batch_bytes(b),
		(u32)cmd->rw.opcode | (u32)le16_to_cpu(cmd->rw.length) << 8);
	blk_execute_rq_nowait(req, false);
}

static void nvme_xdev_ext_member_retire_peer(void *member,
		struct xdev_ext_stor_io *io, bool quiesced)
{
	struct nvme_xdev_ext_peer_trace *trace = io->peer_native;

	nvme_xdev_ext_peer_trace_release(trace, quiesced);
	trace->cookie = 0;
}

static int nvme_xdev_ext_class_submit(struct xdev_ext_mech_stage *st,
		struct xdev_ext_mech_batch *b)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);

	return xdev_ext_storfam_submit(&p->family, b, &bp->family);
}

/*
 * Session worker, polled stage: one pass over the hardware queues that hold
 * this stage's live requests, host-page and device-memory slots alike.
 * Completions found run the same end_io, claim and publish as interrupts.
 */
static int nvme_xdev_ext_member_poll(void *member,
		const struct xdev_ext_stor_poll_view *views, u32 nr_views)
{
	struct nvme_xdev_ext_mech_stage *p = member;

	return xdev_ext_stor_block_poll(p->family.dev->queue(member), views, nr_views);
}

static int nvme_xdev_ext_class_poll(struct xdev_ext_mech_stage *st)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;

	return xdev_ext_storfam_poll(&p->family);
}

static const struct xdev_ext_stor_dev_ops nvme_xdev_ext_member_ops = {
	.bind = nvme_xdev_ext_member_bind,
	.unbind = nvme_xdev_ext_member_unbind,
	.identity = nvme_xdev_ext_member_identity,
	.requester = nvme_xdev_ext_member_requester,
	.queue = nvme_xdev_ext_member_queue,
	.decode = nvme_xdev_ext_member_decode,
	.encode = nvme_xdev_ext_member_encode,
	.encode_dptr = nvme_xdev_ext_member_encode_dptr,
	.request_init = nvme_xdev_ext_member_request_init,
	.post = nvme_xdev_ext_member_post,
	.retire_peer = nvme_xdev_ext_member_retire_peer,
	.peer_slot_bytes = sizeof(struct nvme_xdev_ext_peer_slot),
	.peer_native_offset = offsetof(struct nvme_xdev_ext_peer_slot, trace),
	.poll = nvme_xdev_ext_member_poll,
};

static void nvme_xdev_ext_stage_fill_cqe(struct xdev_ext_mech_stage *st,
		struct xdev_ext_mech_batch *b, void *cqe)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;
	struct nvme_xdev_ext_mech_batch *bp = xdev_ext_mech_batch_priv(b);

	xdev_ext_storfam_consume(&p->family, b, &bp->family);
	memcpy(cqe, &bp->cqe, sizeof(bp->cqe));
}

static void nvme_xdev_ext_class_mark_dead(struct xdev_ext_mech_stage *st)
{
	struct nvme_xdev_ext_mech_stage *p = st->priv;

	if (p)
		xdev_ext_storfam_mark_dead(&p->family);
}

static const struct xdev_ext_mech_class_ops nvme_xdev_ext_mech_class = {
 .decl = &xdev_ext_mech_class_decls[XDEV_EXT_MECH_CLASS_NVME],
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
	.poll = nvme_xdev_ext_class_poll,
	.fam.stor = &nvme_xdev_ext_stor_hooks,
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
