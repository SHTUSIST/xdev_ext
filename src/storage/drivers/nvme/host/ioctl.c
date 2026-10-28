// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2011-2014, Intel Corporation.
 * Copyright (c) 2017-2021 Christoph Hellwig.
 */
#include <linux/blk-integrity.h>
#include <linux/ptrace.h>	/* for force_successful_syscall_return */
#include <linux/nvme_ioctl.h>
#include <linux/nvme_xdev_ext_passthru.h>
#include <linux/io_uring/cmd.h>
#include <linux/xdev_ext_binding.h>
#include <linux/xdev_ext_mech.h>
#include "../../../io_uring/xdev_ext_mech_core.h"
#include "nvme.h"
#ifdef CONFIG_XDEV_EXT_MECH
#include <trace/events/xdev_ext.h>
#include <uapi/linux/xdev_ext_peer.h>
#endif

enum {
	NVME_IOCTL_VEC		= (1 << 0),
	NVME_IOCTL_PARTITION	= (1 << 1),
};

static bool nvme_cmd_allowed(struct nvme_ns *ns, struct nvme_command *c,
		unsigned int flags, bool open_for_write)
{
	u32 effects;

	/*
	 * Do not allow unprivileged passthrough on partitions, as that allows an
	 * escape from the containment of the partition.
	 */
	if (flags & NVME_IOCTL_PARTITION)
		goto admin;

	/*
	 * Do not allow unprivileged processes to send vendor specific or fabrics
	 * commands as we can't be sure about their effects.
	 */
	if (c->common.opcode >= nvme_cmd_vendor_start ||
	    c->common.opcode == nvme_fabrics_command)
		goto admin;

	/*
	 * Do not allow unprivileged passthrough of admin commands except
	 * for a subset of identify commands that contain information required
	 * to form proper I/O commands in userspace and do not expose any
	 * potentially sensitive information.
	 */
	if (!ns) {
		if (c->common.opcode == nvme_admin_identify) {
			switch (c->identify.cns) {
			case NVME_ID_CNS_NS:
			case NVME_ID_CNS_CS_NS:
			case NVME_ID_CNS_NS_CS_INDEP:
			case NVME_ID_CNS_CS_CTRL:
			case NVME_ID_CNS_CTRL:
				return true;
			}
		}
		goto admin;
	}

	/*
	 * Check if the controller provides a Commands Supported and Effects log
	 * and marks this command as supported.  If not reject unprivileged
	 * passthrough.
	 */
	effects = nvme_command_effects(ns->ctrl, ns, c->common.opcode);
	if (!(effects & NVME_CMD_EFFECTS_CSUPP))
		goto admin;

	/*
	 * Don't allow passthrough for command that have intrusive (or unknown)
	 * effects.
	 */
	if (effects & ~(NVME_CMD_EFFECTS_CSUPP | NVME_CMD_EFFECTS_LBCC |
			NVME_CMD_EFFECTS_UUID_SEL |
			NVME_CMD_EFFECTS_SCOPE_MASK))
		goto admin;

	/*
	 * Only allow I/O commands that transfer data to the controller or that
	 * change the logical block contents if the file descriptor is open for
	 * writing.
	 */
	if ((nvme_is_write(c) || (effects & NVME_CMD_EFFECTS_LBCC)) &&
	    !open_for_write)
		goto admin;

	return true;
admin:
	return capable(CAP_SYS_ADMIN);
}

/*
 * Convert integer values from ioctl structures to user pointers, silently
 * ignoring the upper bits in the compat case to match behaviour of 32-bit
 * kernels.
 */
static void __user *nvme_to_user_ptr(uintptr_t ptrval)
{
	if (in_compat_syscall())
		ptrval = (compat_uptr_t)ptrval;
	return (void __user *)ptrval;
}

static struct request *nvme_alloc_user_request(struct request_queue *q,
		struct nvme_command *cmd, blk_opf_t rq_flags,
		blk_mq_req_flags_t blk_flags)
{
	struct request *req;

	req = blk_mq_alloc_request(q, nvme_req_op(cmd) | rq_flags, blk_flags);
	if (IS_ERR(req))
		return req;
	nvme_init_request(req, cmd);
	nvme_req(req)->flags |= NVME_REQ_USERCMD;
	return req;
}

static int nvme_map_user_request(struct request *req, u64 ubuffer,
		unsigned bufflen, void __user *meta_buffer, unsigned meta_len,
		struct iov_iter *iter, unsigned int flags)
{
	struct request_queue *q = req->q;
	struct nvme_ns *ns = q->queuedata;
	struct block_device *bdev = ns ? ns->disk->part0 : NULL;
	bool supports_metadata = bdev && blk_get_integrity(bdev->bd_disk);
	struct nvme_ctrl *ctrl = nvme_req(req)->ctrl;
	bool has_metadata = meta_buffer && meta_len;
	struct bio *bio = NULL;
	int ret;

	if (!nvme_ctrl_sgl_supported(ctrl))
		dev_warn_once(ctrl->device, "using unchecked data buffer\n");
	if (has_metadata) {
		if (!supports_metadata)
			return -EINVAL;

		if (!nvme_ctrl_meta_sgl_supported(ctrl))
			dev_warn_once(ctrl->device,
				      "using unchecked metadata buffer\n");
	}

	if (iter)
		ret = blk_rq_map_user_iov(q, req, NULL, iter, GFP_KERNEL);
	else
		ret = blk_rq_map_user_io(req, NULL, nvme_to_user_ptr(ubuffer),
				bufflen, GFP_KERNEL, flags & NVME_IOCTL_VEC, 0,
				0, rq_data_dir(req));

	if (ret)
		return ret;

	bio = req->bio;
	if (bdev)
		bio_set_dev(bio, bdev);

	if (has_metadata) {
		ret = blk_rq_integrity_map_user(req, meta_buffer, meta_len);
		if (ret)
			goto out_unmap;
	}

	return ret;

out_unmap:
	if (bio)
		blk_rq_unmap_user(bio);
	return ret;
}

static int nvme_submit_user_cmd(struct request_queue *q,
		struct nvme_command *cmd, u64 ubuffer, unsigned bufflen,
		void __user *meta_buffer, unsigned meta_len,
		u64 *result, unsigned timeout, unsigned int flags)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_ctrl *ctrl;
	struct request *req;
	struct bio *bio;
	u32 effects;
	int ret;

	req = nvme_alloc_user_request(q, cmd, 0, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->timeout = timeout;
	if (ubuffer && bufflen) {
		ret = nvme_map_user_request(req, ubuffer, bufflen, meta_buffer,
				meta_len, NULL, flags);
		if (ret)
			goto out_free_req;
	}

	bio = req->bio;
	ctrl = nvme_req(req)->ctrl;

	effects = nvme_passthru_start(ctrl, ns, cmd->common.opcode);
	ret = nvme_execute_rq(req, false);
	if (result)
		*result = le64_to_cpu(nvme_req(req)->result.u64);
	if (bio)
		blk_rq_unmap_user(bio);
	blk_mq_free_request(req);

	if (effects)
		nvme_passthru_end(ctrl, ns, effects, cmd, ret);
	return ret;

out_free_req:
	blk_mq_free_request(req);
	return ret;
}

static int nvme_submit_io(struct nvme_ns *ns, struct nvme_user_io __user *uio)
{
	struct nvme_user_io io;
	struct nvme_command c;
	unsigned length, meta_len;
	void __user *metadata;

	if (copy_from_user(&io, uio, sizeof(io)))
		return -EFAULT;
	if (io.flags)
		return -EINVAL;

	switch (io.opcode) {
	case nvme_cmd_write:
	case nvme_cmd_read:
	case nvme_cmd_compare:
		break;
	default:
		return -EINVAL;
	}

	length = (io.nblocks + 1) << ns->head->lba_shift;

	if ((io.control & NVME_RW_PRINFO_PRACT) &&
	    (ns->head->ms == ns->head->pi_size)) {
		/*
		 * Protection information is stripped/inserted by the
		 * controller.
		 */
		if (nvme_to_user_ptr(io.metadata))
			return -EINVAL;
		meta_len = 0;
		metadata = NULL;
	} else {
		meta_len = (io.nblocks + 1) * ns->head->ms;
		metadata = nvme_to_user_ptr(io.metadata);
	}

	if (ns->head->features & NVME_NS_EXT_LBAS) {
		length += meta_len;
		meta_len = 0;
	} else if (meta_len) {
		if ((io.metadata & 3) || !io.metadata)
			return -EINVAL;
	}

	memset(&c, 0, sizeof(c));
	c.rw.opcode = io.opcode;
	c.rw.flags = io.flags;
	c.rw.nsid = cpu_to_le32(ns->head->ns_id);
	c.rw.slba = cpu_to_le64(io.slba);
	c.rw.length = cpu_to_le16(io.nblocks);
	c.rw.control = cpu_to_le16(io.control);
	c.rw.dsmgmt = cpu_to_le32(io.dsmgmt);
	c.rw.reftag = cpu_to_le32(io.reftag);
	c.rw.lbat = cpu_to_le16(io.apptag);
	c.rw.lbatm = cpu_to_le16(io.appmask);

	return nvme_submit_user_cmd(ns->queue, &c, io.addr, length, metadata,
			meta_len, NULL, 0, 0);
}

static bool nvme_validate_passthru_nsid(struct nvme_ctrl *ctrl,
					struct nvme_ns *ns, __u32 nsid)
{
	if (ns && nsid != ns->head->ns_id) {
		dev_err(ctrl->device,
			"%s: nsid (%u) in cmd does not match nsid (%u) of namespace\n",
			current->comm, nsid, ns->head->ns_id);
		return false;
	}

	return true;
}

static int nvme_user_cmd(struct nvme_ctrl *ctrl, struct nvme_ns *ns,
		struct nvme_passthru_cmd __user *ucmd, unsigned int flags,
		bool open_for_write)
{
	struct nvme_passthru_cmd cmd;
	struct nvme_command c;
	unsigned timeout = 0;
	u64 result;
	int status;

	if (copy_from_user(&cmd, ucmd, sizeof(cmd)))
		return -EFAULT;
	if (cmd.flags)
		return -EINVAL;
	if (!nvme_validate_passthru_nsid(ctrl, ns, cmd.nsid))
		return -EINVAL;

	memset(&c, 0, sizeof(c));
	c.common.opcode = cmd.opcode;
	c.common.flags = cmd.flags;
	c.common.nsid = cpu_to_le32(cmd.nsid);
	c.common.cdw2[0] = cpu_to_le32(cmd.cdw2);
	c.common.cdw2[1] = cpu_to_le32(cmd.cdw3);
	c.common.cdw10 = cpu_to_le32(cmd.cdw10);
	c.common.cdw11 = cpu_to_le32(cmd.cdw11);
	c.common.cdw12 = cpu_to_le32(cmd.cdw12);
	c.common.cdw13 = cpu_to_le32(cmd.cdw13);
	c.common.cdw14 = cpu_to_le32(cmd.cdw14);
	c.common.cdw15 = cpu_to_le32(cmd.cdw15);

	if (!nvme_cmd_allowed(ns, &c, 0, open_for_write))
		return -EACCES;

	if (cmd.timeout_ms)
		timeout = msecs_to_jiffies(cmd.timeout_ms);

	status = nvme_submit_user_cmd(ns ? ns->queue : ctrl->admin_q, &c,
			cmd.addr, cmd.data_len, nvme_to_user_ptr(cmd.metadata),
			cmd.metadata_len, &result, timeout, 0);

	if (status >= 0) {
		if (put_user(result, &ucmd->result))
			return -EFAULT;
	}

	return status;
}

static int nvme_user_cmd64(struct nvme_ctrl *ctrl, struct nvme_ns *ns,
		struct nvme_passthru_cmd64 __user *ucmd, unsigned int flags,
		bool open_for_write)
{
	struct nvme_passthru_cmd64 cmd;
	struct nvme_command c;
	unsigned timeout = 0;
	int status;

	if (copy_from_user(&cmd, ucmd, sizeof(cmd)))
		return -EFAULT;
	if (cmd.flags)
		return -EINVAL;
	if (!nvme_validate_passthru_nsid(ctrl, ns, cmd.nsid))
		return -EINVAL;

	memset(&c, 0, sizeof(c));
	c.common.opcode = cmd.opcode;
	c.common.flags = cmd.flags;
	c.common.nsid = cpu_to_le32(cmd.nsid);
	c.common.cdw2[0] = cpu_to_le32(cmd.cdw2);
	c.common.cdw2[1] = cpu_to_le32(cmd.cdw3);
	c.common.cdw10 = cpu_to_le32(cmd.cdw10);
	c.common.cdw11 = cpu_to_le32(cmd.cdw11);
	c.common.cdw12 = cpu_to_le32(cmd.cdw12);
	c.common.cdw13 = cpu_to_le32(cmd.cdw13);
	c.common.cdw14 = cpu_to_le32(cmd.cdw14);
	c.common.cdw15 = cpu_to_le32(cmd.cdw15);

	if (!nvme_cmd_allowed(ns, &c, flags, open_for_write))
		return -EACCES;

	if (cmd.timeout_ms)
		timeout = msecs_to_jiffies(cmd.timeout_ms);

	status = nvme_submit_user_cmd(ns ? ns->queue : ctrl->admin_q, &c,
			cmd.addr, cmd.data_len, nvme_to_user_ptr(cmd.metadata),
			cmd.metadata_len, &cmd.result, timeout, flags);

	if (status >= 0) {
		if (put_user(cmd.result, &ucmd->result))
			return -EFAULT;
	}

	return status;
}

struct nvme_uring_data {
	__u64	metadata;
	__u64	addr;
	__u32	data_len;
	__u32	metadata_len;
	__u32	timeout_ms;
};

struct nvme_xdev_ext_sidecar {
	struct xdev_ext_binding_token token;
	struct xdev_ext_binding_ctx_v2 dispatch_ctx;
	struct nvme_xdev_ext_identity identity;
	struct nvme_xdev_ext_decoded decoded;
	struct nvme_uring_data data_snapshot;
	struct iov_iter vector_iter;
	const struct nvme_ns_head *head;
	const struct gendisk *disk;
	const struct request_queue *queue;
	struct nvme_xdev_ext_resource_state resources;
	/* F_XDEV_EXT_BUILD: the ring's NVMe mechanism stage, held until done */
	struct xdev_ext_mech_stage *mech_stage;
	u64 vector_address;
	u32 vector_count;
	bool vector_imported;
};

static atomic64_t nvme_xdev_ext_policy_errors;

/* Shared with the NVMe mechanism class, which binds a namespace once. */
int nvme_xdev_ext_capture_identity(struct nvme_ns *ns,
			      struct nvme_xdev_ext_identity *identity,
			      const struct nvme_ns_head **head_out,
			      const struct gendisk **disk_out,
			      const struct request_queue **queue_out)
{
	struct nvme_ns_head *head = READ_ONCE(ns->head);
	struct gendisk *disk = READ_ONCE(ns->disk);
	struct request_queue *queue = READ_ONCE(ns->queue);
	sector_t sectors;
	u8 lba_shift;

	if (!head || !disk || !queue)
		return -ENODEV;

	lba_shift = READ_ONCE(head->lba_shift);
	if (lba_shift < SECTOR_SHIFT || lba_shift >= 32)
		return -EINVAL;
	sectors = get_capacity(disk);
	if (lba_shift > SECTOR_SHIFT &&
	    (sectors & ((1ULL << (lba_shift - SECTOR_SHIFT)) - 1)))
		return -EINVAL;

	*identity = (struct nvme_xdev_ext_identity) {
		.nsid = READ_ONCE(head->ns_id),
		.lba_shift = lba_shift,
		.namespace_ready = test_bit(NVME_NS_READY, &ns->flags),
		.namespace_removing = test_bit(NVME_NS_REMOVING, &ns->flags),
		.csi = READ_ONCE(head->ids.csi),
		.metadata_size = READ_ONCE(head->ms),
		.pi_size = READ_ONCE(head->pi_size),
		.pi_type = READ_ONCE(head->pi_type),
		.capacity_lbas = sectors >> (lba_shift - SECTOR_SHIFT),
		.diskseq = READ_ONCE(disk->diskseq),
	};
	memcpy(identity->eui64, head->ids.eui64, sizeof(identity->eui64));
	memcpy(identity->nguid, head->ids.nguid, sizeof(identity->nguid));
	memcpy(identity->uuid, &head->ids.uuid, sizeof(identity->uuid));
	*head_out = head;
	*disk_out = disk;
	*queue_out = queue;
	return 0;
}

static struct nvme_xdev_ext_admission
nvme_xdev_ext_make_admission(const struct nvme_command *c,
			const struct nvme_uring_data *data,
			const struct nvme_xdev_ext_identity *identity)
{
	return (struct nvme_xdev_ext_admission) {
		.opcode = c->common.opcode,
		.lba_shift = identity->lba_shift,
		.namespace_ready = identity->namespace_ready,
		.namespace_removing = identity->namespace_removing,
		.csi = identity->csi,
		.metadata_size = identity->metadata_size,
		.pi_size = identity->pi_size,
		.pi_type = identity->pi_type,
		.command_nsid = le32_to_cpu(c->common.nsid),
		.live_nsid = identity->nsid,
		.data_len = data->data_len,
		.metadata_len = data->metadata_len,
		.cdw10 = le32_to_cpu(c->common.cdw10),
		.cdw11 = le32_to_cpu(c->common.cdw11),
		.cdw12 = le32_to_cpu(c->common.cdw12),
		.metadata = data->metadata,
		.capacity_lbas = identity->capacity_lbas,
	};
}

static int nvme_xdev_ext_initial_admit(struct nvme_ns *ns,
				  const struct nvme_command *c,
				  const struct nvme_uring_data *data,
				  const struct request_queue *request_queue,
				  bool build,
				  struct nvme_xdev_ext_identity *identity,
				  struct nvme_xdev_ext_decoded *decoded,
				  const struct nvme_ns_head **head,
				  const struct gendisk **disk,
				  const struct request_queue **queue)
{
	struct nvme_xdev_ext_admission admission;
	int ret;

	ret = nvme_xdev_ext_capture_identity(ns, identity, head, disk, queue);
	if (ret)
		return ret;
	if (*queue != request_queue)
		return -ESTALE;
	admission = nvme_xdev_ext_make_admission(c, data, identity);
	/*
	 * A built command carries no SLBA/NLB yet: check identity and an
	 * LBA-aligned length now, and decode only what the program built.
	 */
	if (build) {
		ret = nvme_xdev_ext_build_user_check((const u8 *)c);
		if (ret)
			return ret;
		*decoded = (struct nvme_xdev_ext_decoded) {};
		return nvme_xdev_ext_admit_identity(&admission);
	}
	return nvme_xdev_ext_admit(&admission, decoded);
}

static int nvme_xdev_ext_dispatch_admitted(unsigned int issue_flags,
				      struct io_uring_cmd *ioucmd,
				      struct nvme_xdev_ext_sidecar *sidecar)
{
	struct xdev_ext_binding_plan plan;
	u64 byte_length = sidecar->decoded.byte_length;
	u64 byte_offset = sidecar->decoded.byte_offset;
	bool fixed_buffer = ioucmd->flags & IORING_URING_CMD_FIXED;
	bool fixed_file = cmd_to_io_kiocb(ioucmd)->flags & REQ_F_FIXED_FILE;
	bool poll = issue_flags & IO_URING_F_IOPOLL;
	bool write = sidecar->decoded.write;
	int ret;

	ret = nvme_xdev_ext_lifecycle_prepare(&sidecar->resources.lifecycle);
	if (ret)
		return ret;

	sidecar->dispatch_ctx =
		xdev_ext_binding_make_nvme_ctx(write, byte_offset, byte_length);
	sidecar->dispatch_ctx.endpoint_id = sidecar->identity.diskseq;
	sidecar->dispatch_ctx.capabilities =
		nvme_xdev_ext_capabilities_vec(poll, fixed_file, fixed_buffer,
					  sidecar->vector_imported);

	ret = xdev_ext_binding_dispatch(&sidecar->dispatch_ctx, &sidecar->token,
				   &plan);
	if (ret)
		return ret;
	if (plan.action == XDEV_EXT_BINDING_ACTION_TERMINAL)
		return -EPERM;
	return 0;
}

static int nvme_xdev_ext_final_admit(struct nvme_ns *ns,
				const struct nvme_command *c,
				const struct nvme_uring_data *data,
				const struct nvme_xdev_ext_sidecar *sidecar)
{
	struct nvme_xdev_ext_identity identity;
	struct nvme_xdev_ext_admission admission;
	struct nvme_xdev_ext_decoded decoded;
	const struct nvme_ns_head *head;
	const struct request_queue *queue;
	const struct gendisk *disk;
	int ret;

	ret = nvme_xdev_ext_capture_identity(ns, &identity, &head, &disk, &queue);
	if (ret)
		return ret;
	if (head != sidecar->head || disk != sidecar->disk ||
	    queue != sidecar->queue)
		return -ESTALE;
	if (!nvme_xdev_ext_identity_equal(&sidecar->identity, &identity))
		return -ESTALE;
	admission = nvme_xdev_ext_make_admission(c, data, &identity);
	ret = nvme_xdev_ext_admit(&admission, &decoded);
	if (ret)
		return ret;
	if (decoded.slba != sidecar->decoded.slba ||
	    decoded.nlb != sidecar->decoded.nlb ||
	    decoded.byte_offset != sidecar->decoded.byte_offset ||
	    decoded.byte_length != sidecar->decoded.byte_length ||
	    decoded.write != sidecar->decoded.write)
		return -ESTALE;
	return 0;
}

#ifdef CONFIG_XDEV_EXT_MECH
/*
 * CREATE of an NVMe mechanism stage on @file: READ or WRITE passthrough
 * there passes the same permission and effects check as a uring_cmd.
 */
bool nvme_xdev_ext_mech_cmd_allowed(struct nvme_ns *ns, struct file *file,
			       bool write)
{
	struct nvme_command c = {};

	c.rw.opcode = write ? nvme_cmd_write : nvme_cmd_read;
	c.rw.nsid = cpu_to_le32(ns->head->ns_id);
	return nvme_cmd_allowed(ns, &c, 0, file->f_mode & FMODE_WRITE);
}

/*
 * F_XDEV_EXT_BUILD issue, before anything is allocated: the NVMe stage of this
 * ring's mechanism session for this file, held until the command completes
 * or unwinds.  -EOPNOTSUPP when there is none: a built command never falls
 * back to a C path.
 */
static int nvme_xdev_ext_build_stage(struct io_uring_cmd *ioucmd,
				const struct nvme_command *c,
				struct nvme_xdev_ext_sidecar *sidecar)
{
	struct xdev_ext_mech_stage *st;

	st = xdev_ext_mech_stage_get_cmd(ioucmd, XDEV_EXT_MECH_CLASS_NVME);
	if (IS_ERR(st))
		return PTR_ERR(st);
	sidecar->mech_stage = st;
	if ((st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE) != nvme_is_write(c))
		return -EOPNOTSUPP;
	return 0;
}

static void nvme_xdev_ext_build_put(struct nvme_xdev_ext_sidecar *sidecar)
{
	if (!sidecar->mech_stage)
		return;
	xdev_ext_mech_stage_put(sidecar->mech_stage);
	sidecar->mech_stage = NULL;
}

static struct xdev_ext_binding_ctx_v2
nvme_xdev_ext_build_base(const struct xdev_ext_mech_stage *st,
		    const struct nvme_xdev_ext_sidecar *sidecar, u64 request_id)
{
	struct xdev_ext_binding_ctx_v2 base;

	base = xdev_ext_binding_make_nvme_ctx(st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE,
					 sidecar->decoded.byte_offset,
					 sidecar->data_snapshot.data_len);
	base.request_id = request_id;
	base.chain_id = xdev_ext_mech_session_id(st->s);
	base.endpoint_id = sidecar->identity.diskseq;
	return base;
}

/*
 * N1, where a plain F_XDEV_EXT command runs the frozen policy dispatch: the
 * request is allocated and its data mapped.  The program builds one SQE in
 * a zeroed scratch slot; C validates it against the stage window, writes
 * only cdw10..cdw12 into the stack command and the request command, and
 * decodes the request command again, so final admission sees exactly what
 * executes.  The program's request id is the io_uring user_data.
 */
static noinline_for_stack int
nvme_xdev_ext_build(struct io_uring_cmd *ioucmd, struct nvme_ns *ns,
	       struct request *req, struct nvme_command *c,
	       struct nvme_xdev_ext_sidecar *sidecar)
{
	const struct nvme_xdev_ext_identity *id = &sidecar->identity;
	u64 request_id = cmd_to_io_kiocb(ioucmd)->cqe.user_data;
	struct nvme_command *rq_cmd = nvme_req(req)->cmd;
	struct xdev_ext_mech_stage *st = sidecar->mech_stage;
	struct nvme_xdev_ext_admission admission;
	struct nvme_xdev_ext_mech_bounds bounds;
	struct nvme_xdev_ext_decoded validated;
	struct xdev_ext_nvme_mech_info info;
	struct xdev_ext_binding_ctx_v2 base;
	struct xdev_ext_mech_call_args a;
	u8 sqe[NVME_XDEV_EXT_SQE_SIZE] = {};
	bool illegal;
	int slots, ret;
	s32 prog;

	ret = nvme_xdev_ext_lifecycle_prepare(&sidecar->resources.lifecycle);
	if (ret)
		return ret;
	if (!xdev_ext_mech_session_admits(st->s))
		return -ESHUTDOWN;
	/* The window was bound against this namespace as it is now. */
	ret = nvme_xdev_ext_mech_stage_matches(st, ns, id);
	if (ret)
		return ret;

	nvme_xdev_ext_mech_fill_info(st, NULL, &info);
	base = nvme_xdev_ext_build_base(st, sidecar, request_id);
	a = (struct xdev_ext_mech_call_args) {
		.member = XDEV_EXT_MECH_MEMBER_BUILD,
		.callsite = XDEV_EXT_MECH_SITE_URING_CMD,
		.base = &base,
		.batch_id = request_id,
		.info_size = sizeof(info),
		.info = &info,
		.scratch = sqe,
		.desc_size = NVME_XDEV_EXT_SQE_SIZE,
		.desc_cap = 1,
	};
	ret = xdev_ext_mech_call(st, &a, &prog, NULL);
	if (ret)
		return ret;
	prog = xdev_ext_mech_ret_resolve(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_MEMBER_BUILD,
				    XDEV_EXT_MECH_SITE_URING_CMD, prog, &illegal);
	if (illegal)
		xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
	slots = xdev_ext_mech_slots_used(sqe, NVME_XDEV_EXT_SQE_SIZE, 1);
	ret = nvme_xdev_ext_build_errno(prog, slots);
	if (ret)
		return ret;

	bounds = (struct nvme_xdev_ext_mech_bounds) {
		.window_slba = st->arg0,
		.window_nlb = st->arg1,
		.capacity_lbas = id->capacity_lbas,
		.data_len = sidecar->data_snapshot.data_len,
		.lba_shift = id->lba_shift,
		.write = st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE,
	};
	ret = nvme_xdev_ext_mech_validate(sqe, &bounds, &validated);
	if (ret) {
		xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_REJECTS, 1);
		return ret;
	}

	c->common.cdw10 = cpu_to_le32(nvme_xdev_ext_sqe_dw(sqe, 10));
	c->common.cdw11 = cpu_to_le32(nvme_xdev_ext_sqe_dw(sqe, 11));
	c->common.cdw12 = cpu_to_le32(nvme_xdev_ext_sqe_dw(sqe, 12));
	rq_cmd->common.cdw10 = c->common.cdw10;
	rq_cmd->common.cdw11 = c->common.cdw11;
	rq_cmd->common.cdw12 = c->common.cdw12;
	admission = nvme_xdev_ext_make_admission(rq_cmd, &sidecar->data_snapshot,
					    id);
	return nvme_xdev_ext_build_redecode(&admission, &validated,
				       &sidecar->decoded);
}
#else
static int nvme_xdev_ext_build_stage(struct io_uring_cmd *ioucmd,
				const struct nvme_command *c,
				struct nvme_xdev_ext_sidecar *sidecar)
{
	return -EOPNOTSUPP;
}

static void nvme_xdev_ext_build_put(struct nvme_xdev_ext_sidecar *sidecar)
{
}

static int nvme_xdev_ext_build(struct io_uring_cmd *ioucmd, struct nvme_ns *ns,
			  struct request *req, struct nvme_command *c,
			  struct nvme_xdev_ext_sidecar *sidecar)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_XDEV_EXT_MECH */

static void nvme_xdev_ext_preaccept_unwind(struct nvme_xdev_ext_sidecar *sidecar,
				      struct request *req)
{
	enum nvme_xdev_ext_cleanup_action action;

	if (!sidecar)
		return;
	nvme_xdev_ext_build_put(sidecar);
	while ((action = nvme_xdev_ext_preaccept_next(&sidecar->resources))) {
		switch (action) {
		case NVME_XDEV_EXT_CLEANUP_UNMAP:
			if (WARN_ON_ONCE(!req || !req->bio))
				break;
			blk_rq_unmap_user(req->bio);
			break;
		case NVME_XDEV_EXT_CLEANUP_FREE_REQUEST:
			if (!WARN_ON_ONCE(!req))
				blk_mq_free_request(req);
			break;
		case NVME_XDEV_EXT_CLEANUP_PUT_TOKEN:
			xdev_ext_binding_token_put(&sidecar->token);
			break;
		default:
			WARN_ON_ONCE(1);
			return;
		}
	}
}

/*
 * This overlays struct io_uring_cmd pdu.
 * Expect build errors if this grows larger than that.
 */
struct nvme_uring_cmd_pdu {
	struct request *req;
	struct bio *bio;
	u64 result;
	int status;
	u32 trace_bytes; /* existing alignment padding; assigned only when tracing */
};

static inline struct nvme_uring_cmd_pdu *nvme_uring_cmd_pdu(
		struct io_uring_cmd *ioucmd)
{
	return io_uring_cmd_to_pdu(ioucmd, struct nvme_uring_cmd_pdu);
}

static void nvme_xdev_ext_complete(struct nvme_xdev_ext_sidecar *sidecar,
			      int native_status)
{
	struct xdev_ext_binding_normalized_result normalized;
	struct xdev_ext_binding_plan plan;
	u64 byte_length = sidecar->decoded.byte_length;
	int ret;

	normalized =
		xdev_ext_binding_normalize_status_result(native_status, byte_length);
	sidecar->dispatch_ctx.event = XDEV_EXT_BINDING_EVENT_COMPLETE;
	sidecar->dispatch_ctx.result = normalized.result;
	sidecar->dispatch_ctx.bytes_done = normalized.bytes_done;
	ret = xdev_ext_binding_complete(&sidecar->dispatch_ctx, &sidecar->token,
				   &plan);
	if (ret)
		atomic64_inc(&nvme_xdev_ext_policy_errors);
}

#ifdef CONFIG_XDEV_EXT_MECH
/*
 * N2, in task_work after the data was unmapped: the program reads the
 * native status and result exactly as completed.  The CQE is not changed.
 */
static void nvme_xdev_ext_build_complete(struct io_uring_cmd *ioucmd,
				    struct nvme_xdev_ext_sidecar *sidecar,
				    const struct nvme_uring_cmd_pdu *pdu)
{
	u64 request_id = cmd_to_io_kiocb(ioucmd)->cqe.user_data;
	struct xdev_ext_mech_stage *st = sidecar->mech_stage;
	struct xdev_ext_nvme_mech_info info;
	struct xdev_ext_binding_ctx_v2 base;
	struct xdev_ext_nvme_mech_cqe cqe;
	struct xdev_ext_mech_call_args a;
	bool illegal;
	s32 prog;

	nvme_xdev_ext_mech_cqe(pdu->status, pdu->result, &cqe);
	nvme_xdev_ext_mech_fill_info(st, NULL, &info);
	base = nvme_xdev_ext_build_base(st, sidecar, request_id);
	base.event = XDEV_EXT_BINDING_EVENT_COMPLETE;
	a = (struct xdev_ext_mech_call_args) {
		.member = XDEV_EXT_MECH_MEMBER_COMPLETE,
		.callsite = XDEV_EXT_MECH_SITE_URING_CMD,
		.base = &base,
		.batch_id = request_id,
		.info_size = sizeof(info),
		.info = &info,
		.cqe = &cqe,
		.cqe_size = sizeof(cqe),
		.cqe_cap = 1,
	};
	if (xdev_ext_mech_call(st, &a, &prog, NULL)) {
		xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
		return;
	}
	xdev_ext_mech_ret_resolve(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_MEMBER_COMPLETE,
			     XDEV_EXT_MECH_SITE_URING_CMD, prog, &illegal);
	if (illegal)
		xdev_ext_mech_count(st->s, XDEV_EXT_MECH_CNT_PROTOCOL_ERR, 1);
}
#else
static void nvme_xdev_ext_build_complete(struct io_uring_cmd *ioucmd,
				    struct nvme_xdev_ext_sidecar *sidecar,
				    const struct nvme_uring_cmd_pdu *pdu)
{
}
#endif /* CONFIG_XDEV_EXT_MECH */

static void nvme_uring_task_cb(struct io_uring_cmd *ioucmd,
			       unsigned issue_flags)
{
	struct nvme_uring_cmd_pdu *pdu = nvme_uring_cmd_pdu(ioucmd);
	struct nvme_xdev_ext_sidecar *sidecar =
		io_uring_cmd_get_async_data(ioucmd)->op_data;
	enum nvme_xdev_ext_cleanup_action action;

	if (!sidecar) {
		if (pdu->bio) {
			blk_rq_unmap_user(pdu->bio);
			pdu->bio = NULL;
		}
		io_uring_cmd_done(ioucmd, pdu->status, pdu->result,
				  issue_flags);
		return;
	}

	while ((action = nvme_xdev_ext_completion_next(&sidecar->resources))) {
		switch (action) {
		case NVME_XDEV_EXT_CLEANUP_UNMAP:
			if (WARN_ON_ONCE(!pdu->bio))
				break;
			blk_rq_unmap_user(pdu->bio);
			pdu->bio = NULL;
			break;
		case NVME_XDEV_EXT_CLEANUP_COMPLETE_POLICY:
			if (sidecar->mech_stage)
				nvme_xdev_ext_build_complete(ioucmd, sidecar, pdu);
			else
				nvme_xdev_ext_complete(sidecar, pdu->status);
			break;
		case NVME_XDEV_EXT_CLEANUP_PUT_TOKEN:
			xdev_ext_binding_token_put(&sidecar->token);
			break;
		case NVME_XDEV_EXT_CLEANUP_DONE:
			nvme_xdev_ext_build_put(sidecar);
			io_uring_cmd_done(ioucmd, pdu->status, pdu->result,
					  issue_flags);
			return;
		default:
			WARN_ON_ONCE(1);
			return;
		}
	}
}

#ifdef CONFIG_XDEV_EXT_MECH
/* U user_data is only a cookie; immutable workload sideband supplies identity. */
static void nvme_uring_native_trace(struct request *req,
				   const char *phase, int status)
{
	struct io_uring_cmd *cmd = req->end_io_data;
	struct nvme_command *c = nvme_req(req)->cmd;

	if (trace_native_event_enabled()) {
		struct task_struct *owner = io_uring_cmd_get_task(cmd)->group_leader;
		struct nvme_uring_cmd_pdu *pdu = nvme_uring_cmd_pdu(cmd);
		u64 cookie = cmd_to_io_kiocb(cmd)->cqe.user_data;
		struct xdev_ext_native_event e = {
			.phase = phase, .origin = "U", .class_id = XDEV_EXT_MECH_CLASS_NVME,
			.accepted = 1, .status = status, .cookie = cookie,
			.address = le64_to_cpu(c->rw.slba),
			.bytes = !strcmp(phase, "native_submit") ? blk_rq_bytes(req) : pdu->trace_bytes,
			.aux = (u32)c->rw.opcode | (u32)le16_to_cpu(c->rw.length) << 8,
			.sequence = (u64)(unsigned long)req, .origin_tgid = task_tgid_nr(owner),
			.process_start_ticks = nsec_to_clock_t(owner->start_boottime),
			.native_user_data = cookie,
		};

		if (!strcmp(phase, "native_submit")) {
			struct req_iterator iter;
			struct bio_vec bvec;
			struct xdev_ext_native_event span = e;
			u64 offset = 0;

			pdu->trace_bytes = blk_rq_bytes(req);
			e.bytes = pdu->trace_bytes;
			span.phase = "native_span";
			rq_for_each_segment(bvec, req, iter) {
				span.address = page_to_phys(bvec.bv_page) + bvec.bv_offset;
				span.bytes = bvec.bv_len;
				span.aux = offset;
				trace_native_event(&span);
				offset += bvec.bv_len;
			}
		}
		trace_native_event(&e);
	}
}

#else
static inline void nvme_uring_native_trace(struct request *req,
					const char *phase, int status) {}
#endif

static enum rq_end_io_ret nvme_uring_cmd_end_io(struct request *req,
						blk_status_t err)
{
	struct io_uring_cmd *ioucmd = req->end_io_data;
	struct nvme_uring_cmd_pdu *pdu = nvme_uring_cmd_pdu(ioucmd);

	if (nvme_req(req)->flags & NVME_REQ_CANCELLED) {
		pdu->status = -EINTR;
	} else {
		pdu->status = nvme_req(req)->status;
		if (!pdu->status)
			pdu->status = blk_status_to_errno(err);
	}
	nvme_uring_native_trace(req, "native_complete", pdu->status);
	pdu->result = le64_to_cpu(nvme_req(req)->result.u64);
	if (io_uring_cmd_get_async_data(ioucmd)->op_data) {
		struct nvme_xdev_ext_sidecar *sidecar =
			io_uring_cmd_get_async_data(ioucmd)->op_data;

		sidecar->resources.request_allocated = 0;
	}

	/*
	 * IOPOLL could potentially complete this request directly, but
	 * if multiple rings are polling on the same queue, then it's possible
	 * for one ring to find completions for another ring. Punting the
	 * completion via task_work will always direct it to the right
	 * location, rather than potentially complete requests for ringA
	 * under iopoll invocations from ringB.
	 */
	io_uring_cmd_do_in_task_lazy(ioucmd, nvme_uring_task_cb);
	return RQ_END_IO_FREE;
}

static int nvme_uring_cmd_io(struct nvme_ctrl *ctrl, struct nvme_ns *ns,
		struct io_uring_cmd *ioucmd, unsigned int issue_flags, bool vec)
{
	struct nvme_uring_cmd_pdu *pdu = nvme_uring_cmd_pdu(ioucmd);
	const struct nvme_uring_cmd *cmd = io_uring_sqe_cmd(ioucmd->sqe);
	struct request_queue *q = ns ? ns->queue : ctrl->admin_q;
	struct nvme_xdev_ext_sidecar *xdev_ext_sidecar = NULL;
	struct nvme_xdev_ext_identity xdev_ext_identity;
	struct nvme_xdev_ext_decoded xdev_ext_decoded;
	const struct nvme_ns_head *xdev_ext_head;
	const struct request_queue *xdev_ext_queue;
	const struct gendisk *xdev_ext_disk;
	struct nvme_uring_data d;
	struct nvme_command c;
	struct iov_iter iter;
	struct iov_iter *map_iter = NULL;
	struct request *req = NULL;
	blk_opf_t rq_flags = REQ_ALLOC_CACHE;
	blk_mq_req_flags_t blk_flags = 0;
	u32 xdev_ext_flags = 0;
	bool xdev_ext_build = false;
	bool xdev_ext = false;
	int ret;

	if (ns) {
		xdev_ext_flags = READ_ONCE(cmd->rsvd2);
		if (!nvme_xdev_ext_flags_valid(xdev_ext_flags))
			return -EINVAL;
		xdev_ext = nvme_xdev_ext_opted_in(xdev_ext_flags);
		xdev_ext_build = nvme_xdev_ext_build_requested(xdev_ext_flags);
	}

	c.common.opcode = READ_ONCE(cmd->opcode);
	c.common.flags = READ_ONCE(cmd->flags);
	if (c.common.flags)
		return -EINVAL;

	c.common.command_id = 0;
	c.common.nsid = cpu_to_le32(cmd->nsid);
	if (!nvme_validate_passthru_nsid(ctrl, ns, le32_to_cpu(c.common.nsid)))
		return -EINVAL;

	c.common.cdw2[0] = cpu_to_le32(READ_ONCE(cmd->cdw2));
	c.common.cdw2[1] = cpu_to_le32(READ_ONCE(cmd->cdw3));
	c.common.metadata = 0;
	c.common.dptr.prp1 = c.common.dptr.prp2 = 0;
	c.common.cdw10 = cpu_to_le32(READ_ONCE(cmd->cdw10));
	c.common.cdw11 = cpu_to_le32(READ_ONCE(cmd->cdw11));
	c.common.cdw12 = cpu_to_le32(READ_ONCE(cmd->cdw12));
	c.common.cdw13 = cpu_to_le32(READ_ONCE(cmd->cdw13));
	c.common.cdw14 = cpu_to_le32(READ_ONCE(cmd->cdw14));
	c.common.cdw15 = cpu_to_le32(READ_ONCE(cmd->cdw15));

	if (!nvme_cmd_allowed(ns, &c, 0, ioucmd->file->f_mode & FMODE_WRITE))
		return -EACCES;

	d.metadata = READ_ONCE(cmd->metadata);
	d.addr = READ_ONCE(cmd->addr);
	d.data_len = READ_ONCE(cmd->data_len);
	d.metadata_len = READ_ONCE(cmd->metadata_len);
	d.timeout_ms = READ_ONCE(cmd->timeout_ms);

	if (xdev_ext) {
		struct io_uring_cmd_data *async_data =
			io_uring_cmd_get_async_data(ioucmd);
		gfp_t gfp = issue_flags & IO_URING_F_NONBLOCK ?
			GFP_NOWAIT : GFP_KERNEL;
		u32 effective_data_len;

		if (vec && !(ioucmd->flags & IORING_URING_CMD_FIXED))
			return -EOPNOTSUPP;

		xdev_ext_sidecar = async_data->op_data;
		if (!xdev_ext_sidecar) {
			xdev_ext_sidecar = kzalloc(sizeof(*xdev_ext_sidecar), gfp);
			if (!xdev_ext_sidecar)
				return -ENOMEM;
			async_data->op_data = xdev_ext_sidecar;
		}
		if (xdev_ext_sidecar->resources.lifecycle !=
		    NVME_XDEV_EXT_LIFECYCLE_EMPTY)
			return -EBUSY;

		if (vec) {
			int ddir = nvme_is_write(&c) ? WRITE : READ;

			if (!xdev_ext_sidecar->vector_imported) {
				ret = io_uring_cmd_import_fixed_vec(ioucmd,
								    u64_to_user_ptr(d.addr),
								    d.data_len, ddir, &iter,
								    issue_flags);
				if (ret < 0)
					goto out_xdev_ext_unwind;
				ret = nvme_xdev_ext_effective_data_len(true, true,
								  d.data_len,
								  iov_iter_count(&iter),
								  &effective_data_len);
				if (ret)
					goto out_xdev_ext_unwind;
				xdev_ext_sidecar->vector_iter = iter;
				xdev_ext_sidecar->vector_address = d.addr;
				xdev_ext_sidecar->vector_count = d.data_len;
				xdev_ext_sidecar->vector_imported = true;
			} else {
				if (xdev_ext_sidecar->vector_address != d.addr ||
				    xdev_ext_sidecar->vector_count != d.data_len) {
					ret = -ESTALE;
					goto out_xdev_ext_unwind;
				}
				effective_data_len =
					iov_iter_count(&xdev_ext_sidecar->vector_iter);
			}
			d.data_len = effective_data_len;
			iter = xdev_ext_sidecar->vector_iter;
			map_iter = &iter;
		} else {
			ret = nvme_xdev_ext_effective_data_len(false,
							  ioucmd->flags &
								IORING_URING_CMD_FIXED,
							  d.data_len, 0,
							  &effective_data_len);
			if (ret)
				goto out_xdev_ext_unwind;
			d.data_len = effective_data_len;
		}
		xdev_ext_sidecar->data_snapshot = d;

		if (xdev_ext_build) {
			ret = nvme_xdev_ext_build_stage(ioucmd, &c, xdev_ext_sidecar);
			if (ret)
				goto out_xdev_ext_unwind;
		}
		ret = nvme_xdev_ext_initial_admit(ns, &c,
					     &xdev_ext_sidecar->data_snapshot, q,
					     xdev_ext_build, &xdev_ext_identity,
					     &xdev_ext_decoded, &xdev_ext_head, &xdev_ext_disk,
					     &xdev_ext_queue);
		if (ret)
			goto out_xdev_ext_unwind;
		xdev_ext_sidecar->identity = xdev_ext_identity;
		xdev_ext_sidecar->decoded = xdev_ext_decoded;
		xdev_ext_sidecar->head = xdev_ext_head;
		xdev_ext_sidecar->disk = xdev_ext_disk;
		xdev_ext_sidecar->queue = xdev_ext_queue;
	}

	if (d.data_len && (ioucmd->flags & IORING_URING_CMD_FIXED) &&
	    !(xdev_ext && vec)) {
		int ddir = nvme_is_write(&c) ? WRITE : READ;

		if (vec)
			ret = io_uring_cmd_import_fixed_vec(ioucmd,
					u64_to_user_ptr(d.addr), d.data_len,
					ddir, &iter, issue_flags);
		else
			ret = io_uring_cmd_import_fixed(d.addr, d.data_len,
					ddir, &iter, ioucmd, issue_flags);
		if (ret < 0)
			goto out_xdev_ext_unwind;

		map_iter = &iter;
	}

	if (issue_flags & IO_URING_F_NONBLOCK) {
		rq_flags |= REQ_NOWAIT;
		blk_flags = BLK_MQ_REQ_NOWAIT;
	}
	if (issue_flags & IO_URING_F_IOPOLL)
		rq_flags |= REQ_POLLED;

	req = nvme_alloc_user_request(q, &c, rq_flags, blk_flags);
	if (IS_ERR(req)) {
		ret = PTR_ERR(req);
		req = NULL;
		goto out_xdev_ext_unwind;
	}
	if (xdev_ext)
		nvme_xdev_ext_resource_request_allocated(&xdev_ext_sidecar->resources);
	req->timeout = d.timeout_ms ? msecs_to_jiffies(d.timeout_ms) : 0;

	if (d.data_len) {
		ret = nvme_map_user_request(req, d.addr, d.data_len,
			nvme_to_user_ptr(d.metadata), d.metadata_len,
			map_iter, vec ? NVME_IOCTL_VEC : 0);
		if (ret) {
			if (xdev_ext)
				goto out_xdev_ext_unwind;
			goto out_free_req;
		}
	}
	if (xdev_ext) {
		nvme_xdev_ext_resource_user_mapped(&xdev_ext_sidecar->resources);
		/*
		 * Request allocation and mapping above can return -EAGAIN under
		 * IO_URING_F_NONBLOCK (no free tag, or a bvec layout that would
		 * need a split).  Dispatching only now keeps that -EAGAIN
		 * retryable from io-wq without replaying policy-visible work.
		 */
		if (xdev_ext_build)
			ret = nvme_xdev_ext_build(ioucmd, ns, req, &c, xdev_ext_sidecar);
		else
			ret = nvme_xdev_ext_dispatch_admitted(issue_flags, ioucmd,
							 xdev_ext_sidecar);
		if (ret)
			goto out_xdev_ext_unwind;
		ret = nvme_xdev_ext_final_admit(ns, xdev_ext_build ? nvme_req(req)->cmd : &c,
					   &xdev_ext_sidecar->data_snapshot,
					   xdev_ext_sidecar);
		if (ret)
			goto out_xdev_ext_unwind;
		if (!nvme_xdev_ext_lifecycle_accept(&xdev_ext_sidecar->resources.lifecycle)) {
			ret = -EPROTO;
			goto out_xdev_ext_unwind;
		}
	}

	/* to free bio on completion, as req->bio will be null at that time */
	pdu->bio = req->bio;
	pdu->req = req;
	req->end_io_data = ioucmd;
	req->end_io = nvme_uring_cmd_end_io;
	nvme_uring_native_trace(req, "native_submit", 0);
	blk_execute_rq_nowait(req, false);
	return -EIOCBQUEUED;

out_free_req:
	blk_mq_free_request(req);
out_xdev_ext_unwind:
	nvme_xdev_ext_preaccept_unwind(xdev_ext_sidecar, req);
	/* Never let io_uring replay a command after policy-visible work. */
	if (xdev_ext)
		ret = nvme_xdev_ext_issue_errno(&xdev_ext_sidecar->resources, ret);
	return ret;
}

static bool is_ctrl_ioctl(unsigned int cmd)
{
	if (cmd == NVME_IOCTL_ADMIN_CMD || cmd == NVME_IOCTL_ADMIN64_CMD)
		return true;
	if (is_sed_ioctl(cmd))
		return true;
	return false;
}

static int nvme_ctrl_ioctl(struct nvme_ctrl *ctrl, unsigned int cmd,
		void __user *argp, bool open_for_write)
{
	switch (cmd) {
	case NVME_IOCTL_ADMIN_CMD:
		return nvme_user_cmd(ctrl, NULL, argp, 0, open_for_write);
	case NVME_IOCTL_ADMIN64_CMD:
		return nvme_user_cmd64(ctrl, NULL, argp, 0, open_for_write);
	default:
		return sed_ioctl(ctrl->opal_dev, cmd, argp);
	}
}

#ifdef COMPAT_FOR_U64_ALIGNMENT
struct nvme_user_io32 {
	__u8	opcode;
	__u8	flags;
	__u16	control;
	__u16	nblocks;
	__u16	rsvd;
	__u64	metadata;
	__u64	addr;
	__u64	slba;
	__u32	dsmgmt;
	__u32	reftag;
	__u16	apptag;
	__u16	appmask;
} __attribute__((__packed__));
#define NVME_IOCTL_SUBMIT_IO32	_IOW('N', 0x42, struct nvme_user_io32)
#endif /* COMPAT_FOR_U64_ALIGNMENT */

#ifdef CONFIG_XDEV_EXT_MECH
static int nvme_peer_rw_allowed(struct nvme_ns *ns,
                               const struct xdev_ext_peer_nvme_rw *u,
                               unsigned int flags, bool open_for_write, struct file *allocation)
{
 struct nvme_command cmd = {};
 bool write = u->flags & XDEV_EXT_PEER_NVME_F_WRITE;
 if (!capable(CAP_SYS_RAWIO)) return -EPERM;
 if (u->reserved || (u->flags & ~XDEV_EXT_PEER_NVME_F_WRITE)) return -EINVAL;
 if (flags & NVME_IOCTL_PARTITION) return -EOPNOTSUPP;
 if (write && !open_for_write) return -EBADF;
 if (!ns->ctrl->ops->peer_rw) return -EOPNOTSUPP;
 cmd.rw.opcode = write ? nvme_cmd_write : nvme_cmd_read;
 cmd.rw.nsid = cpu_to_le32(ns->head->ns_id);
 if (!nvme_cmd_allowed(ns, &cmd, flags, open_for_write)) return -EACCES;
 return ns->ctrl->ops->peer_rw(ns, u, allocation, NULL);
}
static int nvme_peer_ioctl(struct nvme_ns *ns, unsigned int cmd,
                           void __user *argp, unsigned int flags, bool open_for_write)
{
 struct xdev_ext_peer_nvme_rw u;
 struct xdev_ext_peer_nvme_batch *batch;
 struct file *allocation;
 u32 i;
 int ret;
 if (cmd == XDEV_EXT_PEER_NVME_RW) {
  if (copy_from_user(&u, argp, sizeof(u))) return -EFAULT;
  allocation = fget(u.allocation_fd);
  if (!allocation) return -EBADF;
  ret = nvme_peer_rw_allowed(ns, &u, flags, open_for_write, allocation);
  fput(allocation);
  return ret;
 }
 batch = memdup_user(argp, sizeof(*batch));
 if (IS_ERR(batch)) return PTR_ERR(batch);
 if (!batch->nr || batch->nr > XDEV_EXT_PEER_NVME_MAX_DESCS ||
     batch->reserved || batch->completed || batch->status) { ret = -EINVAL; goto out; }
 /* Snapshot all descriptors before the first native command. */
 for (i = 0; i < batch->nr; i++)
  if (batch->desc[i].reserved) { ret = -EINVAL; goto out; }
 allocation = fget(batch->allocation_fd);
 if (!allocation) { ret = -EBADF; goto out; }
 for (i = 0; i < batch->nr; i++) {
  u = (struct xdev_ext_peer_nvme_rw){ .allocation_fd = batch->allocation_fd,
        .flags = batch->flags, .generation = batch->generation,
        .offset = batch->desc[i].offset, .slba = batch->desc[i].slba,
        .bytes = batch->desc[i].bytes };
  ret = nvme_peer_rw_allowed(ns, &u, flags, open_for_write, allocation);
  batch->status = ret;
  if (ret) break;
  batch->completed++;
 }
 fput(allocation);
 ret = copy_to_user(argp, batch, sizeof(*batch)) ? -EFAULT : batch->status;
out:
 kfree(batch); return ret;
}
#endif

static int nvme_ns_ioctl(struct nvme_ns *ns, unsigned int cmd,
		void __user *argp, unsigned int flags, bool open_for_write)
{
	switch (cmd) {
#ifdef CONFIG_XDEV_EXT_MECH
	case XDEV_EXT_PEER_NVME_RW:
	case XDEV_EXT_PEER_NVME_BATCH:
		return nvme_peer_ioctl(ns, cmd, argp, flags, open_for_write);
#endif
	case NVME_IOCTL_ID:
		force_successful_syscall_return();
		return ns->head->ns_id;
	case NVME_IOCTL_IO_CMD:
		return nvme_user_cmd(ns->ctrl, ns, argp, flags, open_for_write);
	/*
	 * struct nvme_user_io can have different padding on some 32-bit ABIs.
	 * Just accept the compat version as all fields that are used are the
	 * same size and at the same offset.
	 */
#ifdef COMPAT_FOR_U64_ALIGNMENT
	case NVME_IOCTL_SUBMIT_IO32:
#endif
	case NVME_IOCTL_SUBMIT_IO:
		return nvme_submit_io(ns, argp);
	case NVME_IOCTL_IO64_CMD_VEC:
		flags |= NVME_IOCTL_VEC;
		fallthrough;
	case NVME_IOCTL_IO64_CMD:
		return nvme_user_cmd64(ns->ctrl, ns, argp, flags,
				       open_for_write);
	default:
		return -ENOTTY;
	}
}

int nvme_ioctl(struct block_device *bdev, blk_mode_t mode,
		unsigned int cmd, unsigned long arg)
{
	struct nvme_ns *ns = bdev->bd_disk->private_data;
	bool open_for_write = mode & BLK_OPEN_WRITE;
	void __user *argp = (void __user *)arg;
	unsigned int flags = 0;

	if (bdev_is_partition(bdev))
		flags |= NVME_IOCTL_PARTITION;

	if (is_ctrl_ioctl(cmd))
		return nvme_ctrl_ioctl(ns->ctrl, cmd, argp, open_for_write);
	return nvme_ns_ioctl(ns, cmd, argp, flags, open_for_write);
}

long nvme_ns_chr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct nvme_ns *ns =
		container_of(file_inode(file)->i_cdev, struct nvme_ns, cdev);
	bool open_for_write = file->f_mode & FMODE_WRITE;
	void __user *argp = (void __user *)arg;

	if (is_ctrl_ioctl(cmd))
		return nvme_ctrl_ioctl(ns->ctrl, cmd, argp, open_for_write);
	return nvme_ns_ioctl(ns, cmd, argp, 0, open_for_write);
}

static int nvme_uring_cmd_checks(unsigned int issue_flags)
{

	/* NVMe passthrough requires big SQE/CQE support */
	if ((issue_flags & (IO_URING_F_SQE128|IO_URING_F_CQE32)) !=
	    (IO_URING_F_SQE128|IO_URING_F_CQE32))
		return -EOPNOTSUPP;
	return 0;
}

static int nvme_ns_uring_cmd(struct nvme_ns *ns, struct io_uring_cmd *ioucmd,
			     unsigned int issue_flags)
{
	struct nvme_ctrl *ctrl = ns->ctrl;
	int ret;

	ret = nvme_uring_cmd_checks(issue_flags);
	if (ret)
		return ret;

	switch (ioucmd->cmd_op) {
	case NVME_URING_CMD_IO:
		ret = nvme_uring_cmd_io(ctrl, ns, ioucmd, issue_flags, false);
		break;
	case NVME_URING_CMD_IO_VEC:
		ret = nvme_uring_cmd_io(ctrl, ns, ioucmd, issue_flags, true);
		break;
	default:
		ret = -ENOTTY;
	}

	return ret;
}

int nvme_ns_chr_uring_cmd(struct io_uring_cmd *ioucmd, unsigned int issue_flags)
{
	struct nvme_ns *ns = container_of(file_inode(ioucmd->file)->i_cdev,
			struct nvme_ns, cdev);

	return nvme_ns_uring_cmd(ns, ioucmd, issue_flags);
}

int nvme_ns_chr_uring_cmd_iopoll(struct io_uring_cmd *ioucmd,
				 struct io_comp_batch *iob,
				 unsigned int poll_flags)
{
	struct nvme_uring_cmd_pdu *pdu = nvme_uring_cmd_pdu(ioucmd);
	struct request *req = pdu->req;

	if (req && blk_rq_is_poll(req))
		return blk_rq_poll(req, iob, poll_flags);
	return 0;
}
#ifdef CONFIG_NVME_MULTIPATH
static int nvme_ns_head_ctrl_ioctl(struct nvme_ns *ns, unsigned int cmd,
		void __user *argp, struct nvme_ns_head *head, int srcu_idx,
		bool open_for_write)
	__releases(&head->srcu)
{
	struct nvme_ctrl *ctrl = ns->ctrl;
	int ret;

	nvme_get_ctrl(ns->ctrl);
	srcu_read_unlock(&head->srcu, srcu_idx);
	ret = nvme_ctrl_ioctl(ns->ctrl, cmd, argp, open_for_write);

	nvme_put_ctrl(ctrl);
	return ret;
}

int nvme_ns_head_ioctl(struct block_device *bdev, blk_mode_t mode,
		unsigned int cmd, unsigned long arg)
{
	struct nvme_ns_head *head = bdev->bd_disk->private_data;
	bool open_for_write = mode & BLK_OPEN_WRITE;
	void __user *argp = (void __user *)arg;
	struct nvme_ns *ns;
	int srcu_idx, ret = -EWOULDBLOCK;
	unsigned int flags = 0;

	if (bdev_is_partition(bdev))
		flags |= NVME_IOCTL_PARTITION;

	srcu_idx = srcu_read_lock(&head->srcu);
	ns = nvme_find_path(head);
	if (!ns)
		goto out_unlock;

	/*
	 * Handle ioctls that apply to the controller instead of the namespace
	 * separately and drop the ns SRCU reference early.  This avoids a
	 * deadlock when deleting namespaces using the passthrough interface.
	 */
	if (is_ctrl_ioctl(cmd))
		return nvme_ns_head_ctrl_ioctl(ns, cmd, argp, head, srcu_idx,
					       open_for_write);

	ret = nvme_ns_ioctl(ns, cmd, argp, flags, open_for_write);
out_unlock:
	srcu_read_unlock(&head->srcu, srcu_idx);
	return ret;
}

long nvme_ns_head_chr_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	bool open_for_write = file->f_mode & FMODE_WRITE;
	struct cdev *cdev = file_inode(file)->i_cdev;
	struct nvme_ns_head *head =
		container_of(cdev, struct nvme_ns_head, cdev);
	void __user *argp = (void __user *)arg;
	struct nvme_ns *ns;
	int srcu_idx, ret = -EWOULDBLOCK;

	srcu_idx = srcu_read_lock(&head->srcu);
	ns = nvme_find_path(head);
	if (!ns)
		goto out_unlock;

	if (is_ctrl_ioctl(cmd))
		return nvme_ns_head_ctrl_ioctl(ns, cmd, argp, head, srcu_idx,
				open_for_write);

	ret = nvme_ns_ioctl(ns, cmd, argp, 0, open_for_write);
out_unlock:
	srcu_read_unlock(&head->srcu, srcu_idx);
	return ret;
}

int nvme_ns_head_chr_uring_cmd(struct io_uring_cmd *ioucmd,
		unsigned int issue_flags)
{
	struct cdev *cdev = file_inode(ioucmd->file)->i_cdev;
	struct nvme_ns_head *head = container_of(cdev, struct nvme_ns_head, cdev);
	int srcu_idx = srcu_read_lock(&head->srcu);
	struct nvme_ns *ns = nvme_find_path(head);
	int ret = -EINVAL;

	if (ns)
		ret = nvme_ns_uring_cmd(ns, ioucmd, issue_flags);
	srcu_read_unlock(&head->srcu, srcu_idx);
	return ret;
}
#endif /* CONFIG_NVME_MULTIPATH */

int nvme_dev_uring_cmd(struct io_uring_cmd *ioucmd, unsigned int issue_flags)
{
	struct nvme_ctrl *ctrl = ioucmd->file->private_data;
	int ret;

	/* IOPOLL not supported yet */
	if (issue_flags & IO_URING_F_IOPOLL)
		return -EOPNOTSUPP;

	ret = nvme_uring_cmd_checks(issue_flags);
	if (ret)
		return ret;

	switch (ioucmd->cmd_op) {
	case NVME_URING_CMD_ADMIN:
		ret = nvme_uring_cmd_io(ctrl, NULL, ioucmd, issue_flags, false);
		break;
	case NVME_URING_CMD_ADMIN_VEC:
		ret = nvme_uring_cmd_io(ctrl, NULL, ioucmd, issue_flags, true);
		break;
	default:
		ret = -ENOTTY;
	}

	return ret;
}

static int nvme_dev_user_cmd(struct nvme_ctrl *ctrl, void __user *argp,
		bool open_for_write)
{
	struct nvme_ns *ns;
	int ret, srcu_idx;

	srcu_idx = srcu_read_lock(&ctrl->srcu);
	if (list_empty(&ctrl->namespaces)) {
		ret = -ENOTTY;
		goto out_unlock;
	}

	ns = list_first_or_null_rcu(&ctrl->namespaces, struct nvme_ns, list);
	if (ns != list_last_entry(&ctrl->namespaces, struct nvme_ns, list)) {
		dev_warn(ctrl->device,
			"NVME_IOCTL_IO_CMD not supported when multiple namespaces present!\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	dev_warn(ctrl->device,
		"using deprecated NVME_IOCTL_IO_CMD ioctl on the char device!\n");
	if (!nvme_get_ns(ns)) {
		ret = -ENXIO;
		goto out_unlock;
	}
	srcu_read_unlock(&ctrl->srcu, srcu_idx);

	ret = nvme_user_cmd(ctrl, ns, argp, 0, open_for_write);
	nvme_put_ns(ns);
	return ret;

out_unlock:
	srcu_read_unlock(&ctrl->srcu, srcu_idx);
	return ret;
}

long nvme_dev_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	bool open_for_write = file->f_mode & FMODE_WRITE;
	struct nvme_ctrl *ctrl = file->private_data;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case NVME_IOCTL_ADMIN_CMD:
		return nvme_user_cmd(ctrl, NULL, argp, 0, open_for_write);
	case NVME_IOCTL_ADMIN64_CMD:
		return nvme_user_cmd64(ctrl, NULL, argp, 0, open_for_write);
	case NVME_IOCTL_IO_CMD:
		return nvme_dev_user_cmd(ctrl, argp, open_for_write);
	case NVME_IOCTL_RESET:
		if (!capable(CAP_SYS_ADMIN))
			return -EACCES;
		dev_warn(ctrl->device, "resetting controller\n");
		return nvme_reset_ctrl_sync(ctrl);
	case NVME_IOCTL_SUBSYS_RESET:
		if (!capable(CAP_SYS_ADMIN))
			return -EACCES;
		return nvme_reset_subsystem(ctrl);
	case NVME_IOCTL_RESCAN:
		if (!capable(CAP_SYS_ADMIN))
			return -EACCES;
		nvme_queue_scan(ctrl);
		return 0;
	default:
		return -ENOTTY;
	}
}
