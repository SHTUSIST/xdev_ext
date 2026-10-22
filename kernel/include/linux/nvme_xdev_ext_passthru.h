/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NVME_XDEV_EXT_PASSTHRU_H
#define _LINUX_NVME_XDEV_EXT_PASSTHRU_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#include <uapi/linux/nvme_ioctl.h>
#include <uapi/linux/xdev_ext_binding.h>
#include <uapi/linux/xdev_ext_mech.h>
#else
#include <errno.h>
#include <linux/types.h>
#include "../uapi/linux/nvme_ioctl.h"
#include "../uapi/linux/xdev_ext_binding.h"
#include "../uapi/linux/xdev_ext_mech.h"
#endif

#define NVME_XDEV_EXT_NVM_WRITE	0x01U
#define NVME_XDEV_EXT_NVM_READ	0x02U
#define NVME_XDEV_EXT_CSI_NVM	0x00U
#define NVME_XDEV_EXT_SQE_SIZE	64U
/* cdw12[15:0] is a 0's based block count. */
#define NVME_XDEV_EXT_MAX_NLB	65536U

/* Scalar inputs captured from one namespace command and its live namespace. */
struct nvme_xdev_ext_admission {
	__u8 opcode;
	__u8 lba_shift;
	__u8 namespace_ready;
	__u8 namespace_removing;
	__u8 csi;
	__u8 reserved0;
	__u16 metadata_size;
	__u16 pi_size;
	__u8 pi_type;
	__u8 reserved1[3];
	__u32 command_nsid;
	__u32 live_nsid;
	__u32 data_len;
	__u32 metadata_len;
	__u32 cdw10;
	__u32 cdw11;
	__u32 cdw12;
	__u32 reserved2;
	__u64 metadata;
	__u64 capacity_lbas;
};

struct nvme_xdev_ext_decoded {
	__u64 slba;
	__u64 nlb;
	__u64 byte_offset;
	__u64 byte_length;
	__u8 write;
	__u8 reserved[7];
};

/*
 * Pointer-free bounds C holds for one NVMe stage.  A mechanism program
 * builds a READ or WRITE in a 64-byte scratch SQE; nvme_xdev_ext_mech_validate()
 * admits it against these before any byte reaches the real command.
 */
struct nvme_xdev_ext_mech_bounds {
	__u64 window_slba;
	__u64 window_nlb;
	__u64 capacity_lbas;
	__u32 data_len;		/* bytes already mapped for the batch */
	__u16 control_allow;	/* cdw12[31:16] bits the program may set */
	__u8 lba_shift;
	__u8 write;		/* stage direction */
};

/* Pointer-free namespace identity used by initial/final admission. */
struct nvme_xdev_ext_identity {
	__u32 nsid;
	__u8 lba_shift;
	__u8 namespace_ready;
	__u8 namespace_removing;
	__u8 csi;
	__u16 metadata_size;
	__u16 pi_size;
	__u8 pi_type;
	__u8 reserved[3];
	__u64 capacity_lbas;
	__u64 diskseq;
	__u8 eui64[8];
	__u8 nguid[16];
	__u8 uuid[16];
};

enum nvme_xdev_ext_lifecycle {
	NVME_XDEV_EXT_LIFECYCLE_EMPTY,
	NVME_XDEV_EXT_LIFECYCLE_PREPARED,
	NVME_XDEV_EXT_LIFECYCLE_ACCEPTED,
	NVME_XDEV_EXT_LIFECYCLE_COMPLETED,
	NVME_XDEV_EXT_LIFECYCLE_UNWOUND,
};

enum nvme_xdev_ext_cleanup_action {
	NVME_XDEV_EXT_CLEANUP_NONE,
	NVME_XDEV_EXT_CLEANUP_UNMAP,
	NVME_XDEV_EXT_CLEANUP_FREE_REQUEST,
	NVME_XDEV_EXT_CLEANUP_PUT_TOKEN,
	NVME_XDEV_EXT_CLEANUP_COMPLETE_POLICY,
	NVME_XDEV_EXT_CLEANUP_DONE,
};

struct nvme_xdev_ext_resource_state {
	enum nvme_xdev_ext_lifecycle lifecycle;
	__u8 request_allocated;
	__u8 user_mapped;
	__u8 done;
	__u8 reserved;
};

static inline int nvme_xdev_ext_flags_valid(__u32 flags)
{
	if (flags & ~NVME_URING_CMD_F_KNOWN_MASK)
		return 0;
	/* A built command is an opted-in command. */
	return !(flags & NVME_URING_CMD_F_XDEV_EXT_BUILD) ||
	       !!(flags & NVME_URING_CMD_F_XDEV_EXT);
}

static inline int nvme_xdev_ext_opted_in(__u32 flags)
{
	return !!(flags & NVME_URING_CMD_F_XDEV_EXT);
}

static inline int nvme_xdev_ext_build_requested(__u32 flags)
{
	return !!(flags & NVME_URING_CMD_F_XDEV_EXT_BUILD);
}

/*
 * NVME_URING_CMD_IO_VEC stores an iovec count in cmd.data_len.  XDEV_EXT policy
 * must instead see the byte count from the one imported, registered-buffer
 * snapshot that will be mapped for DMA.  Mutable non-fixed vectors are kept
 * outside the opt-in contract.
 */
static inline int nvme_xdev_ext_effective_data_len(int vec, int fixed_buffer,
					      __u32 command_data_len,
					      __u64 imported_bytes,
					      __u32 *effective_bytes)
{
	if (!effective_bytes)
		return -EINVAL;
	if (!vec) {
		*effective_bytes = command_data_len;
		return 0;
	}
	if (!fixed_buffer)
		return -EOPNOTSUPP;
	if (!command_data_len || !imported_bytes)
		return -EINVAL;
	if (imported_bytes > (__u64)~(__u32)0)
		return -EOVERFLOW;
	*effective_bytes = (__u32)imported_bytes;
	return 0;
}

static inline __u32 nvme_xdev_ext_capabilities_vec(int poll, int fixed_file,
					      int fixed_buffer,
					      int multibuffer)
{
	__u32 capabilities = XDEV_EXT_BINDING_CAP_ASYNC;

	if (poll)
		capabilities |= XDEV_EXT_BINDING_CAP_POLL;
	if (fixed_file)
		capabilities |= XDEV_EXT_BINDING_CAP_FIXED_FILE;
	if (fixed_buffer)
		capabilities |= XDEV_EXT_BINDING_CAP_FIXED_BUFFER;
	if (multibuffer)
		capabilities |= XDEV_EXT_BINDING_CAP_MULTIBUFFER;
	return capabilities;
}

static inline __u32 nvme_xdev_ext_capabilities(int poll, int fixed_file,
					  int fixed_buffer)
{
	return nvme_xdev_ext_capabilities_vec(poll, fixed_file, fixed_buffer, 0);
}

static inline int nvme_xdev_ext_bytes_equal(const __u8 *a, const __u8 *b,
				       __u32 length)
{
	__u32 i;

	for (i = 0; i < length; i++)
		if (a[i] != b[i])
			return 0;
	return 1;
}

static inline int
nvme_xdev_ext_identity_equal(const struct nvme_xdev_ext_identity *a,
			const struct nvme_xdev_ext_identity *b)
{
	return a && b &&
	       a->nsid == b->nsid &&
	       a->lba_shift == b->lba_shift &&
	       a->namespace_ready == b->namespace_ready &&
	       a->namespace_removing == b->namespace_removing &&
	       a->csi == b->csi &&
	       a->metadata_size == b->metadata_size &&
	       a->pi_size == b->pi_size &&
	       a->pi_type == b->pi_type &&
	       a->capacity_lbas == b->capacity_lbas &&
	       a->diskseq == b->diskseq &&
	       nvme_xdev_ext_bytes_equal(a->eui64, b->eui64,
				    sizeof(a->eui64)) &&
	       nvme_xdev_ext_bytes_equal(a->nguid, b->nguid,
				    sizeof(a->nguid)) &&
	       nvme_xdev_ext_bytes_equal(a->uuid, b->uuid, sizeof(a->uuid));
}

static inline int nvme_xdev_ext_lba_shift_check(__u8 lba_shift)
{
	if (lba_shift < 9)
		return -EINVAL;
	if (lba_shift >= 32)
		return -EOVERFLOW;
	return 0;
}

/* Live namespace, identity, NVM read/write, no metadata or PI. */
static inline int
nvme_xdev_ext_admit_namespace(const struct nvme_xdev_ext_admission *input)
{
	if (!input->namespace_ready || input->namespace_removing)
		return -ENODEV;
	if (!input->live_nsid || input->command_nsid != input->live_nsid)
		return -EXDEV;
	if (input->csi != NVME_XDEV_EXT_CSI_NVM)
		return -EOPNOTSUPP;
	if (input->opcode != NVME_XDEV_EXT_NVM_READ &&
	    input->opcode != NVME_XDEV_EXT_NVM_WRITE)
		return -EOPNOTSUPP;
	if (input->metadata || input->metadata_len || input->metadata_size ||
	    input->pi_size || input->pi_type)
		return -EOPNOTSUPP;
	return nvme_xdev_ext_lba_shift_check(input->lba_shift);
}

/*
 * Decode SLBA and NLB from cdw10..cdw12 and bound them by the mapped length
 * and the capacity.  The caller has checked lba_shift and zeroed *decoded.
 */
static inline int nvme_xdev_ext_decode_rw(const struct nvme_xdev_ext_admission *input,
				     struct nvme_xdev_ext_decoded *decoded)
{
	__u64 slba, nlb, byte_length;

	slba = ((__u64)input->cdw11 << 32) | input->cdw10;
	nlb = (__u64)(input->cdw12 & 0xffffU) + 1;
	if (nlb > (~(__u64)0 >> input->lba_shift))
		return -EOVERFLOW;
	byte_length = nlb << input->lba_shift;
	if (!input->data_len)
		return -EINVAL;
	if (byte_length > (__u64)~(__u32)0 ||
	    byte_length != input->data_len)
		return -EMSGSIZE;
	if (slba > (~(__u64)0 >> input->lba_shift))
		return -EOVERFLOW;
	if (slba > input->capacity_lbas ||
	    nlb > input->capacity_lbas - slba)
		return -ERANGE;

	decoded->slba = slba;
	decoded->nlb = nlb;
	decoded->byte_offset = slba << input->lba_shift;
	decoded->byte_length = byte_length;
	decoded->write = input->opcode == NVME_XDEV_EXT_NVM_WRITE;
	return 0;
}

static inline int nvme_xdev_ext_admit(const struct nvme_xdev_ext_admission *input,
				 struct nvme_xdev_ext_decoded *decoded)
{
	int ret;

	if (!input || !decoded)
		return -EINVAL;
	*decoded = (struct nvme_xdev_ext_decoded) {};

	ret = nvme_xdev_ext_admit_namespace(input);
	if (ret)
		return ret;
	return nvme_xdev_ext_decode_rw(input, decoded);
}

/*
 * Initial admission of a command whose SLBA and NLB a mechanism program
 * builds after the data is mapped: the namespace checks of nvme_xdev_ext_admit()
 * and a length of whole LBAs that one command can carry.  cdw10..cdw12 are
 * not decoded here; nvme_xdev_ext_mech_validate() admits the built values.
 */
static inline int
nvme_xdev_ext_admit_identity(const struct nvme_xdev_ext_admission *input)
{
	int ret;

	if (!input)
		return -EINVAL;
	ret = nvme_xdev_ext_admit_namespace(input);
	if (ret)
		return ret;
	if (!input->data_len)
		return -EINVAL;
	if ((input->data_len & ((1U << input->lba_shift) - 1)) ||
	    (input->data_len >> input->lba_shift) > NVME_XDEV_EXT_MAX_NLB)
		return -EMSGSIZE;
	return 0;
}

/* Dword @dw of a little-endian NVMe SQE, in CPU order. */
static inline __u32 nvme_xdev_ext_sqe_dw(const __u8 *sqe, unsigned int dw)
{
	const __u8 *p = sqe + 4 * dw;

	return (__u32)p[0] | (__u32)p[1] << 8 | (__u32)p[2] << 16 |
	       (__u32)p[3] << 24;
}

/*
 * Admit a READ/WRITE a mechanism program built in the NVME_XDEV_EXT_SQE_SIZE
 * byte scratch SQE.  The program may set only the opcode, SLBA (cdw10/cdw11),
 * NLB (cdw12[15:0]) and whitelisted cdw12[31:16] bits; every field C or
 * nvme-pci writes (flags with FUSE and PSDT, command_id, nsid, MPTR, DPTR)
 * and every unused dword (cdw2, cdw3, cdw13..cdw15) must be zero.  On
 * success *decoded is what final admission of the command carrying the
 * built cdw10..cdw12 decodes to.
 */
static inline int
nvme_xdev_ext_mech_validate(const __u8 *sqe,
		       const struct nvme_xdev_ext_mech_bounds *bounds,
		       struct nvme_xdev_ext_decoded *decoded)
{
	struct nvme_xdev_ext_admission input;
	__u64 slba, nlb, offset;
	unsigned int dw;
	int ret;

	if (!sqe || !bounds || !decoded)
		return -EINVAL;
	*decoded = (struct nvme_xdev_ext_decoded) {};

	ret = nvme_xdev_ext_lba_shift_check(bounds->lba_shift);
	if (ret)
		return ret;
	if (sqe[0] != (bounds->write ? NVME_XDEV_EXT_NVM_WRITE : NVME_XDEV_EXT_NVM_READ))
		return -EOPNOTSUPP;
	if (nvme_xdev_ext_sqe_dw(sqe, 0) >> 8)
		return -EPERM;
	for (dw = 1; dw < NVME_XDEV_EXT_SQE_SIZE / 4; dw++)
		if ((dw < 10 || dw > 12) && nvme_xdev_ext_sqe_dw(sqe, dw))
			return -EPERM;

	input = (struct nvme_xdev_ext_admission) {
		.opcode = sqe[0],
		.lba_shift = bounds->lba_shift,
		.data_len = bounds->data_len,
		.cdw10 = nvme_xdev_ext_sqe_dw(sqe, 10),
		.cdw11 = nvme_xdev_ext_sqe_dw(sqe, 11),
		.cdw12 = nvme_xdev_ext_sqe_dw(sqe, 12),
		.capacity_lbas = bounds->capacity_lbas,
	};
	if ((input.cdw12 >> 16) & ~(__u32)bounds->control_allow)
		return -EPERM;

	/* Window first: an SLBA outside it is -ERANGE, not decode's -EOVERFLOW. */
	slba = ((__u64)input.cdw11 << 32) | input.cdw10;
	nlb = (__u64)(input.cdw12 & 0xffffU) + 1;
	if (slba < bounds->window_slba)
		return -ERANGE;
	offset = slba - bounds->window_slba;
	if (offset >= bounds->window_nlb ||
	    nlb > bounds->window_nlb - offset)
		return -ERANGE;
	return nvme_xdev_ext_decode_rw(&input, decoded);
}

/*
 * The user half of an NVME_URING_CMD_F_XDEV_EXT_BUILD command, as the SQE C
 * assembled from it: the program is the only source of cdw10..cdw12, and
 * cdw2, cdw3 and cdw13..cdw15 have no meaning for a built READ/WRITE, so
 * each of them must be zero.  C owns dwords 4..9 (MPTR, DPTR) itself.
 */
static inline int nvme_xdev_ext_build_user_check(const __u8 *sqe)
{
	unsigned int dw;

	if (!sqe)
		return -EINVAL;
	for (dw = 2; dw < NVME_XDEV_EXT_SQE_SIZE / 4; dw++)
		if ((dw <= 3 || dw >= 10) && nvme_xdev_ext_sqe_dw(sqe, dw))
			return -EINVAL;
	return 0;
}

/*
 * Errno of the build callback of an F_XDEV_EXT_BUILD command, from its resolved
 * return value (xdev_ext_mech_ret_resolve()) and the scratch slots it used
 * (xdev_ext_mech_slots_used()).  SUBMIT needs exactly the one SQE; a uring_cmd
 * has no C default build; ABORT cancels the command.
 */
static inline int nvme_xdev_ext_build_errno(__s32 ret, int slots)
{
	switch (ret) {
	case XDEV_EXT_MECH_BUILD_SUBMIT:
		if (slots < 0)
			return slots;
		return slots == 1 ? 0 : -EPROTO;
	case XDEV_EXT_MECH_BUILD_DEFAULT:
		return -EOPNOTSUPP;
	default:
		return -ECANCELED;
	}
}

/*
 * Decode the command that will execute, after the built cdw10..cdw12 were
 * written into it, and require it to be exactly what validation admitted.
 */
static inline int
nvme_xdev_ext_build_redecode(const struct nvme_xdev_ext_admission *final,
			const struct nvme_xdev_ext_decoded *validated,
			struct nvme_xdev_ext_decoded *decoded)
{
	int ret;

	ret = nvme_xdev_ext_admit(final, decoded);
	if (ret)
		return ret;
	if (decoded->slba != validated->slba ||
	    decoded->nlb != validated->nlb ||
	    decoded->byte_offset != validated->byte_offset ||
	    decoded->byte_length != validated->byte_length ||
	    decoded->write != validated->write) {
		*decoded = (struct nvme_xdev_ext_decoded) {};
		return -EPROTO;
	}
	return 0;
}

/*
 * Completion copy for an NVMe mechanism program.  @status follows the NVMe
 * uring_cmd convention: a positive NVMe status exactly as completed
 * (nvme_req(req)->status, SCT/SC/DNR untouched), a negative errno when the
 * device reported none (cancellation, transport error), or 0.  Nothing is
 * folded into an errno.
 */
static inline void nvme_xdev_ext_mech_cqe(int status, __u64 result,
				     struct xdev_ext_nvme_mech_cqe *cqe)
{
	*cqe = (struct xdev_ext_nvme_mech_cqe) {
		.result = result,
		.status = status > 0 ? (__u16)status : 0,
		.err = status < 0 ? status : 0,
	};
}

/*
 * CREATE of an NVMe mechanism stage: the namespace admission of
 * nvme_xdev_ext_admit() for the stage direction, a non-empty LBA window inside
 * the capacity, and session batches of @group_bytes that are whole LBAs one
 * command can carry and the window can hold.
 */
static inline int
nvme_xdev_ext_mech_bind_check(const struct nvme_xdev_ext_identity *id, int write,
			 __u64 window_slba, __u64 window_nlb,
			 __u32 group_bytes)
{
	struct nvme_xdev_ext_admission input;
	int ret;

	if (!id)
		return -EINVAL;
	input = (struct nvme_xdev_ext_admission) {
		.opcode = write ? NVME_XDEV_EXT_NVM_WRITE : NVME_XDEV_EXT_NVM_READ,
		.lba_shift = id->lba_shift,
		.namespace_ready = id->namespace_ready,
		.namespace_removing = id->namespace_removing,
		.csi = id->csi,
		.metadata_size = id->metadata_size,
		.pi_size = id->pi_size,
		.pi_type = id->pi_type,
		.command_nsid = id->nsid,
		.live_nsid = id->nsid,
		.data_len = group_bytes,
		.capacity_lbas = id->capacity_lbas,
	};
	ret = nvme_xdev_ext_admit_identity(&input);
	if (ret)
		return ret;
	if (!window_nlb)
		return -EINVAL;
	if (window_slba > id->capacity_lbas ||
	    window_nlb > id->capacity_lbas - window_slba ||
	    (group_bytes >> id->lba_shift) > window_nlb)
		return -ERANGE;
	return 0;
}

/* Queue limits a batch payload must meet to reach the device as it is. */
struct nvme_xdev_ext_queue_caps {
	__u64 virt_boundary_mask;
	__u32 page_size;
	__u32 dma_align_mask;	/* dma_alignment | dma_pad_mask */
	__u32 max_segments;
	__u32 max_segment_size;
	__u32 max_bytes;	/* max_hw_sectors in bytes */
	__u32 lba_size;		/* a power of two */
};

/*
 * Walk of a batch payload, one page-local piece at a time in DMA order,
 * before a bio is built from it: the DMA alignment that blk_rq_append_bio()
 * does not check, and the virtual-boundary gaps and segment limit for which
 * it would have to split (it returns -EREMOTEIO instead).  A piece that
 * starts where the previous one ended in the same page merges with it, as
 * bio_add_page() does.
 */
struct nvme_xdev_ext_seg_walk {
	struct nvme_xdev_ext_queue_caps caps;
	__u32 segs;
	__u32 seg_len;		/* bytes of the current segment */
	__u32 bytes;
	__u32 end;		/* page offset where the last piece ended */
};

static inline void nvme_xdev_ext_seg_walk_init(struct nvme_xdev_ext_seg_walk *walk,
					  const struct nvme_xdev_ext_queue_caps *caps)
{
	*walk = (struct nvme_xdev_ext_seg_walk) { .caps = *caps };
}

/* -EREMOTEIO: the device cannot take the payload as it is. */
static inline int nvme_xdev_ext_seg_add(struct nvme_xdev_ext_seg_walk *walk,
				   __u32 page_off, __u32 len, int same_page)
{
	const struct nvme_xdev_ext_queue_caps *caps = &walk->caps;

	if (!len || page_off >= caps->page_size ||
	    len > caps->page_size - page_off)
		return -EINVAL;
	if ((page_off | len) & caps->dma_align_mask)
		return -EREMOTEIO;
	if (len > caps->max_bytes - walk->bytes)
		return -EMSGSIZE;
	if (walk->segs && same_page && page_off == walk->end) {
		if (len > caps->max_segment_size - walk->seg_len)
			return -EREMOTEIO;
		walk->seg_len += len;
	} else {
		if (walk->segs && ((page_off | walk->end) &
				   caps->virt_boundary_mask))
			return -EREMOTEIO;
		if (walk->segs >= caps->max_segments ||
		    len > caps->max_segment_size)
			return -EREMOTEIO;
		walk->segs++;
		walk->seg_len = len;
	}
	walk->bytes += len;
	walk->end = page_off + len;
	return 0;
}

static inline int nvme_xdev_ext_seg_done(const struct nvme_xdev_ext_seg_walk *walk)
{
	if (!walk->segs)
		return -EINVAL;
	if (walk->bytes & (walk->caps.lba_size - 1))
		return -EMSGSIZE;
	return 0;
}

static inline int
nvme_xdev_ext_lifecycle_prepare(enum nvme_xdev_ext_lifecycle *state)
{
	if (!state)
		return -EINVAL;
	/* One io_uring command gets at most one policy dispatch. */
	if (*state != NVME_XDEV_EXT_LIFECYCLE_EMPTY)
		return -EBUSY;
	*state = NVME_XDEV_EXT_LIFECYCLE_PREPARED;
	return 0;
}

static inline int nvme_xdev_ext_lifecycle_accept(enum nvme_xdev_ext_lifecycle *state)
{
	if (!state || *state != NVME_XDEV_EXT_LIFECYCLE_PREPARED)
		return 0;
	*state = NVME_XDEV_EXT_LIFECYCLE_ACCEPTED;
	return 1;
}

static inline int nvme_xdev_ext_lifecycle_complete(enum nvme_xdev_ext_lifecycle *state)
{
	if (!state || *state != NVME_XDEV_EXT_LIFECYCLE_ACCEPTED)
		return 0;
	*state = NVME_XDEV_EXT_LIFECYCLE_COMPLETED;
	return 1;
}

static inline int nvme_xdev_ext_lifecycle_unwind(enum nvme_xdev_ext_lifecycle *state)
{
	if (!state || *state != NVME_XDEV_EXT_LIFECYCLE_PREPARED)
		return 0;
	*state = NVME_XDEV_EXT_LIFECYCLE_UNWOUND;
	return 1;
}

static inline void
nvme_xdev_ext_resource_request_allocated(struct nvme_xdev_ext_resource_state *state)
{
	if (state)
		state->request_allocated = 1;
}

static inline void
nvme_xdev_ext_resource_user_mapped(struct nvme_xdev_ext_resource_state *state)
{
	if (state)
		state->user_mapped = 1;
}

/* Return cleanup work one step at a time in the required ownership order. */
static inline enum nvme_xdev_ext_cleanup_action
nvme_xdev_ext_preaccept_next(struct nvme_xdev_ext_resource_state *state)
{
	if (!state || state->lifecycle == NVME_XDEV_EXT_LIFECYCLE_ACCEPTED ||
	    state->lifecycle == NVME_XDEV_EXT_LIFECYCLE_COMPLETED)
		return NVME_XDEV_EXT_CLEANUP_NONE;
	if (state->user_mapped) {
		state->user_mapped = 0;
		return NVME_XDEV_EXT_CLEANUP_UNMAP;
	}
	if (state->request_allocated) {
		state->request_allocated = 0;
		return NVME_XDEV_EXT_CLEANUP_FREE_REQUEST;
	}
	if (nvme_xdev_ext_lifecycle_unwind(&state->lifecycle))
		return NVME_XDEV_EXT_CLEANUP_PUT_TOKEN;
	return NVME_XDEV_EXT_CLEANUP_NONE;
}

/* Task-work order is unmap, one policy completion (or defensive put), done. */
static inline enum nvme_xdev_ext_cleanup_action
nvme_xdev_ext_completion_next(struct nvme_xdev_ext_resource_state *state)
{
	if (!state || state->done)
		return NVME_XDEV_EXT_CLEANUP_NONE;
	if (state->user_mapped) {
		state->user_mapped = 0;
		return NVME_XDEV_EXT_CLEANUP_UNMAP;
	}
	if (nvme_xdev_ext_lifecycle_complete(&state->lifecycle))
		return NVME_XDEV_EXT_CLEANUP_COMPLETE_POLICY;
	if (nvme_xdev_ext_lifecycle_unwind(&state->lifecycle))
		return NVME_XDEV_EXT_CLEANUP_PUT_TOKEN;
	state->done = 1;
	return NVME_XDEV_EXT_CLEANUP_DONE;
}

/*
 * io_uring retries a nonblocking issue that returned -EAGAIN from io-wq.  For
 * an opted-in command that is correct only while no policy dispatch has
 * happened (the lifecycle is still EMPTY after pre-accept unwind); afterwards
 * the retry would replay policy-visible work, so the command fails with
 * -EBUSY.  Allocation and mapping run before dispatch so that their -EAGAIN
 * stays retryable.
 */
static inline int
nvme_xdev_ext_issue_errno(const struct nvme_xdev_ext_resource_state *state, int ret)
{
	if (ret != -EAGAIN)
		return ret;
	if (!state || state->lifecycle != NVME_XDEV_EXT_LIFECYCLE_EMPTY)
		return -EBUSY;
	return ret;
}

#endif /* _LINUX_NVME_XDEV_EXT_PASSTHRU_H */
