/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __XDEV_EXT_MECH_COMMON_H
#define __XDEV_EXT_MECH_COMMON_H

/* Programs build against this tree's mechanism UAPI, not a local copy. */
#include "../../../../../include/uapi/linux/xdev_ext_mech.h"
#include <linux/if_xdp.h>
#include <bpf/bpf_helpers.h>
#include "../xdev_ext_mech_test.h"

/*
 * BTF-visible struct_ops types; libbpf matches them to the kernel by name.
 * Layout from XDEV_EXT_MECH_OPS_TYPE() in include/linux/xdev_ext_mech.h.
 */
#define XDEV_EXT_MECH_TEST_OPS(name)						\
struct name {								\
	__u32 abi_version;						\
	__u32 flags;							\
	__s32 (*prepare)(const struct xdev_ext_mech_ctx *ctx);		\
	__s32 (*build)(const struct xdev_ext_mech_ctx *ctx);			\
	__s32 (*complete)(const struct xdev_ext_mech_ctx *ctx);		\
} __attribute__((preserve_access_index))

XDEV_EXT_MECH_TEST_OPS(xdev_ext_nvme_mech_ops);
XDEV_EXT_MECH_TEST_OPS(xdev_ext_afxdp_mech_ops);
XDEV_EXT_MECH_TEST_OPS(xdev_ext_ce_mech_ops);

/*
 * Views are valid for the running callback only.  rdonly_buf_size and
 * rdwr_buf_size must be constants; every view may be NULL.
 */
extern __u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx,
			  const __u64 rdonly_buf_size) __ksym;
extern __u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 slot,
			  const __u64 rdwr_buf_size) __ksym;
extern __u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx, __u32 slot,
			 const __u64 rdonly_buf_size) __ksym;
extern __u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *ctx, __u32 pos,
			   __u32 off, const __u64 rdonly_buf_size) __ksym;
extern __u32 bpf_xdev_ext_frame_crc32c(const struct xdev_ext_mech_ctx *ctx, __u32 pos,
				  __u32 off, __u32 len, __u32 seed) __ksym;
extern __u32 bpf_xdev_ext_crc32c(const void *buf, __u32 buf__sz,
			    __u32 seed) __ksym;
extern __u8 *bpf_xdev_ext_afxdp_hdr(const struct xdev_ext_mech_ctx *ctx, __u32 pos,
			       __u32 off, const __u64 rdwr_buf_size) __ksym;
extern __u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *ctx,
                                 const __u64 rdwr_buf_size) __ksym;
extern int bpf_xdev_ext_afxdp_hold(const struct xdev_ext_mech_ctx *ctx, __u64 key,
			      __u32 pos, __u32 span_off, __u32 span_len) __ksym;

/* The 64-byte NVMe read/write SQE (struct nvme_rw_command), little endian. */
struct xdev_ext_mech_nvme_rw {
	__u8 opcode;
	__u8 flags;
	__u16 command_id;
	__u32 nsid;
	__u32 cdw2;
	__u32 cdw3;
	__u64 metadata;
	__u64 prp1;
	__u64 prp2;
	__u64 slba;		/* cdw10..11 */
	__u16 length;		/* cdw12[15:0], 0's based */
	__u16 control;		/* cdw12[31:16] */
	__u32 dsmgmt;		/* cdw13 */
	__u32 reftag;		/* cdw14 */
	__u16 lbat;		/* cdw15 */
	__u16 lbatm;
};

_Static_assert(sizeof(struct xdev_ext_mech_nvme_rw) == XDEV_EXT_NVME_MECH_DESC_SIZE,
	       "NVMe scratch SQE is one 64-byte command");

#define XDEV_EXT_MECH_NVME_OP_WRITE		0x01
#define XDEV_EXT_MECH_NVME_OP_READ		0x02

/* NXP wire header, as nxp_wire_header_encode() in nvme_xdp_pipeline_core.h. */
#define XDEV_EXT_MECH_NXP_MAGIC		0x4e585032U	/* "NXP2" */
#define XDEV_EXT_MECH_NXP_VERSION		2
#define XDEV_EXT_MECH_NXP_HDR		40
#define XDEV_EXT_MECH_NXP_CSUM		36
#define XDEV_EXT_MECH_NXP_DIR_WRITE		2		/* NXP_IO_WRITE */

static __always_inline void xdev_ext_mech_put_be16(__u8 *p, __u16 v)
{
	p[0] = v >> 8;
	p[1] = v;
}

static __always_inline void xdev_ext_mech_put_be32(__u8 *p, __u32 v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

static __always_inline void xdev_ext_mech_put_be64(__u8 *p, __u64 v)
{
	xdev_ext_mech_put_be32(p, v >> 32);
	xdev_ext_mech_put_be32(p + 4, v);
}

static __always_inline __u16 xdev_ext_mech_get_be16(const __u8 *p)
{
	return (__u16)p[0] << 8 | p[1];
}

static __always_inline __u32 xdev_ext_mech_get_be32(const __u8 *p)
{
	return (__u32)p[0] << 24 | (__u32)p[1] << 16 | (__u32)p[2] << 8 | p[3];
}

static __always_inline __u64 xdev_ext_mech_get_be64(const __u8 *p)
{
	return (__u64)xdev_ext_mech_get_be32(p) << 32 | xdev_ext_mech_get_be32(p + 4);
}

static __always_inline void
xdev_ext_mech_observe(const struct xdev_ext_mech_ctx *mctx,
		 const struct xdev_ext_mech_frame_info *f0, struct xdev_ext_mech_obs *obs)
{
	const __u8 *p;
	__u64 head;

	obs->calls++;
	p = bpf_xdev_ext_frame(mctx, 0, f0->data_off, sizeof(head));
	if (!p)
		return;
	__builtin_memcpy(&head, p, sizeof(head));	/* little endian */
	obs->head = head;
	obs->head_crc = bpf_xdev_ext_crc32c(&head, sizeof(head), ~0U);
	obs->data_crc = bpf_xdev_ext_frame_crc32c(mctx, 0, f0->data_off,
					     f0->data_len, ~0U);
}

#endif /* __XDEV_EXT_MECH_COMMON_H */
