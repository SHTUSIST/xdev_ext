// SPDX-License-Identifier: GPL-2.0
/*
 * Guest test program of the CPU BPF compute callback
 * (Documentation/userspace-api/xdev_ext-compute.rst). Correctness only.
 * build and complete keep the class defaults; compute runs once per batch.
 * The mode is set with xdev_ext_mech_ctl attach --set mode=N:
 *   0  every frame: XOR all payload bytes but the last four with 0x5a, then
 *      seal: the last four bytes become ~crc32c(~0, XORed bytes), little
 *      endian, the layout of XDEV_EXT_CPU_XFORM_CRC32C_SEAL
 *   1  record a wrong output length for frame 0 (the batch fails, -EPROTO)
 *   2  return -EBADMSG without touching the payload
 *   3  check the context and the view bounds at probe_cap (the frame
 *      capacity, --set probe_cap=N), then as mode 0
 */
#include <linux/bpf.h>		/* struct bpf_iter_num for bpf_for() */
#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>

#define TEST_EFAULT 14
#define TEST_EBADMSG 74

__u32 mode;
__u32 probe_cap;

static __always_inline int probe(const struct xdev_ext_mech_ctx *mctx, __u32 pos)
{
	if (mctx->member != XDEV_EXT_MECH_MEMBER_COMPUTE ||
	    mctx->callsite != XDEV_EXT_MECH_SITE_WORKER ||
	    mctx->class_id != XDEV_EXT_MECH_CLASS_CPU || probe_cap < 64 ||
	    bpf_xdev_ext_frame_len(mctx, pos) > probe_cap)
		return -TEST_EFAULT;
	/* The last byte of the capacity is writable, the next one is not. */
	if (!bpf_xdev_ext_frame_rw(mctx, pos, probe_cap - 1, 1) ||
	    bpf_xdev_ext_frame_rw(mctx, pos, probe_cap, 1) ||
	    !bpf_xdev_ext_frame_rw(mctx, pos, probe_cap - 4, 4) ||
	    bpf_xdev_ext_frame_rw(mctx, pos, probe_cap - 3, 4) ||
	    !bpf_xdev_ext_frame_rw(mctx, pos, 0, 64))
		return -TEST_EFAULT;
	/* The shared read-only view stays available to compute. */
	if (!bpf_xdev_ext_frame(mctx, pos, 0, 1))
		return -TEST_EFAULT;
	return 0;
}

static __always_inline int xor_seal(const struct xdev_ext_mech_ctx *mctx, __u32 pos)
{
	__u32 len = bpf_xdev_ext_frame_len(mctx, pos), crc = ~0U;
	__u8 *p;
	int i;

	if (len < 4)
		return -TEST_EBADMSG;
	bpf_for(i, 0, len - 4) {
		p = bpf_xdev_ext_frame_rw(mctx, pos, i, 1);
		if (!p)
			return -TEST_EFAULT;
		*p ^= 0x5a;
		crc = bpf_xdev_ext_crc32c(p, 1, crc);
	}
	p = bpf_xdev_ext_frame_rw(mctx, pos, len - 4, 4);
	if (!p)
		return -TEST_EFAULT;
	crc = ~crc;
	p[0] = crc;
	p[1] = crc >> 8;
	p[2] = crc >> 16;
	p[3] = crc >> 24;
	return bpf_xdev_ext_frame_set_len(mctx, pos, len) ? -TEST_EFAULT : 0;
}

SEC("struct_ops/compute_test_compute")
__s32 BPF_PROG(compute_test_compute, const struct xdev_ext_mech_ctx *mctx)
{
	int pos, err;

	if (mode == 2)
		return -TEST_EBADMSG;
	if (mode == 1) {
		bpf_xdev_ext_frame_set_len(mctx, 0, bpf_xdev_ext_frame_len(mctx, 0) + 1);
		return 0;
	}
	bpf_for(pos, 0, mctx->nr_frames) {
		if (mode == 3) {
			err = probe(mctx, pos);
			if (err)
				return err;
		}
		err = xor_seal(mctx, pos);
		if (err)
			return err;
	}
	return 0;
}

SEC("struct_ops/compute_test_build")
__s32 BPF_PROG(compute_test_build, const struct xdev_ext_mech_ctx *mctx)
{
	return XDEV_EXT_MECH_BUILD_DEFAULT;
}

SEC("struct_ops/compute_test_complete")
__s32 BPF_PROG(compute_test_complete, const struct xdev_ext_mech_ctx *mctx)
{
	return XDEV_EXT_MECH_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops compute_test_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)compute_test_build,
	.complete = (void *)compute_test_complete,
	.compute = (void *)compute_test_compute,
};

char _license[] SEC("license") = "GPL";
