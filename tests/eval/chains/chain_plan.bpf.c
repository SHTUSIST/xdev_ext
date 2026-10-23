// SPDX-License-Identifier: GPL-2.0
/*
 * IAA plan of the eval chains.  build describes one whole-batch transform:
 * the batch payload as source, the CREATE-time destination capacity.
 * complete continues only on a zero status with output inside the
 * capacity and, when the loader set expect_out, of exactly that length
 * (a decompressed fixed-size record).  chain_bench reads chain_counts
 * after the campaign.  Written against the UAPI header, without vmlinux.h,
 * like selftests/xdev_ext_mech/iaa_transform/iaa_pair.bpf.c.
 */
#include "include/uapi/linux/xdev_ext_mech.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct xdev_ext_iaa_mech_ops {
	__u32 abi_version, flags;
	__s32 (*prepare)(const struct xdev_ext_mech_ctx *);
	__s32 (*build)(const struct xdev_ext_mech_ctx *);
	__s32 (*complete)(const struct xdev_ext_mech_ctx *);
} __attribute__((preserve_access_index));

extern __u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *, const __u64) __ksym;
extern __u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *, __u32, const __u64) __ksym;
extern __u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *, __u32, const __u64) __ksym;

/* Exact output length every batch must produce; 0 accepts any. */
__u32 expect_out;

struct chain_counts {
	__u64 builds, completes, errors, produced_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct chain_counts);
} chain_counts SEC(".maps");

static __always_inline struct chain_counts *counts(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&chain_counts, &key);
}

SEC("struct_ops/chain_iaa_build")
__s32 BPF_PROG(chain_iaa_build, const struct xdev_ext_mech_ctx *m)
{
	const struct xdev_ext_iaa_mech_info *info;
	struct chain_counts *c = counts();
	struct xdev_ext_iaa_desc *d;

	(void)ctx;
	if (c)
		__sync_fetch_and_add(&c->builds, 1);
	if (m->class_id != XDEV_EXT_MECH_CLASS_IAA)
		goto bad;
	info = (void *)bpf_xdev_ext_info(m, sizeof(*info));
	d = (void *)bpf_xdev_ext_desc(m, 0, sizeof(*d));
	if (!info || !d || !info->nr_frames || !m->base.length ||
	    !info->dst_capacity)
		goto bad;
	d->src_len = m->base.length;
	d->dst_capacity = info->dst_capacity;
	return XDEV_EXT_MECH_BUILD_SUBMIT;
bad:
	if (c)
		__sync_fetch_and_add(&c->errors, 1);
	return XDEV_EXT_MECH_BUILD_ABORT;
}

SEC("struct_ops/chain_iaa_complete")
__s32 BPF_PROG(chain_iaa_complete, const struct xdev_ext_mech_ctx *m)
{
	const struct xdev_ext_iaa_mech_cqe *q;
	struct chain_counts *c = counts();

	(void)ctx;
	q = (void *)bpf_xdev_ext_cqe(m, 0, sizeof(*q));
	if (!q || q->status || !q->produced || q->produced > q->capacity ||
	    (expect_out && q->produced != expect_out)) {
		if (c)
			__sync_fetch_and_add(&c->errors, 1);
		return XDEV_EXT_MECH_ABORT;
	}
	if (c) {
		__sync_fetch_and_add(&c->completes, 1);
		__sync_fetch_and_add(&c->produced_bytes, q->produced);
	}
	return XDEV_EXT_MECH_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_iaa_mech_ops chain_iaa_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)chain_iaa_build,
	.complete = (void *)chain_iaa_complete,
};

char LICENSE[] SEC("license") = "GPL";
