// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>

/*
 * The NXP receive side of tools/xdev_ext_mech/nxp_mech.bpf.c (plan section 4.3),
 * kept here because that object is not part of the selftests build.  An RX
 * complete reads Ethernet, IPv4, UDP and the NXP header of the frame just
 * received, checks the flow against the session peer and the CRC32C over
 * header and payload, and holds segments strictly in generation and segment
 * order, as nxp_wire_group_accept() does in user space.  Out-of-order,
 * duplicate, corrupt and foreign-session NXP frames are recycled; traffic
 * outside the flow is published.  The serialized generic and native callsites may
 * hold or advance the group.
 */
#define NXP_IP		14
#define NXP_UDP		34
#define NXP_HDR		42
#define NXP_PAYLOAD	82

__u64 nxp_session;		/* sender's NXP session id */
__u32 nxp_total_len;		/* payload bytes per group */
__u32 nxp_segments;		/* frames per group */
__u32 nxp_next_generation;	/* next group expected */
__u32 nxp_next_segment;
__u32 nxp_next_offset;
__u64 nxp_held;
__u64 nxp_recycled;
__u64 nxp_published;

static __always_inline __u32 nxp_raw32(const __u8 *p)
{
	__u32 v;

	__builtin_memcpy(&v, p, sizeof(v));
	return v;
}

static __always_inline __u16 nxp_raw16(const __u8 *p)
{
	__u16 v;

	__builtin_memcpy(&v, p, sizeof(v));
	return v;
}

static __always_inline __s32 nxp_verdict(__s32 verdict)
{
	if (verdict == XDEV_EXT_MECH_HOLD)
		nxp_held++;
	else if (verdict == XDEV_EXT_MECH_RECYCLE)
		nxp_recycled++;
	else
		nxp_published++;
	return verdict;
}

/* Peer to local over IPv4 UDP, unfragmented. */
static __always_inline int nxp_flow(const struct xdev_ext_afxdp_mech_info *info,
				    const __u8 *p)
{
	int i;

	for (i = 0; i < 6; i++)
		if (p[i] != info->peer.local_mac[i] ||
		    p[6 + i] != info->peer.peer_mac[i])
			return 0;
	return p[12] == 0x08 && p[13] == 0x00 && p[NXP_IP] == 0x45 &&
	       p[NXP_IP + 9] == 17 &&
	       !(xdev_ext_mech_get_be16(p + NXP_IP + 6) & 0x3fff) &&
	       nxp_raw32(p + NXP_IP + 12) == info->peer.peer_ip &&
	       nxp_raw32(p + NXP_IP + 16) == info->peer.local_ip &&
	       nxp_raw16(p + NXP_UDP) == info->peer.peer_port &&
	       nxp_raw16(p + NXP_UDP + 2) == info->peer.local_port;
}

/* Receive only: transmit lives in tools/xdev_ext_mech/nxp_mech.bpf.c. */
SEC("struct_ops/build")
__s32 BPF_PROG(nxp_rx_only_build, const struct xdev_ext_mech_ctx *mctx)
{
	return XDEV_EXT_MECH_BUILD_ABORT;
}

SEC("struct_ops/complete")
__s32 BPF_PROG(nxp_rx_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_afxdp_mech_info *info;
	const struct xdev_ext_mech_frame_info *f0;
	__u8 hdr[XDEV_EXT_MECH_NXP_HDR];
	__u32 len, gen, seg, count, crc;
	const __u8 *p, *nxp;

	if (mctx->callsite != XDEV_EXT_MECH_SITE_RX_GENERIC &&
	    mctx->callsite != XDEV_EXT_MECH_SITE_RX_NATIVE)
		return nxp_verdict(XDEV_EXT_MECH_PUBLISH);
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info)
		return nxp_verdict(XDEV_EXT_MECH_PUBLISH);
	f0 = &info->f[0];
	if (f0->data_len < NXP_PAYLOAD)
		return nxp_verdict(XDEV_EXT_MECH_PUBLISH);
	p = bpf_xdev_ext_frame(mctx, 0, f0->data_off, NXP_PAYLOAD);
	if (!p || !nxp_flow(info, p))
		return nxp_verdict(XDEV_EXT_MECH_PUBLISH);

	nxp = p + NXP_HDR;
	len = xdev_ext_mech_get_be32(nxp + 32);
	if (xdev_ext_mech_get_be32(nxp) != XDEV_EXT_MECH_NXP_MAGIC ||
	    nxp[4] != XDEV_EXT_MECH_NXP_VERSION || nxp[5] != XDEV_EXT_MECH_NXP_HDR ||
	    nxp[6] != XDEV_EXT_MECH_NXP_DIR_WRITE || nxp[7] ||
	    f0->data_len != NXP_PAYLOAD + len ||
	    xdev_ext_mech_get_be16(p + NXP_IP + 2) != NXP_PAYLOAD - NXP_IP + len ||
	    xdev_ext_mech_get_be16(p + NXP_UDP + 4) != NXP_PAYLOAD - NXP_UDP + len ||
	    xdev_ext_mech_get_be64(nxp + 8) != nxp_session)
		return nxp_verdict(XDEV_EXT_MECH_RECYCLE);

	__builtin_memcpy(hdr, nxp, XDEV_EXT_MECH_NXP_CSUM);
	__builtin_memset(hdr + XDEV_EXT_MECH_NXP_CSUM, 0,
			 XDEV_EXT_MECH_NXP_HDR - XDEV_EXT_MECH_NXP_CSUM);
	crc = bpf_xdev_ext_crc32c(hdr, sizeof(hdr), ~0U);
	crc = bpf_xdev_ext_frame_crc32c(mctx, 0, f0->data_off + NXP_PAYLOAD, len,
				   crc);
	if (~crc != xdev_ext_mech_get_be32(nxp + XDEV_EXT_MECH_NXP_CSUM))
		return nxp_verdict(XDEV_EXT_MECH_RECYCLE);

	gen = xdev_ext_mech_get_be32(nxp + 16);
	seg = xdev_ext_mech_get_be16(nxp + 20);
	count = xdev_ext_mech_get_be16(nxp + 22);
	if (xdev_ext_mech_get_be32(nxp + 24) != nxp_total_len ||
	    count != nxp_segments || gen != nxp_next_generation ||
	    seg != nxp_next_segment ||
	    xdev_ext_mech_get_be32(nxp + 28) != nxp_next_offset ||
	    bpf_xdev_ext_afxdp_hold(mctx, gen, seg, f0->data_off + NXP_PAYLOAD,
			       len))
		return nxp_verdict(XDEV_EXT_MECH_RECYCLE);

	nxp_next_offset += len;
	if (++nxp_next_segment == count) {
		nxp_next_generation++;
		nxp_next_segment = 0;
		nxp_next_offset = 0;
	}
	return nxp_verdict(XDEV_EXT_MECH_HOLD);
}

SEC(".struct_ops.link")
struct xdev_ext_afxdp_mech_ops nxp_afxdp_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)nxp_rx_only_build,
	.complete = (void *)nxp_rx_complete,
};

char _license[] SEC("license") = "GPL";
