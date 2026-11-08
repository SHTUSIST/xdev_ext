// SPDX-License-Identifier: GPL-2.0
/*
 * XDP program for net_af_xdp's xdp_prog= option on devices without native
 * XDP (thunderbolt-net has no ndo_bpf).
 *
 * Why it is needed: with libxdp, the PMD's default program is attached in
 * native mode, because libxdp v1.6.2 (lib/libxdp/xsk.c, xsk_convert_xdp_flags)
 * maps "no mode flag" to XDP_MODE_NATIVE, and the kernel refuses native mode
 * on a device without ndo_bpf.  For xdp_prog= the PMD attaches with libbpf's
 * bpf_xdp_attach(ifindex, fd, XDP_FLAGS_UPDATE_IF_NOEXIST) (DPDK 24.11.8
 * rte_eth_af_xdp.c), so the kernel picks generic (skb) mode itself.
 *
 * Behaviour is that of libxdp's default program (lib/libxdp/xsk_def_xdp_prog.c
 * at v1.6.2): an XSKMAP named xsks_map with 64 queue ids, and every frame is
 * redirected to the socket bound to its RX queue, or passed to the kernel
 * when no socket is bound.  The dispatcher bookkeeping of libxdp
 * (run config, refcount, metadata) is omitted because this program is
 * attached on its own.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int tb_xsk_redirect(struct xdp_md *ctx)
{
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
