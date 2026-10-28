// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* The gated AF_XDP RX test binds one socket to queue 0 of its veth. */
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} xdev_ext_rx_xsks SEC(".maps");

/* Set before load.  The default empty range redirects nothing. */
const volatile __u16 xdev_ext_rx_ethertype_first = 1;
const volatile __u16 xdev_ext_rx_ethertype_last;

/* Only the test's own EtherTypes enter the socket.  Neighbour discovery and
 * other link-local traffic a veth sends after link-up keeps the stack path,
 * so it can never take one of the test's fill-ring frames.
 */
SEC("xdp")
int xdev_ext_xsk_rx_redirect(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *ethernet = data;
	__u16 protocol;

	if ((void *)(ethernet + 1) > data_end)
		return XDP_PASS;
	protocol = bpf_ntohs(ethernet->h_proto);
	if (protocol < xdev_ext_rx_ethertype_first ||
	    protocol > xdev_ext_rx_ethertype_last)
		return XDP_PASS;
	return bpf_redirect_map(&xdev_ext_rx_xsks, 0, XDP_DROP);
}

char LICENSE[] SEC("license") = "GPL";
