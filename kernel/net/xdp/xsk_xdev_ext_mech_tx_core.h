/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_XDP_XSK_XDEV_EXT_MECH_TX_CORE_H
#define _NET_XDP_XSK_XDEV_EXT_MECH_TX_CORE_H

/*
 * Pure rules of the AF_XDP mechanism TX stage.  A TX build fills one
 * struct xdp_desc per batch frame, slot i for frame i, each a complete
 * Ethernet/IPv4/UDP packet to the session peer that starts in the frame's
 * header room and ends exactly where the frame's data ends.  C validates
 * every field before anything is sent, then writes the only header fields
 * a program never does: the IPv4 header checksum, and a zero UDP checksum
 * (the receiver checks the IPv4 one only).  One submit attempt sends the
 * frames in slot order through a send step the caller supplies; a retried
 * batch never puts a frame on the wire twice.  No locking here; net/xdp and
 * tools/testing/selftests/xsk_xdev_ext compile the same code.
 */

#ifdef __KERNEL__
#include <linux/if_xdp.h>
#include <linux/string.h>
#else
#include <string.h>
#include "../../include/uapi/linux/if_xdp.h"
#endif
#include "xsk_xdev_ext_mech_core.h"

/* Packet offsets: Ethernet, then IPv4 without options, then UDP. */
#define XSK_XDEV_EXT_MECH_ETH_HLEN		14U
#define XSK_XDEV_EXT_MECH_IP_OFF		XSK_XDEV_EXT_MECH_ETH_HLEN
#define XSK_XDEV_EXT_MECH_IP_HLEN		20U
#define XSK_XDEV_EXT_MECH_UDP_OFF		(XSK_XDEV_EXT_MECH_IP_OFF + XSK_XDEV_EXT_MECH_IP_HLEN)
#define XSK_XDEV_EXT_MECH_TX_HLEN		(XSK_XDEV_EXT_MECH_UDP_OFF + 8U)

/* What a TX descriptor is checked against, fixed for the session. */
struct xsk_xdev_ext_mech_tx_bounds {
	__u32 hdr_room;
	__u32 mtu;
	struct xdev_ext_mech_peer peer;
};

static inline __u16 xsk_xdev_ext_mech_be16(const __u8 *p)
{
	return (__u16)(p[0] << 8 | p[1]);
}

/*
 * Descriptor @d against its batch frame @f, whose chunk bytes start at
 * @chunk: 0, or the error C aborts the batch with.  -EINVAL: options set,
 * or a data span reaching into the header room; -ERANGE: the packet does
 * not start in this frame's header room or its headers run past it;
 * -EMSGSIZE: the packet does not end exactly at the end of the frame's
 * data, exceeds MTU + Ethernet header, or an IPv4/UDP length disagrees;
 * -EPROTO: not IPv4 without options carrying unfragmented UDP; -EPERM: a
 * MAC, address or port other than the session's.
 */
static inline int xsk_xdev_ext_mech_tx_check(const struct xdp_desc *d,
					const struct xdev_ext_mech_frame_info *f,
					const __u8 *chunk,
					const struct xsk_xdev_ext_mech_tx_bounds *bd)
{
	const struct xdev_ext_mech_peer *pe = &bd->peer;
	const __u8 *p, *ip, *udp;
	__u64 off;

	if (d->options)
		return -EINVAL;
	if (f->data_off < bd->hdr_room)
		return -EINVAL;
	if (d->addr < f->umem_addr)
		return -ERANGE;
	off = d->addr - f->umem_addr;
	/* starts in the header room and keeps all its headers there */
	if (!xdev_ext_mech_span_in(off, XSK_XDEV_EXT_MECH_TX_HLEN, bd->hdr_room))
		return -ERANGE;
	if (off + d->len != (__u64)f->data_off + f->data_len ||
	    d->len > (__u64)bd->mtu + XSK_XDEV_EXT_MECH_ETH_HLEN)
		return -EMSGSIZE;

	p = chunk + off;
	ip = p + XSK_XDEV_EXT_MECH_IP_OFF;
	udp = p + XSK_XDEV_EXT_MECH_UDP_OFF;
	if (memcmp(p, pe->peer_mac, 6) || memcmp(p + 6, pe->local_mac, 6))
		return -EPERM;
	if (xsk_xdev_ext_mech_be16(p + 12) != 0x0800)	/* ETH_P_IP */
		return -EPROTO;
	if (ip[0] != 0x45 || ip[9] != 17 ||		/* IPPROTO_UDP */
	    (xsk_xdev_ext_mech_be16(ip + 6) & 0x3fff))	/* IP_MF | IP_OFFSET */
		return -EPROTO;
	if (memcmp(ip + 12, &pe->local_ip, 4) || memcmp(ip + 16, &pe->peer_ip, 4))
		return -EPERM;
	if (xsk_xdev_ext_mech_be16(ip + 2) != d->len - XSK_XDEV_EXT_MECH_IP_OFF)
		return -EMSGSIZE;
	if (memcmp(udp, &pe->local_port, 2) || memcmp(udp + 2, &pe->peer_port, 2))
		return -EPERM;
	if (xsk_xdev_ext_mech_be16(udp + 4) != d->len - XSK_XDEV_EXT_MECH_UDP_OFF)
		return -EMSGSIZE;
	return 0;
}

/*
 * The used scratch slots of a TX build against the @nr_frames batch frames
 * @f with chunk bytes @chunk: exactly one descriptor per frame, slot i for
 * frame i.  On 0, @out holds the @n accepted descriptors.
 */
static inline int xsk_xdev_ext_mech_tx_validate(const __u8 *scratch, __u32 n,
					   const struct xdev_ext_mech_frame_info *f,
					   const __u8 *const *chunk,
					   __u32 nr_frames,
					   const struct xsk_xdev_ext_mech_tx_bounds *bd,
					   struct xdp_desc *out)
{
	struct xdp_desc d;
	__u32 i;
	int err;

	if (!n || n != nr_frames || n > XDEV_EXT_MECH_MAX_FRAMES)
		return -EINVAL;
	for (i = 0; i < n; i++) {
		memcpy(&d, scratch + (size_t)i * sizeof(d), sizeof(d));
		err = xsk_xdev_ext_mech_tx_check(&d, &f[i], chunk[i], bd);
		if (err)
			return err;
		out[i] = d;
	}
	return 0;
}

/* IPv4 header checksum of the 20 bytes at @ip, its own field taken as 0. */
static inline __u16 xsk_xdev_ext_mech_ipv4_csum(const __u8 *ip)
{
	__u32 sum = 0, i;

	for (i = 0; i < XSK_XDEV_EXT_MECH_IP_HLEN; i += 2)
		if (i != 10)
			sum += xsk_xdev_ext_mech_be16(ip + i);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (__u16)~sum;
}

/* The header fields only C writes, on a validated packet at @pkt. */
static inline void xsk_xdev_ext_mech_tx_finish(__u8 *pkt)
{
	__u8 *ip = pkt + XSK_XDEV_EXT_MECH_IP_OFF;
	__u16 csum = xsk_xdev_ext_mech_ipv4_csum(ip);

	ip[10] = csum >> 8;
	ip[11] = csum & 0xff;
	pkt[XSK_XDEV_EXT_MECH_UDP_OFF + 6] = 0;
	pkt[XSK_XDEV_EXT_MECH_UDP_OFF + 7] = 0;
}

/*
 * One submit attempt of batch @id over @n validated frames.  *@sent[i] is
 * the id of the last batch that put frame i on the wire, so a RETRY of the
 * same batch (same nonzero @id) skips those frames; the others go out in
 * slot order through @xmit until the first failure.  @err[i] becomes 0 for
 * a frame on the wire, the failure for the frame that failed and
 * -ECANCELED for the frames after it.  Returns the batch status: 0 or the
 * first failure, of which C repeats only -EAGAIN (xdev_ext_mech_retry_ok()).
 */
static inline int xsk_xdev_ext_mech_tx_run(__u64 id, __u32 n, __u64 *const *sent,
				      __s32 *err,
				      int (*xmit)(void *arg, __u32 slot),
				      void *arg)
{
	int status = 0, ret;
	__u32 i;

	for (i = 0; i < n; i++) {
		if (status) {
			err[i] = -ECANCELED;
			continue;
		}
		err[i] = 0;
		if (id && *sent[i] == id)
			continue;
		ret = xmit(arg, i);
		if (ret < 0) {
			err[i] = ret;
			status = ret;
			continue;
		}
		*sent[i] = id;
	}
	return status;
}

#endif /* _NET_XDP_XSK_XDEV_EXT_MECH_TX_CORE_H */
