/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_NXP_H
#define CHAIN_NXP_H

/*
 * NXP segment headers for the user-space arms (staged chain_bench,
 * uo_bench).  The 40 NXP bytes are exactly those a session's AF_XDP TX
 * build writes (xdev_ext_mp_tx_encode, CRC32C over the header with a zero
 * checksum field and then the payload), so a user-space sender is accepted
 * by a session receiver (xdev_ext_mp_rx_parse) and the reverse;
 * test_chain_spec.c checks that against the kernel parser.  The CRC is
 * chain_crc32c_fast(), the hardware CRC32C of the same class as the
 * kernel crc32c() a session plan calls (chain_crc.h).
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "chain_crc.h"
#include "chain_oracle.h"
#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"

struct chain_nxp {
	const struct xdev_ext_mech_peer *peer;	/* this end is "local" */
	uint64_t session;
	uint32_t group_bytes, seg_len, nr_segs;
};

static inline void chain_nxp_seg(const struct chain_nxp *n, uint32_t j,
				 uint32_t *off, uint32_t *len)
{
	*off = j * n->seg_len;
	*len = n->group_bytes - *off < n->seg_len ? n->group_bytes - *off : n->seg_len;
}

/*
 * The full XDEV_EXT_MP_PKT_HDR_LEN (Ethernet, IPv4, UDP, NXP) header of
 * segment @j of group @g into @pkt, IPv4 checksum filled in, CRC over
 * @payload; an AF_XDP sender transmits all of it, a UDP socket sender the
 * last XDEV_EXT_MP_NXP_LEN bytes.
 */
static inline int chain_nxp_build(const struct chain_nxp *n, uint8_t *pkt,
				  uint64_t g, uint32_t j, const uint8_t *payload)
{
	uint8_t prep[XDEV_EXT_MP_NXP_LEN];
	struct xdev_ext_mp_tx_seg seg = {
		.session_id = n->session, .generation = (__u32)(g + 1),
		.total_len = n->group_bytes, .count = (__u16)n->nr_segs,
		.index = (__u16)j,
	};
	uint8_t *ip = pkt + XDEV_EXT_MP_ETH_LEN;
	uint32_t off, len, crc;
	__u16 sum;

	if (g >= 0xffffffffULL || j >= n->nr_segs)
		return -EINVAL;
	chain_nxp_seg(n, j, &off, &len);
	seg.relative_offset = off;
	seg.payload_len = len;
	if (xdev_ext_mp_tx_encode(pkt, n->peer, &seg))
		return -EINVAL;
	sum = xdev_ext_mp_ip_csum(ip);
	xdev_ext_mp_put_be16(ip + 10, sum);
	xdev_ext_mp_nxp_crc_prep(prep, pkt + XDEV_EXT_MP_NXP_OFF);
	crc = chain_crc32c_fast(XDEV_EXT_MP_CRC32C_SEED, prep, sizeof(prep));
	crc = chain_crc32c_fast(crc, payload, len);
	xdev_ext_mp_nxp_crc_store(pkt + XDEV_EXT_MP_NXP_OFF, crc);
	return 0;
}

/* 0 when the 40 NXP bytes @nxp are segment @j of group @g, CRC included. */
static inline int chain_nxp_check(const struct chain_nxp *n, const uint8_t *nxp,
				  uint64_t g, uint32_t j, const uint8_t *payload)
{
	uint8_t prep[XDEV_EXT_MP_NXP_LEN];
	uint32_t off, len, crc;

	chain_nxp_seg(n, j, &off, &len);
	if (xdev_ext_mp_get_be32(nxp) != XDEV_EXT_MP_NXP_MAGIC ||
	    nxp[4] != XDEV_EXT_MP_NXP_VERSION || nxp[5] != XDEV_EXT_MP_NXP_LEN ||
	    nxp[6] != XDEV_EXT_MP_NXP_DIR_WRITE || nxp[7] ||
	    xdev_ext_mp_get_be64(nxp + 8) != n->session ||
	    xdev_ext_mp_get_be32(nxp + 16) != g + 1 ||
	    xdev_ext_mp_get_be16(nxp + 20) != j ||
	    xdev_ext_mp_get_be16(nxp + 22) != n->nr_segs ||
	    xdev_ext_mp_get_be32(nxp + 24) != n->group_bytes ||
	    xdev_ext_mp_get_be32(nxp + 28) != off ||
	    xdev_ext_mp_get_be32(nxp + 32) != len)
		return -EPROTO;
	xdev_ext_mp_nxp_crc_prep(prep, nxp);
	crc = chain_crc32c_fast(XDEV_EXT_MP_CRC32C_SEED, prep, sizeof(prep));
	crc = chain_crc32c_fast(crc, payload, len);
	return xdev_ext_mp_nxp_crc_ok(nxp, crc) ? 0 : -EBADMSG;
}

#endif /* CHAIN_NXP_H */
