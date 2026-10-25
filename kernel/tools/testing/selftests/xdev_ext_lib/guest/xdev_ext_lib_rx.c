// SPDX-License-Identifier: GPL-2.0
/*
 * Independent receiver for the libxdev_ext guest test.  It shares no code
 * with the product: a plain AF_PACKET socket captures the frames that
 * arrive on @ifname through the ordinary driver path (no XDP program, no
 * AF_XDP, no mechanism session), checks every header field and the NXP
 * CRC32C with its own decoder, reassembles groups 1..G of @group_bytes, and
 * writes the reassembled bytes with plain pwrite() to @dst at @dst_offset.
 * The host compares that image region against the source image.
 *
 *   xdev_ext_lib_rx --ifname IF --dst /dev/nvmeXnY --dst-offset BYTES
 *	--session S --groups G --group-bytes B --mtu M
 *	--src-mac M --dst-mac M --src-ip A --dst-ip A --src-port P --dst-port P
 *	--timeout-ms T --ready FILE
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define HDR_ETH 14U
#define HDR_IP 20U
#define HDR_UDP 8U
#define HDR_NXP 40U
#define HDR_ALL (HDR_ETH + HDR_IP + HDR_UDP + HDR_NXP)

struct cfg {
	const char *ifname, *dst, *ready;
	uint64_t dst_offset, session, groups;
	uint32_t group_bytes, mtu, seg, count;
	uint8_t src_mac[6], dst_mac[6];
	uint32_t src_ip, dst_ip;	/* network order */
	uint16_t src_port, dst_port;	/* host order */
	int timeout_ms;
};

static uint32_t be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static uint16_t be16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t crc32c(uint32_t crc, const uint8_t *p, size_t n)
{
	size_t i;
	int k;

	for (i = 0; i < n; i++) {
		crc ^= p[i];
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0x82f63b78U & (0U - (crc & 1U)));
	}
	return crc;
}

static bool ip_csum_ok(const uint8_t *ip)
{
	uint32_t sum = 0, i;

	for (i = 0; i < HDR_IP; i += 2)
		sum += be16(ip + i);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum == 0xffff;
}

static int parse_mac(const char *s, uint8_t mac[6])
{
	unsigned int b[6], i;

	if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
		return -1;
	for (i = 0; i < 6; i++)
		mac[i] = (uint8_t)b[i];
	return 0;
}

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Why a frame addressed to this flow is refused; NULL when it is a segment. */
static const char *check(const struct cfg *c, const uint8_t *f, size_t len,
			 uint64_t *gen, uint32_t *index, uint32_t *plen)
{
	const uint8_t *ip = f + HDR_ETH, *udp = ip + HDR_IP, *nxp = udp + HDR_UDP;
	uint32_t total, rel, count, crc;
	uint8_t hdr[HDR_NXP];

	if (len < HDR_ALL)
		return "short";
	if (memcmp(f, c->dst_mac, 6) || memcmp(f + 6, c->src_mac, 6))
		return "mac";
	if (ip[0] != 0x45 || (be16(ip + 6) & 0x3fff) || !ip_csum_ok(ip))
		return "ipv4";
	if (be16(ip + 2) != len - HDR_ETH || be16(ip + 2) > c->mtu)
		return "ip-length";
	if (memcmp(ip + 12, &c->src_ip, 4) || memcmp(ip + 16, &c->dst_ip, 4))
		return "ip-address";
	if (be16(udp) != c->src_port || be16(udp + 2) != c->dst_port ||
	    be16(udp + 4) != len - HDR_ETH - HDR_IP)
		return "udp";
	if (be32(nxp) != 0x4e585032U || nxp[4] != 2 || nxp[5] != HDR_NXP ||
	    nxp[6] != 2 || nxp[7])
		return "nxp-header";
	if (((uint64_t)be32(nxp + 8) << 32 | be32(nxp + 12)) != c->session)
		return "session";
	*gen = be32(nxp + 16);
	*index = be16(nxp + 20);
	count = be16(nxp + 22);
	total = be32(nxp + 24);
	rel = be32(nxp + 28);
	*plen = be32(nxp + 32);
	if (!*gen || *gen > c->groups)
		return "generation";
	if (count != c->count || *index >= count || total != c->group_bytes)
		return "segment-count";
	if (rel != *index * c->seg || *plen != len - HDR_ALL ||
	    *plen != (c->group_bytes - rel < c->seg ? c->group_bytes - rel : c->seg))
		return "segment-span";
	memcpy(hdr, nxp, 36);
	memset(hdr + 36, 0, 4);
	crc = crc32c(0xffffffffU, hdr, sizeof(hdr));
	crc = crc32c(crc, f + HDR_ALL, *plen);
	if (be32(nxp + 36) != ~crc)
		return "crc32c";
	return NULL;
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "ifname", 1, 0, 'i' }, { "dst", 1, 0, 'D' }, { "dst-offset", 1, 0, 'O' },
		{ "session", 1, 0, 'S' }, { "groups", 1, 0, 'g' },
		{ "group-bytes", 1, 0, 'b' }, { "mtu", 1, 0, 'M' },
		{ "src-mac", 1, 0, 'a' }, { "dst-mac", 1, 0, 'A' },
		{ "src-ip", 1, 0, 'p' }, { "dst-ip", 1, 0, 'P' },
		{ "src-port", 1, 0, 'x' }, { "dst-port", 1, 0, 'y' },
		{ "timeout-ms", 1, 0, 't' }, { "ready", 1, 0, 'r' }, { 0, 0, 0, 0 } };
	struct cfg c = { .mtu = 1500, .timeout_ms = 60000 };
	uint64_t segments = 0, unique = 0, dup = 0, bad = 0, foreign = 0, deadline;
	struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL) };
	uint8_t *data, *seen, frame[16384];
	int opt, fd, out, bufsz = 64 << 20;
	const char *result = "timeout";
	size_t total;

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (opt) {
		case 'i': c.ifname = optarg; break;
		case 'D': c.dst = optarg; break;
		case 'O': c.dst_offset = strtoull(optarg, NULL, 0); break;
		case 'S': c.session = strtoull(optarg, NULL, 0); break;
		case 'g': c.groups = strtoull(optarg, NULL, 0); break;
		case 'b': c.group_bytes = (uint32_t)strtoul(optarg, NULL, 0); break;
		case 'M': c.mtu = (uint32_t)strtoul(optarg, NULL, 0); break;
		case 'a': if (parse_mac(optarg, c.src_mac)) return 2; break;
		case 'A': if (parse_mac(optarg, c.dst_mac)) return 2; break;
		case 'p': if (inet_pton(AF_INET, optarg, &c.src_ip) != 1) return 2; break;
		case 'P': if (inet_pton(AF_INET, optarg, &c.dst_ip) != 1) return 2; break;
		case 'x': c.src_port = (uint16_t)atoi(optarg); break;
		case 'y': c.dst_port = (uint16_t)atoi(optarg); break;
		case 't': c.timeout_ms = atoi(optarg); break;
		case 'r': c.ready = optarg; break;
		default: return 2;
		}
	}
	if (!c.ifname || !c.dst || !c.ready || !c.session || !c.groups || !c.group_bytes ||
	    c.mtu <= HDR_IP + HDR_UDP + HDR_NXP)
		return 2;
	/* Segment size of the NXP layout: MTU payload, 8-byte aligned. */
	c.seg = (c.mtu - HDR_IP - HDR_UDP - HDR_NXP) & ~7U;
	c.count = (c.group_bytes + c.seg - 1) / c.seg;
	total = (size_t)c.groups * c.group_bytes;
	data = calloc(1, total);
	seen = calloc(c.groups, c.count);
	if (!data || !seen)
		return 3;
	fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (fd < 0)
		return 3;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bufsz, sizeof(bufsz)))
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
	sll.sll_ifindex = (int)if_nametoindex(c.ifname);
	if (!sll.sll_ifindex || bind(fd, (struct sockaddr *)&sll, sizeof(sll)))
		return 3;
	out = open(c.ready, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out < 0)
		return 3;
	close(out);
	printf("XDEV_EXT_LIB_RX_READY ifname=%s seg=%u count=%u\n", c.ifname, c.seg, c.count);
	fflush(stdout);
	deadline = now_ms() + (uint64_t)c.timeout_ms;
	while (unique < c.groups * c.count) {
		struct sockaddr_ll from;
		socklen_t fl = sizeof(from);
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		uint64_t now = now_ms(), gen;
		uint32_t index, plen;
		const char *why;
		ssize_t n;
		size_t pos;

		if (now >= deadline)
			break;
		if (poll(&pfd, 1, (int)(deadline - now)) <= 0)
			continue;
		n = recvfrom(fd, frame, sizeof(frame), MSG_TRUNC, (struct sockaddr *)&from, &fl);
		if (n < 0 || from.sll_pkttype == PACKET_OUTGOING)
			continue;
		if ((size_t)n > sizeof(frame)) {
			bad++;
			continue;
		}
		/* Only frames of this IPv4/UDP flow are examined. */
		if ((size_t)n < HDR_ETH + HDR_IP + HDR_UDP || be16(frame + 12) != ETH_P_IP ||
		    frame[HDR_ETH + 9] != 17 ||
		    be16(frame + HDR_ETH + HDR_IP + 2) != c.dst_port) {
			foreign++;
			continue;
		}
		segments++;
		why = check(&c, frame, (size_t)n, &gen, &index, &plen);
		if (why) {
			if (bad < 8)
				printf("XDEV_EXT_LIB_RX_BAD reason=%s len=%zd\n", why, n);
			bad++;
			continue;
		}
		pos = (size_t)(gen - 1) * c.count + index;
		if (seen[pos]) {
			if (memcmp(data + (gen - 1) * c.group_bytes + index * c.seg,
				   frame + HDR_ALL, plen))
				bad++;
			dup++;
			continue;
		}
		memcpy(data + (gen - 1) * c.group_bytes + index * c.seg, frame + HDR_ALL, plen);
		seen[pos] = 1;
		unique++;
	}
	if (unique == c.groups * c.count)
		result = "complete";
	out = open(c.dst, O_WRONLY | O_CLOEXEC);
	if (out < 0 || pwrite(out, data, total, (off_t)c.dst_offset) != (ssize_t)total ||
	    fsync(out))
		result = "write-failed";
	if (out >= 0)
		close(out);
	printf("XDEV_EXT_LIB_RX result=%s groups=%llu segments=%llu unique=%llu duplicates=%llu bad=%llu foreign=%llu expected=%llu\n",
	       result, (unsigned long long)c.groups, (unsigned long long)segments,
	       (unsigned long long)unique, (unsigned long long)dup, (unsigned long long)bad,
	       (unsigned long long)foreign, (unsigned long long)(c.groups * c.count));
	return !strcmp(result, "complete") && !bad ? 0 : 1;
}
