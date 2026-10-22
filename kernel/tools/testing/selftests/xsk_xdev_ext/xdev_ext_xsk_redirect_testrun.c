// SPDX-License-Identifier: GPL-2.0
/*
 * Load the generated XSK redirect programs into the running kernel's
 * verifier, and run the test-action variants on synthetic frames with
 * BPF_PROG_TEST_RUN.  The test action returns XDP_TX where the production
 * program would call bpf_redirect_map(), because with an empty XSKMAP a
 * match and a miss would both return XDP_PASS.
 *
 * Nothing here attaches a program to an interface, creates an AF_XDP socket
 * or creates a network namespace.  The one XSKMAP exists only so the
 * production programs can be verified, and every fd is closed before exit.
 * Without uid 0 the program exits 4, the kselftest skip code.
 */
#include <errno.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "../../../include/xdev_ext_xsk_redirect_prog.h"
#include "../../../xdev_ext_bpf_raw.h"

#define KSFT_SKIP 4

#define PEER_IPV4	UINT32_C(0xc0000201)	/* 192.0.2.1 */
#define LOCAL_IPV4	UINT32_C(0xc0000202)	/* 192.0.2.2 */
#define OTHER_IPV4	UINT32_C(0xc6336407)	/* 198.51.100.7 */
#define PEER_PORT	54321
#define LOCAL_PORT	12345
#define FLOW_MAGIC	UINT32_C(0x4e585032)
#define FRAME_MAX_LEN	1514U
#define HEADERS_LEN	(14U + 20U + 8U)

static const uint8_t local_mac[6] = { 0xa2, 0x15, 0x00, 0xc0, 0xff, 0xee };
static const uint8_t other_mac[6] = { 0xa2, 0x15, 0x00, 0xc0, 0xff, 0xef };
static const uint8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint8_t peer_mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

static unsigned int checks;
static unsigned int failures;
static char verifier_log[64 * 1024];

struct frame {
	uint8_t dst_mac[6];
	uint16_t ethertype;
	bool vlan;
	uint8_t ihl_words;
	uint16_t frag;
	uint8_t protocol;
	uint32_t src_ipv4;
	uint32_t dst_ipv4;
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t payload_len;
	uint32_t payload_magic;
	int ip_len_delta;
	int udp_len_delta;
	size_t truncate_to;
};

static struct frame matching_frame(void)
{
	struct frame frame = {
		.ethertype = ETH_P_IP,
		.ihl_words = 5,
		.protocol = IPPROTO_UDP,
		.src_ipv4 = PEER_IPV4,
		.dst_ipv4 = LOCAL_IPV4,
		.src_port = PEER_PORT,
		.dst_port = LOCAL_PORT,
		.payload_len = 64,
		.payload_magic = FLOW_MAGIC,
	};

	memcpy(frame.dst_mac, local_mac, sizeof(frame.dst_mac));
	return frame;
}

static void put16(uint8_t *at, uint16_t value)
{
	at[0] = value >> 8;
	at[1] = value & 0xff;
}

static void put32(uint8_t *at, uint32_t value)
{
	put16(at, value >> 16);
	put16(at + 2, value & 0xffff);
}

static uint16_t ipv4_checksum(const uint8_t *header, size_t len)
{
	uint32_t sum = 0;

	for (size_t i = 0; i + 1 < len; i += 2)
		sum += (uint32_t)header[i] << 8 | header[i + 1];
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

/* Ethernet, optional 802.1Q tag, IPv4 with NOP options when ihl_words > 5,
 * UDP with a zero checksum, then the payload.  Returns the frame length. */
static size_t build_frame(const struct frame *f, uint8_t *buf, size_t cap)
{
	size_t ip_header_len = (size_t)f->ihl_words * 4;
	size_t l2_len = f->vlan ? 18 : 14;
	size_t udp_len = 8 + f->payload_len;
	size_t len = l2_len + ip_header_len + udp_len;
	uint8_t *ip = buf + l2_len;
	uint8_t *udp = ip + ip_header_len;

	if (len > cap)
		return 0;
	memset(buf, 0, len);
	memcpy(buf, f->dst_mac, 6);
	memcpy(buf + 6, peer_mac, 6);
	if (f->vlan) {
		put16(buf + 12, ETH_P_8021Q);
		put16(buf + 14, 7);
	}
	put16(buf + l2_len - 2, f->ethertype);

	ip[0] = 0x40 | f->ihl_words;
	put16(ip + 2, (uint16_t)(ip_header_len + udp_len + f->ip_len_delta));
	put16(ip + 6, f->frag);
	ip[8] = 64;
	ip[9] = f->protocol;
	put32(ip + 12, f->src_ipv4);
	put32(ip + 16, f->dst_ipv4);
	memset(ip + 20, 1, ip_header_len - 20);
	put16(ip + 10, ipv4_checksum(ip, ip_header_len));

	put16(udp, f->src_port);
	put16(udp + 2, f->dst_port);
	put16(udp + 4, (uint16_t)(udp_len + f->udp_len_delta));
	for (size_t i = 0; i < f->payload_len; i++)
		udp[8 + i] = (uint8_t)i;
	if (f->payload_len >= 4)
		put32(udp + 8, f->payload_magic);

	if (f->truncate_to && f->truncate_to < len)
		len = f->truncate_to;
	return len;
}

static const char *action_name(uint32_t action)
{
	switch (action) {
	case XDP_ABORTED:
		return "XDP_ABORTED";
	case XDP_DROP:
		return "XDP_DROP";
	case XDP_PASS:
		return "XDP_PASS";
	case XDP_TX:
		return "XDP_TX";
	case XDP_REDIRECT:
		return "XDP_REDIRECT";
	default:
		return "unknown";
	}
}

/* Build and load one program.  The first load runs without a log so a long
 * log can never turn an accepted program into ENOSPC; a rejected program is
 * loaded again with log_level 1 and the verifier's reason is printed. */
static int load_program(const char *label, int map_fd,
			const struct xdev_ext_xsk_flow_filter *filter,
			uint32_t options)
{
	struct bpf_insn program[XDEV_EXT_XSK_REDIRECT_MAX_INSNS];
	size_t count = 0;
	int fd;
	int ret;

	checks++;
	ret = xdev_ext_xsk_prog_build(map_fd, filter, options, program,
				 XDEV_EXT_XSK_REDIRECT_MAX_INSNS, &count);
	if (ret) {
		failures++;
		printf("FAIL: build %s: %s\n", label, strerror(-ret));
		return ret;
	}
	fd = xdev_ext_bpf_raw_prog_load(BPF_PROG_TYPE_XDP, "xdev_ext_xsk_test",
				   program, count, "GPL", NULL, 0, 0);
	if (fd >= 0) {
		printf("PASS: load %s: %zu instructions accepted\n", label,
		       count);
		return fd;
	}
	failures++;
	printf("FAIL: load %s: %s\n", label, strerror(-fd));
	verifier_log[0] = '\0';
	ret = xdev_ext_bpf_raw_prog_load(BPF_PROG_TYPE_XDP, "xdev_ext_xsk_test",
				    program, count, "GPL", verifier_log,
				    sizeof(verifier_log), 1);
	if (ret >= 0)
		close(ret);
	printf("verifier log for %s (reload: %d):\n%s\n", label, ret,
	       verifier_log);
	return fd;
}

static void run_case(const char *program_label, int prog_fd,
		     const char *name, const struct frame *frame,
		     uint32_t expected)
{
	uint8_t buf[2048];
	uint32_t retval = UINT32_MAX;
	size_t len = build_frame(frame, buf, sizeof(buf));
	int ret;

	checks++;
	if (prog_fd < 0 || !len) {
		failures++;
		printf("FAIL: %s: %s: no program or frame\n", program_label,
		       name);
		return;
	}
	ret = xdev_ext_bpf_raw_prog_test_run(prog_fd, buf, (uint32_t)len, &retval);
	if (ret || retval != expected) {
		failures++;
		printf("FAIL: %s: %s (%zu bytes): ret %d, got %s (%u), expected %s\n",
		       program_label, name, len, ret, action_name(retval),
		       retval, action_name(expected));
		return;
	}
	printf("PASS: %s: %s (%zu bytes) -> %s\n", program_label, name, len,
	       action_name(retval));
}

/* Every packet shape that must stay with the kernel stack, on a program whose
 * filter has the interface MAC and the frame length bound. */
static void run_unconnected_cases(const char *label, int fd)
{
	struct frame frame;

	frame = matching_frame();
	run_case(label, fd, "exact match", &frame, XDP_TX);
	frame.payload_len = 0;
	run_case(label, fd, "zero-length datagram", &frame, XDP_TX);
	frame.payload_len = FRAME_MAX_LEN - HEADERS_LEN;
	run_case(label, fd, "frame of exactly max_len", &frame, XDP_TX);
	frame.payload_len++;
	run_case(label, fd, "one byte over max_len", &frame, XDP_PASS);

	frame = matching_frame();
	frame.src_ipv4 = OTHER_IPV4;
	frame.src_port = 999;
	run_case(label, fd, "any source while unconnected", &frame, XDP_TX);

	frame = matching_frame();
	frame.ethertype = ETH_P_IPV6;
	run_case(label, fd, "IPv6 ethertype", &frame, XDP_PASS);
	frame = matching_frame();
	frame.vlan = true;
	run_case(label, fd, "802.1Q tag", &frame, XDP_PASS);
	frame = matching_frame();
	frame.ihl_words = 6;
	run_case(label, fd, "IPv4 options", &frame, XDP_PASS);
	frame = matching_frame();
	frame.frag = 0x2000;
	run_case(label, fd, "more-fragments flag", &frame, XDP_PASS);
	frame = matching_frame();
	frame.frag = 0x0001;
	run_case(label, fd, "fragment offset", &frame, XDP_PASS);
	frame = matching_frame();
	frame.dst_port = LOCAL_PORT + 1;
	run_case(label, fd, "other destination port", &frame, XDP_PASS);
	frame = matching_frame();
	frame.dst_ipv4 = OTHER_IPV4;
	run_case(label, fd, "other destination address", &frame, XDP_PASS);
	frame = matching_frame();
	memcpy(frame.dst_mac, other_mac, sizeof(frame.dst_mac));
	run_case(label, fd, "other destination MAC", &frame, XDP_PASS);
	frame = matching_frame();
	memcpy(frame.dst_mac, broadcast_mac, sizeof(frame.dst_mac));
	run_case(label, fd, "broadcast destination MAC", &frame, XDP_PASS);
	frame = matching_frame();
	frame.protocol = IPPROTO_TCP;
	run_case(label, fd, "TCP protocol", &frame, XDP_PASS);
	frame = matching_frame();
	frame.truncate_to = HEADERS_LEN - 1;
	run_case(label, fd, "truncated UDP header", &frame, XDP_PASS);
	frame = matching_frame();
	frame.udp_len_delta = -1;
	run_case(label, fd, "UDP length disagrees with IPv4", &frame,
		 XDP_PASS);
	frame = matching_frame();
	frame.ip_len_delta = 8;
	frame.udp_len_delta = 8;
	run_case(label, fd, "IPv4 length beyond the frame", &frame, XDP_PASS);
}

static void run_connected_cases(const char *label, int fd)
{
	struct frame frame;

	frame = matching_frame();
	run_case(label, fd, "exact match from the peer", &frame, XDP_TX);
	frame.src_ipv4 = OTHER_IPV4;
	run_case(label, fd, "non-peer source address", &frame, XDP_PASS);
	frame = matching_frame();
	frame.src_port = PEER_PORT + 1;
	run_case(label, fd, "non-peer source port", &frame, XDP_PASS);
	frame = matching_frame();
	frame.payload_len = FRAME_MAX_LEN - HEADERS_LEN + 1;
	run_case(label, fd, "one byte over max_len", &frame, XDP_PASS);
	frame = matching_frame();
	memcpy(frame.dst_mac, other_mac, sizeof(frame.dst_mac));
	run_case(label, fd, "other destination MAC", &frame, XDP_PASS);
}

/* The payload-magic mode keeps its old meaning: magic required, no MAC or
 * length check unless asked for. */
static void run_magic_cases(const char *label, int fd)
{
	struct frame frame;

	frame = matching_frame();
	run_case(label, fd, "exact match with magic", &frame, XDP_TX);
	frame.payload_magic = FLOW_MAGIC + 1;
	run_case(label, fd, "wrong magic", &frame, XDP_PASS);
	frame = matching_frame();
	frame.payload_len = 0;
	run_case(label, fd, "datagram too short for magic", &frame, XDP_PASS);
	frame = matching_frame();
	memcpy(frame.dst_mac, other_mac, sizeof(frame.dst_mac));
	run_case(label, fd, "MAC unchecked without F_DST_MAC", &frame, XDP_TX);
}

static void run_bare_tuple_cases(const char *label, int fd)
{
	struct frame frame;

	frame = matching_frame();
	run_case(label, fd, "exact match", &frame, XDP_TX);
	memcpy(frame.dst_mac, other_mac, sizeof(frame.dst_mac));
	run_case(label, fd, "MAC unchecked without F_DST_MAC", &frame, XDP_TX);
	frame = matching_frame();
	frame.payload_len = FRAME_MAX_LEN - HEADERS_LEN + 1;
	run_case(label, fd, "length unchecked without F_MAX_LEN", &frame,
		 XDP_TX);
	frame = matching_frame();
	frame.dst_port = LOCAL_PORT + 1;
	run_case(label, fd, "other destination port", &frame, XDP_PASS);
}

static void close_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

int main(void)
{
	const struct xdev_ext_xsk_flow_filter magic = {
		.flags = XDEV_EXT_XSK_FILTER_F_ALL,
		.src_ipv4 = PEER_IPV4,
		.dst_ipv4 = LOCAL_IPV4,
		.payload_magic = FLOW_MAGIC,
		.src_port = PEER_PORT,
		.dst_port = LOCAL_PORT,
	};
	const struct xdev_ext_xsk_flow_filter bare = {
		.flags = XDEV_EXT_XSK_FILTER_F_DST_IPV4 | XDEV_EXT_XSK_FILTER_F_DST_PORT,
		.dst_ipv4 = LOCAL_IPV4,
		.dst_port = LOCAL_PORT,
	};
	struct xdev_ext_xsk_flow_filter tuple = bare;
	struct xdev_ext_xsk_flow_filter connected;
	struct xdev_ext_xsk_flow_filter widest_len;
	struct {
		const char *label;
		const struct xdev_ext_xsk_flow_filter *filter;
		int fd;
	} redirect[] = {
		{ "redirect payload-magic", &magic, -1 },
		{ "redirect tuple", &tuple, -1 },
		{ "redirect connected", &connected, -1 },
		{ "redirect bare tuple", &bare, -1 },
		{ "redirect max_len 65535", &widest_len, -1 },
	};
	int tx_magic = -1, tx_tuple = -1, tx_connected = -1, tx_bare = -1;
	struct utsname uts;
	int map_fd;

	if (getuid() != 0 || geteuid() != 0) {
		printf("SKIP: xdev_ext_xsk_redirect_testrun needs uid 0 for BPF_PROG_LOAD\n");
		return KSFT_SKIP;
	}
	if (!uname(&uts))
		printf("kernel %s, verifier of the running kernel\n",
		       uts.release);

	tuple.flags |= XDEV_EXT_XSK_FILTER_F_DST_MAC | XDEV_EXT_XSK_FILTER_F_MAX_LEN;
	memcpy(tuple.dst_mac, local_mac, sizeof(tuple.dst_mac));
	tuple.max_len = FRAME_MAX_LEN;
	connected = tuple;
	connected.flags |= XDEV_EXT_XSK_FILTER_F_SRC_IPV4 | XDEV_EXT_XSK_FILTER_F_SRC_PORT;
	connected.src_ipv4 = PEER_IPV4;
	connected.src_port = PEER_PORT;
	widest_len = tuple;
	widest_len.max_len = UINT16_MAX;

	/* Private, never inserted into any socket, closed below. */
	map_fd = xdev_ext_bpf_raw_map_create(BPF_MAP_TYPE_XSKMAP, sizeof(uint32_t),
					sizeof(uint32_t), 4, "xdev_ext_xsk_test");
	checks++;
	if (map_fd < 0) {
		failures++;
		printf("FAIL: XSKMAP create: %s\n", strerror(-map_fd));
	} else {
		printf("PASS: private XSKMAP created\n");
	}

	/* Production programs: the running verifier must accept them, and with
	 * the map empty a matching frame falls back to XDP_PASS. */
	for (size_t i = 0; map_fd >= 0 && i < sizeof(redirect) / sizeof(redirect[0]); i++) {
		struct frame frame = matching_frame();

		redirect[i].fd = load_program(redirect[i].label, map_fd,
					      redirect[i].filter, 0);
		run_case(redirect[i].label, redirect[i].fd,
			 "matching frame, empty XSKMAP", &frame, XDP_PASS);
	}

	tx_magic = load_program("test-action payload-magic", -1, &magic,
				XDEV_EXT_XSK_PROG_TEST_ACTION_TX);
	tx_tuple = load_program("test-action tuple", -1, &tuple,
				XDEV_EXT_XSK_PROG_TEST_ACTION_TX);
	tx_connected = load_program("test-action connected", -1, &connected,
				    XDEV_EXT_XSK_PROG_TEST_ACTION_TX);
	tx_bare = load_program("test-action bare tuple", -1, &bare,
			       XDEV_EXT_XSK_PROG_TEST_ACTION_TX);

	run_magic_cases("test-action payload-magic", tx_magic);
	run_unconnected_cases("test-action tuple", tx_tuple);
	run_connected_cases("test-action connected", tx_connected);
	run_bare_tuple_cases("test-action bare tuple", tx_bare);

	for (size_t i = 0; i < sizeof(redirect) / sizeof(redirect[0]); i++)
		close_fd(&redirect[i].fd);
	close_fd(&tx_magic);
	close_fd(&tx_tuple);
	close_fd(&tx_connected);
	close_fd(&tx_bare);
	close_fd(&map_fd);

	printf("xdev_ext_xsk_redirect_testrun: %u checks, %u failures\n", checks,
	       failures);
	return failures ? 1 : 0;
}
