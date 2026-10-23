// SPDX-License-Identifier: GPL-2.0
/*
 * Host checks of uo_core.h: spec parsing and refusals, the frame map of the
 * shared region, the vectored NVMe passthrough command, and that a segment
 * built in a region chunk is what a session receiver (xdev_ext_mp_rx_parse)
 * accepts and what the user-space receiver itself accepts.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uo_core.h"
#include "../chains/chain_nxp.h"

static unsigned int checks, failures;

#define EXPECT_EQ(actual, expected) do {					\
	long long _a = (long long)(actual), _e = (long long)(expected);		\
	checks++;								\
	if (_a != _e) {								\
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",		\
			__FILE__, __LINE__, #actual, _a, _e);			\
		failures++;							\
	}									\
} while (0)
#define EXPECT_PREFIX(msg, prefix) do {						\
	checks++;								\
	if (strncmp((msg), (prefix), strlen(prefix))) {				\
		fprintf(stderr, "%s:%d: got '%s', expected prefix '%s'\n",	\
			__FILE__, __LINE__, (msg), (prefix));			\
		failures++;							\
	}									\
} while (0)

#define PEER "\"peer\":{\"local_mac\":\"02:00:00:00:00:01\",\"peer_mac\":" \
	"\"02:00:00:00:00:02\",\"local_ip\":\"192.0.2.1\",\"peer_ip\":\"192.0.2.2\"," \
	"\"local_port\":54321,\"peer_port\":12345,\"session\":270019}"

static int spec(const char *chain, const char *extra, bool cuda, struct uo_spec *s,
		struct chain_err *e)
{
	static char text[4096];
	int n = snprintf(text, sizeof(text),
			 "{\"schema\":\"xdev-uo-spec-v1\",\"chain\":\"%s\",\"mode\":\"correctness\","
			 "\"wait\":\"eventfd\",\"group_bytes\":8192,\"batches\":64,\"depth\":8,"
			 "\"nvme\":{\"ng\":\"/dev/ng0n1\",\"block\":\"/dev/nvme0n1\",\"slba\":0,"
			 "\"nlb\":65536,\"lba_bytes\":512},\"nic\":{\"ifname\":\"eth0\"},"
			 PEER "%s%s}", chain, *extra ? "," : "", extra);

	memset(e, 0, sizeof(*e));
	if (uo_parse(text, (size_t)n, s, e))
		return -1;
	return uo_validate(s, cuda, e);
}

static void test_spec(void)
{
	static struct uo_spec s;
	struct chain_err e;

	EXPECT_EQ(spec("nvme-nic", "", false, &s, &e), 0);
	EXPECT_EQ(s.rx, 0);
	EXPECT_EQ(s.gpu, 0);
	EXPECT_EQ(s.wait, UO_WAIT_EVENTFD);
	EXPECT_EQ(s.nvme_io, UO_IO_PASSTHRU_VEC);
	EXPECT_EQ(s.hugepage, 1);
	EXPECT_EQ(spec("nic-nvme", "\"oracle\":{\"kind\":\"file\",\"path\":\"/dev/nvme1n1\","
		       "\"reference\":\"/tmp/r\"}", false, &s, &e), 0);
	EXPECT_EQ(s.rx, 1);
	EXPECT_EQ(s.oracle, CH_ORACLE_FILE);
	EXPECT_EQ(spec("nvme-gpu-nic", "\"gpu\":{\"bdf\":\"0000:65:00.0\"}", true, &s, &e), 0);
	EXPECT_EQ(s.gpu, 1);
	EXPECT_EQ(s.load, CH_LOAD_CLOSED);
	EXPECT_EQ(spec("nvme-nic", "\"load\":\"sustained\"", false, &s, &e), 0);
	EXPECT_EQ(s.load, CH_LOAD_SUSTAINED);
	EXPECT_EQ(spec("nvme-nic", "\"load\":\"open\"", false, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: load=open");

	EXPECT_EQ(spec("nvme-gpu-nic", "\"gpu\":{\"bdf\":\"0000:65:00.0\"}", false, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: nvme-gpu-nic needs a UO_CUDA=1 build");
	EXPECT_EQ(spec("nvme-gpu-nic", "", true, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: nvme-gpu-nic needs gpu.bdf");
	EXPECT_EQ(spec("nvme-iaa-gpu", "", true, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: the user-space orchestrator has no IAA stage");
	EXPECT_EQ(spec("nvme-crc-nic", "", true, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: in-frame transform not implemented");
	EXPECT_EQ(spec("nvme-nic", "\"oracle\":{\"kind\":\"file\",\"path\":\"/x\","
		       "\"reference\":\"/r\"}", false, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: a sender has no local oracle");
	EXPECT_EQ(spec("nvme-nic", "\"wait\":\"poll\"", false, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: JSON at byte");	/* wait given twice */
	EXPECT_EQ(spec("nvme-nic", "\"burst\":3", false, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: batches and warmup must be multiples of burst");
	EXPECT_EQ(spec("nvme-nic", "\"zzz\":1", false, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: unknown member zzz");
	EXPECT_EQ(spec("other", "", false, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: unknown chain other");
}

static void test_map(void)
{
	static struct uo_spec s;
	static uint8_t region[64 * UO_CHUNK];
	struct iovec iov[UO_MAX_SEGS];
	struct nvme_uring_cmd c;
	struct chain_err e;
	struct uo_map m;
	uint32_t off, len;

	EXPECT_EQ(spec("nvme-nic", "", false, &s, &e), 0);
	EXPECT_EQ(uo_map(&s, 1500, &m, &e), 0);
	EXPECT_EQ(m.l.hdr_room, 360);
	EXPECT_EQ(m.l.seg_len, 1432);
	EXPECT_EQ(m.segs, 6);
	EXPECT_EQ(m.headroom, 0);
	EXPECT_EQ(uo_chunk(&m, 2, 3), (2 * 6 + 3) * 4096);
	uo_span(&m, 5, &off, &len);
	EXPECT_EQ(off, 360);
	EXPECT_EQ(len, 8192 - 5 * 1432);
	EXPECT_EQ(uo_iov(&m, region, 1, iov), 6);
	EXPECT_EQ((uint8_t *)iov[0].iov_base - region, 6 * 4096 + 360);
	EXPECT_EQ((uint8_t *)iov[5].iov_base - region, 11 * 4096 + 360);
	EXPECT_EQ(iov[5].iov_len, 1032);
	uo_nvme_cmd(&s, 7, false, 3, iov, 6, &c);
	EXPECT_EQ(c.opcode, 0x02);
	EXPECT_EQ(c.nsid, 7);
	EXPECT_EQ(c.data_len, 6);
	EXPECT_EQ(c.cdw10, 3 * 16);
	EXPECT_EQ(c.cdw11, 0);
	EXPECT_EQ(c.cdw12, 15);
	EXPECT_EQ(c.addr, (uintptr_t)iov);
	uo_nvme_cmd(&s, 7, true, 0x100000000ULL, iov, 6, &c);
	EXPECT_EQ(c.opcode, 0x01);
	EXPECT_EQ(c.cdw10, 0);
	EXPECT_EQ(c.cdw11, 16);

	/* Receiver: payload at the session's hdr_room after XDP headroom. */
	EXPECT_EQ(spec("nic-nvme", "", false, &s, &e), 0);
	EXPECT_EQ(uo_map(&s, 1500, &m, &e), 0);
	EXPECT_EQ(m.headroom, 22);

	/* NXP segments of 1432 bytes are not whole LBAs: read-fixed refuses. */
	EXPECT_EQ(spec("nvme-nic", "\"nvme_io\":\"read-fixed\"", false, &s, &e), 0);
	EXPECT_EQ(uo_map(&s, 1500, &m, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: read-fixed needs LBA-sized, LBA-aligned segments");
	/* The largest legal slot set (64 x 32 chunks) fills exactly half. */
	EXPECT_EQ(spec("nvme-nic", "", false, &s, &e), 0);
	s.depth = 64;
	s.group_bytes = 32 * 1432;
	s.lba_bytes = 8;
	s.nlb = 1ULL << 30;
	EXPECT_EQ(uo_map(&s, 1500, &m, &e), 0);
	EXPECT_EQ(m.segs * s.depth, CHAIN_XSK_FRAMES / 2);
	EXPECT_EQ(spec("nvme-nic", "", false, &s, &e), 0);
	s.nlb = 63 * 16;
	EXPECT_EQ(uo_map(&s, 1500, &m, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: NVMe window holds fewer groups");
}

/* A frame built in a sender's chunk parses at a receiver as segment j. */
static void test_wire(void)
{
	static uint8_t chunk[UO_CHUNK], payload[8192];
	static struct uo_spec tx, rx;
	struct chain_err e;
	struct uo_map m;
	struct xdp_desc d;
	struct chain_nxp n;
	struct xdev_ext_mp_rx_cfg cfg;
	struct xdev_ext_mp_segment seg = { 0 };
	uint32_t j, off, len, data_off;

	EXPECT_EQ(spec("nvme-nic", "", false, &tx, &e), 0);
	EXPECT_EQ(spec("nic-nvme", "", false, &rx, &e), 0);
	/* The receiver is the other end: swap the endpoint pair. */
	rx.peer = (struct xdev_ext_mech_peer){ .local_ip = tx.peer.peer_ip,
		.peer_ip = tx.peer.local_ip, .local_port = tx.peer.peer_port,
		.peer_port = tx.peer.local_port };
	memcpy(rx.peer.local_mac, tx.peer.peer_mac, 6);
	memcpy(rx.peer.peer_mac, tx.peer.local_mac, 6);
	EXPECT_EQ(uo_map(&tx, 1500, &m, &e), 0);
	n = (struct chain_nxp){ .peer = &tx.peer, .session = 270019, .group_bytes = 8192,
		.seg_len = m.l.seg_len, .nr_segs = m.segs };
	cfg = (struct xdev_ext_mp_rx_cfg){ .session_id = 270019, .mtu = 1500,
		.frame_size = 4096, .hdr_room = m.l.hdr_room, .seg_len = m.l.seg_len,
		.group_bytes = 8192 };
	chain_fill(payload, sizeof(payload), 11, 9, false);
	for (j = 0; j < m.segs; j++) {
		uo_span(&m, j, &off, &len);
		memset(chunk, 0, sizeof(chunk));
		memcpy(chunk + off, payload + j * m.l.seg_len, len);
		EXPECT_EQ(chain_nxp_build(&n, chunk + off - XDEV_EXT_MP_PKT_HDR_LEN, 9, j,
					  chunk + off), 0);
		xdev_ext_mp_tx_desc(&d, 0, off, len);
		EXPECT_EQ(d.addr, off - XDEV_EXT_MP_PKT_HDR_LEN);
		EXPECT_EQ(d.len, XDEV_EXT_MP_PKT_HDR_LEN + len);
		/* A receiving chunk places the same packet at XDP headroom + 22. */
		data_off = XDEV_EXT_MECH_CTL_XDP_HEADROOM + 22;
		EXPECT_EQ(data_off, d.addr);
		EXPECT_EQ(xdev_ext_mp_rx_parse(chunk + d.addr, data_off, d.len, &rx.peer,
					  &cfg, &seg), XDEV_EXT_MP_RX_SEGMENT);
		EXPECT_EQ(seg.payload_off, off);
		EXPECT_EQ(seg.index, j);
		EXPECT_EQ(seg.generation, 10);
		EXPECT_EQ(chain_nxp_check(&n, chunk + d.addr + XDEV_EXT_MP_NXP_OFF, 9, j,
					  chunk + off), 0);
	}
}

/* A refusal message with quotes and a newline stays one valid JSON line. */
static void test_refusal_line(void)
{
	static struct uo_spec s;
	struct chain_err e;
	char *out = NULL;
	size_t size = 0;
	FILE *f;

	EXPECT_EQ(spec("nvme-gpu-nic", "\"gpu\":[1]", true, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: gpu must be {\"bdf\": ...}");
	f = open_memstream(&out, &size);
	uo_print_refusal(f, true, e.msg);
	uo_print_refusal(f, false, "unsupported: a\tb\n");
	fclose(f);
	EXPECT_EQ(strcmp(out, "{\"schema\":\"xdev-uo-result-v1\",\"status\":\"invalid\","
			 "\"failure\":\"invalid: gpu must be {\\\"bdf\\\": ...}\"}\n"
			 "{\"schema\":\"xdev-uo-result-v1\",\"status\":\"not_run\","
			 "\"failure\":\"unsupported: a\\u0009b\\u000a\"}\n"), 0);
	free(out);
}

/* --validate FILE [cuda]: uo_parse + uo_validate of a spec file. */
static int validate(const char *path, bool cuda)
{
	static struct uo_spec s;
	static char text[1 << 16];
	struct chain_err e = { { 0 } };
	FILE *f = fopen(path, "rb");
	size_t n;

	if (!f)
		return 2;
	n = fread(text, 1, sizeof(text), f);
	fclose(f);
	if (uo_parse(text, n, &s, &e) || uo_validate(&s, cuda, &e)) {
		printf("%s\n", e.msg);
		return strncmp(e.msg, "unsupported:", 12) ? 2 : 4;
	}
	printf("ok %s rx=%d gpu=%d\n", s.chain, s.rx, s.gpu);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 3 && !strcmp(argv[1], "--validate"))
		return validate(argv[2], argc == 4 && !strcmp(argv[3], "cuda"));
	test_spec();
	test_map();
	test_wire();
	test_refusal_line();
	printf("%s: %u checks, %u failures\n", failures ? "FAIL" : "PASS", checks, failures);
	return failures ? 1 : 0;
}
