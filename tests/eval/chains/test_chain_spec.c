// SPDX-License-Identifier: GPL-2.0
/*
 * Host checks of the pure parts of chain_bench: the strict JSON subset, spec
 * validation and every refusal, the CREATE stage list and io_uring UMEM
 * layout, the oracle helpers, and the NXP headers of the user-space arms
 * against the kernel's own receive parser (xdev_ext_mp_rx_parse).
 *
 *   test_chain_spec			run every check
 *   test_chain_spec --pattern SEED G OFF N [text]
 *					print N expected bytes as hex
 *					(test_run.py compares run.py's copy)
 *   test_chain_spec --validate FILE	chain_parse + chain_validate (+ the
 *					ring UMEM layout) of a spec, as
 *					chain_bench --check, without libbpf
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "chain_check.h"
#include "chain_crc.h"
#include "chain_nxp.h"
#include "chain_oracle.h"
#include "chain_spec.h"
#include "chain_timing.h"

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
#define EXPECT_TRUE(v) EXPECT_EQ(!!(v), 1)
#define EXPECT_PREFIX(msg, prefix) do {						\
	checks++;								\
	if (strncmp((msg), (prefix), strlen(prefix))) {				\
		fprintf(stderr, "%s:%d: got '%s', expected prefix '%s'\n",	\
			__FILE__, __LINE__, (msg), (prefix));			\
		failures++;							\
	}									\
} while (0)

/* --- JSON ------------------------------------------------------------------ */

static int parse(const char *text)
{
	static struct cj_doc d;

	return cj_parse(&d, text, strlen(text));
}

static void test_json(void)
{
	static struct cj_doc d;
	char buf[16];
	uint64_t v = 0;
	bool b = false;
	int root;

	static const char doc[] = "{\"a\":18446744073709551615,\"b\":[1,{\"c\":true}],"
				  "\"s\":\"x\\\"y\"}";

	root = cj_parse(&d, doc, sizeof(doc) - 1);
	EXPECT_TRUE(root >= 0);
	EXPECT_EQ(cj_u64(&d, root, "a", &v), 0);
	EXPECT_TRUE(v == UINT64_MAX);
	EXPECT_EQ(cj_str(&d, root, "s", buf, sizeof(buf)), 0);
	EXPECT_EQ(strcmp(buf, "x\"y"), 0);
	EXPECT_EQ(d.n[cj_get(&d, root, "b")].count, 2);
	EXPECT_EQ(cj_bool(&d, d.n[d.n[cj_get(&d, root, "b")].child].next, "c", &b), 0);
	EXPECT_TRUE(b);
	EXPECT_EQ(cj_u64(&d, root, "missing", &v), 1);
	EXPECT_EQ(cj_u64(&d, root, "s", &v), -1);
	EXPECT_EQ(cj_str(&d, root, "s", buf, 3), -1);	/* does not fit */

	EXPECT_EQ(parse("{\"a\":1,\"a\":2}"), -1);		/* duplicate */
	EXPECT_EQ(parse("{\"a\":-1}"), -1);
	EXPECT_EQ(parse("{\"a\":1.5}"), -1);
	EXPECT_EQ(parse("{\"a\":1e3}"), -1);
	EXPECT_EQ(parse("{\"a\":01}"), -1);
	EXPECT_EQ(parse("{\"a\":18446744073709551616}"), -1);
	EXPECT_EQ(parse("{\"a\":null}"), -1);
	EXPECT_EQ(parse("{\"a\":\"\\u0041\"}"), -1);
	EXPECT_EQ(parse("{\"a\":1} x"), -1);
	EXPECT_EQ(parse("[1]"), -1);
	EXPECT_EQ(parse("{\"a\":[[[[[[[[[1]]]]]]]]]}"), -1);	/* too deep */
	EXPECT_EQ(parse("{\"a\":1,}"), -1);
	EXPECT_TRUE(parse(" {\n\"a\" : [ ] }\n") >= 0);
}

/* --- specs ------------------------------------------------------------------ */

#define PEER "\"peer\":{\"local_mac\":\"02:00:00:00:00:01\",\"peer_mac\":" \
	"\"02:00:00:00:00:02\",\"local_ip\":\"192.0.2.1\",\"peer_ip\":\"192.0.2.2\"," \
	"\"local_port\":54321,\"peer_port\":12345,\"session\":270019}"
#define CE "\"ce\":{\"dev\":\"/dev/xdev_ext_ce_sim\",\"va\":0,\"len\":1048576}"
#define NVME_FROM "{\"class\":\"nvme\",\"dir\":\"from\",\"dev\":\"/dev/ng0n1\"," \
	"\"block\":\"/dev/nvme0n1\",\"slba\":0,\"nlb\":65536}"
#define NVME_TO "{\"class\":\"nvme\",\"dir\":\"to\",\"dev\":\"/dev/ng1n1\"," \
	"\"block\":\"/dev/nvme1n1\",\"slba\":0,\"nlb\":65536}"
#define XSK_TO "{\"class\":\"afxdp\",\"dir\":\"to\",\"ifname\":\"eth0\"}"
#define XSK_FROM "{\"class\":\"afxdp\",\"dir\":\"from\",\"ifname\":\"eth1\",\"queue\":3}"
#define CE_TO "{\"class\":\"ce\",\"dir\":\"to\"}"
#define CE_FROM "{\"class\":\"ce\",\"dir\":\"from\"}"
#define IAA_FROM "{\"class\":\"iaa\",\"dir\":\"from\",\"software\":true," \
	"\"capacity\":8192,\"expect\":8192}"

#define IAA_HW "{\"class\":\"iaa\",\"dir\":\"from\",\"capacity\":8192,\"expect\":8192}"

static const char *const nvme_gpu_nic_stages =
	"[" NVME_FROM "," CE_TO "," CE_FROM "," XSK_TO "]";

/* A spec of @chain with @stages; @extra is spliced in before "stages". */
static int spec_g(uint32_t group, const char *chain, const char *arm, const char *mode,
		  const char *extra, const char *stages, struct chain_spec *s,
		  struct chain_err *e)
{
	static char text[8192];
	int n = snprintf(text, sizeof(text),
			 "{\"schema\":\"xdev-chain-spec-v1\",\"chain\":\"%s\",\"arm\":\"%s\","
			 "\"mode\":\"%s\",\"group_bytes\":%u,\"batches\":64,\"depth\":8,"
			 PEER "," CE ",%s%s\"stages\":%s}", chain, arm, mode, group, extra,
			 *extra ? "," : "", stages);

	memset(e, 0, sizeof(*e));
	if (n < 0 || (size_t)n >= sizeof(text))
		return -2;
	if (chain_parse(text, (size_t)n, s, e))
		return -1;
	return chain_validate(s, e);
}

static int spec(const char *chain, const char *arm, const char *mode,
		const char *extra, const char *stages, struct chain_spec *s,
		struct chain_err *e)
{
	return spec_g(8192, chain, arm, mode, extra, stages, s, e);
}

static void test_specs(void)
{
	static struct chain_spec s;
	struct chain_err e;

	EXPECT_EQ(spec("nvme-gpu-nic", "session", "correctness", "", nvme_gpu_nic_stages,
		       &s, &e), 0);
	EXPECT_EQ(s.nr_stages, 4);
	EXPECT_EQ(s.st[3].cls, CH_AFXDP);
	EXPECT_EQ(s.peer.local_port, htons(54321));
	EXPECT_EQ(s.nxp_session, 270019);
	EXPECT_EQ(chain_windows(&s), 64);
	EXPECT_EQ(spec("nic-gpu-nvme", "session", "correctness", "",
		       "[" XSK_FROM "," CE_TO "," CE_FROM "," NVME_TO "]", &s, &e), 0);
	EXPECT_TRUE(chain_rx_first(&s));
	EXPECT_EQ(s.st[0].queue, 3);
	EXPECT_EQ(spec("nvme-nic", "staged", "timing", "", "[" NVME_FROM "," XSK_TO "]",
		       &s, &e), 0);
	EXPECT_EQ(spec("nic-nvme", "session", "timing", "\"afxdp_mode\":\"copy\"",
		       "[" XSK_FROM "," NVME_TO "]", &s, &e), 0);
	EXPECT_EQ(s.xsk_mode, CH_XSK_COPY);
	EXPECT_EQ(spec("nvme-iaa-gpu", "session", "correctness", "",
		       "[" NVME_FROM "," IAA_FROM "," CE_TO "]", &s, &e), 0);
	EXPECT_EQ(spec("custom", "session", "correctness", "",
		       "[" NVME_FROM "," CE_TO "]", &s, &e), 0);
	EXPECT_EQ(spec("nvme-gpu-nic", "session", "timing",
		       "\"start_per\":\"run\",\"warmup\":3,\"burst\":5", nvme_gpu_nic_stages,
		       &s, &e), -1);	/* CE simulator in a timed run */
	EXPECT_PREFIX(e.msg, "unsupported: the CE simulator");

	/* The capability refusals the reviewer's chains run into. */
	EXPECT_EQ(spec("nvme-crc-nic", "session", "correctness", "",
		       "[" NVME_FROM "," XSK_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: in-frame transform not implemented");
	EXPECT_EQ(spec("nvme-crc-nic", "staged", "timing", "",
		       "[" NVME_FROM "," XSK_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: in-frame transform not implemented");
	EXPECT_EQ(spec("nic-iaa-gpu", "session", "correctness", "",
		       "[" XSK_FROM "," IAA_FROM "," CE_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: one session cannot hold AF_XDP RX and an IAA");
	EXPECT_EQ(spec("custom", "session", "correctness", "",
		       "[" XSK_FROM "," IAA_FROM "," CE_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: one session cannot hold AF_XDP RX and an IAA");
	EXPECT_EQ(spec("nvme-nic", "session", "correctness", "\"plan\":\"default\"",
		       "[" NVME_FROM "," XSK_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: no mechanism class registers default_build");
	EXPECT_EQ(spec("nvme-iaa-gpu", "staged", "timing", "\"staged_gpu\":\"cuda\"",
		       "[" NVME_FROM "," IAA_FROM "," CE_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: staged nvme-iaa-gpu has no device decompressor");
	EXPECT_EQ(spec("custom", "session", "correctness", "",
		       "[" NVME_FROM ",{\"class\":\"iaa\",\"dir\":\"from\",\"capacity\":16384},"
		       CE_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: CE copies stay inside one group_bytes");
	EXPECT_EQ(spec("nvme-gpu-nic", "staged", "correctness", "", nvme_gpu_nic_stages,
		       &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: staged GPU leg needs");
	/* deflate admits CRYPTO_ACOMP_DST_MAX bytes of source and destination. */
	EXPECT_EQ(spec_g(131072, "custom", "session", "correctness", "",
			 "[" NVME_FROM ",{\"class\":\"iaa\",\"dir\":\"from\",\"capacity\":131072}]",
			 &s, &e), 0);
	EXPECT_EQ(spec_g(262144, "custom", "session", "correctness", "",
			 "[" NVME_FROM ",{\"class\":\"iaa\",\"dir\":\"from\",\"capacity\":131072}]",
			 &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: IAA stage 1: deflate takes at most CRYPTO_ACOMP_DST_MAX");
	EXPECT_EQ(spec_g(65536, "custom", "session", "correctness", "",
			 "[" NVME_FROM ",{\"class\":\"iaa\",\"dir\":\"from\",\"capacity\":262144}]",
			 &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: IAA stage 1: deflate takes at most CRYPTO_ACOMP_DST_MAX");
	/* A timed IAA stage must be the device, not the CPU fallback. */
	EXPECT_EQ(spec("custom", "session", "timing", "", "[" NVME_FROM "," IAA_FROM "]",
		       &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: IAA stage 1 uses deflate-generic");

	/* Malformed specs. */
	EXPECT_EQ(spec("nvme-gpu-nic", "session", "correctness", "",
		       "[" NVME_FROM "," CE_TO "," XSK_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: chain nvme-gpu-nic has 4 stages");
	EXPECT_EQ(spec("nvme-gpu-nic", "session", "correctness", "",
		       "[" NVME_FROM "," CE_FROM "," CE_TO "," XSK_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: stage 1 does not match");
	EXPECT_EQ(spec("custom", "session", "correctness", "",
		       "[" NVME_FROM "," CE_TO "," CE_FROM "," CE_TO "," XSK_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: at most 4 stages");
	EXPECT_EQ(spec("custom", "session", "correctness", "",
		       "[" NVME_FROM "," XSK_TO "," CE_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: AF_XDP TX must be the last stage");
	EXPECT_EQ(spec("custom", "session", "correctness", "", "[" CE_TO "," CE_FROM "]",
		       &s, &e), -1);
	EXPECT_PREFIX(e.msg, "unsupported: stage 0 must be");
	EXPECT_EQ(spec("nvme-nic", "session", "correctness", "\"burst\":5",
		       "[" NVME_FROM "," XSK_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: batches and warmup must be multiples of burst");
	EXPECT_EQ(spec("nic-nvme", "session", "correctness", "\"start_per\":\"run\"",
		       "[" XSK_FROM "," NVME_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: an AF_XDP RX chain has no START");
	EXPECT_EQ(spec("nvme-iaa-gpu", "session", "timing",
		       "\"oracle\":{\"kind\":\"ce-window\",\"reference\":\"/r\",\"every_window\":true}",
		       "[" NVME_FROM "," IAA_HW "," CE_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: every_window");
	EXPECT_EQ(spec("nvme-nic", "session", "correctness", "\"depth\":65",
		       "[" NVME_FROM "," XSK_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: JSON at byte");	/* depth given twice */
	EXPECT_EQ(spec("nvme-nic", "session", "correctness", "\"bogus\":1",
		       "[" NVME_FROM "," XSK_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: unknown member bogus");
	EXPECT_EQ(spec("nvme-nic", "session", "fast", "", "[" NVME_FROM "," XSK_TO "]",
		       &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: mode=fast");
	EXPECT_EQ(spec("other", "session", "correctness", "", "[" NVME_FROM "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: unknown chain other");
}

static void test_depth_limit(void)
{
	static struct chain_spec s;
	static const char text[] =
		"{\"schema\":\"xdev-chain-spec-v1\",\"chain\":\"custom\",\"arm\":\"session\","
		"\"mode\":\"correctness\",\"group_bytes\":4096,\"batches\":8,\"depth\":65,"
		"\"stages\":[" NVME_FROM "]}";
	struct chain_err e = { { 0 } };

	EXPECT_EQ(chain_parse(text, sizeof(text) - 1, &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: depth=65 outside [1, 64]");
}

/* --- CREATE stage list and pool layout --------------------------------------- */

static void test_layout(void)
{
	static struct chain_spec s;
	struct xdev_ext_mech_stage_uapi u[XDEV_EXT_MECH_MAX_STAGES];
	struct chain_iou_plan p;
	struct chain_err e;
	int fds[4] = { 10, 11, 12, 13 };

	EXPECT_EQ(spec("nvme-gpu-nic", "session", "correctness", "", nvme_gpu_nic_stages,
		       &s, &e), 0);
	chain_stage_uapi(&s, fds, 99, 0x200000, (uint32_t[4]){ 0 }, u);
	EXPECT_EQ(u[0].class_id, XDEV_EXT_MECH_CLASS_NVME);
	EXPECT_EQ(u[0].direction, XDEV_EXT_MECH_DIR_FROM_DEVICE);
	EXPECT_EQ(u[0].fd, 10);
	EXPECT_EQ(u[0].arg1, 65536);
	EXPECT_EQ(u[1].class_id, XDEV_EXT_MECH_CLASS_CE);
	EXPECT_EQ(u[1].direction, XDEV_EXT_MECH_DIR_TO_DEVICE);
	EXPECT_EQ(u[1].arg0, 0x200000);
	EXPECT_EQ(u[1].arg1, 1048576);
	EXPECT_EQ(u[2].direction, XDEV_EXT_MECH_DIR_FROM_DEVICE);
	EXPECT_EQ(u[3].class_id, XDEV_EXT_MECH_CLASS_AFXDP);
	EXPECT_EQ(u[3].fd, 99);
	EXPECT_EQ(u[3].flags, 0);

	/* NVMe -> IAA -> CE on the ring UMEM: sources, then IAA leases. */
	EXPECT_EQ(spec("nvme-iaa-gpu", "session", "correctness", "\"burst\":4",
		       "[" NVME_FROM "," IAA_FROM "," CE_TO "]", &s, &e), 0);
	EXPECT_EQ(chain_iou_layout(&s, &p, &e), 0);
	EXPECT_EQ(p.l.frame_size, 4096);
	EXPECT_EQ(p.l.hdr_room, 0);
	EXPECT_EQ(p.l.seg_len, 4096);
	EXPECT_EQ(p.src_frames, 2);
	EXPECT_EQ(p.lend_frames, 4 * 2);
	EXPECT_EQ(p.iaa_first[1], 8 * 2);
	EXPECT_EQ(p.pool_frames, 8 * 2 + 8 * 2);
	chain_stage_uapi(&s, fds, -1, 0, p.iaa_first, u);
	EXPECT_EQ(u[1].class_id, XDEV_EXT_MECH_CLASS_IAA);
	EXPECT_EQ(u[1].flags, XDEV_EXT_IAA_F_SOFTWARE);
	EXPECT_EQ(u[1].arg0, 16);
	EXPECT_EQ(u[1].arg1, 8192);
	EXPECT_EQ(u[2].class_id, XDEV_EXT_MECH_CLASS_CE);

	/* A frame bigger than the group: one frame per batch (hardware IAA). */
	EXPECT_EQ(spec("nvme-iaa-gpu", "session", "correctness",
		       "\"pool\":{\"frame_size\":16384,\"frames\":100}",
		       "[" NVME_FROM "," IAA_FROM "," CE_TO "]", &s, &e), 0);
	EXPECT_EQ(chain_iou_layout(&s, &p, &e), 0);
	EXPECT_EQ(p.src_frames, 1);
	EXPECT_EQ(p.iaa_first[1], 8);
	EXPECT_EQ(p.pool_frames, 100);
	EXPECT_EQ(spec("nvme-iaa-gpu", "session", "correctness",
		       "\"pool\":{\"frames\":10}",
		       "[" NVME_FROM "," IAA_FROM "," CE_TO "]", &s, &e), 0);
	EXPECT_EQ(chain_iou_layout(&s, &p, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: pool.frames 10 below the 32 frames");
	EXPECT_EQ(spec("nvme-iaa-gpu", "session", "correctness",
		       "\"pool\":{\"frame_size\":3000}",
		       "[" NVME_FROM "," IAA_FROM "," CE_TO "]", &s, &e), 0);
	EXPECT_EQ(chain_iou_layout(&s, &p, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: pool.frame_size must be a power of two");

	EXPECT_EQ(chain_nvme_window_ok(&s.st[0], 512, 8192, 4096), 0);
	EXPECT_EQ(chain_nvme_window_ok(&s.st[0], 512, 8192, 4097), -ERANGE);
	EXPECT_EQ(chain_nvme_window_ok(&s.st[0], 4096, 6144, 1), -EINVAL);
}

/* --- oracle ------------------------------------------------------------------ */

static void test_oracle(void)
{
	static uint8_t ref[4 * 64], win[3 * 80];
	uint64_t found = 0, want;
	unsigned int g;

	/* Standard CRC32C check value: crc32c("123456789") = 0xe3069283. */
	EXPECT_EQ((uint32_t)~chain_crc32c(0xffffffffU, "123456789", 9), 0xe3069283U);
	EXPECT_EQ(chain_byte(1, 0x0102030405060708ULL, 0), 0x08);
	EXPECT_EQ(chain_byte(1, 0x0102030405060708ULL, 7), 0x01);
	EXPECT_TRUE(chain_byte(1, 5, 100) != chain_byte(2, 5, 100) ||
		    chain_byte(1, 5, 101) != chain_byte(2, 5, 101));
	EXPECT_TRUE(chain_text_byte(9, 3, 70) >= 'a' && chain_text_byte(9, 3, 70) <= 'p');
	EXPECT_EQ(chain_text_byte(9, 3, 64), chain_text_byte(9, 3, 127));

	for (g = 0; g < 4; g++)
		chain_fill(ref + g * 64, 64, 7, g, false);
	memset(win, 0xa6, sizeof(win));
	memcpy(win + 0 * 80, ref + 3 * 64, 64);	/* slot 0: group 3 */
	memcpy(win + 2 * 80, ref + 1 * 64, 64);	/* slot 2: group 1, slot 1 pristine */
	want = 3;
	EXPECT_EQ(chain_check_window(win, 3, 80, 64, ref, 4, 0xa6, &want, 1, &found), 0);
	EXPECT_EQ(found, 2);
	want = 2;
	EXPECT_EQ(chain_check_window(win, 3, 80, 64, ref, 4, 0xa6, &want, 1, &found), -1);
	win[2 * 80 + 40] ^= 1;
	EXPECT_EQ(chain_check_window(win, 3, 80, 64, ref, 4, 0xa6, NULL, 0, &found), 3);
	win[2 * 80 + 40] ^= 1;
	win[1 * 80 + 63] = 0;			/* a partial write into a pristine slot */
	EXPECT_EQ(chain_check_window(win, 3, 80, 64, ref, 4, 0xa6, NULL, 0, &found), 2);
	/* Each group is written once, by one batch: two slots naming it is wrong. */
	memset(win, 0xa6, sizeof(win));
	memcpy(win + 0 * 80, ref + 1 * 64, 64);
	memcpy(win + 2 * 80, ref + 1 * 64, 64);
	EXPECT_EQ(chain_check_window(win, 3, 80, 64, ref, 4, 0xa6, NULL, 0, &found), 3);
	EXPECT_EQ(chain_first_diff(ref, ref, 64), -1);
	EXPECT_EQ(chain_first_diff(ref, ref + 64, 64), 0);
}

/* --- NXP: user-space header accepted by the session's receive parser --------- */

static void test_nxp(void)
{
	static uint8_t frame[4096], payload[8192];
	/* Receiver's view: local = the receiving end. */
	struct xdev_ext_mech_peer tx = { .local_mac = { 2, 0, 0, 0, 0, 1 },
		.peer_mac = { 2, 0, 0, 0, 0, 2 }, .local_ip = htonl(0xc0000201),
		.peer_ip = htonl(0xc0000202), .local_port = htons(54321),
		.peer_port = htons(12345) };
	struct xdev_ext_mech_peer rx = { .local_mac = { 2, 0, 0, 0, 0, 2 },
		.peer_mac = { 2, 0, 0, 0, 0, 1 }, .local_ip = tx.peer_ip,
		.peer_ip = tx.local_ip, .local_port = tx.peer_port,
		.peer_port = tx.local_port };
	struct xdev_ext_mech_layout l;
	struct chain_nxp n;
	struct xdev_ext_mp_rx_cfg cfg;
	__u32 headroom = 0, j, off, len, crc;
	uint8_t prep[XDEV_EXT_MP_NXP_LEN];

	EXPECT_EQ(xdev_ext_mech_ctl_layout(1500, 8192, &l), 0);
	EXPECT_EQ(xdev_ext_mech_ctl_rx_headroom(&l, &headroom), 0);
	n = (struct chain_nxp){ .peer = &tx, .session = 270019, .group_bytes = 8192,
		.seg_len = l.seg_len, .nr_segs = (8192 + l.seg_len - 1) / l.seg_len };
	cfg = (struct xdev_ext_mp_rx_cfg){ .session_id = 270019, .mtu = 1500,
		.frame_size = l.frame_size, .hdr_room = l.hdr_room, .seg_len = l.seg_len,
		.group_bytes = 8192 };
	chain_fill(payload, sizeof(payload), 3, 41, false);
	for (j = 0; j < n.nr_segs; j++) {
		/* The receiving chunk: XDP headroom + UMEM headroom, then the packet. */
		uint32_t data_off = XDEV_EXT_MECH_CTL_XDP_HEADROOM + headroom;
		struct xdev_ext_mp_segment seg = { 0 };

		chain_nxp_seg(&n, j, &off, &len);
		EXPECT_EQ(chain_nxp_build(&n, frame + data_off, 41, j, payload + off), 0);
		memcpy(frame + data_off + XDEV_EXT_MP_PKT_HDR_LEN, payload + off, len);
		EXPECT_EQ(xdev_ext_mp_rx_parse(frame + data_off, data_off,
					  XDEV_EXT_MP_PKT_HDR_LEN + len, &rx, &cfg, &seg),
			  XDEV_EXT_MP_RX_SEGMENT);
		EXPECT_EQ(seg.generation, 42);
		EXPECT_EQ(seg.index, j);
		EXPECT_EQ(seg.payload_off, l.hdr_room);
		/* The receiver's CRC check, as nxp_rx_complete() does it. */
		xdev_ext_mp_nxp_crc_prep(prep, frame + data_off + XDEV_EXT_MP_NXP_OFF);
		crc = chain_crc32c(XDEV_EXT_MP_CRC32C_SEED, prep, sizeof(prep));
		crc = chain_crc32c(crc, frame + seg.payload_off, seg.payload_len);
		EXPECT_TRUE(xdev_ext_mp_nxp_crc_ok(frame + data_off + XDEV_EXT_MP_NXP_OFF, crc));
		/* And the user-space receiver's own check of the same bytes. */
		n.peer = &rx;
		EXPECT_EQ(chain_nxp_check(&n, frame + data_off + XDEV_EXT_MP_NXP_OFF, 41, j,
					  payload + off), 0);
		EXPECT_EQ(chain_nxp_check(&n, frame + data_off + XDEV_EXT_MP_NXP_OFF, 40, j,
					  payload + off), -EPROTO);
		payload[off] ^= 1;
		EXPECT_EQ(chain_nxp_check(&n, frame + data_off + XDEV_EXT_MP_NXP_OFF, 41, j,
					  payload + off), -EBADMSG);
		payload[off] ^= 1;
		n.peer = &tx;
	}
	EXPECT_EQ(n.nr_segs, 6);
}

/* --- counters and copy policy ------------------------------------------------- */

static void good_stats(const struct chain_spec *s, struct xdev_ext_mech_stats *st,
		       uint64_t groups, uint32_t frames)
{
	unsigned int i;

	memset(st, 0, sizeof(*st));
	st->state = XDEV_EXT_MECH_SESSION_ACTIVE;
	st->batches_done = groups;
	for (i = 0; i < s->nr_stages; i++)
		st->submitted[i] = st->completed[i] = groups;
	if (chain_rx_first(s)) {
		st->submitted[0] = 0;
		st->held = st->recycled = groups * frames;
	}
}

static void test_counters(void)
{
	static struct chain_spec s;
	struct xdev_ext_mech_stats st;
	struct chain_err e;

	/* io_uring UMEM with START user frames: every lent frame comes back. */
	EXPECT_EQ(spec("nvme-iaa-gpu", "session", "correctness", "",
		       "[" NVME_FROM "," IAA_FROM "," CE_TO "]", &s, &e), 0);
	good_stats(&s, &st, 64, 2);
	st.published = 64 * 2;			/* 64 STARTs of 1 batch x 2 frames */
	EXPECT_TRUE(chain_counters_bad(&s, &st, 64, 2, 64 * 2) == NULL);
	st.published = 64 * 2 - 1;		/* one lent frame never returned */
	EXPECT_TRUE(chain_counters_bad(&s, &st, 64, 2, 64 * 2) != NULL);
	st.published = 64 * 2 + 1;
	EXPECT_TRUE(chain_counters_bad(&s, &st, 64, 2, 64 * 2) != NULL);

	/* Socket UMEM: nothing is lent, so nothing may be published. */
	EXPECT_EQ(spec("nvme-gpu-nic", "session", "correctness", "", nvme_gpu_nic_stages,
		       &s, &e), 0);
	good_stats(&s, &st, 64, 6);
	EXPECT_TRUE(chain_counters_bad(&s, &st, 64, 6, 0) == NULL);
	st.published = 1;
	EXPECT_TRUE(chain_counters_bad(&s, &st, 64, 6, 0) != NULL);
	EXPECT_EQ(spec("nic-gpu-nvme", "session", "correctness", "",
		       "[" XSK_FROM "," CE_TO "," CE_FROM "," NVME_TO "]", &s, &e), 0);
	good_stats(&s, &st, 64, 6);
	EXPECT_TRUE(chain_counters_bad(&s, &st, 64, 6, 0) == NULL);
	st.held--;
	EXPECT_TRUE(chain_counters_bad(&s, &st, 64, 6, 0) != NULL);
}

static void test_copy_policy(void)
{
	static struct chain_spec s;
	struct chain_err e;
	const char *copy[] = { CHAIN_COPY_XSK }, *bounce[] = { CHAIN_COPY_BOUNCE },
		   *both[] = { CHAIN_COPY_XSK, CHAIN_COPY_BOUNCE };

	/* The E7 copy-mode ablation declares exactly the AF_XDP copy. */
	EXPECT_EQ(spec("nic-nvme", "session", "timing", "\"afxdp_mode\":\"copy\"",
		       "[" XSK_FROM "," NVME_TO "]", &s, &e), 0);
	EXPECT_TRUE(chain_undeclared_copy(&s, copy, 1) == NULL);
	EXPECT_TRUE(chain_undeclared_copy(&s, NULL, 0) == NULL);
	EXPECT_TRUE(chain_undeclared_copy(&s, both, 2) == bounce[0]);
	/* Zero-copy runs declare nothing. */
	EXPECT_EQ(spec("nic-nvme", "session", "timing", "",
		       "[" XSK_FROM "," NVME_TO "]", &s, &e), 0);
	EXPECT_TRUE(chain_undeclared_copy(&s, copy, 1) == copy[0]);
	EXPECT_TRUE(chain_undeclared_copy(&s, NULL, 0) == NULL);
}

/* The wire CRC of the user-space arms against the table oracle. */
static void test_crc_fast(void)
{
	static uint8_t buf[3 * 8192 + 64];
	uint64_t x = 0x9e3779b97f4a7c15ULL;
	unsigned int i, n, bad = 0;

	for (i = 0; i < sizeof(buf); i++) {
		x = chain_mix(x + i);
		buf[i] = (uint8_t)x;
	}
	chain_crc32c_init();
	for (n = 0; n < 4000; n++) {
		size_t off = chain_mix(n) % 64, len = chain_mix(n + 7919) % (3 * 8192);
		uint32_t seed = (uint32_t)chain_mix(n + 104729);

		if (n < 16)
			len = n;			/* every short length */
		else if (n < 32)
			len = 3 * CHAIN_CRC_LANE + n - 24;	/* the 3-way boundary */
		bad += chain_crc32c_fast(seed, buf + off, len) !=
		       chain_crc32c(seed, buf + off, len);
	}
	EXPECT_EQ(bad, 0);
	EXPECT_EQ((uint32_t)~chain_crc32c_fast(0xffffffffU, "123456789", 9), 0xe3069283U);
#if defined(__x86_64__)
	if (__builtin_cpu_supports("sse4.2"))
		EXPECT_EQ(strcmp(chain_crc32c_impl(), "sse4.2-crc32q-3way"), 0);
#endif
}

/* --- sustained load ----------------------------------------------------------- */

static void test_sustained(void)
{
	static struct chain_spec s;
	struct chain_iou_plan p;
	struct chain_sustained t;
	uint64_t done[4] = { 0 };
	struct chain_err e;

	EXPECT_EQ(spec("nvme-iaa-gpu", "session", "correctness",
		       "\"load\":\"sustained\",\"burst\":4,\"warmup\":8",
		       "[" NVME_FROM "," IAA_FROM "," CE_TO "]", &s, &e), 0);
	EXPECT_EQ(s.load, CH_LOAD_SUSTAINED);
	EXPECT_EQ(chain_records(&s), (64 + 8) / 4);
	EXPECT_EQ(chain_start_batches(&s), 64 + 8);	/* one START for the campaign */
	EXPECT_EQ(chain_iou_layout(&s, &p, &e), 0);
	EXPECT_EQ(p.lend_frames, 8 * 2);		/* depth batches lent */
	EXPECT_EQ(spec("nvme-nic", "session", "correctness",
		       "\"load\":\"sustained\",\"start_per\":\"run\"",
		       "[" NVME_FROM "," XSK_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: start_per run is a closed-load option");
	EXPECT_EQ(spec("nvme-iaa-gpu", "session", "correctness",
		       "\"load\":\"sustained\",\"oracle\":{\"kind\":\"ce-window\","
		       "\"reference\":\"/r\",\"every_window\":true}",
		       "[" NVME_FROM "," IAA_FROM "," CE_TO "]", &s, &e), -1);
	EXPECT_PREFIX(e.msg, "invalid: every_window needs the closed load");
	EXPECT_EQ(spec("nic-nvme", "session", "timing", "\"load\":\"sustained\"",
		       "[" XSK_FROM "," NVME_TO "]", &s, &e), 0);

	/* Records complete by count: record r once (r + 1) x burst batches did. */
	chain_sustained_init(&t, 4, 1, 2, done);
	t.t_begin = 5;
	chain_sustained_note(&t, 1, 10);
	EXPECT_EQ(t.next, 0);
	EXPECT_EQ(chain_sustained_t0(&t), 5);
	chain_sustained_note(&t, 2, 20);		/* exactly one record's batches */
	EXPECT_EQ(t.next, 1);
	chain_sustained_note(&t, 3, 25);
	EXPECT_EQ(t.next, 1);
	EXPECT_EQ(done[0], 20);
	EXPECT_EQ(chain_sustained_t0(&t), 20);		/* after the warmup record */
	chain_sustained_note(&t, 100, 30);		/* more than the campaign */
	EXPECT_EQ(t.next, 4);
	EXPECT_EQ(done[1], 30);
	EXPECT_EQ(done[3], 30);
	EXPECT_TRUE(chain_sustained_complete(&t));
	chain_sustained_init(&t, 4, 0, 2, done);
	t.t_begin = 7;
	EXPECT_EQ(chain_sustained_t0(&t), 7);
	EXPECT_TRUE(!chain_sustained_complete(&t));
}

static void put(const char *dir, const char *name, const char *text)
{
	char path[512];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "w");
	if (f) {
		fputs(text, f);
		fclose(f);
	}
}

static void test_env(void)
{
	char dir[] = "/tmp/chain-env-XXXXXX", sub[600], why[128] = "";

	if (!mkdtemp(dir)) {
		EXPECT_TRUE(0);
		return;
	}
	snprintf(sub, sizeof(sub), "%s/proc", dir);
	mkdir(sub, 0700);
	snprintf(sub, sizeof(sub), "%s/sys", dir);
	mkdir(sub, 0700);
	snprintf(sub, sizeof(sub), "%s/sys/hypervisor", dir);
	mkdir(sub, 0700);
	put(dir, "proc/cpuinfo", "processor\t: 0\nflags\t\t: fpu sse4_2 hypervisorx\n");
	EXPECT_TRUE(!chain_env_virtual(dir, why, sizeof(why)));
	put(dir, "proc/cpuinfo", "processor\t: 0\nflags\t\t: fpu hypervisor sse4_2\n");
	EXPECT_TRUE(chain_env_virtual(dir, why, sizeof(why)));
	EXPECT_PREFIX(why, "the CPU flags in /proc/cpuinfo include hypervisor");
	put(dir, "proc/cpuinfo", "flags\t\t: fpu hypervisor\n");
	EXPECT_TRUE(chain_env_virtual(dir, why, sizeof(why)));
	put(dir, "proc/cpuinfo", "flags\t\t: fpu\n");
	put(dir, "sys/hypervisor/type", "xen\n");
	EXPECT_TRUE(chain_env_virtual(dir, why, sizeof(why)));
	EXPECT_PREFIX(why, "/sys/hypervisor/type reports xen");
	put(dir, "sys/hypervisor/type", "");
	EXPECT_TRUE(!chain_env_virtual(dir, why, sizeof(why)));
	snprintf(sub, sizeof(sub), "rm -rf '%s'", dir);
	if (system(sub))
		fprintf(stderr, "cannot remove %s\n", dir);
}

static int pattern(int argc, char **argv)
{
	unsigned long long seed, g, off, nr, i;

	if (argc < 6 || argc > 7)
		return 2;
	seed = strtoull(argv[2], NULL, 0);
	g = strtoull(argv[3], NULL, 0);
	off = strtoull(argv[4], NULL, 0);
	nr = strtoull(argv[5], NULL, 0);
	for (i = 0; i < nr; i++)
		printf("%02x", argc == 7 ? chain_text_byte(seed, g, off + i) :
					   chain_byte(seed, g, off + i));
	printf("\n");
	return 0;
}

static int validate(const char *path)
{
	static struct chain_spec s;
	static char text[1 << 16];
	struct chain_iou_plan p;
	struct chain_err e = { { 0 } };
	FILE *f = fopen(path, "rb");
	size_t n;

	if (!f)
		return 2;
	n = fread(text, 1, sizeof(text), f);
	fclose(f);
	if (chain_parse(text, n, &s, &e) || chain_validate(&s, &e) ||
	    (!chain_has(&s, CH_AFXDP) && chain_iou_layout(&s, &p, &e))) {
		printf("%s\n", e.msg);
		return strncmp(e.msg, "unsupported:", 12) ? 2 : 4;
	}
	printf("ok %s stages=%u windows=%llu\n", s.chain, s.nr_stages,
	       (unsigned long long)chain_windows(&s));
	return 0;
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--pattern"))
		return pattern(argc, argv);
	if (argc == 3 && !strcmp(argv[1], "--validate"))
		return validate(argv[2]);
	test_json();
	test_specs();
	test_depth_limit();
	test_layout();
	test_oracle();
	test_nxp();
	test_counters();
	test_copy_policy();
	test_crc_fast();
	test_sustained();
	test_env();
	printf("%s: %u checks, %u failures\n", failures ? "FAIL" : "PASS", checks, failures);
	return failures ? 1 : 0;
}
