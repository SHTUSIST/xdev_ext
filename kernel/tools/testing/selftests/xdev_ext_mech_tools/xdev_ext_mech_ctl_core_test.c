// SPDX-License-Identifier: GPL-2.0
/*
 * User-space checks of tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h: the frame layout
 * xdev_ext_mech_ctl gives a session, its CLI value parsing, how it sets a BPF
 * global in a section image, and the verdict and exact text of every marker
 * line the KVM harness greps.  Build with -I <kernel tree>.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "io_uring/xdev_ext_mech_core.h"
#include "nvme_xdp_pipeline_core.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual, expected) do {                                      \
	long long _actual = (long long)(actual);                              \
	long long _expected = (long long)(expected);                          \
	checks++;                                                              \
	if (_actual != _expected) {                                            \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",         \
			__FILE__, __LINE__, #actual, _actual, _expected);      \
		failures++;                                                     \
	}                                                                       \
} while (0)

#define EXPECT_STR(actual, expected) do {                                     \
	checks++;                                                              \
	if (strcmp((actual), (expected))) {                                    \
		fprintf(stderr, "%s:%d: got '%s'\n%*s expected '%s'\n",          \
			__FILE__, __LINE__, (actual),                           \
			(int)strlen(__FILE__) + 6, "", (expected));             \
		failures++;                                                     \
	}                                                                       \
} while (0)

#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define EXPECT_FALSE(value) EXPECT_EQ(!!(value), 0)

/* The receiving pipeline's frame (nvme_xdp_pipeline.c). */
_Static_assert(XDEV_EXT_MECH_CTL_FRAME_SIZE == 4096, "FRAME_SIZE");
_Static_assert(XDEV_EXT_MECH_CTL_HDR_ROOM == 256 + 22 + XDEV_EXT_MP_PKT_HDR_LEN,
	       "XDP_PACKET_HEADROOM + PKT_START_OFF + headers");

static void test_xsk_mode(void)
{
	EXPECT_EQ(xdev_ext_mech_ctl_xsk_flags(false), XDP_ZEROCOPY);
	EXPECT_EQ(xdev_ext_mech_ctl_xsk_flags(true), XDP_COPY);
	EXPECT_EQ(xdev_ext_mech_ctl_xsk_mode_check(false, XDP_OPTIONS_ZEROCOPY), 0);
	EXPECT_EQ(xdev_ext_mech_ctl_xsk_mode_check(false, 0), -EOPNOTSUPP);
	EXPECT_EQ(xdev_ext_mech_ctl_xsk_mode_check(true, 0), 0);
	EXPECT_EQ(xdev_ext_mech_ctl_xsk_mode_check(true, XDP_OPTIONS_ZEROCOPY), -EPROTO);
}

static void test_layout(void)
{
	struct nxp_wire_layout wire;
	struct xdev_ext_mech_layout l;
	__u32 headroom = 0;

	EXPECT_EQ(xdev_ext_mech_ctl_layout(1500, 8192, &l), 0);
	EXPECT_EQ(l.frame_size, 4096);
	EXPECT_EQ(l.hdr_room, 360);
	EXPECT_EQ(l.seg_len, 1432);
	EXPECT_EQ(l.group_bytes, 8192);
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), 6);
	/* The layout the user-space receiver plans for the same group. */
	EXPECT_EQ(nxp_wire_mtu_layout_plan(1, 1, 8192, 1500, 4096, 360, 8,
					   &wire), 0);
	EXPECT_EQ(l.seg_len, wire.segment_data_limit);
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), wire.segment_count);
	for (__u32 i = 0; i < 6; i++) {
		struct nxp_wire_segment seg;
		__u32 off = 0, len = 0;

		EXPECT_EQ(xdev_ext_mech_layout_span(&l, i, &off, &len), 0);
		EXPECT_EQ(nxp_wire_segment_at(&wire, NXP_IO_WRITE, (uint16_t)i,
					      &seg), 0);
		EXPECT_EQ(off, 360);
		EXPECT_EQ(len, seg.payload_len);
	}
	EXPECT_EQ(xdev_ext_mech_ctl_rx_headroom(&l, &headroom), 0);
	EXPECT_EQ(headroom, 22);

	EXPECT_EQ(xdev_ext_mech_ctl_layout(9000, 8192, &l), 0);
	EXPECT_EQ(l.seg_len, 3736);
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), 3);
	/* 33 frames do not fit one batch. */
	EXPECT_EQ(xdev_ext_mech_ctl_layout(1500, 33 * 1432, &l), -E2BIG);
	EXPECT_EQ(xdev_ext_mech_ctl_layout(1500, 32 * 1432, &l), 0);
	EXPECT_EQ(xdev_ext_mech_ctl_layout(1500, 0, &l), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_layout(60, 8192, &l), -EMSGSIZE);
	l.hdr_room = 100;
	EXPECT_EQ(xdev_ext_mech_ctl_rx_headroom(&l, &headroom), -EINVAL);
}

static void test_parse(void)
{
	__u8 mac[6];
	char name[16];
	__u64 v;

	EXPECT_EQ(xdev_ext_mech_ctl_parse_u64("0", &v), 0);
	EXPECT_EQ(v, 0);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_u64("18446744073709551615", &v), 0);
	EXPECT_EQ(v, UINT64_MAX);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_u64("0x1000", &v), 0);
	EXPECT_EQ(v, 4096);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_u64("18446744073709551616", &v), -ERANGE);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_u64("-1", &v), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_u64(" 1", &v), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_u64("1k", &v), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_u64("", &v), -EINVAL);

	EXPECT_EQ(xdev_ext_mech_ctl_parse_mac("02:00:0a:FF:00:01", mac), 0);
	EXPECT_EQ(mac[0], 0x02);
	EXPECT_EQ(mac[3], 0xff);
	EXPECT_EQ(mac[5], 0x01);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_mac("02:00:0a:ff:00", mac), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_mac("02:00:0a:ff:00:01:02", mac), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_mac("02:00:0a:ff:00:1g", mac), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_mac("2:0:a:ff:0:1", mac), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_mac("02-00-0a-ff-00-01", mac), -EINVAL);

	EXPECT_EQ(xdev_ext_mech_ctl_parse_set("nxp_session=0x1122", name,
					 sizeof(name), &v), 0);
	EXPECT_STR(name, "nxp_session");
	EXPECT_EQ(v, 0x1122);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_set("mode=2", name, sizeof(name), &v), 0);
	EXPECT_STR(name, "mode");
	EXPECT_EQ(xdev_ext_mech_ctl_parse_set("mode", name, sizeof(name), &v),
		  -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_set("=2", name, sizeof(name), &v),
		  -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_set("mode=", name, sizeof(name), &v),
		  -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_set("a_very_long_global=1", name,
					 sizeof(name), &v), -ENAMETOOLONG);
	EXPECT_EQ(xdev_ext_mech_ctl_parse_set("mo-de=1", name, sizeof(name), &v),
		  -EINVAL);
}

static void test_set_value(void)
{
	__u8 image[16];
	__u64 u64;
	__u32 u32;

	memset(image, 0xee, sizeof(image));
	EXPECT_EQ(xdev_ext_mech_ctl_set_value(image, sizeof(image), 8, 8,
					 0x0102030405060708ULL), 0);
	memcpy(&u64, image + 8, 8);
	EXPECT_EQ(u64, 0x0102030405060708ULL);
	EXPECT_EQ(image[7], 0xee);
	EXPECT_EQ(xdev_ext_mech_ctl_set_value(image, sizeof(image), 0, 4, 7), 0);
	memcpy(&u32, image, 4);
	EXPECT_EQ(u32, 7);
	EXPECT_EQ(image[4], 0xee);
	EXPECT_EQ(xdev_ext_mech_ctl_set_value(image, sizeof(image), 4, 1, 255), 0);
	EXPECT_EQ(image[4], 255);
	EXPECT_EQ(xdev_ext_mech_ctl_set_value(image, sizeof(image), 4, 1, 256),
		  -ERANGE);
	EXPECT_EQ(xdev_ext_mech_ctl_set_value(image, sizeof(image), 6, 2, 65536),
		  -ERANGE);
	EXPECT_EQ(xdev_ext_mech_ctl_set_value(image, sizeof(image), 0, 4,
					 0x100000000ULL), -ERANGE);
	EXPECT_EQ(xdev_ext_mech_ctl_set_value(image, sizeof(image), 12, 8, 1),
		  -ERANGE);
	EXPECT_EQ(xdev_ext_mech_ctl_set_value(image, sizeof(image), 0xfffffffcU, 8,
					 1), -ERANGE);
	EXPECT_EQ(xdev_ext_mech_ctl_set_value(image, sizeof(image), 0, 3, 1),
		  -EINVAL);
}

static struct xdev_ext_mech_stats clean_nic_nvme(void)
{
	return (struct xdev_ext_mech_stats) {
		.session_id = 9, .batches_done = 64, .held = 384,
		.recycled = 384, .submitted = { 0, 64 }, .completed = { 0, 64 },
		.state = XDEV_EXT_MECH_SESSION_ACTIVE,
	};
}

static void test_nic_nvme(void)
{
	struct xdev_ext_mech_stats s = clean_nic_nvme();
	char line[512];

	EXPECT_TRUE(xdev_ext_mech_ctl_report_nic_nvme(line, sizeof(line), &s, 64,
						 6));
	EXPECT_STR(line, "XDEV_EXT_MECH_NIC_NVME_E2E=PASS groups=64 held=384 "
		   "nvme_submitted=64 nvme_completed=64 recycled=384 "
		   "published=0 errors=0 sequestered=0 inflight=0");
	EXPECT_TRUE(xdev_ext_mech_ctl_report_fq_dup(line, sizeof(line), &s, 64, 6,
					       1));
	EXPECT_STR(line, "XDEV_EXT_MECH_FQ_DUP_REJECT=PASS pushed=1 "
		   "batches_done=64 errors=0");

	/* Each counter off by one fails the run. */
	for (int field = 0; field < 11; field++) {
		s = clean_nic_nvme();
		switch (field) {
		case 0: s.batches_done--; break;
		case 1: s.batches_abort++; break;
		case 2: s.held--; break;
		case 3: s.recycled--; break;
		case 4: s.submitted[1]--; break;
		case 5: s.completed[1]--; break;
		case 6: s.published++; break;
		case 7: s.sequestered++; break;
		case 8: s.inflight++; break;
		case 9: s.rejects++; break;
		case 10: s.protocol_err++; break;
		}
		EXPECT_FALSE(xdev_ext_mech_ctl_report_nic_nvme(line, sizeof(line),
							  &s, 64, 6));
		EXPECT_EQ(strncmp(line, "XDEV_EXT_MECH_NIC_NVME_E2E=FAIL ", 27), 0);
		EXPECT_FALSE(xdev_ext_mech_ctl_report_fq_dup(line, sizeof(line), &s,
							64, 6, 1));
	}
	/* A dup that was never pushed proves nothing. */
	s = clean_nic_nvme();
	EXPECT_FALSE(xdev_ext_mech_ctl_report_fq_dup(line, sizeof(line), &s, 64, 6,
						0));
}

static void test_negative_arms(void)
{
	struct xdev_ext_mech_stats s = {
		.batches_abort = 64, .held = 384, .recycled = 384,
		.rejects = 64, .submitted = { 0, 0 },
		.state = XDEV_EXT_MECH_SESSION_ACTIVE,
	};
	char line[512];

	EXPECT_TRUE(xdev_ext_mech_ctl_report_window_reject(line, sizeof(line), &s,
						      64));
	EXPECT_STR(line, "XDEV_EXT_MECH_NVME_WINDOW_REJECT=PASS errors=64 "
		   "nvme_submitted=0");
	s.submitted[1] = 1;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_window_reject(line, sizeof(line), &s,
						       64));
	s.submitted[1] = 0;
	s.batches_done = 1;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_window_reject(line, sizeof(line), &s,
						       64));
	s.batches_done = 0;
	s.recycled = 383;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_window_reject(line, sizeof(line), &s,
						       64));

	s = (struct xdev_ext_mech_stats) { .native_publish = 384, .published = 384 };
	EXPECT_TRUE(xdev_ext_mech_ctl_report_native_copy(line, sizeof(line), &s));
	EXPECT_STR(line, "XDEV_EXT_MECH_NATIVE_COPY=PASS held=0 native_publish=384");
	s.held = 6;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_native_copy(line, sizeof(line), &s));
	s = (struct xdev_ext_mech_stats) { 0 };
	EXPECT_FALSE(xdev_ext_mech_ctl_report_native_copy(line, sizeof(line), &s));

	s = (struct xdev_ext_mech_stats) {
		.timeouts = 1, .held = 389, .recycled = 389, .batches_done = 64,
	};
	EXPECT_TRUE(xdev_ext_mech_ctl_report_group_timeout(line, sizeof(line), &s));
	EXPECT_STR(line, "XDEV_EXT_MECH_GROUP_TIMEOUT=PASS timeouts=1 held=389 "
		   "recycled=389");
	s.recycled--;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_group_timeout(line, sizeof(line),
						       &s));
	s.recycled++;
	s.timeouts = 0;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_group_timeout(line, sizeof(line),
						       &s));

	EXPECT_TRUE(xdev_ext_mech_ctl_report_shared_umem(line, sizeof(line),
						    -EBUSY));
	EXPECT_STR(line, "XDEV_EXT_MECH_SHARED_UMEM_REJECT=PASS err=-EBUSY");
	EXPECT_FALSE(xdev_ext_mech_ctl_report_shared_umem(line, sizeof(line), 0));
	EXPECT_STR(line, "XDEV_EXT_MECH_SHARED_UMEM_REJECT=FAIL err=0");
	EXPECT_FALSE(xdev_ext_mech_ctl_report_shared_umem(line, sizeof(line),
						     -EINVAL));
	EXPECT_STR(line, "XDEV_EXT_MECH_SHARED_UMEM_REJECT=FAIL err=-EINVAL");

	s = (struct xdev_ext_mech_stats) {
		.state = XDEV_EXT_MECH_SESSION_STOPPED, .last_err = -ECANCELED,
		.batches_done = 30,
	};
	EXPECT_TRUE(xdev_ext_mech_ctl_report_prog_detach(line, sizeof(line), &s));
	EXPECT_STR(line, "XDEV_EXT_MECH_PROG_DETACH=PASS last_err=-ECANCELED "
		   "state=STOPPED");
	s.state = XDEV_EXT_MECH_SESSION_ACTIVE;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_prog_detach(line, sizeof(line), &s));
	s.state = XDEV_EXT_MECH_SESSION_STOPPED;
	s.last_err = 0;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_prog_detach(line, sizeof(line), &s));
	s.last_err = -ECANCELED;
	s.inflight = 1;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_prog_detach(line, sizeof(line), &s));

	/* A freed session left nothing in flight: batches hold references. */
	EXPECT_TRUE(xdev_ext_mech_ctl_report_ring_exit(line, sizeof(line), NULL));
	EXPECT_STR(line, "XDEV_EXT_MECH_RING_EXIT=PASS inflight=0 state=FREED");
	s = (struct xdev_ext_mech_stats) { .state = XDEV_EXT_MECH_SESSION_STOPPED };
	EXPECT_TRUE(xdev_ext_mech_ctl_report_ring_exit(line, sizeof(line), &s));
	EXPECT_STR(line, "XDEV_EXT_MECH_RING_EXIT=PASS inflight=0 state=STOPPED");
	s = (struct xdev_ext_mech_stats) {
		.state = XDEV_EXT_MECH_SESSION_ZOMBIE, .inflight = 2,
		.sequestered = 1,
	};
	EXPECT_TRUE(xdev_ext_mech_ctl_report_ring_exit(line, sizeof(line), &s));
	EXPECT_STR(line, "XDEV_EXT_MECH_RING_EXIT=PASS inflight=2 state=ZOMBIE");
	s.state = XDEV_EXT_MECH_SESSION_STOPPING;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_ring_exit(line, sizeof(line), &s));

	s = (struct xdev_ext_mech_stats) {
		.state = XDEV_EXT_MECH_SESSION_STOPPED, .last_err = -ENXIO,
		.batches_abort = 1,
	};
	EXPECT_TRUE(xdev_ext_mech_ctl_report_unbind(line, sizeof(line), &s));
	EXPECT_STR(line, "XDEV_EXT_MECH_XSK_UNBIND_INFLIGHT=PASS last_err=-ENXIO "
		   "state=STOPPED inflight=0");
	s.state = XDEV_EXT_MECH_SESSION_ZOMBIE;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_unbind(line, sizeof(line), &s));
}

static void test_sources(void)
{
	struct xdev_ext_mech_stats s = {
		.state = XDEV_EXT_MECH_SESSION_ACTIVE,
		.batches_done = 64, .submitted = { 64, 384 },
		.completed = { 64, 384 },
	};
	char line[512];

	EXPECT_TRUE(xdev_ext_mech_ctl_report_nvme_nic(line, sizeof(line), &s, 64));
	EXPECT_STR(line, "XDEV_EXT_MECH_NVME_NIC_E2E=PASS groups=64 "
		   "nvme_submitted=64 nvme_completed=64 tx_submitted=384 "
		   "tx_completed=384 errors=0 sequestered=0 inflight=0");
	s.completed[1]--;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_nvme_nic(line, sizeof(line), &s, 64));
	s.completed[1]++;
	s.batches_abort = 1;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_nvme_nic(line, sizeof(line), &s, 64));

	/* Chain a: NVMe READ, CE H2D, CE D2H, NVMe WRITE. */
	s = (struct xdev_ext_mech_stats) {
		.batches_done = 8, .submitted = { 8, 8, 8, 8 },
		.completed = { 8, 8, 8, 8 },
	};
	EXPECT_TRUE(xdev_ext_mech_ctl_report_ce_chain(line, sizeof(line), &s, 'a',
						 8, 4, true, true));
	EXPECT_STR(line, "XDEV_EXT_MECH_CE_SIM=PASS chain=a");
	EXPECT_TRUE(xdev_ext_mech_ctl_report_ce_chain(line, sizeof(line), &s, 'a',
						 8, 4, false, true));
	EXPECT_STR(line, "XDEV_EXT_MECH_CE_GPU=PASS chain=a");
	/* Chain d's frame compare failed. */
	EXPECT_FALSE(xdev_ext_mech_ctl_report_ce_chain(line, sizeof(line), &s, 'd',
						  8, 2, true, false));
	EXPECT_STR(line, "XDEV_EXT_MECH_CE_SIM=FAIL chain=d");
	/* A native command that never completed. */
	s.submitted[1] = 9;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_ce_chain(line, sizeof(line), &s, 'a',
						  8, 4, true, true));
	s.submitted[1] = 8;
	s.completed[2] = 7;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_ce_chain(line, sizeof(line), &s, 'a',
						  8, 4, true, true));
	/* Stages past nr_stages do not count. */
	EXPECT_TRUE(xdev_ext_mech_ctl_report_ce_chain(line, sizeof(line), &s, 'd',
						 8, 2, true, true));
	s.sequestered = 1;
	EXPECT_FALSE(xdev_ext_mech_ctl_report_ce_chain(line, sizeof(line), &s, 'd',
						  8, 2, true, true));
}

static void test_stats_line(void)
{
	struct xdev_ext_mech_stats s = {
		.session_id = 0x1234, .batches_done = 1, .batches_abort = 2,
		.rejects = 3, .recycled = 4, .held = 5, .sequestered = 6,
		.timeouts = 7, .inflight = 8, .native_publish = 9,
		.protocol_err = 10, .published = 11,
		.submitted = { 12, 13, 14, 15 },
		.completed = { 16, 17, 18, 19 },
		.last_err = -ECANCELED, .state = XDEV_EXT_MECH_SESSION_ZOMBIE,
	};
	char line[512];

	EXPECT_TRUE(xdev_ext_mech_ctl_stats_line(line, sizeof(line), &s) > 0);
	EXPECT_STR(line, "XDEV_EXT_MECH_STATS session=4660 state=ZOMBIE "
		   "last_err=-ECANCELED batches_done=1 batches_abort=2 "
		   "rejects=3 recycled=4 held=5 sequestered=6 timeouts=7 "
		   "inflight=8 native_publish=9 protocol_err=10 published=11 "
		   "submitted=12,13,14,15 completed=16,17,18,19");
	EXPECT_EQ(xdev_ext_mech_ctl_stats_line(line, 10, &s), -ENOSPC);

	EXPECT_STR(xdev_ext_mech_ctl_state_name(XDEV_EXT_MECH_SESSION_NONE), "NONE");
	EXPECT_STR(xdev_ext_mech_ctl_state_name(XDEV_EXT_MECH_SESSION_ACTIVE), "ACTIVE");
	EXPECT_STR(xdev_ext_mech_ctl_state_name(XDEV_EXT_MECH_SESSION_ERROR), "ERROR");
	EXPECT_STR(xdev_ext_mech_ctl_state_name(XDEV_EXT_MECH_SESSION_STOPPING),
		   "STOPPING");
	EXPECT_STR(xdev_ext_mech_ctl_state_name(XDEV_EXT_MECH_SESSION_STOPPED),
		   "STOPPED");
	EXPECT_STR(xdev_ext_mech_ctl_state_name(99), "UNKNOWN");

	EXPECT_STR(xdev_ext_mech_ctl_errname(0), "0");
	EXPECT_STR(xdev_ext_mech_ctl_errname(-EBUSY), "-EBUSY");
	EXPECT_STR(xdev_ext_mech_ctl_errname(-ENXIO), "-ENXIO");
	EXPECT_STR(xdev_ext_mech_ctl_errname(-ECANCELED), "-ECANCELED");
	EXPECT_STR(xdev_ext_mech_ctl_errname(-EOPNOTSUPP), "-EOPNOTSUPP");
	EXPECT_STR(xdev_ext_mech_ctl_errname(-ERANGE), "-ERANGE");
	EXPECT_STR(xdev_ext_mech_ctl_errname(-EPERM), "-EPERM");
	EXPECT_STR(xdev_ext_mech_ctl_errname(-ESHUTDOWN), "-ESHUTDOWN");
	EXPECT_STR(xdev_ext_mech_ctl_errname(-4000), "-4000");
	EXPECT_STR(xdev_ext_mech_ctl_errname(5), "5");

	/* Truncation never writes past the buffer and fails the line. */
	s = clean_nic_nvme();
	EXPECT_TRUE(xdev_ext_mech_ctl_report_nic_nvme(line, sizeof(line), &s, 64,
						 6));
	EXPECT_FALSE(xdev_ext_mech_ctl_report_nic_nvme(line, 20, &s, 64, 6));
	EXPECT_EQ(strlen(line), 19);
}

/* --quiet-wait: who may use it, when the one look suffices, its lines. */
static void test_quiet_wait(void)
{
	struct xdev_ext_mech_stats s = clean_nic_nvme();
	char line[160];

	/* Off: nothing to check, whatever the command. */
	EXPECT_EQ(xdev_ext_mech_ctl_quiet_check(false, false, 3, true), 0);
	/* On: a plain nic-nvme run only. */
	EXPECT_EQ(xdev_ext_mech_ctl_quiet_check(true, true, 0, false), 0);
	EXPECT_EQ(xdev_ext_mech_ctl_quiet_check(true, false, 0, false), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_quiet_check(true, true, 1, false), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_ctl_quiet_check(true, true, 0, true), -EINVAL);

	/* Every group ended, by the eventfd count and by STATS. */
	EXPECT_TRUE(xdev_ext_mech_ctl_quiet_done(64, 64, &s));
	EXPECT_TRUE(xdev_ext_mech_ctl_quiet_done(65, 64, &s));
	EXPECT_FALSE(xdev_ext_mech_ctl_quiet_done(63, 64, &s));
	EXPECT_FALSE(xdev_ext_mech_ctl_quiet_done(0, 64, &s));
	s.batches_done = 63;
	EXPECT_FALSE(xdev_ext_mech_ctl_quiet_done(64, 64, &s));
	s.batches_abort = 1;	/* an aborted batch ended too */
	EXPECT_TRUE(xdev_ext_mech_ctl_quiet_done(64, 64, &s));
	s = clean_nic_nvme();
	s.batches_done = 512;
	EXPECT_TRUE(xdev_ext_mech_ctl_quiet_done(512, 512, &s));
	EXPECT_FALSE(xdev_ext_mech_ctl_quiet_done(511, 512, &s));

	EXPECT_TRUE(xdev_ext_mech_ctl_quiet_line(line, sizeof(line), 4242, 7, 512));
	EXPECT_STR(line, "XDEV_EXT_MECH_QUIET_WAIT pid=4242 eventfd=7 "
		   "signal=SIGUSR1 groups=512");
	EXPECT_TRUE(xdev_ext_mech_ctl_quiet_wake_line(line, sizeof(line), true, 64,
						 false));
	EXPECT_STR(line, "XDEV_EXT_MECH_QUIET_WAKE by=signal eventfd_count=64 "
		   "fallback=0");
	EXPECT_TRUE(xdev_ext_mech_ctl_quiet_wake_line(line, sizeof(line), false, 3,
						 true));
	EXPECT_STR(line, "XDEV_EXT_MECH_QUIET_WAKE by=timeout eventfd_count=3 "
		   "fallback=1");
	EXPECT_FALSE(xdev_ext_mech_ctl_quiet_line(line, 16, 4242, 7, 512));
	EXPECT_EQ(strlen(line), 15);
}

int main(void)
{
	test_xsk_mode();
	test_layout();
	test_parse();
	test_set_value();
	test_nic_nvme();
	test_negative_arms();
	test_sources();
	test_stats_line();
	test_quiet_wait();

	if (failures) {
		fprintf(stderr, "FAIL: %u of %u checks\n", failures, checks);
		return 1;
	}
	printf("PASS: %u xdev_ext_mech_ctl checks\n", checks);
	return 0;
}
