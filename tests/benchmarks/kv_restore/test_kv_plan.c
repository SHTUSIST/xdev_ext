// SPDX-License-Identifier: GPL-2.0
/*
 * Host test of kv_plan.h, the restore arithmetic of the K-KV driver, and of
 * the kernel's own pure admission rules applied to the plan it produces:
 * CREATE layout (peer frame geometry, frames per batch), START with ordered
 * user frames on a PEER pool (host 2 destination, host 1 recycled staging
 * ring) and the XDOMAIN element budget.  Built with -I <kernel tree> of the
 * source view; nothing here opens a device.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "io_uring/xdev_ext_mech_step.h"
#include "io_uring/xdomain/xdev_ext_xdomain_early.h"
#include "kv_plan.h"
#include "kv_index.h"

static unsigned checks, failures;
#define EXPECT(c, why) do { checks++; if (!(c)) { failures++; \
	fprintf(stderr, "%s:%d: FAIL %s\n", __FILE__, __LINE__, why); } } while (0)
#define EXPECT_EQ(a, b, why) do { long long _a = (long long)(a), _b = (long long)(b); \
	checks++; if (_a != _b) { failures++; \
	fprintf(stderr, "%s:%d: FAIL %s: got %lld want %lld\n", __FILE__, __LINE__, why, _a, _b); } \
	} while (0)

#define KIB 1024ULL
#define GIB (1ULL << 30)

static const struct kv_window win = { .slba = 2048, .nlb = 40 * GIB / 512, .lba_bytes = 512 };
static const struct kv_geometry geo = { .group_bytes = 256 * KIB, .frame_bytes = 128 * KIB,
	.depth = 32, .window = 32, .early = true };

static struct kv_request req(uint64_t slba, uint64_t bytes, uint64_t ordinal)
{
	return (struct kv_request){ .object_slba = slba, .bytes = bytes, .ordinal = ordinal };
}

static void test_mapping(void)
{
	/* Qwen3-8B BF16, 16K tokens, object 6 GiB into the window. */
	uint64_t slba = 2048 + 6 * GIB / 512, bytes = 16384ULL * 147456, blocks = 256 * KIB / 512;
	struct kv_request r = req(slba, bytes, 2);
	struct kv_plan p;

	EXPECT_EQ(kv_plan_make(&win, &geo, &r, &p), 0, "valid restore plans");
	EXPECT_EQ(p.groups, bytes / (256 * KIB), "whole groups");
	EXPECT_EQ(p.slots, win.nlb / blocks, "window slots");
	EXPECT_EQ(p.slot0, (slba - win.slba) / blocks, "first slot is the object's");
	EXPECT_EQ(p.first_seq, 2 * p.slots + p.slot0, "keys of ordinal 2");
	for (uint64_t i = 0; i < p.groups; i += p.groups / 7 + 1) {
		uint64_t key = p.first_seq + i;
		EXPECT_EQ(win.slba + (key % p.slots) * blocks, slba + i * blocks,
			  "key i reads the object's group i");
		EXPECT_EQ(kv_plan_group_slba(&p, &win, i), slba + i * blocks, "group LBA helper");
	}
	EXPECT_EQ(kv_plan_group_slba(&p, &win, p.groups), UINT64_MAX, "no group past the plan");
	EXPECT_EQ(p.frames_per_group, 2, "two 128 KiB frames per 256 KiB group");
	EXPECT_EQ(p.host2_frames, p.groups * 2, "one destination frame per payload frame");
	EXPECT_EQ(p.host1_pool_frames, 32 * 2, "host 1 ring holds depth groups");
	EXPECT_EQ(p.host1_recycle_frames, 32 * 2, "recycled ring lends min(groups, depth) groups");
}

static void test_indices(void)
{
	struct kv_request r = req(2048, 8 * 163840, 1); /* 8 tokens of Qwen3-14B: 5 groups */
	struct kv_plan p;
	uint32_t idx[64];

	r.dst_frame0 = 3;
	EXPECT_EQ(kv_plan_make(&win, &geo, &r, &p), 0, "small restore plans");
	EXPECT_EQ(p.groups, 5, "five groups");
	EXPECT_EQ(p.host1_recycle_frames, 5 * 2, "fewer groups than depth lend fewer templates");
	EXPECT_EQ(p.host2_pool_frames, 3 + 10, "exact pool by default");
	kv_plan_host2_indices(&p, idx);
	for (uint32_t i = 0; i < 10; i++)
		EXPECT_EQ(idx[i], 3 + i, "destination frames are contiguous from dst_frame0");
	kv_plan_host1_indices(&p, idx);
	for (uint32_t i = 0; i < 10; i++)
		EXPECT_EQ(idx[i], i, "host 1 templates are the ring's first frames");
	r.pool_frames = 12;
	EXPECT_EQ(kv_plan_make(&win, &geo, &r, &p), -ENOSPC, "destination pool too small");
}

static void test_refusals(void)
{
	struct kv_plan p;
	struct kv_request ok = req(2048, 4096ULL * 163840, 1);
	struct kv_geometry g;
	struct kv_request r;
	struct kv_window w;

#define BAD_GEO(field, value, err) do { g = geo; g.field = value; \
	EXPECT_EQ(kv_plan_make(&win, &g, &ok, &p), err, #field " = " #value); } while (0)
	BAD_GEO(group_bytes, 192 * KIB, -EINVAL);  /* not whole frames */
	BAD_GEO(frame_bytes, 2 * KIB, -EINVAL);
	BAD_GEO(frame_bytes, 4096 * KIB, -EINVAL);
	BAD_GEO(group_bytes, 512 * KIB, -E2BIG);   /* 128 NHI elements */
	BAD_GEO(depth, 65, -EINVAL);
	BAD_GEO(window, 33, -EINVAL);
	BAD_GEO(window, 0, -EINVAL);
	g = geo; g.frame_bytes = 4 * KIB; g.group_bytes = 132 * KIB;
	EXPECT_EQ(kv_plan_make(&win, &g, &ok, &p), -E2BIG, "33 frames per batch");
	g = geo; g.frame_bytes = 96 * KIB; g.group_bytes = 192 * KIB;
	EXPECT_EQ(kv_plan_make(&win, &g, &ok, &p), -EINVAL, "frame not a power of two");
	g = geo; g.depth = 8; g.window = 16;
	EXPECT_EQ(kv_plan_make(&win, &g, &ok, &p), -EINVAL, "window above depth");
#undef BAD_GEO
	r = ok; r.bytes = 4095ULL * 163840;
	EXPECT_EQ(kv_plan_make(&win, &geo, &r, &p), -EINVAL, "bytes not whole groups");
	r = ok; r.ordinal = 0;
	EXPECT_EQ(kv_plan_make(&win, &geo, &r, &p), -EINVAL, "ordinal 0");
	r = ok; r.object_slba = 2049;
	EXPECT_EQ(kv_plan_make(&win, &geo, &r, &p), -EINVAL, "object off a slot boundary");
	r = ok; r.object_slba = 1024;
	EXPECT_EQ(kv_plan_make(&win, &geo, &r, &p), -ERANGE, "object before the window");
	r = ok; r.object_slba = 2048 + win.nlb - 512;
	EXPECT_EQ(kv_plan_make(&win, &geo, &r, &p), -ERANGE, "object runs past the window");
	r = ok; r.bytes = 32768ULL * 163840;
	g = geo; g.frame_bytes = 64 * KIB;
	EXPECT_EQ(kv_plan_make(&win, &g, &r, &p), -E2BIG, "81920 frame indices exceed one START");
	EXPECT_EQ(kv_plan_make(&win, &geo, &r, &p), 0, "128 KiB frames fit 32K tokens");
	r = ok; r.ordinal = UINT64_MAX / 2;
	EXPECT_EQ(kv_plan_make(&win, &geo, &r, &p), -EOVERFLOW, "keys overflow");
	w = win; w.lba_bytes = 520;
	EXPECT_EQ(kv_plan_make(&w, &geo, &ok, &p), -EINVAL, "LBA not a power of two");
	/* Window of exactly 8 slots: slots 3..7 fit, a sixth group does not. */
	w = (struct kv_window){ .slba = 0, .nlb = 8 * 512, .lba_bytes = 512 };
	r = req(3 * 512, 5 * 256 * KIB, 1);
	EXPECT_EQ(kv_plan_make(&w, &geo, &r, &p), 0, "last group on the last slot");
	EXPECT_EQ(kv_plan_group_slba(&p, &w, 4), 7 * 512, "the last group reads the last slot");
	r.bytes += 256 * KIB;
	EXPECT_EQ(kv_plan_make(&w, &geo, &r, &p), -ERANGE, "one group past the last slot");
	w.nlb = 512 - 1;
	r = req(0, 256 * KIB, 1);
	EXPECT_EQ(kv_plan_make(&w, &geo, &r, &p), -ERANGE, "a window shorter than one group");
}

/* What xdev_ext_session_start_frames() submits for a kv_start (libxdev_ext). */
static uint32_t lent[1];
static void library_start(const struct kv_start *k, struct xdev_ext_mech_start *st)
{
	*st = (struct xdev_ext_mech_start){
		.nr_batches = k->nr_batches, .first_seq = k->first_seq ? k->first_seq : 1,
		.flags = (k->recycle ? XDEV_EXT_MECH_START_F_RECYCLE : 0) |
			 XDEV_EXT_MECH_START_F_USER_FRAMES | XDEV_EXT_MECH_START_F_ORDERED_FRAMES,
		.nr_user_frames = k->nr_frames, .user_frames = (uintptr_t)lent,
	};
}

/* The kernel's own CREATE/START/XDOMAIN rules accept what the plan builds. */
static void test_kernel_rules(void)
{
	struct kv_request r = req(2048, 32768ULL * 163840, 1);
	struct xdev_ext_mech_layout l;
	struct xdev_ext_mech_start st;
	struct kv_start ks;
	struct kv_plan p;
	__u32 count = 0;

	EXPECT_EQ(kv_plan_make(&win, &geo, &r, &p), 0, "32K-token plan");
	kv_plan_layout(&geo, &l);
	EXPECT_EQ(xdev_ext_mech_peer_layout_check(&l), 0, "PEER frame geometry admitted");
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), (int)p.frames_per_group, "frames per batch");

	kv_plan_host2_start(&p, &ks);
	EXPECT(!ks.recycle, "host 2 lends ordered frames without recycling");
	library_start(&ks, &st);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, XDEV_EXT_MECH_POOL_PEER, false,
			p.frames_per_group, (__u32)p.host2_pool_frames), 0,
		  "host 2 START admitted on its exact pool");
	EXPECT_EQ(xdev_ext_mech_start_check(&st, XDEV_EXT_MECH_POOL_PEER, false,
			p.frames_per_group, (__u32)p.host2_pool_frames - 1), -ENOSPC,
		  "negative control: one frame short");

	kv_plan_host1_start(&p, &ks);
	EXPECT(ks.recycle, "host 1 recycles its staging ring");
	library_start(&ks, &st);
	EXPECT_EQ(st.nr_user_frames, p.host1_recycle_frames, "ring templates");
	EXPECT_EQ(xdev_ext_mech_start_check(&st, XDEV_EXT_MECH_POOL_PEER, false,
			p.frames_per_group, p.host1_pool_frames), 0, "host 1 START admitted");
	st.nr_user_frames += 1;
	EXPECT(xdev_ext_mech_start_check(&st, XDEV_EXT_MECH_POOL_PEER, false,
			p.frames_per_group, p.host1_pool_frames) != 0,
	       "negative control: partial template refused");

	EXPECT_EQ(xdev_ext_xd_early_shape(geo.group_bytes, geo.frame_bytes, &count), 0,
		  "EARLY shape of the group");
	EXPECT_EQ(count, geo.group_bytes / 4096, "64 NHI elements per group");
	EXPECT(xdev_ext_xd_budget_ok(geo.depth, count, XDEV_EXT_XD_DATA_RING),
	       "XDOMAIN depth/element budget");
	EXPECT_EQ(kv_plan_xdomain_arg1(&geo), (__u64)geo.window << XDEV_EXT_XDOMAIN_WINDOW_SHIFT,
		  "arg1 = channel 0 | window << 32");
}

/*
 * CE VMM destination: host 2 receives into a recycled ring of host frames
 * (IOU_UMEM) and the copy engine places each group, so its START lends the
 * ring, not the destination, and the START frame-index limit does not bound
 * the restore; the destination extent and its pool check are unchanged.
 */
static void test_host2_ring(void)
{
	const struct kv_geometry g = { .group_bytes = 128 * KIB, .frame_bytes = 4096,
		.depth = 32, .window = 32, .early = true };
	struct kv_request r = req(2048, 32768ULL * 163840, 1);
	struct xdev_ext_mech_layout l;
	struct xdev_ext_mech_start st;
	struct kv_start ks;
	struct kv_plan p;
	uint32_t idx[32 * 32 + 1];

	EXPECT_EQ(kv_plan_make(&win, &g, &r, &p), -E2BIG, "PEER: 1.3M destination frames refused");
	r.host2_ring = true;
	EXPECT_EQ(kv_plan_make(&win, &g, &r, &p), 0, "ring: 5 GiB restore planned");
	EXPECT(p.host2_ring, "plan records the ring");
	EXPECT_EQ(p.groups, 40960, "groups");
	EXPECT_EQ(p.host2_frames, 40960ULL * 32, "destination extent in frames");
	EXPECT_EQ(p.host2_start_frames, 32 * 32, "START lends depth groups of frames");
	kv_plan_host2_start(&p, &ks);
	EXPECT(ks.recycle, "host 2 recycles its ring");
	EXPECT_EQ(ks.nr_frames, 32 * 32, "ring templates");
	EXPECT_EQ(ks.first_seq, p.first_seq, "keys unchanged");
	EXPECT_EQ(ks.nr_batches, p.groups, "one batch per group");
	idx[32 * 32] = 0xdeadbeef;
	kv_plan_host2_indices(&p, idx);
	EXPECT(idx[0] == 0 && idx[32 * 32 - 1] == 32 * 32 - 1, "ring indices from frame 0");
	EXPECT_EQ(idx[32 * 32], 0xdeadbeef, "no index past the ring");
	kv_plan_layout(&g, &l);
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), 32, "32 host frames per batch");
	library_start(&ks, &st);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, XDEV_EXT_MECH_POOL_IOU_UMEM, false, 32, 32 * 32), 0,
		  "ring START admitted on a UMEM of depth groups");
	r.bytes = 16ULL * 163840;	/* 20 groups < depth: the ring shrinks to the restore */
	EXPECT_EQ(kv_plan_make(&win, &g, &r, &p), 0, "short ring restore");
	EXPECT_EQ(p.host2_start_frames, 20 * 32, "ring of min(groups, depth)");
	r.pool_frames = 20 * 32 - 1;
	EXPECT_EQ(kv_plan_make(&win, &g, &r, &p), -ENOSPC, "destination pool still checked");
	r.pool_frames = 0;
	r.dst_frame0 = 7;
	EXPECT_EQ(kv_plan_make(&win, &g, &r, &p), 0, "destination offset");
	EXPECT_EQ(p.host2_dst_frame0, 7, "destination offset kept");
	kv_plan_host2_indices(&p, idx);
	EXPECT_EQ(idx[0], 0, "ring indices do not follow the destination offset");
	r.host2_ring = false;
	EXPECT_EQ(kv_plan_make(&win, &g, &r, &p), 0, "PEER short restore");
	EXPECT_EQ(p.host2_start_frames, 20 * 32, "PEER START lends the destination frames");
	kv_plan_host2_indices(&p, idx);
	EXPECT_EQ(idx[0], 7, "PEER indices start at the destination");
}

static void test_pattern(void)
{
	uint8_t a[4096], b[4096];
	uint64_t bad = 0;

	EXPECT_EQ(kv_mix64(0), 0xE220A8397B1DCDAFULL, "SplitMix64 reference output");
	kv_pattern_block(7, 0, a);
	kv_pattern_block(7, 1, b);
	EXPECT(memcmp(a, b, sizeof(a)), "distinct blocks differ");
	EXPECT_EQ(kv_pattern_check(7, 0, a, sizeof(a), &bad), 0, "block 0 matches");
	EXPECT_EQ(kv_pattern_check(7, 4096, b, sizeof(b), &bad), 0, "block 1 matches at its offset");
	b[4095] ^= 1;
	EXPECT_EQ(kv_pattern_check(7, 4096, b, sizeof(b), &bad), -EIO, "a flipped byte is found");
	EXPECT_EQ(bad, 4096 + 4095, "first bad byte offset");
	EXPECT_EQ(kv_pattern_check(7, 100, a + 100, 4096 - 100, &bad), 0, "unaligned start");
}

/* vLLM block order: page (b, l) at (b * layers + l) * page_bytes. */
static void test_block_layout(void)
{
	const struct kv_block_layout q8 = { .block_size = 16, .layers = 36, .heads = 8,
		.state_bytes = 512 };
	const struct kv_block_layout big = { .block_size = 64, .layers = 36, .heads = 8,
		.state_bytes = 512 };
	struct kv_block_layout bad = q8;
	struct kv_page_piece pc[4];
	uint64_t off = 0;

	EXPECT_EQ(kv_page_bytes(&q8), 65536, "H * N * C");
	EXPECT_EQ(kv_block_bytes(&q8), 36 * 65536ULL, "layers pages per block");
	EXPECT_EQ(kv_block_layout_check(&q8, 128 * KIB), 0, "64 KiB pages in 128 KiB groups");
	EXPECT_EQ(kv_block_layout_check(&big, 128 * KIB), 0, "half a 256 KiB page per group");
	bad.heads = 5;
	EXPECT_EQ(kv_block_layout_check(&bad, 128 * KIB), -EINVAL, "40 KiB pages split by groups");
	bad = q8;
	bad.layers = 0;
	EXPECT_EQ(kv_block_layout_check(&bad, 128 * KIB), -EINVAL, "no layers");
	bad = (struct kv_block_layout){ .block_size = 16, .layers = 3, .heads = 1, .state_bytes = 512 };
	EXPECT_EQ(kv_block_layout_check(&bad, 128 * KIB), -EINVAL, "24 KiB blocks not tiled");
	EXPECT_EQ(kv_page_offset(&q8, 3, 2, &off), 0, "page offset");
	EXPECT_EQ(off, (3 * 36 + 2) * 65536ULL, "block 3 layer 2");
	EXPECT_EQ(kv_page_offset(&q8, 0, 36, &off), -ERANGE, "layer past the model");
	EXPECT_EQ(kv_group_pages(&q8, 18, 128 * KIB, pc, 4), 2, "two pages per group");
	EXPECT_EQ(pc[0].block, 1, "group 18 starts block 1");
	EXPECT_EQ(pc[1].layer, 1, "second page is layer 1");
	EXPECT_EQ(pc[1].group_off, 65536, "second page at 64 KiB");
	EXPECT_EQ(kv_group_pages(&big, 3, 128 * KIB, pc, 4), 1, "one piece");
	EXPECT_EQ(pc[0].layer, 1, "group 3 is layer 1");
	EXPECT_EQ(pc[0].page_off, 128 * KIB, "second half of the page");
	EXPECT_EQ(kv_group_pages(&q8, 0, 128 * KIB, pc, 1), -ENOSPC, "too few pieces");
}

static void test_index(void)
{
	const char *h = "abababababababababababababababababababababababababababababababab";
	char line[512], text[2048];
	struct kv_index_entry e;
	struct kv_index ix = { 0 };
	uint64_t slba = 0, bytes = 0;
	FILE *f;

	snprintf(line, sizeof(line), "prefix %s object=conv-a slba=2048 offset=2359296 "
		 "bytes=603979776 tokens=4096 fnv1a=0x0000000000001234\n", h);
	EXPECT_EQ(kv_index_parse_line(line, &e), 0, "entry parses");
	EXPECT(!strcmp(e.hash, h) && !strcmp(e.object, "conv-a"), "hash and object");
	EXPECT_EQ(e.slba, 2048, "slba");
	EXPECT_EQ(e.offset, 2359296, "offset");
	EXPECT_EQ(e.tokens, 4096, "tokens");
	EXPECT(e.has_fnv1a && e.fnv1a == 0x1234, "fnv1a");
	EXPECT_EQ(kv_index_resolve(&e, 512, &slba, &bytes), 0, "resolve");
	EXPECT_EQ(slba, 2048 + 2359296 / 512, "restore starts at the offset");
	EXPECT_EQ(bytes, 603979776, "restore bytes");
	EXPECT_EQ(kv_index_resolve(&e, 4096 * 1024, &slba, &bytes), -EINVAL, "offset not whole LBAs");
	EXPECT_EQ(kv_index_parse_line("# note\n", &e), 1, "comment skipped");
	EXPECT_EQ(kv_index_parse_line("   \n", &e), 1, "blank skipped");
	{
		static const char *const bad[] = {
			"prefix xyz object=a slba=1 offset=0 bytes=1 tokens=1",
			"suffix abababababababababababababababababababababababababababababababab object=a slba=1 offset=0 bytes=1 tokens=1",
			"prefix abababababababababababababababababababababababababababababababab object=a slba=1 offset=0 bytes=1",
			"prefix abababababababababababababababababababababababababababababababab object=a slba=x offset=0 bytes=1 tokens=1",
			"prefix abababababababababababababababababababababababababababababababab object=a slba=1 offset=0 bytes=1 tokens=1 color=red",
			"prefix abababababababababababababababababababababababababababababababab object=a slba=1 slba=1 offset=0 bytes=1 tokens=1",
			"prefix abababababababababababababababababababababababababababababababab object=a slba=1 offset=0 bytes=1 tokens=0",
			"prefix abababababababababababababababababababababababababababababababab object=a slba=-1 offset=0 bytes=1 tokens=1",
			"prefix ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB object=a slba=1 offset=0 bytes=1 tokens=1",
		};
		for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
			EXPECT_EQ(kv_index_parse_line(bad[i], &e), -EINVAL, bad[i]);
	}
	snprintf(text, sizeof(text), "xdev-kv-index 1\n# c\n%s"
		 "prefix cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd object=b "
		 "slba=4096 offset=0 bytes=10 tokens=16\n", line);
	f = fmemopen(text, strlen(text), "r");
	EXPECT_EQ(kv_index_load(f, &ix), 0, "file loads");
	fclose(f);
	EXPECT_EQ(ix.n, 2, "two entries");
	EXPECT(kv_index_find(&ix, h) && kv_index_find(&ix, h)->slba == 2048, "find first");
	EXPECT(!kv_index_find(&ix, "00"), "unknown hash");
	kv_index_free(&ix);
	f = fmemopen(line, strlen(line), "r");
	EXPECT_EQ(kv_index_load(f, &ix), -EINVAL, "header required");
	fclose(f);
	snprintf(text, sizeof(text), "xdev-kv-index 1\n%s%s", line, line);
	f = fmemopen(text, strlen(text), "r");
	EXPECT_EQ(kv_index_load(f, &ix), -EEXIST, "repeated prefix refused");
	fclose(f);
	EXPECT_EQ(ix.n, 0, "nothing kept after a refusal");
}

int main(void)
{
	test_mapping();
	test_indices();
	test_refusals();
	test_kernel_rules();
	test_host2_ring();
	test_pattern();
	test_block_layout();
	test_index();
	printf("kv_plan: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
