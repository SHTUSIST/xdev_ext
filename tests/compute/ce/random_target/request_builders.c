// SPDX-License-Identifier: GPL-2.0
/* Actual paired callbacks. Request/map/info/scratch transport only is host C. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "vmlinux.h"
#include "paired-callback.bpf.c"
/* Symbol qualification only: preserve the original frozen driver/wants. */
#define ce_plan_build request_ce_build
#define ce_plan_complete request_ce_complete
#define blocktable_build request_nvme_build
#define blocktable_complete request_nvme_complete

enum { PAYLOAD = 1048576, FRAME = 32768, FRAMES = 32, DEPTH = 2,
	WINDOW = 4194304, CAP = 64, HEAD = 64 };
/* Exact shared-map value and key types from the actual paired object. */
static struct nvme_ce_request_value requests[4];
static struct xdev_ext_ce_mech_info ce_info[DEPTH];
static struct xdev_ext_nvme_mech_info nvme_info;
static struct xdev_ext_ce_copy_desc ce_scratch[DEPTH][CAP];
static unsigned char nvme_scratch[64];
static struct xdev_ext_ce_mech_cqe ce_cqe;
static struct xdev_ext_nvme_mech_cqe nvme_cqe;
static unsigned batch_slot, scratch_cap = CAP;
static int ce_call, missing, no_info, no_desc, no_cqe;
static unsigned checks, failures;
static unsigned map_lookups;

void *bpf_map_lookup_elem(const void *map, const void *key)
{
	const struct nvme_ce_request_key *k = key;
	map_lookups++;
	if (map != &request_map || missing || k->session_id != 42 ||
	    k->request_key < 400 || k->request_key > 403)
		return NULL;
	return &requests[k->request_key - 400];
}
__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx, size_t n)
{
	(void)ctx;
	if (no_info)
		return NULL;
	if (ce_call)
		return n == sizeof(ce_info[0]) ? (void *)&ce_info[batch_slot] : NULL;
	return n == sizeof(nvme_info) ? (void *)&nvme_info : NULL;
}
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 slot, size_t n)
{
	(void)ctx;
	if (no_desc)
		return NULL;
	if (ce_call)
		return slot < scratch_cap && n == sizeof(ce_scratch[0][0]) ?
			(void *)&ce_scratch[batch_slot][slot] : NULL;
	return !slot && n == sizeof(nvme_scratch) ? nvme_scratch : NULL;
}
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx, __u32 slot, size_t n)
{
	(void)ctx;
	if (no_cqe || slot)
		return NULL;
	if (ce_call)
		return n == sizeof(ce_cqe) ? (void *)&ce_cqe : NULL;
	return n == sizeof(nvme_cqe) ? (void *)&nvme_cqe : NULL;
}
static void expect(const char *label, long long got, long long want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL %s: got %lld expected %lld\n", label, got, want);
		failures++;
	}
}
static struct xdev_ext_mech_ctx initialize(void)
{
	struct xdev_ext_mech_ctx c = { .session_id = 42, .nr_frames = FRAMES,
		.desc_cap = CAP, .batch_id = 71 };
	unsigned i, j;
	c.base.src_offset = 400;
	c.base.request_id = 71; /* actual batch id, neither key nor slot */
	c.base.length = PAYLOAD;
	c.base.direction = XDEV_EXT_MP_DIR_FROM_DEVICE;
	memset(ce_info, 0, sizeof(ce_info));
	memset(&nvme_info, 0, sizeof(nvme_info));
	memset(ce_scratch, 0, sizeof(ce_scratch));
	memset(nvme_scratch, 0, sizeof(nvme_scratch));
	memset(&ce_cqe, 0, sizeof(ce_cqe));
	memset(&nvme_cqe, 0, sizeof(nvme_cqe));
	missing = no_info = no_desc = no_cqe = ce_call = 0;
	map_lookups = 0;
	batch_slot = 0;
	scratch_cap = CAP;
	requests[0] = (struct nvme_ce_request_value){ 0, 1, PAYLOAD, 0 };
	requests[1] = (struct nvme_ce_request_value){ 2097152, 1048577, PAYLOAD, 0 };
	requests[2] = (struct nvme_ce_request_value){ 1048576, 2097153, PAYLOAD, 0 };
	requests[3] = (struct nvme_ce_request_value){ 2097152, 1, PAYLOAD, 0 };
	nvme_info.l.group_bytes = PAYLOAD;
	nvme_info.lba_shift = 9;
	nvme_info.max_nlb = 2048;
	nvme_info.window_slba = 4096;
	nvme_info.window_nlb = 16384;
	nvme_info.capacity_lbas = 32768;
	for (i = 0; i < DEPTH; i++) {
		ce_info[i].l = (struct xdev_ext_mech_layout){
			.frame_size = 65536, .hdr_room = HEAD,
			.seg_len = FRAME, .group_bytes = PAYLOAD };
		ce_info[i].gpu_window_len = WINDOW;
		ce_info[i].gpu_seg_size = 65536;
		ce_info[i].max_entry_len = 65536;
		ce_info[i].nr_frames = FRAMES;
		ce_info[i].window_slot = i;
		ce_info[i].window_depth = DEPTH;
		ce_info[i].lease_generation = 71 + i;
		for (j = 0; j < FRAMES; j++)
			ce_info[i].f[j] = (struct xdev_ext_mech_frame_info){
				.umem_addr = (i * FRAMES + j) * 65536ULL,
				.data_off = HEAD, .data_len = FRAME };
	}
	return c;
}
static int nvme_build(struct xdev_ext_mech_ctx *c)
{
	ce_call = 0;
	memset(nvme_scratch, 0, sizeof(nvme_scratch));
	return blocktable_build(NULL, c);
}
static int ce_build(struct xdev_ext_mech_ctx *c)
{
	ce_call = 1;
	memset(ce_scratch[batch_slot], 0, sizeof(ce_scratch[batch_slot]));
	return ce_plan_build(NULL, c);
}
static void sqe(unsigned opcode, unsigned lba, unsigned nlb_minus_one)
{
	unsigned char want[64] = {0};
	want[0] = opcode;
	want[40] = lba & 255;
	want[41] = (lba >> 8) & 255;
	want[42] = (lba >> 16) & 255;
	want[48] = nlb_minus_one & 255;
	want[49] = (nlb_minus_one >> 8) & 255;
	expect("entire literal SQE bytes", memcmp(nvme_scratch, want, 64), 0);
}
static void controls(void)
{
	struct xdev_ext_mech_ctx c = initialize();
	struct xdev_ext_ce_copy_desc d = {0};
	static const unsigned keys[] = {401, 400, 403, 402};
	static const unsigned lbas[] = {8192, 4096, 8192, 6144};
	unsigned i;
	for (i = 0; i < 4; i++) {
		c.base.src_offset = keys[i];
		expect("old random/repeat/out-of-order READ callback", nvme_build(&c), 1);
		sqe(2, lbas[i], 2047);
	}
	c = initialize();
	/* Same frozen aligned wants remain valid when a future paired callback
	 * consumes these held records. Only target-cohort input uses offset1. */
	requests[0].gpu_byte_offset = 0;
	requests[1].gpu_byte_offset = PAYLOAD;
	for (batch_slot = 0; batch_slot < DEPTH; batch_slot++) {
		c.base.src_offset = 400 + batch_slot;
		c.batch_id = 71 + batch_slot;
		c.base.request_id = c.batch_id;
		c.base.direction = XDEV_EXT_MP_DIR_TO_DEVICE;
		expect("old CE aligned depth2 slot callback", ce_build(&c), 1);
		for (i = 0; i < FRAMES; i++) {
			d = (struct xdev_ext_ce_copy_desc){ .frame_pos = i,
				.frame_off = HEAD, .gpu_off = batch_slot * (uint64_t)PAYLOAD + i * FRAME,
				.len = FRAME, .flags = i == 31 ? 1 : 0 };
			expect("old full aligned CE descriptor", memcmp(&ce_scratch[batch_slot][i], &d, sizeof(d)), 0);
		}
		expect("old CE stops after32", ce_scratch[batch_slot][32].len, 0);
	}
	memset(nvme_scratch, 0, 64);
	expect("pure WRITE helper real stage direction", xdev_ext_mp_nvme_rw(nvme_scratch, 1, 8192, PAYLOAD, 9), 0);
	sqe(1, 8192, 2047);
	memset(nvme_scratch, 0, 64);
	expect("shift31 maximum legal aligned u32 length", xdev_ext_mp_nvme_rw(nvme_scratch, 2, 4096, 2147483648U, 31), 0);
	sqe(2, 4096, 0);
	expect("shift8 rejected", xdev_ext_mp_nvme_rw(nvme_scratch, 2, 0, 512, 8), -EINVAL);
	expect("shift32 rejected", xdev_ext_mp_nvme_rw(nvme_scratch, 2, 0, 512, 32), -EINVAL);
	expect("zero bytes rejected", xdev_ext_mp_nvme_rw(nvme_scratch, 2, 0, 0, 9), -EINVAL);
	expect("unaligned bytes rejected", xdev_ext_mp_nvme_rw(nvme_scratch, 2, 0, 513, 9), -EINVAL);
	expect("encoded maximum65536 NLB", xdev_ext_mp_nvme_rw(nvme_scratch, 2, 0, 33554432, 9), 0);
	expect("encoded maximum+1 NLB", xdev_ext_mp_nvme_rw(nvme_scratch, 2, 0, 33554944, 9), -EMSGSIZE);
	expect("invalid direction", xdev_ext_mp_nvme_rw(nvme_scratch, 0, 0, 512, 9), -EINVAL);
	expect("CE one final legacy frame", xdev_ext_mp_ce_entry(&d, 31, 32, 64, 32768, 1015808, WINDOW, 65536, 65536), 0);
	expect("legacy completion point", d.flags, 1);
	expect("CE zero length", xdev_ext_mp_ce_entry(&d, 0, 1, 64, 0, 0, WINDOW, 65536, 65536), -EINVAL);
	expect("CE segment crossing", xdev_ext_mp_ce_entry(&d, 1, 32, 64, 32768, 32769, WINDOW, 65536, 65536), -EXDEV);
	expect("CE per-entry max", xdev_ext_mp_ce_entry(&d, 0, 32, 64, 32768, 0, WINDOW, 65536, 16384), -EMSGSIZE);
	expect("CE exact window end", xdev_ext_mp_ce_entry(&d, 31, 32, 64, 1, WINDOW - 1, WINDOW, 65536, 65536), 0);
	expect("CE window overflow", xdev_ext_mp_ce_entry(&d, 0, 32, 64, 2, UINT64_MAX, UINT64_MAX, 0, 0), -ERANGE);
	c = initialize();
#define BAD_NVME(label, change) do { c = initialize(); change; expect(label, nvme_build(&c), 2); } while (0)
	BAD_NVME("missing record", missing = 1);
	BAD_NVME("foreign session", c.session_id = 43);
	BAD_NVME("unknown key", c.base.src_offset = 404);
	BAD_NVME("source alignment", requests[0].nvme_byte_offset = 1);
	BAD_NVME("source overflow", requests[0].nvme_byte_offset = UINT64_MAX - 511);
	BAD_NVME("length mismatch", requests[0].byte_length = 512);
	BAD_NVME("reserved record", requests[0].reserved = 1);
	BAD_NVME("group mismatch", nvme_info.l.group_bytes = 512);
	BAD_NVME("source shift low", nvme_info.lba_shift = 8);
	BAD_NVME("source shift high", nvme_info.lba_shift = 32);
	BAD_NVME("namespace window wrap", nvme_info.window_slba = UINT64_MAX - 1);
	BAD_NVME("namespace window length overflow", nvme_info.window_nlb = UINT64_MAX);
	BAD_NVME("empty namespace window", nvme_info.window_nlb = 0);
	BAD_NVME("namespace capacity", nvme_info.capacity_lbas = 4096);
	BAD_NVME("queue max NLB", nvme_info.max_nlb = 2047);
	BAD_NVME("missing info", no_info = 1);
	BAD_NVME("missing scratch", no_desc = 1);
	c = initialize(); requests[0].nvme_byte_offset = 0;
	requests[0].byte_length = 2147483648U;
	c.base.length = 2147483648ULL; nvme_info.l.group_bytes = 2147483648U;
	nvme_info.lba_shift = 31;
	expect("actual callback shift31 legal one large LBA", nvme_build(&c), 1);
	sqe(2, 4096, 0);
	c = initialize(); requests[0].nvme_byte_offset = 7340032;
	expect("source exact authorized window end", nvme_build(&c), 1); sqe(2, 18432, 2047);
	requests[0].nvme_byte_offset = 7340544;
	expect("source one LBA beyond end", nvme_build(&c), 2);
	c = initialize(); ce_call = 1;
	expect("CE success completion", ce_plan_complete(NULL, &c), 0);
	ce_cqe.outcome = 1; expect("CE pre-submit retry", ce_plan_complete(NULL, &c), 2);
	ce_cqe.outcome = 2; expect("CE UNKNOWN cannot become success", ce_plan_complete(NULL, &c), 3);
	ce_call = 0; expect("NVMe worker NEXT", blocktable_complete(NULL, &c), 0);
	c.callsite = 3; expect("NVMe uring DONE", blocktable_complete(NULL, &c), 1);
	nvme_cqe.err = -EIO; expect("NVMe error ABORT", blocktable_complete(NULL, &c), 3);
	c = initialize(); no_cqe = 1;
	expect("NVMe missing CQE", blocktable_complete(NULL, &c), 3);
	ce_call = 1; expect("CE missing CQE", ce_plan_complete(NULL, &c), 3);
	c = initialize(); no_info = 1; expect("CE missing info", ce_build(&c), 2);
	c = initialize(); no_desc = 1; expect("CE missing scratch", ce_build(&c), 2);
}

/* Hand-derived 64KiB pattern: each pair of 32KiB host frames yields
 * 32768,32767,1 bytes. These are absolute offsets relative to the first
 * 64KiB pair; the last piece is still frame1, not descriptor position2. */
static void plan48(unsigned slot, uint64_t target)
{
	unsigned pair, part, completions = 0;
	static const unsigned lens[3] = {32768, 32767, 1};
	static const unsigned frame_delta[3] = {0, 1, 1};
	static const unsigned host[3] = {64, 64, 32831};
	static const unsigned gpu_delta[3] = {0, 32768, 65535};
	for (pair = 0; pair < 16; pair++) for (part = 0; part < 3; part++) {
		unsigned n = pair * 3 + part;
		const struct xdev_ext_ce_copy_desc *d = &ce_scratch[slot][n];
		expect("48piece actual original frame identity", d->frame_pos, pair * 2 + frame_delta[part]);
		expect("48piece actual original frame offset", d->frame_off, host[part]);
		expect("48piece literal length", d->len, lens[part]);
		expect("48piece literal contiguous GPU offset", d->gpu_off, target + pair * 65536 + gpu_delta[part]);
		expect("only final actual piece completes", d->flags, n == 47 ? 1 : 0);
		completions += !!(d->flags & 1);
	}
	expect("exact48 no trailing entry", ce_scratch[slot][48].len, 0);
	expect("exactly one final completion", completions, 1);
}
/* Coverage oracle: literal piece count is independent of splitter output.
 * Walking emitted intervals checks no dropped/repeated/gapped host or GPU
 * byte; this is not a second splitting algorithm. */
static void coverage(unsigned want, unsigned seg, unsigned max, uint64_t target)
{
	unsigned i, frame = 0, off = HEAD, total = 0, points = 0;
	uint64_t gpu = target;
	for (i = 0; i < want; i++) {
		const struct xdev_ext_ce_copy_desc *d = &ce_scratch[0][i];
		expect("coverage frame", d->frame_pos, frame);
		expect("coverage host offset", d->frame_off, off);
		expect("coverage contiguous GPU byte", d->gpu_off, gpu);
		expect("coverage nonempty bounded host span", d->len && d->len <= HEAD + FRAME - off, 1);
		expect("coverage segment bound", !seg || (d->len && d->gpu_off / seg == (d->gpu_off + d->len - 1) / seg), 1);
		expect("coverage per-entry bound", !max || d->len <= max, 1);
		expect("coverage last piece completion only", d->flags, i + 1 == want ? 1 : 0);
		points += !!(d->flags & 1);
		/* An incorrect output must produce an assertion1, not unsafe oracle
		 * arithmetic or memory access. No output controls test input. */
		if (!d->len || off > HEAD + FRAME || d->len > HEAD + FRAME - off)
			continue;
		off += d->len; total += d->len; gpu += d->len;
		if (off == HEAD + FRAME) { frame++; off = HEAD; }
	}
	expect("coverage all32 frames", frame, 32);
	expect("coverage whole1MiB", total, PAYLOAD);
	expect("coverage exact target end", gpu, target + PAYLOAD);
	expect("coverage one completion", points, 1);
	if (want < CAP) expect("coverage no extra entry", ce_scratch[0][want].len, 0);
}
static void targets(void)
{
	struct xdev_ext_mech_ctx c;
	struct xdev_ext_ce_copy_desc held[CAP];
	unsigned direction;
	for (direction = 1; direction <= 2; direction++) {
		c = initialize(); c.base.direction = direction;
		batch_slot = 0;
		expect("actual callback arbitrary byte target first batch", ce_build(&c), 1);
		plan48(0, 1);
		memcpy(held, ce_scratch[0], sizeof(held));
		batch_slot = 1; c.base.src_offset = 401; c.batch_id = 72;
		c.base.request_id = c.batch_id;
		expect("actual callback adjacent byte target concurrent input", ce_build(&c), 1);
		plan48(1, 1048577);
		expect("second build preserves first batch scratch", memcmp(held, ce_scratch[0], sizeof(held)), 0);
		/* Key403 repeats source of401 and target of400. Ownership comes from
		 * actual C lease later; builder must not reject/rewrite repeats. */
		c.base.src_offset = 403; c.batch_id = 73;
		c.base.request_id = c.batch_id;
		ce_info[1].lease_generation = c.batch_id;
		expect("actual callback repeated source/target key", ce_build(&c), 1);
		plan48(1, 1);
	}
	c = initialize(); ce_info[0].gpu_seg_size = 32768; c.base.direction = 1;
	expect("exact64 pieces remain legal", ce_build(&c), 1);
	coverage(64, 32768, 65536, 1);
	expect("64piece final frame identity", ce_scratch[0][63].frame_pos, 31);
	expect("64piece final original offset", ce_scratch[0][63].frame_off, 32831);
	expect("64piece final byte", ce_scratch[0][63].len, 1);
	expect("64piece final GPU offset", ce_scratch[0][63].gpu_off, 1048576);
	expect("64piece only final completion", ce_scratch[0][62].flags, 0);
	expect("64piece completion", ce_scratch[0][63].flags, 1);
	c = initialize(); ce_info[0].gpu_seg_size = 131072; ce_info[0].max_entry_len = 131072;
	expect("128KiB segment exact40 pieces", ce_build(&c), 1);
	coverage(40, 131072, 131072, 1);
	c = initialize(); ce_info[0].gpu_seg_size = 0; ce_info[0].max_entry_len = 0;
	expect("unsegmented arbitrary byte target exact32", ce_build(&c), 1);
	coverage(32, 0, 0, 1);
	c = initialize(); requests[0].gpu_byte_offset = 3145728;
	expect("target exact authorized window end", ce_build(&c), 1);
	coverage(32, 65536, 65536, 3145728);
	c = initialize(); requests[0].gpu_byte_offset = 3145727;
	expect("target unaligned one byte before last legal start", ce_build(&c), 1);
	coverage(48, 65536, 65536, 3145727);
	c = initialize(); ce_info[0].gpu_seg_size = 16384;
	expect("96 required pieces refuse without shrink", ce_build(&c), 2);
	c = initialize(); ce_info[0].max_entry_len = 16384;
	expect("max-entry split requires80 and refuses", ce_build(&c), 2);
	c = initialize(); ce_info[0].gpu_window_len = PAYLOAD + 1;
	expect("range depth2 not limited by slot-address capacity", ce_build(&c), 1);
	plan48(0, 1);
#define BAD_CE(label, change) do { c = initialize(); change; expect(label, ce_build(&c), 2); } while (0)
	BAD_CE("target missing record", missing = 1);
	BAD_CE("target foreign session", c.session_id = 43);
	BAD_CE("target unknown key", c.base.src_offset = 404);
	BAD_CE("target overflow", requests[0].gpu_byte_offset = UINT64_MAX);
	BAD_CE("target one byte beyond window", requests[0].gpu_byte_offset = 3145729);
	BAD_CE("target record length mismatch", requests[0].byte_length = 512);
	BAD_CE("target record reserved", requests[0].reserved = 1);
	BAD_CE("target wrong actual direction", c.base.direction = 0);
	BAD_CE("target zero generation", ce_info[0].lease_generation = 0);
	BAD_CE("target invalid slot", ce_info[0].window_slot = DEPTH);
	BAD_CE("target empty depth", ce_info[0].window_depth = 0);
	BAD_CE("target zero frame", ce_info[0].f[0].data_len = 0);
	BAD_CE("target span exceeds host frame", ce_info[0].f[0].data_off = UINT32_MAX);
	BAD_CE("target incomplete total", ce_info[0].f[31].data_len = 32767);
	BAD_CE("target scratch cap47", scratch_cap = 47);
}
static void writes(void)
{
	struct xdev_ext_mech_ctx c = initialize();
	static const unsigned keys[4] = {401, 400, 403, 402};
	static const unsigned lbas[4] = {8192, 4096, 8192, 6144};
	unsigned i;
	c.base.direction = XDEV_EXT_MP_DIR_TO_DEVICE;
	for (i = 0; i < 4; i++) {
		c.base.src_offset = keys[i];
		expect("actual WRITE map callback accepts stage direction", nvme_build(&c), 1);
		sqe(1, lbas[i], 2047);
	}
}
int main(int argc, char **argv)
{
	if (argc != 2) return 2;
	if (!strcmp(argv[1], "controls")) controls();
	else if (!strcmp(argv[1], "targets")) targets();
	else if (!strcmp(argv[1], "writes")) writes();
	else return 2;
	printf("%s: %u checks, %u failures\n", argv[1], checks, failures);
	return failures ? 1 : 0;
}
