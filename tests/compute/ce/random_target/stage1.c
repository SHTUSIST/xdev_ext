// SPDX-License-Identifier: GPL-2.0
/* Actual header rules only. New behavior must fail at runtime, not at setup. */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "io_uring/xdev_ext_mech_step.h"
#include "io_uring/xdev_ext_mech_ce_core.h"
#include "io_uring/xdev_ext_compfam_copy_core.h"

/* Frozen candidate input, not a fallback implementation or production macro. */
enum {
	TARGET_RANGE = 1U,
	UNKNOWN_CE_FLAG = 1U << 28,
	FRAME_BYTES = 32768U,
	PAYLOAD = 1048576U,
	WINDOW_BYTES = 4194304U,
	FRAME_COUNT = 32U,
	RANGE_ENTRIES = 64U,
};

static unsigned int checks, failures;

static void expect(const char *name, long long got, long long want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL %s: got %lld expected %lld\n", name, got, want);
		failures++;
	}
}

static struct xdev_ext_mech_create request(bool save)
{
	struct xdev_ext_mech_create c = {
		.abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.nr_stages = 2, .pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM,
		.pool_fd = -1, .depth = 4, .eventfd = -1,
		.layout = { .frame_size = FRAME_BYTES, .seg_len = FRAME_BYTES,
			    .group_bytes = PAYLOAD },
	};
	unsigned int nvme = save ? 1U : 0U, ce = 1U - nvme;

	c.st[nvme] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_NVME, .fd = 4,
		.direction = save ? XDEV_EXT_MECH_DIR_TO_DEVICE :
			XDEV_EXT_MECH_DIR_FROM_DEVICE,
		.arg0 = 0, .arg1 = 32768,
	};
	c.st[ce] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_CE, .fd = 5,
		.direction = save ? XDEV_EXT_MECH_DIR_FROM_DEVICE :
			XDEV_EXT_MECH_DIR_TO_DEVICE,
		.arg0 = 0x10000000ULL, .arg1 = WINDOW_BYTES,
	};
	return c;
}

static void check_create(const char *name, const struct xdev_ext_mech_create *c,
		int want)
{
	__u32 frames = UINT32_MAX;
	int ret = xdev_ext_mech_create_check(c, &frames);

	expect(name, ret, want);
	if (!ret)
		expect("CREATE keeps 1 MiB in 32 host frames", frames, FRAME_COUNT);
}

/* This is an explicit input row, not a registered production declaration.
 * Only known_flags changes; role/check_stage and all other rules are actual.
 * It exposes composition checks after flag recognition, independently of the
 * currently unregistered flag. No callback body is replaced or stubbed.
 */
static void check_qualified_topology(const char *name,
		const struct xdev_ext_mech_create *c, int want)
{
	struct xdev_ext_mech_class_desc ce =
		*xdev_ext_mech_class_desc(XDEV_EXT_MECH_CLASS_CE);
	const struct xdev_ext_mech_class_desc *rows[XDEV_EXT_MECH_MAX_STAGES];
	__u32 frames = UINT32_MAX, i;
	int ret;

	ce.known_flags |= TARGET_RANGE;
	for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++)
		rows[i] = c->st[i].class_id == XDEV_EXT_MECH_CLASS_CE ? &ce :
			xdev_ext_mech_class_desc(c->st[i].class_id);
	ret = xdev_ext_mech_create_check_desc(c, rows, &frames);
	expect(name, ret, want);
	if (!ret)
		expect("qualified CREATE keeps 32 host frames", frames, FRAME_COUNT);
}

static struct xdev_ext_window_copy_geom geometry(void)
{
	return (struct xdev_ext_window_copy_geom) {
		.window_len = WINDOW_BYTES, .host_bytes = PAYLOAD,
		.seg_size = 65536, .max_entry_len = 65536,
		.frame_size = FRAME_BYTES, .nr_frames = FRAME_COUNT,
		.alignment = 1, .directions = XDEV_EXT_WINDOW_COPY_DIRS,
	};
}

static void frames_init(struct xdev_ext_mech_frame_info *f, __u32 *indices)
{
	__u32 i;

	for (i = 0; i < FRAME_COUNT; i++) {
		f[i] = (struct xdev_ext_mech_frame_info) {
			.umem_addr = (__u64)i * FRAME_BYTES, .data_len = FRAME_BYTES,
		};
		indices[i] = i;
	}
}

/* Fixture inputs: split the first count-32 frames into equal halves. These
 * aligned pieces isolate storage capacity from the separate range mode.
 */
static __u32 aligned_pieces(struct xdev_ext_ce_copy_desc *d, __u32 count)
{
	__u32 i, n = 0, split = count - FRAME_COUNT;

	memset(d, 0, RANGE_ENTRIES * sizeof(*d));
	for (i = 0; i < FRAME_COUNT; i++) {
		__u32 len = i < split ? FRAME_BYTES / 2 : FRAME_BYTES;

		d[n++] = (struct xdev_ext_ce_copy_desc) {
			.frame_pos = i, .gpu_off = (__u64)i * FRAME_BYTES, .len = len,
		};
		if (i < split)
			d[n++] = (struct xdev_ext_ce_copy_desc) {
				.frame_pos = i, .frame_off = len,
				.gpu_off = (__u64)i * FRAME_BYTES + len, .len = len,
			};
	}
	d[n - 1].flags = XDEV_EXT_CE_F_COMPLETION_POINT;
	return n;
}

static void raw_unaligned_control(void)
{
	struct xdev_ext_window_copy_geom g = geometry();
	struct xdev_ext_mech_frame_info f[FRAME_COUNT];
	struct xdev_ext_ce_copy_desc d[RANGE_ENTRIES] = { 0 };
	__u32 indices[FRAME_COUNT], i, n = 0;
	__u64 host_off[RANGE_ENTRIES], total = 0;

	frames_init(f, indices);
	/* At GPU offset 1, each odd 32 KiB frame crosses a 64 KiB boundary.
	 * Explicit lengths 32767+1 give 16 single + 16 double entries = 48.
	 */
	for (i = 0; i < FRAME_COUNT; i++) {
		__u32 len = (i & 1U) ? FRAME_BYTES - 1 : FRAME_BYTES;
		__u64 gpu = 1 + (__u64)i * FRAME_BYTES;

		d[n++] = (struct xdev_ext_ce_copy_desc) {
			.frame_pos = i, .gpu_off = gpu, .len = len,
		};
		if (i & 1U)
			d[n++] = (struct xdev_ext_ce_copy_desc) {
				.frame_pos = i, .frame_off = FRAME_BYTES - 1,
				.gpu_off = gpu + FRAME_BYTES - 1, .len = 1,
			};
	}
	d[n - 1].flags = XDEV_EXT_CE_F_COMPLETION_POINT;
	expect("unaligned input has 48 explicit pieces", n, 48);
	expect("actual window rules accept 1 MiB at byte offset 1",
		xdev_ext_window_copy_plan_check(&g, f, indices, FRAME_COUNT,
			XDEV_EXT_MECH_DIR_TO_DEVICE, d, n, RANGE_ENTRIES,
			XDEV_EXT_CE_F_KNOWN_MASK, host_off, &total), 0);
	expect("actual window rules cover all 1 MiB", total, PAYLOAD);
}

static void controls(void)
{
	struct xdev_ext_mech_create c = request(false);
	struct xdev_ext_window_copy_geom g = geometry();
	struct xdev_ext_comp_copy_window w = { 0 };
	struct xdev_ext_comp_copy_plan p, before;
	struct xdev_ext_ce_geom ce_geom = { 0 };
	struct xdev_ext_ce_plan ce_plan;
	struct xdev_ext_mech_frame_info f[FRAME_COUNT];
	struct xdev_ext_ce_copy_desc d[RANGE_ENTRIES];
	__u32 indices[FRAME_COUNT];
	__u64 host_off[RANGE_ENTRIES], total = 0;
	int ret;

	check_create("legacy load 1 MiB depth4", &c, 0);
	c = request(true);
	check_create("legacy save 1 MiB depth4", &c, 0);
	c = request(false);
	c.st[0] = c.st[1];
	c.st[1].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	check_create("legacy flags0 multiCE retained", &c, 0);
	c = request(false);
	c.st[1].class_id = XDEV_EXT_MECH_CLASS_DMA;
	check_create("legacy DMA flags0 retained", &c, 0);
	c.st[1].flags = TARGET_RANGE;
	check_create("DMA refuses CE-only candidate flag", &c, -EINVAL);
	c = request(false);
	c.st[0].flags = TARGET_RANGE;
	check_create("NVMe refuses CE-only candidate flag", &c, -EINVAL);
	c = request(false);
	c.st[1].flags = UNKNOWN_CE_FLAG;
	check_create("unknown CE bit stays refused", &c, -EINVAL);
	c = request(false);
	c.st[1].fd = -1;
	check_create("bad CE fd stays refused", &c, -EBADF);
	c = request(false);
	c.layout.group_bytes += FRAME_BYTES;
	check_create("33 host frames stay refused", &c, -E2BIG);
	expect("host frame capacity stays32", XDEV_EXT_MECH_MAX_FRAMES, 32);
	expect("DMA entry capacity stays32", XDEV_EXT_DMA_MAX_ENTRIES, 32);
	expect("candidate flag is class local",
		TARGET_RANGE & (XDEV_EXT_MECH_STAGE_F_FANOUT | XDEV_EXT_MECH_STAGE_F_POLL), 0);
#ifdef XDEV_EXT_CE_STAGE_F_TARGET_RANGE
	expect("published flag matches frozen candidate input",
		XDEV_EXT_CE_STAGE_F_TARGET_RANGE, TARGET_RANGE);
#endif
	expect("legacy 32 descriptor class remains legal",
		xdev_ext_mech_class_sizes_ok(sizeof(struct xdev_ext_ce_mech_info),
			24, 32, 24, 1, 1296), true);
	expect("4096 byte scratch limit retained",
		xdev_ext_mech_class_sizes_ok(1, 4097, 1, 1, 1, 1), false);
	expect("4096 byte private limit retained",
		xdev_ext_mech_class_sizes_ok(1, 24, 32, 24, 1, 4097), false);
	expect("descriptor65 stays outside stage1 cap",
		xdev_ext_mech_class_sizes_ok(1, 24, 65, 24, 1, 1), false);
	expect("CQE count does not become64",
		xdev_ext_mech_class_sizes_ok(1, 24, 32, 1, 64, 1), false);
	frames_init(f, indices);
	expect("legacy geometry retains depth4 window",
		xdev_ext_comp_copy_prepare(&w, XDEV_EXT_COMP_COPY_WINDOW, &g,
			XDEV_EXT_MECH_DIR_TO_DEVICE, 4, PAYLOAD), 0);
	expect("legacy input has32pieces", aligned_pieces(d, 32), 32);
	ret = xdev_ext_comp_copy_validate(&w, f, indices, FRAME_COUNT,
		d, 32, 32, XDEV_EXT_CE_F_KNOWN_MASK, 0, 19, &p);
	expect("actual legacy common validator accepts32", ret, 0);
	if (!ret) {
		expect("legacy payload unchanged", p.total, PAYLOAD);
		before = p;
		aligned_pieces(d, 33);
		expect("legacy cap32 still rejects33", xdev_ext_comp_copy_validate(
			&w, f, indices, FRAME_COUNT, d, 33, 32,
			XDEV_EXT_CE_F_KNOWN_MASK, 0, 19, &p), -E2BIG);
		expect("rejection keeps admitted plan", memcmp(&p, &before, sizeof(p)), 0);
	}
	/* Exercise the actual compatibility CE plan API, not just a literal32
	 * passed to the common helper. This does not invoke CE runtime validate;
	 * the later mode-selection stage must test that actual path separately.
	 */
	expect("actual legacy CE geometry remains legal",
		xdev_ext_ce_geom_init(&ce_geom, WINDOW_BYTES, WINDOW_BYTES, 65536,
			65536, PAYLOAD, 0, FRAME_BYTES, FRAME_COUNT), 0);
	aligned_pieces(d, 32);
	expect("actual legacy CE plan accepts32",
		xdev_ext_ce_plan_check(&ce_geom, f, indices, FRAME_COUNT, d, 32, &ce_plan), 0);
	aligned_pieces(d, 33);
	expect("legacy33 input has otherwise valid full geometry",
		xdev_ext_window_copy_plan_check(&g, f, indices, FRAME_COUNT,
			XDEV_EXT_MECH_DIR_TO_DEVICE, d, 33, RANGE_ENTRIES,
			XDEV_EXT_CE_F_KNOWN_MASK, host_off, &total), 0);
	expect("legacy33 input retains all 1 MiB", total, PAYLOAD);
	expect("actual legacy CE plan cap rejects33",
		xdev_ext_ce_plan_check(&ce_geom, f, indices, FRAME_COUNT, d, 33, &ce_plan),
		-E2BIG);
	raw_unaligned_control();
}

static void flags(void)
{
	struct xdev_ext_mech_create c = request(false);

	c.st[1].flags = TARGET_RANGE;
	check_create("actual CE row accepts opt-in load depth4", &c, 0);
	c = request(true);
	c.st[0].flags = TARGET_RANGE;
	check_create("actual CE row accepts opt-in save depth4", &c, 0);
	c = request(false);
	c.st[1].flags = TARGET_RANGE | XDEV_EXT_MECH_STAGE_F_POLL;
	check_create("opt-in composes with generic POLL", &c, 0);
	c.st[1].flags = TARGET_RANGE;
	c.depth = 64;
	check_create("opt-in does not reduce depth64", &c, 0);
}

static void topology(void)
{
	struct xdev_ext_mech_create c = request(false);

	c.st[1].flags = TARGET_RANGE;
	check_qualified_topology("qualified load positive", &c, 0);
	c = request(true);
	c.st[0].flags = TARGET_RANGE;
	check_qualified_topology("qualified save positive", &c, 0);
	c = request(false);
	c.st[1].flags = TARGET_RANGE;
	c.st[0].class_id = XDEV_EXT_MECH_CLASS_DMA;
	check_qualified_topology("new mode refuses DMA partner", &c, -EOPNOTSUPP);
	c = request(false);
	c.st[1].flags = TARGET_RANGE;
	c.st[1].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	check_qualified_topology("new mode refuses two producers", &c, -EOPNOTSUPP);
	c = request(true);
	c.st[0].flags = TARGET_RANGE;
	c.st[1].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	check_qualified_topology("new mode refuses save to NVMe READ", &c, -EOPNOTSUPP);
	c = request(true);
	c.st[0].flags = TARGET_RANGE;
	c.nr_stages = 1;
	memset(&c.st[1], 0, sizeof(c.st[1]));
	check_qualified_topology("new mode requires NVMe partner", &c, -EOPNOTSUPP);
	c = request(false);
	c.st[1].flags = TARGET_RANGE;
	c.nr_stages = 3;
	c.st[2] = c.st[1];
	c.st[2].flags = 0;
	check_qualified_topology("new mode refuses extra CE stage", &c, -EOPNOTSUPP);
	c.st[2] = c.st[0];
	c.st[2].direction = XDEV_EXT_MECH_DIR_TO_DEVICE;
	check_qualified_topology("new mode refuses extra NVMe stage", &c, -EOPNOTSUPP);
	c = request(false);
	c.st[1].flags = TARGET_RANGE | XDEV_EXT_MECH_STAGE_F_FANOUT;
	/* Existing generic FANOUT check rejects a preceding producer first. */
	check_qualified_topology("generic FANOUT refusal preserved", &c, -EINVAL);
}

static void capacity(void)
{
	static const __u32 counts[] = { 33, 48, 64 };
	struct xdev_ext_window_copy_geom g = geometry();
	struct xdev_ext_comp_copy_window w = { 0 };
	struct xdev_ext_comp_copy_plan p;
	struct xdev_ext_mech_frame_info f[FRAME_COUNT];
	struct xdev_ext_ce_copy_desc d[RANGE_ENTRIES];
	__u32 indices[FRAME_COUNT], j;

	expect("real class registration admits64 CE descriptors",
		xdev_ext_mech_class_sizes_ok(sizeof(struct xdev_ext_ce_mech_info),
			24, 64, 24, 1, 2576), true);
	expect("actual common plan stores at least64entries",
		sizeof(p.entry) / sizeof(p.entry[0]) >= RANGE_ENTRIES, true);
	frames_init(f, indices);
	expect("capacity cohort uses legacy valid geometry",
		xdev_ext_comp_copy_prepare(&w, XDEV_EXT_COMP_COPY_WINDOW, &g,
			XDEV_EXT_MECH_DIR_TO_DEVICE, 4, PAYLOAD), 0);
	for (j = 0; j < sizeof(counts) / sizeof(counts[0]); j++) {
		__u32 n = aligned_pieces(d, counts[j]);
		int ret;
		char name[100];

		expect("capacity fixture count matches literal", n, counts[j]);
		snprintf(name, sizeof(name), "actual common validator accepts%u pieces", n);
		ret = xdev_ext_comp_copy_validate(&w, f, indices, FRAME_COUNT,
			d, n, RANGE_ENTRIES, XDEV_EXT_CE_F_KNOWN_MASK, 0, 27, &p);
		expect(name, ret, 0);
		if (!ret) {
			expect("capacity plan retains piece count", p.n, n);
			expect("capacity plan retains 1 MiB", p.total, PAYLOAD);
		}
	}
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s controls|flags|topology|capacity\n", argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "controls"))
		controls();
	else if (!strcmp(argv[1], "flags"))
		flags();
	else if (!strcmp(argv[1], "topology"))
		topology();
	else if (!strcmp(argv[1], "capacity"))
		capacity();
	else
		return 2;
	printf("stage1 %s: %u checks, %u failures\n", argv[1], checks, failures);
	return failures ? 1 : 0;
}
