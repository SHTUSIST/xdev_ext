// SPDX-License-Identifier: GPL-2.0
/* actual.h contains selected actual functions/types, not fixture algorithms. */
#include "actual.h"

enum { FRAME = 32768, PAYLOAD = 1048576, WINDOW = 4194304, FRAMES = 32,
	PIECES = 64, TARGET_RANGE = 1 };
static unsigned checks, failures;
static struct xdev_ext_ce_stage ce;
static struct xdev_ext_mech_stage stage;
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_batch batches[1];
static struct xdev_ext_mech_life life[FRAMES];
static const struct fixture_pool_ops pool_ops;

static void expect(const char *name, long long got, long long want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL %s: got %lld expected %lld\n", name, got, want);
		failures++;
	}
}

static void initialize(void)
{
	struct xdev_ext_window_copy_geom g = {
		.window_len = WINDOW, .host_bytes = PAYLOAD, .seg_size = 65536,
		.max_entry_len = 65536, .frame_size = FRAME, .nr_frames = FRAMES,
		.alignment = 1, .directions = XDEV_EXT_WINDOW_COPY_DIRS,
	};
	u32 i;

	memset(&ce, 0, sizeof(ce));
	memset(&session, 0, sizeof(session));
	memset(batches, 0, sizeof(batches));
	stage = (struct xdev_ext_mech_stage){ .priv = &ce };
	session.batches = batches;
	session.life = life;
	session.pool.frame_size = FRAME;
	session.pool.ops = &pool_ops;
	batches[0].s = &session;
	batches[0].id = 29;
	batches[0].nr_frames = FRAMES;
	batches[0].life_active = UINT32_MAX;
	for (i = 0; i < FRAMES; i++) {
		u64 producer = 0;

		batches[0].f[i] = (struct xdev_ext_mech_frame) {
			.index = i, .umem_addr = (u64)i * FRAME, .data_len = FRAME,
		};
		xdev_ext_mech_life_init(&life[i]);
		expect("real lifecycle producer claim", xdev_ext_mech_life_claim(
			&life[i], 0, &producer), 0);
		expect("real lifecycle publish", xdev_ext_mech_life_publish(
			&life[i], producer, 1, FRAME), 0);
		expect("real lifecycle acquire", xdev_ext_mech_life_acquire(
			&life[i], 1, 0, &batches[0].life_token[i]), 0);
	}
	xdev_ext_mech_completion_init(&batches[0].completion);
	expect("real native completion begin", xdev_ext_mech_completion_begin(
		&batches[0].completion, &batches[0].ticket), 0);
	expect("actual common prepare", xdev_ext_comp_copy_prepare(&ce.copy.window,
		XDEV_EXT_COMP_COPY_WINDOW, &g, XDEV_EXT_MECH_DIR_TO_DEVICE, 4, PAYLOAD), 0);
}

/* Explicit aligned descriptors, independent of production target builders. */
static void pieces(struct xdev_ext_ce_copy_desc *d, u32 count)
{
	u32 i, n = 0, split = count - FRAMES;

	memset(d, 0, PIECES * sizeof(*d));
	for (i = 0; i < FRAMES; i++) {
		u32 len = i < split ? FRAME / 2 : FRAME;

		d[n++] = (struct xdev_ext_ce_copy_desc){
			.frame_pos = i, .gpu_off = (u64)i * FRAME, .len = len,
		};
		if (i < split)
			d[n++] = (struct xdev_ext_ce_copy_desc){
				.frame_pos = i, .frame_off = len,
				.gpu_off = (u64)i * FRAME + len, .len = len,
			};
	}
	d[n - 1].flags = XDEV_EXT_CE_F_COMPLETION_POINT;
	expect("explicit piece count", n, count);
}

static void controls(void)
{
	struct xdev_ext_ce_copy_desc d[PIECES];
	struct xdev_ext_comp_copy_plan before;
	int ret;

	initialize();
	pieces(d, 32);
	ret = xdev_ext_ce_validate(&stage, batches, (const u8 *)d, 32);
	expect("actual CE flags0 validates32", ret, 0);
	if (!ret) {
		before = ce.copy.plan;
		pieces(d, 33);
		expect("actual CE flags0 refuses33", xdev_ext_ce_validate(
			&stage, batches, (const u8 *)d, 33), -E2BIG);
		expect("actual refusal keeps admitted plan",
			memcmp(&before, &ce.copy.plan, sizeof(before)), 0);
		expect("actual refusal clears staged batch", ce.copy.staged == NULL, true);
	}
	stage.flags = TARGET_RANGE;
	pieces(d, 32);
	expect("actual opt-in CE retains legal32", xdev_ext_ce_validate(
		&stage, batches, (const u8 *)d, 32), 0);
}

static void mode(void)
{
	static const u32 counts[] = { 33, 48, 64 };
	struct xdev_ext_ce_copy_desc d[PIECES];
	u32 i;

	initialize();
	stage.flags = TARGET_RANGE;
	for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		int ret;
		char label[96];

		pieces(d, counts[i]);
		snprintf(label, sizeof(label), "actual opt-in CE validates%u", counts[i]);
		ret = xdev_ext_ce_validate(&stage, batches, (const u8 *)d, counts[i]);
		expect(label, ret, 0);
		if (!ret) {
			expect("actual admitted count", ce.copy.plan.n, counts[i]);
			expect("actual admitted payload", ce.copy.plan.total, PAYLOAD);
			expect("actual staged batch", ce.copy.staged == batches, true);
		}
	}
}

static void owners(void)
{
	struct xdev_ext_ce_copy_desc d[PIECES];
	struct xdev_ext_comp_copy_transfer transfer[PIECES], before[PIECES];
	struct xdev_ext_ce_xfer native[PIECES];
	struct xdev_ext_mech_batch *b = batches;
	int ret;

	initialize();
	pieces(d, PIECES);
	expect("actual collector supplies frame metadata",
		xdev_ext_comp_copy_collect(&ce.copy, b), FRAMES);
	ret = xdev_ext_comp_copy_validate(&ce.copy.window, ce.copy.fi, ce.copy.index,
		FRAMES, d, PIECES, PIECES, XDEV_EXT_CE_F_KNOWN_MASK, 0, b->id, &ce.copy.plan);
	expect("owner64 input uses actual admitted common plan", ret, 0);
	if (ret)
		return;
	ret = xdev_ext_comp_copy_transfer(&ce.copy.plan, b->id, 0, b,
		xdev_ext_comp_copy_claim, transfer);
	expect("actual64 transfer collects real frame claims", ret, 0);
	if (ret)
		return;
	/* A representation bridge only; native records originate in the actual
	 * common transfer helper. These identical offsets are checked below.
	 */
	memcpy(native, transfer, sizeof(native));
	expect("actual CE owner entrance accepts64", xdev_ext_mech_batch_ce_owners_valid(
		b, b->ticket, native, PIECES), true);
	native[63].generation++;
	expect("actual CE checks last split generation", xdev_ext_mech_batch_ce_owners_valid(
		b, b->ticket, native, PIECES), false);
	native[63].generation--;
	native[63].host_byte_off = PAYLOAD;
	expect("actual CE checks last split host span", xdev_ext_mech_batch_ce_owners_valid(
		b, b->ticket, native, PIECES), false);
	memcpy(native, transfer, sizeof(native));
	expect("actual CE checks native ticket", xdev_ext_mech_batch_ce_owners_valid(
		b, b->ticket + 1, native, PIECES), false);
	expect("actual CE refuses65 before array reads", xdev_ext_mech_batch_ce_owners_valid(
		b, b->ticket, native, 65), false);
	memcpy(before, transfer, sizeof(before));
	b->life_active &= ~(1U << 31);
	expect("actual transfer rejects missing last frame claim",
		xdev_ext_comp_copy_transfer(&ce.copy.plan, b->id, 0, b,
			xdev_ext_comp_copy_claim, transfer), -ESTALE);
	expect("failed claim leaves all transfer outputs unchanged",
		memcmp(before, transfer, sizeof(before)), 0);
}

_Static_assert(sizeof(struct xdev_ext_comp_copy_transfer) == sizeof(struct xdev_ext_ce_xfer),
	"fixture representation bridge needs identical transfer sizes");
#define SAME_OFFSET(field, target) \
	_Static_assert(offsetof(struct xdev_ext_comp_copy_transfer, field) == \
		offsetof(struct xdev_ext_ce_xfer, target), "transfer offset mismatch")
SAME_OFFSET(owner, owner);
SAME_OFFSET(generation, generation);
SAME_OFFSET(host_byte_off, host_byte_off);
SAME_OFFSET(device_off, gpu_off);
SAME_OFFSET(len, len);
SAME_OFFSET(flags, flags);

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	if (!strcmp(argv[1], "controls"))
		controls();
	else if (!strcmp(argv[1], "mode"))
		mode();
	else if (!strcmp(argv[1], "owners"))
		owners();
	else
		return 2;
	printf("runtime %s: %u checks, %u failures\n", argv[1], checks, failures);
	return failures ? 1 : 0;
}
