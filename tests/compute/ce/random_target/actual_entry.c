// SPDX-License-Identifier: GPL-2.0
/* No qualified(): every candidate and staged identity comes from actual C. */
#include "actual-range.h"

enum { FRAME = 32768, PAYLOAD = 1048576, WINDOW = 4194304,
	SEGMENT = 65536, FRAMES = 32, DEPTH = 2, ENTRIES = 64 };
static unsigned checks, failures;
static max_align_t backend_identity;
static struct xdev_ext_ce_stage ce;
static struct xdev_ext_mech_stage stage;
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_batch batches[DEPTH];

static void expect(const char *label, long long got, long long want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL %s: got %lld expected %lld\n", label, got, want);
		failures++;
	}
}

static void initialize(u32 direction, bool target_range)
{
	struct xdev_ext_window_copy_geom g;
	u32 i, j;

	/* Empty objects only: no candidate, staged pointer or active slot input. */
	memset(&ce, 0, sizeof(ce));
	memset(&session, 0, sizeof(session));
	memset(batches, 0, sizeof(batches));
	session.depth = DEPTH;
	session.batches = batches;
	stage = (struct xdev_ext_mech_stage){ .priv = &ce, .s = &session,
		.flags = target_range ? XDEV_EXT_CE_STAGE_F_TARGET_RANGE : 0,
		.direction = direction };
	ce.ops = (const struct xdev_ext_ce_backend_ops *)&backend_identity;
	ce.region.ops = ce.ops;
	ce.region.len = WINDOW;
	ce.region.seg_size = SEGMENT;
	expect("actual CE geometry covers depth2 host frames", xdev_ext_ce_geom_init(
		&ce.geom, WINDOW, WINDOW, SEGMENT, SEGMENT, DEPTH * PAYLOAD,
		0, FRAME, DEPTH * FRAMES), 0);
	g = xdev_ext_ce_window_geom(&ce.geom);
	if (target_range)
		expect("actual target mode prepare keeps depth2", xdev_ext_comp_copy_prepare_mode(
			&ce.copy.window, XDEV_EXT_COMP_COPY_WINDOW, &g, direction,
			DEPTH, PAYLOAD, true), 0);
	else
		expect("actual legacy prepare", xdev_ext_comp_copy_prepare(&ce.copy.window,
			XDEV_EXT_COMP_COPY_WINDOW, &g, direction, DEPTH, PAYLOAD), 0);
	for (i = 0; i < DEPTH; i++) {
		batches[i].s = &session;
		batches[i].id = 71 + i;
		batches[i].nr_frames = FRAMES;
		for (j = 0; j < FRAMES; j++)
			batches[i].f[j] = (struct xdev_ext_mech_frame){
				.index = i * FRAMES + j,
				.umem_addr = (u64)(i * FRAMES + j) * FRAME,
				.data_len = FRAME,
			};
	}
	/* A configured identity and completed CREATE are explicit provider facts.
	 * No backend implementation, native bind or native submit is supplied.
	 */
	expect("actual configured-window lease bind", xdev_ext_ce_lease_bind(
		&stage, &ce, 0x10000000ULL, WINDOW), 0);
	xdev_ext_comp_copy_lease_hold(&ce.lease, false);
}

static u32 descriptors(struct xdev_ext_ce_copy_desc *d, u64 base)
{
	u32 i, n = 0;

	memset(d, 0, ENTRIES * sizeof(*d));
	for (i = 0; i < FRAMES; i++) {
		u64 gpu = base + (u64)i * FRAME;
		u32 first = SEGMENT - (u32)(gpu % SEGMENT);

		if (first > FRAME)
			first = FRAME;
		d[n++] = (struct xdev_ext_ce_copy_desc){
			.frame_pos = i, .gpu_off = gpu, .len = first,
		};
		if (first < FRAME)
			d[n++] = (struct xdev_ext_ce_copy_desc){
				.frame_pos = i, .frame_off = first,
				.gpu_off = gpu + first, .len = FRAME - first,
			};
	}
	d[n - 1].flags = XDEV_EXT_CE_F_COMPLETION_POINT;
	return n;
}

static int enter(u32 slot)
{
	return xdev_ext_ce_copy_lease_get(&ce.copy, &batches[slot]);
}

static void reserved(u32 slot, u64 base, u64 generation)
{
	const struct xdev_ext_ce_lease_slot *owner = &ce.lease.group->slots[slot];

	expect("actual slot is active", owner->active, true);
	expect("actual slot records range mode", owner->target_range, true);
	expect("actual slot records validated target", owner->range_start, base);
	expect("actual slot records full 1 MiB", owner->range_len, PAYLOAD);
	expect("actual slot records actual batch identity", owner->generation, generation);
}

static int publish(u32 slot, u64 base)
{
	struct xdev_ext_ce_copy_desc d[ENTRIES];
	const struct xdev_ext_comp_copy_plan *plan = &ce.copy.plan;
	u32 n = descriptors(d, base);
	int ret;

	expect("unaligned crossing input has48pieces", n, 48);
	ret = xdev_ext_ce_validate(&stage, &batches[slot], (const u8 *)d, n);
	expect("actual validator publishes candidate", ret, 0);
	if (ret)
		return ret;
	/* Read-only inspection. Never repair or fill any of these outputs. */
	expect("actual validator publishes staged batch", ce.copy.staged == &batches[slot], true);
	expect("actual candidate range mode", plan->target_range, true);
	expect("actual candidate target", plan->target_start, base);
	expect("actual candidate full target length", plan->target_len, PAYLOAD);
	expect("actual candidate payload", plan->total, PAYLOAD);
	expect("actual candidate batch identity", plan->batch_id, batches[slot].id);
	expect("actual candidate slot identity", plan->slot, slot);
	expect("actual candidate entry count", plan->n, 48);
	expect("actual candidate first GPU byte", plan->entry[0].device_off, base);
	return 0;
}

static void release(u32 slot, bool unknown)
{
	xdev_ext_ce_batch_release(&stage, &batches[slot], unknown);
}

static void controls(void)
{
	struct xdev_ext_ce_copy_desc d[ENTRIES];
	u32 n;

	initialize(XDEV_EXT_MECH_DIR_TO_DEVICE, false);
	n = descriptors(d, 0);
	expect("legacy aligned input has32pieces", n, 32);
	expect("actual legacy validator still accepts slot0", xdev_ext_ce_validate(
		&stage, batches, (const u8 *)d, n), 0);
	expect("actual legacy candidate stays slot mode", ce.copy.plan.target_range, false);
	expect("actual legacy hook still enters", enter(0), 0);
	release(0, false);
	n = descriptors(d, SEGMENT);
	expect("legacy shifted input retains32pieces", n, 32);
	expect("actual legacy refuses outside slot", xdev_ext_ce_validate(
		&stage, batches, (const u8 *)d, n), -ERANGE);
	n = descriptors(d, 1);
	expect("legacy still refuses48entries", xdev_ext_ce_validate(
		&stage, batches, (const u8 *)d, n), -E2BIG);
	expect("legacy group drains", ce.lease.group->state.active_batches, 0);
	expect("legacy group unbinds", xdev_ext_comp_copy_lease_unbind(&ce.lease, false), true);
}

static void actual_path(u32 direction)
{
	initialize(direction, true);
	expect("no staged candidate initially", ce.copy.staged == NULL, true);
	expect("hook requires actual successful publication", enter(0), -EPROTO);
	expect("unpublished input acquires no owner", ce.lease.group->state.active_batches, 0);
	if (publish(0, 1))
		return;
	expect("successful validation alone reserves nothing", ce.lease.group->state.active_batches, 0);
	expect("actual hook consumes published offset1", enter(0), 0);
	reserved(0, 1, 71);
	if (publish(1, 1))
		return;
	expect("actual overlapping candidate refused before acceptance", enter(1), -EAGAIN);
	expect("actual overlap does not publish second owner", ce.lease.group->slots[1].active, false);
	expect("actual overlap keeps one owner", ce.lease.group->state.active_batches, 1);
	reserved(0, 1, 71);
	if (publish(1, PAYLOAD / 2 + 1))
		return;
	expect("actual partial overlap refused", enter(1), -EAGAIN);
	if (publish(1, PAYLOAD + 1))
		return;
	expect("actual adjacent disjoint candidate enters", enter(1), 0);
	expect("actual depth2 remains concurrent", ce.lease.group->state.active_batches, 2);
	reserved(0, 1, 71);
	reserved(1, PAYLOAD + 1, 72);
	if (publish(1, PAYLOAD + 2))
		return;
	expect("actual new candidate cannot change active generation range", enter(1), -EPROTO);
	reserved(1, PAYLOAD + 1, 72);
	release(1, false);
	expect("actual terminal releases only second batch", ce.lease.group->state.active_batches, 1);
	batches[1].id = 73; /* new request after its preceding terminal release */
	if (publish(1, 1))
		return;
	expect("actual new generation waits for preceding target owner", enter(1), -EAGAIN);
	release(0, false);
	expect("actual terminal drains preceding owner", ce.lease.group->state.active_batches, 0);
	/* Reuse the actual published candidate, with no metadata repair. */
	expect("actual candidate retries after terminal", enter(1), 0);
	reserved(1, 1, 73);
	release(1, true);
	expect("UNKNOWN retains actual range owner", ce.lease.group->state.active_batches, 1);
	expect("UNKNOWN quarantines actual group", ce.lease.group->state.quarantined, true);
	reserved(1, 1, 73);
	expect("UNKNOWN keeps actual lease busy", xdev_ext_comp_copy_lease_busy(&ce.lease), true);
	expect("UNKNOWN denies actual cleanup", xdev_ext_comp_copy_lease_cleanup_begin(&ce.lease), -EBUSY);
	expect("UNKNOWN denies actual unbind", xdev_ext_comp_copy_lease_unbind(&ce.lease, false), false);
	if (publish(1, 1))
		return;
	expect("actual staged same generation cannot bypass UNKNOWN", enter(1), -EBUSY);
	batches[0].id = 74;
	if (publish(0, 2 * PAYLOAD + 1))
		return;
	expect("actual staged disjoint candidate cannot bypass UNKNOWN", enter(0), -EBUSY);
	reserved(1, 1, 73);
	/* The quarantined metadata is intentionally retained until process exit. */
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	if (!strcmp(argv[1], "controls")) controls();
	else if (!strcmp(argv[1], "forward")) actual_path(XDEV_EXT_MECH_DIR_TO_DEVICE);
	else if (!strcmp(argv[1], "reverse")) actual_path(XDEV_EXT_MECH_DIR_FROM_DEVICE);
	else return 2;
	printf("actual-entry %s: %u checks, %u failures\n",
		argv[1], checks, failures);
	return failures ? 1 : 0;
}
