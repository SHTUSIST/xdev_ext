// SPDX-License-Identifier: GPL-2.0
#include "actual-range.h"

enum { FRAME = 32768, PAYLOAD = 1048576, WINDOW = 4194304,
	SEGMENT = 65536, FRAMES = 32, DEPTH = 2, ENTRIES = 64, TARGET_RANGE = 1 };
static unsigned checks, failures, qualified_inputs;
static max_align_t backend_identity;
static struct xdev_ext_ce_stage ce;
static struct xdev_ext_mech_stage stage;
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_batch batches[DEPTH];

static void expect(const char *name, long long got, long long want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL %s: got %lld expected %lld\n", name, got, want);
		failures++;
	}
}

static void initialize(bool range)
{
	u32 i, j;
	struct xdev_ext_window_copy_geom g;

	memset(&ce, 0, sizeof(ce));
	memset(&session, 0, sizeof(session));
	memset(batches, 0, sizeof(batches));
	session.depth = DEPTH;
	session.batches = batches;
	stage = (struct xdev_ext_mech_stage){
		.priv = &ce, .s = &session,
		.flags = range ? TARGET_RANGE : 0,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
	};
	/* Identity only, never dereferenced or installed as a native backend. */
	ce.ops = (const struct xdev_ext_ce_backend_ops *)&backend_identity;
	ce.region.ops = ce.ops;
	ce.region.len = WINDOW;
	ce.region.seg_size = SEGMENT;
	expect("real geometry has two 1 MiB host batches", xdev_ext_ce_geom_init(
		&ce.geom, WINDOW, WINDOW, SEGMENT, SEGMENT, DEPTH * PAYLOAD,
		0, FRAME, DEPTH * FRAMES), 0);
	g = xdev_ext_ce_window_geom(&ce.geom);
	expect("real prepare retains depth2", xdev_ext_comp_copy_prepare(
		&ce.copy.window, XDEV_EXT_COMP_COPY_WINDOW, &g,
		XDEV_EXT_MECH_DIR_TO_DEVICE, DEPTH, PAYLOAD), 0);
	for (i = 0; i < DEPTH; i++) {
		batches[i].s = &session;
		batches[i].id = 41 + i;
		batches[i].nr_frames = FRAMES;
		for (j = 0; j < FRAMES; j++)
			batches[i].f[j] = (struct xdev_ext_mech_frame){
				.index = i * FRAMES + j,
				.umem_addr = (u64)(i * FRAMES + j) * FRAME,
				.data_len = FRAME,
			};
	}
	expect("actual configured-window lease bind", xdev_ext_ce_lease_bind(
		&stage, &ce, 0x10000000ULL, WINDOW), 0);
	/* Explicit input fact: CREATE finished binding. No device callback stub. */
	xdev_ext_comp_copy_lease_hold(&ce.lease, false);
}

static void terminal(u32 slot, bool unknown)
{
	xdev_ext_ce_batch_release(&stage, &batches[slot], unknown);
}

static void cleanup(void)
{
	terminal(0, false);
	terminal(1, false);
	expect("actual normal unbind releases group",
		xdev_ext_comp_copy_lease_unbind(&ce.lease, false), true);
}

/* Fixture descriptors only: one contiguous request, independent of slot. */
static u32 descriptors(struct xdev_ext_ce_copy_desc *d, u64 base, bool halves)
{
	u32 i, n = 0;

	memset(d, 0, ENTRIES * sizeof(*d));
	for (i = 0; i < FRAMES; i++) {
		u64 gpu = base + (u64)i * FRAME;
		u32 first = halves ? FRAME / 2 : FRAME;
		u32 remain = SEGMENT - (u32)(gpu % SEGMENT);

		if (first > remain)
			first = remain;
		d[n++] = (struct xdev_ext_ce_copy_desc){
			.frame_pos = i, .gpu_off = gpu, .len = first,
		};
		if (first != FRAME)
			d[n++] = (struct xdev_ext_ce_copy_desc){
				.frame_pos = i, .frame_off = first,
				.gpu_off = gpu + first, .len = FRAME - first,
			};
	}
	d[n - 1].flags = XDEV_EXT_CE_F_COMPLETION_POINT;
	return n;
}

static int validate(u32 slot, struct xdev_ext_ce_copy_desc *d, u32 n)
{
	return xdev_ext_ce_validate(&stage, &batches[slot], (const u8 *)d, n);
}

/* Qualified metadata INPUT for lease tests, never a replacement validator.
 * The current slot runtime rejects some of these ranges. Validate cohort
 * separately requires that real path to succeed. Future successful actual
 * validation retains any new range metadata; only existing fields are filled.
 */
static void qualified(u32 slot, u64 base)
{
	struct xdev_ext_ce_copy_desc d[ENTRIES];
	u64 host[ENTRIES], total = 0;
	u32 n = descriptors(d, base, false), i;
	int ret = validate(slot, d, n);

	if (ret)
		qualified_inputs++;
	expect("actual collect for qualified range", xdev_ext_comp_copy_collect(
		&ce.copy, &batches[slot]), FRAMES);
	ret = xdev_ext_window_copy_plan_check(&ce.copy.window.geom, ce.copy.fi,
		ce.copy.index, FRAMES, XDEV_EXT_MECH_DIR_TO_DEVICE, d, n, ENTRIES,
		XDEV_EXT_CE_F_KNOWN_MASK, host, &total);
	expect("qualified range has real frame/window/segment permission", ret, 0);
	expect("qualified range retains 1 MiB", total, PAYLOAD);
	if (ret)
		return;
	memset(ce.copy.plan.entry, 0, sizeof(ce.copy.plan.entry));
	for (i = 0; i < n; i++)
		ce.copy.plan.entry[i] = (struct xdev_ext_comp_copy_entry){
			.host_byte_off = host[i], .device_off = d[i].gpu_off,
			.frame_pos = d[i].frame_pos, .len = d[i].len, .flags = d[i].flags,
		};
	ce.copy.plan.batch_id = batches[slot].id;
	ce.copy.plan.slot = slot;
	ce.copy.plan.total = total;
	ce.copy.plan.n = n;
	ce.copy.staged = &batches[slot];
}

static int enter(u32 slot)
{
	return xdev_ext_ce_copy_lease_get(&ce.copy, &batches[slot]);
}

static void controls(void)
{
	struct xdev_ext_ce_copy_desc d[ENTRIES];
	u32 n;

	initialize(false);
	n = descriptors(d, 0, false);
	expect("legacy slot0 1 MiB validates", validate(0, d, n), 0);
	expect("legacy slot0 gets real lease", enter(0), 0);
	n = descriptors(d, PAYLOAD, false);
	expect("legacy slot1 1 MiB validates", validate(1, d, n), 0);
	expect("legacy depth2 is not serialized", enter(1), 0);
	expect("legacy two batches active", ce.lease.group->state.active_batches, 2);
	terminal(0, false);
	expect("terminal releases just slot0", ce.lease.group->state.active_batches, 1);
	terminal(1, false);
	expect("terminal releases slot1", ce.lease.group->state.active_batches, 0);
	n = descriptors(d, 0, false);
	d[1].gpu_off = 0;
	expect("legacy device self-overlap rule remains", validate(0, d, n), 0);
	cleanup();
}

static void validator(void)
{
	struct xdev_ext_ce_copy_desc d[ENTRIES];
	struct xdev_ext_comp_copy_plan before;
	u32 n;

	initialize(true);
	n = descriptors(d, 1, false);
	expect("offset1 has48pieces under declared segment geometry", n, 48);
	expect("actual range validator admits offset1 1 MiB depth2", validate(0, d, n), 0);
	n = descriptors(d, WINDOW - PAYLOAD, false);
	expect("actual range validator admits last window range", validate(0, d, n), 0);
	n = descriptors(d, 0, true);
	expect("continuity controls have64pieces", n, 64);
	expect("actual range validator admits baseline continuous plan", validate(0, d, n), 0);
	memcpy(&before, &ce.copy.plan, sizeof(before));
	d[1].gpu_off++;
	expect("range GPU gap rejected", validate(0, d, n), -EINVAL);
	expect("gap rejection preserves admitted plan", memcmp(&before, &ce.copy.plan, sizeof(before)), 0);
	memcpy(&ce.copy.plan, &before, sizeof(before));
	descriptors(d, 0, true);
	d[1].gpu_off--;
	expect("range GPU self-overlap rejected", validate(0, d, n), -EINVAL);
	expect("self-overlap rejection preserves plan", memcmp(&before, &ce.copy.plan, sizeof(before)), 0);
	memcpy(&ce.copy.plan, &before, sizeof(before));
	descriptors(d, 0, true);
	d[1].gpu_off = 0;
	expect("range GPU backwards entry rejected", validate(0, d, n), -EINVAL);
	expect("backwards rejection preserves plan", memcmp(&before, &ce.copy.plan, sizeof(before)), 0);
	memcpy(&ce.copy.plan, &before, sizeof(before));
	descriptors(d, 0, true);
	d[0].gpu_off = UINT64_MAX;
	expect("range GPU integer overflow refused", validate(0, d, n), -ERANGE);
	expect("overflow rejection preserves plan", memcmp(&before, &ce.copy.plan, sizeof(before)), 0);
	n = descriptors(d, WINDOW - PAYLOAD + 1, false);
	expect("range past window end refused", validate(0, d, n), -ERANGE);
	expect("window rejection preserves plan", memcmp(&before, &ce.copy.plan, sizeof(before)), 0);
	descriptors(d, 0, true);
	batches[0].f[0].data_off = UINT32_MAX;
	d[0].frame_off = UINT32_MAX;
	expect("source frame offset overflow refused", validate(0, d, 64), -ERANGE);
	expect("source offset rejection preserves plan", memcmp(&before, &ce.copy.plan, sizeof(before)), 0);
	batches[0].f[0].data_off = 0;
	descriptors(d, 0, true);
	batches[0].f[0].index = UINT32_MAX;
	expect("source frame index overflow refused", validate(0, d, 64), -ERANGE);
	expect("source index rejection preserves plan", memcmp(&before, &ce.copy.plan, sizeof(before)), 0);
	batches[0].f[0].index = 0;
	cleanup();
}

static void leases(void)
{
	initialize(true);
	qualified(0, 1);
	expect("qualified first range enters", enter(0), 0);
	qualified(0, 1);
	expect("same generation and range idempotent", enter(0), 0);
	expect("idempotence does not count twice", ce.lease.group->state.active_batches, 1);
	qualified(0, 2);
	expect("same generation different range refused", enter(0), -EPROTO);
	qualified(1, 1);
	expect("exact overlap is preaccept backpressure", enter(1), -EAGAIN);
	expect("refused overlap does not publish owner", ce.lease.group->state.active_batches, 1);
	terminal(1, false); /* clean an unexpected old acceptance; no-op on refusal */
	batches[1].id++;
	qualified(1, PAYLOAD / 2 + 1);
	expect("partial overlap is preaccept backpressure", enter(1), -EAGAIN);
	terminal(1, false);
	batches[1].id++;
	qualified(1, PAYLOAD + 1);
	expect("adjacent disjoint range can enter", enter(1), 0);
	expect("new mode keeps two disjoint batches in flight", ce.lease.group->state.active_batches, 2);
	expect("stale terminal cannot clear first owner", xdev_ext_comp_copy_lease_finish(
		&ce.lease, 0, batches[0].id + 1, false), -ESTALE);
	terminal(1, false);
	batches[1].id++;
	qualified(1, 1);
	expect("first owner remains until terminal", enter(1), -EAGAIN);
	terminal(1, false);
	batches[1].id++;
	terminal(0, false);
	qualified(1, 1);
	expect("terminal permits repeated target with new owner", enter(1), 0);
	cleanup();
}

static void unknown(void)
{
	initialize(true);
	qualified(0, 1);
	expect("range before UNKNOWN enters", enter(0), 0);
	terminal(0, true);
	expect("UNKNOWN keeps active range", ce.lease.group->state.active_batches, 1);
	expect("UNKNOWN quarantines group", ce.lease.group->state.quarantined, true);
	expect("UNKNOWN still busy", xdev_ext_comp_copy_lease_busy(&ce.lease), true);
	expect("UNKNOWN refuses cleanup", xdev_ext_comp_copy_lease_cleanup_begin(&ce.lease), -EBUSY);
	expect("UNKNOWN refuses unbind", xdev_ext_comp_copy_lease_unbind(&ce.lease, false), false);
	qualified(0, 1);
	expect("same generation cannot bypass UNKNOWN", enter(0), -EBUSY);
	qualified(1, PAYLOAD + 1);
	expect("new disjoint owner cannot bypass UNKNOWN", enter(1), -EBUSY);
	/* Deliberately retain the quarantined metadata until process exit. */
}

struct race_result { int get, finish; bool unknown; };
static void *race_worker(void *arg)
{
	struct race_result *r = arg;
	schedule_role = 1;
	r->get = enter(1);
	return NULL;
}
static void *race_terminal(void *arg)
{
	struct race_result *r = arg;
	schedule_role = 2;
	r->finish = xdev_ext_comp_copy_lease_finish(&ce.lease, 0, batches[0].id, r->unknown);
	return NULL;
}

static void race(void)
{
	pthread_t worker, finisher;
	struct race_result r = { 0 };

	initialize(true);
	qualified(0, 1);
	expect("race initial owner enters", enter(0), 0);
	qualified(1, 1); /* worker-owned plan remains stable throughout both calls */
	scheduled_mutex = &xdev_ext_ce_lease_domain.lock;
	schedule_enabled = true;
	os_check(pthread_create(&worker, NULL, race_worker, &r));
	os_check(pthread_create(&finisher, NULL, race_terminal, &r));
	os_check(pthread_join(worker, NULL));
	os_check(pthread_join(finisher, NULL));
	schedule_enabled = false;
	expect("worker under actual lock observes preceding range", r.get, -EAGAIN);
	expect("concurrent terminal releases actual owner", r.finish, 0);
	expect("worker retries after terminal", enter(1), 0);
	expect("atomic handoff retains one owner", ce.lease.group->state.active_batches, 1);
	cleanup();
	/* Same real-lock ordering, now terminal fate is UNKNOWN, not release. */
	get_has_lock = false;
	finish_ready = false;
	r = (struct race_result){ .unknown = true };
	initialize(true);
	qualified(0, 1);
	expect("UNKNOWN race initial owner enters", enter(0), 0);
	qualified(1, 1);
	schedule_enabled = true;
	os_check(pthread_create(&worker, NULL, race_worker, &r));
	os_check(pthread_create(&finisher, NULL, race_terminal, &r));
	os_check(pthread_join(worker, NULL));
	os_check(pthread_join(finisher, NULL));
	schedule_enabled = false;
	expect("worker cannot pass owner before UNKNOWN", r.get, -EAGAIN);
	expect("UNKNOWN finish retains owner", r.finish, -EBUSY);
	expect("UNKNOWN race retains just preceding owner", ce.lease.group->state.active_batches, 1);
	expect("UNKNOWN race blocks worker retry", enter(1), -EBUSY);
	expect("UNKNOWN race cannot unbind", xdev_ext_comp_copy_lease_unbind(&ce.lease, false), false);
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	if (!strcmp(argv[1], "controls")) controls();
	else if (!strcmp(argv[1], "validate")) validator();
	else if (!strcmp(argv[1], "lease")) leases();
	else if (!strcmp(argv[1], "unknown")) unknown();
	else if (!strcmp(argv[1], "race")) race();
	else return 2;
	printf("stage2 %s: %u checks, %u failures; qualified legacy-rejected inputs=%u\n",
		argv[1], checks, failures, qualified_inputs);
	return failures ? 1 : 0;
}
