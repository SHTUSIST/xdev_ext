// SPDX-License-Identifier: GPL-2.0
/* Independently specified XDOMAIN RX -> CE TARGET_RANGE data/lifetime checks.
 * Native device execution is the deterministic CE simulator, not GPU DMA.
 * The oracle derives payload from input group IDs and selected target offsets;
 * it reads the entire device window without inspecting generated CE plans.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <linux/types.h>
#include <linux/xdev_ext_mech.h>
#include "chain_api.h"
#include "chain_core_api.h"
#include "chain_ce_api.h"

#define FRAME 4096u
#define GROUP 8192u
#define ACK 3u
#define FAIL 5u
#define BUDGET 200000u
#define FIRST_SEQ 1u
#define CE_GROUP GROUP
#define CE_FRAME FRAME
static unsigned assertions;
static const char *case_name = "?";
#define CHECK(c, why) do { assertions++; if (!(c)) { \
 fprintf(stderr, "CHAIN_ASSERT %s: %s (%s:%d)\n", case_name, why, __FILE__, __LINE__); \
 exit(1); } } while (0)

/* Helpers visible to the independently owned RX fault cases below. */
static struct xdev_ext_mech_session *tx, *rx;
static unsigned depth = 2, frames = 4, window = 2;
static bool early;
static const uint64_t default_targets[] = { 3 * GROUP + 17, 3, 8 * GROUP + 31, 5 * GROUP + 7 };
static const uint64_t *targets = default_targets;
static unsigned target_count = sizeof(default_targets) / sizeof(default_targets[0]);
static void up(void);
static void start(unsigned n);
static void pump(uint64_t advance);
static void settle(unsigned rounds);
static void pristine(void);
static void verify_window(unsigned n);
static void no_reusable_frames(void);
static unsigned count(unsigned kind, unsigned endpoint);
/* Root RX-case API: named wrappers keep this file independently editable. */
static void ce_up(const uint64_t *offsets, unsigned n)
{ if (offsets) { targets = offsets; target_count = n; } up(); }
static void ce_start(unsigned n) { start(n); }
static void ce_pump(uint64_t ns) { pump(ns); }
static void ce_settle(unsigned rounds) { settle(rounds); }
static void ce_pristine(void) { pristine(); }
static void ce_verify(unsigned n) { verify_window(n); }

/* Every group begins with a little-endian ID and its complement. The rest
 * depends on both that ID and byte position, exposing swaps, stale copies,
 * constant-fill "copies", omitted descriptors and off-by-one destinations. */
static uint8_t payload(unsigned group, unsigned offset)
{
	uint64_t id = group;
	uint32_t x;

	if (offset < 8)
		return (uint8_t)(id >> (8 * offset));
	if (offset < 16)
		return (uint8_t)(~id >> (8 * (offset - 8)));
	x = group * 2654435761u ^ offset * 2246822519u;
	x ^= x >> 15;
	x *= 3266489917u;
	return (uint8_t)(x ^ (x >> 8) ^ (x >> 19));
}

static unsigned count(unsigned kind, unsigned endpoint)
{
	unsigned n = 0;

	for (size_t i = 0; i < chain_event_count(); i++) {
		const struct chain_event *e = chain_event_get(i);
		n += e->kind == kind && e->endpoint == endpoint;
	}
	return n;
}

static void pump(uint64_t advance)
{
	unsigned steps = 0;
	int rc;

	while ((rc = chain_pump(1, advance)) == -ELOOP) {
		advance = 0;
		CHECK(++steps < BUDGET, "bounded scheduler drains");
	}
	CHECK(rc == 0, "scheduler reports no error");
}
static void settle(unsigned rounds)
{
	for (unsigned i = 0; i < rounds; i++)
		pump(1000000);
}

static void up(void)
{
	struct chain_link_config cfg = { .frame_size = FRAME, .nr_frames = frames,
		.depth = depth, .group_bytes = GROUP, .early = early,
		.window_tx = window, .window_rx = window };
	size_t bytes;
	uint8_t *disk;
	int err = 0;

	CHECK(chain_world(&cfg) == 0, "two endpoints have a negotiated XDOMAIN data link");
	CHECK(chain_host_mode(), "the composition uses the rings' real IOU_UMEM pools");
	CHECK(target_count > 0, "oracle has an explicit target input table");
	chain_ce_targets(targets, target_count);
	disk = chain_nvme_disk(0, &bytes);
	CHECK(disk && bytes >= (256 + 256) * 512, "sender input window exists");
	memset(disk, 0x5b, bytes);
	/* Sender window is 256 LBAs at LBA256, with 16 groups of 8192 bytes.
	 * NVMe reference program selects request-ID modulo16; first request1
	 * therefore reads group1. This is independent of CE's input/output. */
	for (unsigned group = 0; group < 16; group++)
		for (unsigned i = 0; i < GROUP; i++)
			disk[256 * 512 + group * GROUP + i] = payload(group, i);
	rx = chain_ce_rx_session(&err);
	if (err)
		fprintf(stderr, "CHAIN_CE_CREATE receiver err=%d\n", err);
	CHECK(!err && rx, "actual CREATE binds XDOMAIN RX then CE TARGET_RANGE");
	tx = chain_tx_session(&err, 0);
	CHECK(!err && tx, "sender CREATE binds NVMe READ then XDOMAIN TX");
	chain_ce_poison(CHAIN_CE_POISON);
}

static void start(unsigned n)
{
	CHECK(chain_start(rx, n, FIRST_SEQ) == 0, "receiver START lends Host frames");
	CHECK(chain_start(tx, n, FIRST_SEQ) == 0, "sender START generates matching group IDs");
}

static void expected_window(unsigned n, uint8_t *want)
{
	memset(want, CHAIN_CE_POISON, CHAIN_CE_WINDOW_BYTES);
	for (unsigned g = 0; g < n; g++) {
		uint64_t at = targets[g % target_count];
		CHECK(at <= CHAIN_CE_WINDOW_BYTES - GROUP, "target test input is in bounds");
		for (unsigned j = 0; j < GROUP; j++)
			want[at + j] = payload(g + 1, j);
	}
}

static void verify_window(unsigned n)
{
	static uint8_t actual[CHAIN_CE_WINDOW_BYTES], expected[CHAIN_CE_WINDOW_BYTES];

	expected_window(n, expected);
	CHECK(chain_ce_read(0, actual, sizeof(actual)) == 0,
	      "independent out-of-band read returns the entire device window");
	for (size_t i = 0; i < sizeof(actual); i++)
		if (actual[i] != expected[i]) {
			fprintf(stderr, "CE_DATA_MISMATCH offset=%zu actual=%02x expected=%02x completed_groups=%u\n",
				i, actual[i], expected[i], n);
			CHECK(false, "every payload byte, target offset and untouched guard byte matches");
		}
	assertions++;
}
static void pristine(void) { verify_window(0); }

/* This witness is recorded before RX writes the received bytes. It checks
 * source identity on the link independently of GPU memory or CE plans. */
static void verify_sent(unsigned groups)
{
	unsigned position = 0;

	for (size_t i = 0; i < chain_event_count(); i++) {
		const struct chain_event *e = chain_event_get(i);
		const uint8_t *bytes;

		if (e->kind != CHAIN_EV_DATA_DELIVER || e->endpoint != 0)
			continue;
		bytes = chain_delivered_bytes(e);
		CHECK(bytes && !e->status, "source bytes were captured before receiver write");
		CHECK(position + e->length <= groups * GROUP, "the link carried no extra payload");
		for (unsigned j = 0; j < e->length; j++, position++)
			if (bytes[j] != payload(position / GROUP + 1, position % GROUP)) {
				fprintf(stderr, "CE_SOURCE_MISMATCH group=%u offset=%u actual=%02x\n",
					position / GROUP + 1, position % GROUP, bytes[j]);
				CHECK(false, "input carries the specified distinct group ID and byte pattern");
			}
	}
	CHECK(position == groups * GROUP, "the link carried exactly all requested groups");
}

static void no_reusable_frames(void)
{
	for (unsigned i = 0; i < frames; i++) {
		unsigned state = chain_frame_custody(rx, i);
		CHECK(state != chain_frame_state_free() && state != chain_frame_state_user(),
		      "a receiver frame remains unavailable while its device access is unsettled");
	}
}

static void finished(unsigned n)
{
	struct chain_ce_stats cs = chain_ce_stats();

	CHECK(cs.accepted == n && cs.completed == n && !cs.pending,
	      "exactly the requested native CE copies completed");
	CHECK(cs.copies == n && cs.bytes == (uint64_t)n * GROUP,
	      "the native simulator actually copied every group's bytes");
	CHECK(chain_stage_completed(rx, 0) == n && chain_stage_completed(rx, 1) == n,
	      "real RX and CE stage completions both reached the core worker");
	CHECK(chain_session_done(rx) == n && chain_session_done(tx) == n,
	      "both sessions reached successful final batch disposition");
	CHECK(!chain_session_aborted(rx) && !chain_session_aborted(tx), "no success was hidden by abort");
	CHECK(chain_control_tx_count(1, ACK) == n,
	      "each receiver final release emitted its matching XDOMAIN ACK");
	CHECK(!chain_violations(), "no requester access or ownership boundary was violated");
	verify_sent(n);
	verify_window(n);
}

static void data_ranges(void)
{
	up();
	start(4);
	pump(0);
	settle(4);
	finished(4);
	CHECK(chain_stage_unbind_now(rx, 1) == 0, "quiesced CE stage releases cleanly");
	CHECK(chain_ce_stats().host_unbinds == 1 && chain_ce_stats().region_unbinds == 1,
	      "settled batch release lets native Host and GPU mappings unbind exactly once");
}

static void held_frames(void)
{
	uint8_t before[4 * FRAME];
	size_t bytes;

	up();
	chain_ce_hold(true);
	start(2);
	pump(0);
	CHECK(chain_ce_stats().pending == 2, "two disjoint target ranges may be outstanding");
	CHECK(chain_stage_completed(rx, 0) == 2, "both RX groups fully completed before CE");
	CHECK(!chain_session_done(rx) && !chain_session_done(tx), "held CE completes neither session");
	CHECK(!chain_control_tx_count(1, ACK), "RX success alone emits no final ACK");
	CHECK(chain_stage_unbind_checked(rx, 1) == -EBUSY, "in-flight ranges deny native unbind");
	CHECK(chain_frame_memory(1, &bytes) && bytes == sizeof(before), "four receiver Host frames exist");
	memcpy(before, chain_frame_memory(1, &bytes), sizeof(before));
	no_reusable_frames();
	settle(5);
	CHECK(!memcmp(before, chain_frame_memory(1, &bytes), sizeof(before)),
	      "pending CE source frames retain their received bytes across scheduler progress");
	no_reusable_frames();
	pristine();
	chain_ce_hold(false);
	pump(0);
	settle(2);
	finished(2);
}

static void submit_failed(void)
{
	depth = 1; frames = 2; window = 1;
	up();
	chain_ce_fail_submit(-EIO);
	start(1);
	pump(0);
	settle(2);
	CHECK(chain_ce_stats().rejected == 1 && !chain_ce_stats().accepted,
	      "preaccept CE refusal never creates a native request");
	CHECK(chain_session_aborted(rx) == 1 && !chain_session_done(rx), "refusal aborts the batch");
	CHECK(!chain_control_tx_count(1, ACK), "CE refusal cannot ACK the received group as restored");
	CHECK(!chain_ce_stats().copies && !chain_ce_stats().pending, "refusal copies no bytes");
	pristine();
	CHECK(chain_stage_unbind_now(rx, 1) == 0,
	      "preaccept failure releases its range at final batch disposition");
}

/* RX succeeds with complete data, but this placement's last byte escapes
 * the bound GPU window. CREATE still succeeds; the actual runtime validator
 * must refuse the generated plan before acquiring/submitting a native copy. */
static void invalid_target(void)
{
	static const uint64_t outside[] = { CHAIN_CE_WINDOW_BYTES - GROUP + 1 };

	depth = 1; frames = 2; window = 1;
	targets = outside; target_count = 1;
	up();
	start(1);
	pump(0);
	settle(50);
	CHECK(chain_stage_completed(rx, 0) == 1, "the complete RX reached runtime CE validation");
	CHECK(!chain_stage_submitted(rx, 1) && !chain_ce_stats().accepted && !chain_ce_stats().rejected,
	      "an out-of-window runtime plan never reaches native CE submit");
	CHECK(chain_session_aborted(rx) == 1 && !chain_session_done(rx),
	      "invalid placement aborts the restore");
	CHECK(chain_session_last_err(rx) == -ERANGE, "actual CE validator reports the window bound");
	/* Ordered Host-loan failure stops the session. Paired EARLY may close
	 * the link on STOP before a group FAIL is sent; both protocols must
	 * withhold success, independently of their failure notification. */
	CHECK(!chain_control_tx_count(1, ACK) && !chain_session_done(tx),
	      "invalid placement cannot acknowledge restoration at either endpoint");
	CHECK(!chain_ce_stats().copies && !chain_ce_stats().pending,
	      "rejected plan creates neither a copy nor a live native request");
	for (unsigned i = 0; i < frames; i++)
		CHECK(chain_frame_custody(rx, i) == chain_frame_state_user(),
		      "known-quiesced plan rejection returns its Host frames");
	verify_sent(1);
	pristine();
	CHECK(chain_stage_unbind_now(rx, 1) == 0,
	      "rejected runtime plan leaves no acquired range or native mapping behind");
}

static void contended_range(void)
{
	static const uint64_t same[] = { GROUP + 19, GROUP + 19 };

	targets = same; target_count = 2;
	up();
	chain_ce_hold(true);
	start(2);
	pump(0);
	CHECK(chain_stage_completed(rx, 0) == 2, "both groups reached the CE stage");
	CHECK(chain_ce_stats().accepted == 1 && chain_ce_stats().pending == 1,
	      "an overlapping target cannot reach native CE while the first lease is live");
	no_reusable_frames();
	pristine();
	CHECK(chain_ce_complete_next(0, true, true, UINT64_MAX) == 1, "first copy reports completion");
	CHECK(!chain_session_done(rx) && !chain_control_tx_count(1, ACK),
	      "native completion alone has not run final batch release or ACK");
	CHECK(chain_stage_unbind_checked(rx, 1) == -EBUSY,
	      "range lease remains live between native completion and batch release");
	pump(0);
	settle(2);
	CHECK(chain_ce_stats().accepted == 2 && chain_ce_stats().pending == 1,
	      "waiting overlap is submitted only after the prior batch releases its lease");
	CHECK(chain_session_done(rx) == 1, "only the first group is restored so far");
	verify_window(1);
	CHECK(chain_ce_complete_next(0, true, true, UINT64_MAX) == 1, "second copy completes");
	pump(0);
	settle(2);
	finished(2);
}

static void unknown_completion(bool short_success)
{
	struct chain_ce_lease_snapshot before, uncertain, late;

	depth = 1; frames = 2; window = 1;
	up();
	chain_ce_hold(true);
	start(1);
	pump(0);
	CHECK(chain_ce_stats().pending == 1, "CE accepted one live native request");
	before = chain_ce_lease_snapshot(rx, 1, 0);
	CHECK(before.active_batches == 1 && before.slot_active && before.target_range && !before.quarantined,
	      "accepted CE owns one live target range before any uncertain outcome");
	CHECK(before.generation && before.range_start == targets[0] && before.range_len == GROUP,
	      "live range metadata identifies this generation and the input target");
	CHECK(chain_ce_complete_next(short_success ? 0 : -ETIMEDOUT, true,
		short_success, short_success ? GROUP - 1 : 0) == 1, "native result was injected");
	pump(0);
	settle(2);
	CHECK(!chain_session_done(rx) && !chain_control_tx_count(1, ACK),
	      "uncertain or short CE completion cannot produce successful restore or ACK");
	for (unsigned i = 0; i < frames; i++)
		CHECK(chain_frame_custody(rx, i) == chain_frame_state_sequestered(),
		      "accepted uncertain CE access permanently retains each Host frame");
	/* Unbind also checks the class's ambiguous count; observe the actual
	 * range-owner table separately so that this gate cannot hide release. */
	uncertain = chain_ce_lease_snapshot(rx, 1, 0);
	CHECK(uncertain.active_batches == 1 && uncertain.slot_active && uncertain.quarantined,
	      "final UNKNOWN disposition quarantines the still-active range owner");
	CHECK(uncertain.target_range && uncertain.generation == before.generation &&
	      uncertain.range_start == before.range_start && uncertain.range_len == before.range_len,
	      "UNKNOWN preserves the accepted generation and exact target range");
	CHECK(chain_stage_unbind_checked(rx, 1) == -EBUSY, "uncertain native access denies unbind");
	CHECK(!chain_ce_stats().host_unbinds && !chain_ce_stats().region_unbinds,
	      "uncertain completion retains both native mappings");
	/* A later full-success report for the same accepted ticket must not
	 * override the first uncertain disposition or return its ownership. */
	chain_ce_replay_last_as(0, true, GROUP);
	pump(0);
	settle(2);
	CHECK(!chain_session_done(rx) && !chain_control_tx_count(1, ACK),
	      "a late success callback cannot change the earlier uncertain disposition");
	CHECK(chain_stage_completed(rx, 1) == 1,
	      "the old ticket publishes exactly one core CE completion");
	no_reusable_frames();
	late = chain_ce_lease_snapshot(rx, 1, 0);
	CHECK(late.active_batches == 1 && late.slot_active && late.quarantined,
	      "late success leaves the actual range owner active and quarantined");
	CHECK(late.target_range == uncertain.target_range && late.generation == uncertain.generation &&
	      late.range_start == uncertain.range_start && late.range_len == uncertain.range_len,
	      "late success cannot alter the quarantined generation or target range");
	CHECK(chain_stage_unbind_checked(rx, 1) == -EBUSY, "late callback cannot authorize native unbind");
	if (short_success)
		verify_window(1); /* bytes exist, but the reported short result stays unsafe */
	else
		pristine();
}

static void stale_after_reuse(void)
{
	depth = 1; frames = 2; window = 1;
	up();
	chain_ce_hold(true);
	start(2);
	pump(0);
	CHECK(chain_ce_stats().accepted == 1, "first generation is accepted");
	CHECK(chain_ce_complete_next(0, true, true, UINT64_MAX) == 1, "first generation completes");
	pump(0);
	settle(2);
	CHECK(chain_ce_stats().accepted == 2 && chain_ce_stats().pending == 1,
	      "same batch slot and Host frames are reused only after first final completion");
	CHECK(chain_session_done(rx) == 1 && chain_stage_completed(rx, 1) == 1,
	      "the second generation is still incomplete");
	verify_window(1);
	chain_ce_replay_last();
	pump(0);
	CHECK(chain_session_done(rx) == 1 && chain_stage_completed(rx, 1) == 1,
	      "old ticket cannot finish the new generation's CE cookie");
	CHECK(chain_ce_stats().pending == 1, "old callback consumes no live native request");
	no_reusable_frames();
	verify_window(1);
	CHECK(chain_ce_complete_next(0, true, true, UINT64_MAX) == 1, "live ticket completes the second group");
	pump(0);
	settle(2);
	finished(2);
}

#include "ce_rx_cases.h"

int main(int argc, char **argv)
{
	char name[96];
	size_t len;

	if (argc != 2 || (len = strlen(argv[1])) >= sizeof(name))
		return 2;
	case_name = argv[1];
	strcpy(name, case_name);
	if (len > 6 && !strcmp(name + len - 6, "_early")) {
		early = true;
		name[len - 6] = 0;
	}
	if (!strcmp(name, "ce_data_ranges") || !strcmp(name, "ce_data")) data_ranges();
	else if (!strcmp(name, "ce_host_hold")) held_frames();
	else if (!strcmp(name, "ce_submit_fail")) submit_failed();
	else if (!strcmp(name, "ce_plan_bounds")) invalid_target();
	else if (!strcmp(name, "ce_range_overlap")) contended_range();
	else if (!strcmp(name, "ce_unknown_late")) unknown_completion(false);
	else if (!strcmp(name, "ce_short_complete")) unknown_completion(true);
	else if (!strcmp(name, "ce_stale_reuse")) stale_after_reuse();
	else if (!ce_rx_case(name)) return 2;
	printf("CHAIN_CASE %s assertions=%u\n", case_name, assertions);
	return 0;
}
