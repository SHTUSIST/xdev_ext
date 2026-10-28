// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../xdev_ext_reference_policy_core.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static unsigned int checks;
static unsigned int failures;
static int fail_at;
static int null_at;
static unsigned int attach_calls;
static const char *events[32];
static unsigned int event_count;
static uintptr_t next_link = 1;

#define CHECK(condition, message) do { \
	checks++; \
	if (!(condition)) { \
		fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, message); \
		failures++; \
	} \
} while (0)

static void reset_fake(void)
{
	fail_at = -1;
	null_at = -1;
	attach_calls = 0;
	event_count = 0;
	next_link = 1;
	memset(events, 0, sizeof(events));
}

static int fake_attach(void *object, const char *map_name, void **link_out)
{
	(void)object;
	events[event_count++] = map_name;
	if ((int)attach_calls++ == fail_at)
		return -EBUSY;
	if ((int)attach_calls - 1 == null_at) {
		*link_out = NULL;
		return 0;
	}
	*link_out = (void *)next_link++;
	return 0;
}

static void fake_destroy_link(void *link)
{
	static const char *const destroy_events[] = {
		"destroy-1", "destroy-2", "destroy-3", "destroy-4", "destroy-5",
	};

	events[event_count++] = destroy_events[(uintptr_t)link - 1];
}

static void fake_close_object(void *object)
{
	(void)object;
	events[event_count++] = "close-object";
}

static const struct xdev_ext_reference_policy_ops fake_ops = {
	.attach = fake_attach,
	.destroy_link = fake_destroy_link,
	.close_object = fake_close_object,
};

static void test_attaches_all_backends_and_stops_in_reverse(void)
{
	static const char *const expected_attach[] = {
		"socket_policy", "afxdp_policy", "nvme_policy", "iaa_policy",
		"gpu_policy",
	};
	static const char *const expected_stop[] = {
		"destroy-5", "destroy-4", "destroy-3", "destroy-2",
		"destroy-1", "close-object",
	};
	struct xdev_ext_reference_policy_runtime runtime = {};
	unsigned int index;
	int ret;

	reset_fake();
	ret = xdev_ext_reference_policy_start(&runtime, (void *)0xabc, &fake_ops);
	CHECK(ret == 0, "all five policies attach");
	CHECK(runtime.attached == XDEV_EXT_REFERENCE_POLICY_COUNT,
	      "runtime retains all five links");
	CHECK(attach_calls == ARRAY_SIZE(expected_attach),
	      "exactly five attaches were attempted");
	for (index = 0; index < ARRAY_SIZE(expected_attach); index++)
		CHECK(!strcmp(events[index], expected_attach[index]),
		      "policy attach order matches the backend order");

	event_count = 0;
	xdev_ext_reference_policy_stop(&runtime, &fake_ops);
	CHECK(event_count == ARRAY_SIZE(expected_stop),
	      "stop destroys five links and closes the object");
	for (index = 0; index < ARRAY_SIZE(expected_stop); index++)
		CHECK(!strcmp(events[index], expected_stop[index]),
		      "stop order is reverse attach order then object close");
	CHECK(runtime.attached == 0 && !runtime.object,
	      "stop clears ownership state");
}

static void test_partial_failure_rolls_back_and_closes(void)
{
	static const char *const expected[] = {
		"socket_policy", "afxdp_policy", "nvme_policy",
		"destroy-2", "destroy-1", "close-object",
	};
	struct xdev_ext_reference_policy_runtime runtime = {};
	unsigned int index;
	int ret;

	reset_fake();
	fail_at = 2;
	ret = xdev_ext_reference_policy_start(&runtime, (void *)0xdef, &fake_ops);
	CHECK(ret == -EBUSY, "the attach conflict is returned to the caller");
	CHECK(event_count == ARRAY_SIZE(expected),
	      "partial failure records only acquired links plus object close");
	for (index = 0; index < ARRAY_SIZE(expected); index++)
		CHECK(!strcmp(events[index], expected[index]),
		      "partial attach failure rolls back in reverse order");
	CHECK(runtime.attached == 0 && !runtime.object,
	      "partial attach failure leaves no owned state");
}

static void test_every_partial_failure_rolls_back(void)
{
	struct xdev_ext_reference_policy_runtime runtime;
	unsigned int failed;

	for (failed = 0; failed < XDEV_EXT_REFERENCE_POLICY_COUNT; failed++) {
		unsigned int expected_destroy = failed;
		unsigned int index;
		int ret;

		memset(&runtime, 0, sizeof(runtime));
		reset_fake();
		fail_at = (int)failed;
		ret = xdev_ext_reference_policy_start(&runtime, (void *)0xdef,
						 &fake_ops);
		CHECK(ret == -EBUSY, "each attach conflict is returned");
		CHECK(runtime.attached == 0 && !runtime.object,
		      "each attach conflict releases all ownership");
		CHECK(event_count == failed + expected_destroy + 2,
		      "conflict logs attempts, reverse destroys, and close");
		for (index = 0; index < expected_destroy; index++)
			CHECK(!strncmp(events[failed + 1 + index], "destroy-", 8),
			      "rollback contains one destroy per acquired link");
		CHECK(!strcmp(events[event_count - 1], "close-object"),
		      "rollback closes the object last");
	}
}

static void test_success_with_null_link_is_protocol_error(void)
{
	struct xdev_ext_reference_policy_runtime runtime = {};
	int ret;

	reset_fake();
	null_at = 2;
	ret = xdev_ext_reference_policy_start(&runtime, (void *)0xdef, &fake_ops);
	CHECK(ret == -EPROTO, "success without a link is rejected");
	CHECK(runtime.attached == 0 && !runtime.object,
	      "null-link failure rolls back all acquired ownership");
	CHECK(event_count == 6, "null-link rollback destroys two links and closes");
	CHECK(!strcmp(events[3], "destroy-2") &&
	      !strcmp(events[4], "destroy-1") &&
	      !strcmp(events[5], "close-object"),
	      "null-link rollback order is exact");
}

static void test_busy_runtime_is_unchanged(void)
{
	struct xdev_ext_reference_policy_runtime runtime = {
		.object = (void *)0xabc,
		.links = { (void *)1 },
		.attached = 1,
	};
	int ret;

	reset_fake();
	ret = xdev_ext_reference_policy_start(&runtime, (void *)0xdef, &fake_ops);
	CHECK(ret == -EBUSY, "a live runtime cannot be started again");
	CHECK(!event_count && !attach_calls,
	      "busy start does not attach, detach, or close anything");
	CHECK(runtime.object == (void *)0xabc && runtime.attached == 1,
	      "busy start preserves the live runtime");
}

static void test_invalid_start_arguments(void)
{
	struct xdev_ext_reference_policy_runtime runtime = {};
	struct xdev_ext_reference_policy_ops missing = fake_ops;

	reset_fake();
	CHECK(xdev_ext_reference_policy_start(NULL, (void *)1, &fake_ops) == -EINVAL,
	      "null runtime is rejected");
	CHECK(xdev_ext_reference_policy_start(&runtime, NULL, &fake_ops) == -EINVAL,
	      "null object is rejected");
	CHECK(xdev_ext_reference_policy_start(&runtime, (void *)1, NULL) == -EINVAL,
	      "null operations are rejected");
	missing.attach = NULL;
	CHECK(xdev_ext_reference_policy_start(&runtime, (void *)1, &missing) == -EINVAL,
	      "missing attach operation is rejected");
	missing = fake_ops;
	missing.destroy_link = NULL;
	CHECK(xdev_ext_reference_policy_start(&runtime, (void *)1, &missing) == -EINVAL,
	      "missing destroy operation is rejected");
	missing = fake_ops;
	missing.close_object = NULL;
	CHECK(xdev_ext_reference_policy_start(&runtime, (void *)1, &missing) == -EINVAL,
	      "missing close operation is rejected");
	CHECK(!event_count && !attach_calls,
	      "invalid starts have no ownership side effects");
}

static void test_backend_descriptor_contract(void)
{
	static const char *const expected_maps[] = {
		"socket_policy", "afxdp_policy", "nvme_policy", "iaa_policy",
		"gpu_policy",
	};
	static const char *const expected_names[] = {
		"socket", "afxdp", "nvme", "iaa", "gpu",
	};
	static const unsigned int expected_ids[] = {
		XDEV_EXT_BINDING_BACKEND_SOCKET, XDEV_EXT_BINDING_BACKEND_AFXDP,
		XDEV_EXT_BINDING_BACKEND_NVME, XDEV_EXT_BINDING_BACKEND_IAA,
		XDEV_EXT_BINDING_BACKEND_GPU,
	};
	unsigned int index;

	CHECK(ARRAY_SIZE(xdev_ext_reference_policy_descriptors) ==
	      XDEV_EXT_REFERENCE_POLICY_COUNT,
	      "descriptor table has exactly five policies");
	for (index = 0; index < XDEV_EXT_REFERENCE_POLICY_COUNT; index++) {
		CHECK(!strcmp(xdev_ext_reference_policy_descriptors[index].map_name,
			      expected_maps[index]), "map order is stable");
		CHECK(!strcmp(xdev_ext_reference_policy_descriptors[index].backend_name,
			      expected_names[index]), "backend label is stable");
		CHECK(xdev_ext_reference_policy_descriptors[index].backend ==
		      expected_ids[index], "backend id is stable");
	}
}

static void test_final_stats_format(void)
{
	struct xdev_ext_reference_policy_backend_stats stats = {
		.dispatch_callbacks = 11,
		.dispatch_kfunc_ok = 10,
		.dispatch_kfunc_errors = 1,
		.complete_callbacks = 9,
		.complete_kfunc_ok = 8,
		.complete_kfunc_errors = 1,
		.result_ok = 7,
		.result_errors = 2,
		.bytes_done = 4096,
		.last_result = -5,
	};
	char output[512];
	int ret;

	ret = xdev_ext_reference_policy_format_backend(output, sizeof(output), 0,
						  &stats);
	CHECK(ret > 0, "one backend snapshot formats successfully");
	CHECK(!strcmp(output,
		"XDEV_EXT_REFERENCE_POLICY_FINAL backend=socket id=1 "
		"dispatch_callback=11 dispatch_kfunc_ok=10 dispatch_kfunc_errors=1 "
		"complete_callback=9 complete_kfunc_ok=8 complete_kfunc_errors=1 "
		"result_ok=7 result_errors=2 bytes=4096 last_result=-5\n"),
	      "final snapshot is stable and unambiguous");
	CHECK(xdev_ext_reference_policy_format_backend(output, 8, 0, &stats) ==
	      -ENOSPC, "truncated output is rejected");
	CHECK(xdev_ext_reference_policy_format_backend(NULL, sizeof(output), 0,
						  &stats) == -EINVAL,
	      "null output is rejected");
	CHECK(xdev_ext_reference_policy_format_backend(output, sizeof(output),
						  XDEV_EXT_REFERENCE_POLICY_COUNT,
						  &stats) == -EINVAL,
	      "out-of-range backend is rejected");
	CHECK(xdev_ext_reference_policy_format_backend(output, sizeof(output), 0,
						  NULL) == -EINVAL,
	      "null statistics are rejected");
}

static void test_stage_descriptor_contract(void)
{
	static const struct {
		unsigned int backend;
		const char *stage_name;
		unsigned int stage;
	} expected[] = {
		{ XDEV_EXT_BINDING_BACKEND_SOCKET, "send", XDEV_EXT_BINDING_STAGE_SEND },
		{ XDEV_EXT_BINDING_BACKEND_AFXDP, "afxdp_tx",
		  XDEV_EXT_BINDING_STAGE_AFXDP_TX },
		{ XDEV_EXT_BINDING_BACKEND_AFXDP, "afxdp_rx",
		  XDEV_EXT_BINDING_STAGE_AFXDP_RX },
		{ XDEV_EXT_BINDING_BACKEND_NVME, "nvme_read",
		  XDEV_EXT_BINDING_STAGE_NVME_READ },
		{ XDEV_EXT_BINDING_BACKEND_NVME, "nvme_write",
		  XDEV_EXT_BINDING_STAGE_NVME_WRITE },
		{ XDEV_EXT_BINDING_BACKEND_IAA, "iaa_compress",
		  XDEV_EXT_BINDING_STAGE_IAA_COMPRESS },
		{ XDEV_EXT_BINDING_BACKEND_IAA, "iaa_decompress",
		  XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS },
		{ XDEV_EXT_BINDING_BACKEND_GPU, "gpu_copy",
		  XDEV_EXT_BINDING_STAGE_GPU_COPY },
	};
	struct xdev_ext_reference_policy_stats stats;
	unsigned int index;

	CHECK(ARRAY_SIZE(xdev_ext_reference_policy_stage_descriptors) ==
	      XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT &&
	      XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT == ARRAY_SIZE(expected),
	      "stage table has one row per backend-owned stage");
	CHECK(ARRAY_SIZE(stats.stage) == XDEV_EXT_BINDING_STAGE_MAX,
	      "statistics keep one row per UAPI stage id");
	for (index = 0; index < ARRAY_SIZE(expected); index++) {
		const struct xdev_ext_reference_policy_stage_descriptor *stage =
			&xdev_ext_reference_policy_stage_descriptors[index];

		CHECK(stage->backend == expected[index].backend,
		      "stage row belongs to the expected backend");
		CHECK(!strcmp(stage->stage_name, expected[index].stage_name),
		      "stage label is stable");
		CHECK(stage->stage == expected[index].stage,
		      "stage id is stable");
		CHECK(stage->stage < ARRAY_SIZE(stats.stage),
		      "stage id indexes the statistics array");
	}
}

static void test_stage_stats_format(void)
{
	struct xdev_ext_reference_policy_backend_stats stats = {
		.dispatch_callbacks = 11,
		.dispatch_kfunc_ok = 10,
		.dispatch_kfunc_errors = 1,
		.complete_callbacks = 9,
		.complete_kfunc_ok = 8,
		.complete_kfunc_errors = 1,
		.result_ok = 7,
		.result_errors = 2,
		.bytes_done = 4096,
		.last_result = -5,
	};
	static const char prefix[] = "XDEV_EXT_REFERENCE_POLICY_FINAL";
	char output[XDEV_EXT_REFERENCE_POLICY_LINE_MAX];
	int ret;

	ret = xdev_ext_reference_policy_format_stage(output, sizeof(output), 2,
						&stats);
	CHECK(ret > 0, "one stage snapshot formats successfully");
	CHECK(!strcmp(output,
		"XDEV_EXT_REFERENCE_POLICY_STAGE_FINAL backend=afxdp id=2 "
		"stage=afxdp_rx stage_id=12 "
		"dispatch_callback=11 dispatch_kfunc_ok=10 dispatch_kfunc_errors=1 "
		"complete_callback=9 complete_kfunc_ok=8 complete_kfunc_errors=1 "
		"result_ok=7 result_errors=2 bytes=4096 last_result=-5\n"),
	      "stage snapshot names backend and stage and keeps every counter");
	CHECK(strncmp(output, prefix, sizeof(prefix) - 1),
	      "stage lines never match a ^XDEV_EXT_REFERENCE_POLICY_FINAL count");
	CHECK(xdev_ext_reference_policy_format_stage(output, 8, 2, &stats) ==
	      -ENOSPC, "truncated stage output is rejected");
	CHECK(xdev_ext_reference_policy_format_stage(NULL, sizeof(output), 2,
						&stats) == -EINVAL,
	      "null stage output is rejected");
	CHECK(xdev_ext_reference_policy_format_stage(output, sizeof(output),
						XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT,
						&stats) == -EINVAL,
	      "out-of-range stage row is rejected");
	CHECK(xdev_ext_reference_policy_format_stage(output, sizeof(output), 2,
						NULL) == -EINVAL,
	      "null stage statistics are rejected");
}

static void test_worst_case_lines_fit(void)
{
	struct xdev_ext_reference_policy_backend_stats stats;
	char output[XDEV_EXT_REFERENCE_POLICY_LINE_MAX];
	unsigned int index;

	memset(&stats, 0xff, sizeof(stats));
	stats.last_result = INT64_MIN;
	for (index = 0; index < XDEV_EXT_REFERENCE_POLICY_COUNT; index++)
		CHECK(xdev_ext_reference_policy_format_backend(
			      output, sizeof(output), index, &stats) > 0,
		      "a maximal backend line fits the loader line buffer");
	for (index = 0; index < XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT; index++)
		CHECK(xdev_ext_reference_policy_format_stage(
			      output, sizeof(output), index, &stats) > 0,
		      "a maximal stage line fits the loader line buffer");
}

struct snapshot_capture {
	char text[XDEV_EXT_REFERENCE_POLICY_LINE_MAX *
		  (XDEV_EXT_REFERENCE_POLICY_COUNT + XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT)];
	size_t used;
	unsigned int lines;
	int fail_at;
};

static int capture_line(const char *line, void *opaque)
{
	struct snapshot_capture *capture = opaque;
	size_t length = strlen(line);

	if ((int)capture->lines == capture->fail_at)
		return -EIO;
	capture->lines++;
	if (capture->used + length >= sizeof(capture->text))
		return -ENOSPC;
	memcpy(capture->text + capture->used, line, length + 1);
	capture->used += length;
	return 0;
}

static void set_row(struct xdev_ext_reference_policy_backend_stats *row,
		    unsigned long long calls, unsigned long long bytes)
{
	row->dispatch_callbacks = calls;
	row->dispatch_kfunc_ok = calls;
	row->complete_callbacks = calls;
	row->complete_kfunc_ok = calls;
	row->result_ok = calls;
	row->bytes_done = bytes;
}

static void test_snapshot_keeps_final_lines_and_appends_stage_lines(void)
{
	static const char expected[] =
		"XDEV_EXT_REFERENCE_POLICY_FINAL backend=socket id=1 dispatch_callback=3 dispatch_kfunc_ok=3 dispatch_kfunc_errors=0 complete_callback=3 complete_kfunc_ok=3 complete_kfunc_errors=0 result_ok=3 result_errors=0 bytes=25 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_FINAL backend=afxdp id=2 dispatch_callback=48 dispatch_kfunc_ok=48 dispatch_kfunc_errors=0 complete_callback=48 complete_kfunc_ok=48 complete_kfunc_errors=0 result_ok=48 result_errors=0 bytes=69472 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_FINAL backend=nvme id=3 dispatch_callback=8 dispatch_kfunc_ok=8 dispatch_kfunc_errors=0 complete_callback=8 complete_kfunc_ok=8 complete_kfunc_errors=0 result_ok=8 result_errors=0 bytes=65536 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_FINAL backend=iaa id=4 dispatch_callback=5 dispatch_kfunc_ok=5 dispatch_kfunc_errors=0 complete_callback=5 complete_kfunc_ok=5 complete_kfunc_errors=0 result_ok=5 result_errors=0 bytes=50 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_FINAL backend=gpu id=5 dispatch_callback=1 dispatch_kfunc_ok=1 dispatch_kfunc_errors=0 complete_callback=1 complete_kfunc_ok=1 complete_kfunc_errors=0 result_ok=1 result_errors=0 bytes=7 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_STAGE_FINAL backend=socket id=1 stage=send stage_id=4 dispatch_callback=3 dispatch_kfunc_ok=3 dispatch_kfunc_errors=0 complete_callback=3 complete_kfunc_ok=3 complete_kfunc_errors=0 result_ok=3 result_errors=0 bytes=25 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_STAGE_FINAL backend=afxdp id=2 stage=afxdp_tx stage_id=9 dispatch_callback=24 dispatch_kfunc_ok=24 dispatch_kfunc_errors=0 complete_callback=24 complete_kfunc_ok=24 complete_kfunc_errors=0 result_ok=24 result_errors=0 bytes=34000 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_STAGE_FINAL backend=afxdp id=2 stage=afxdp_rx stage_id=12 dispatch_callback=24 dispatch_kfunc_ok=24 dispatch_kfunc_errors=0 complete_callback=24 complete_kfunc_ok=24 complete_kfunc_errors=0 result_ok=24 result_errors=0 bytes=35472 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_STAGE_FINAL backend=nvme id=3 stage=nvme_read stage_id=7 dispatch_callback=4 dispatch_kfunc_ok=4 dispatch_kfunc_errors=0 complete_callback=4 complete_kfunc_ok=4 complete_kfunc_errors=0 result_ok=4 result_errors=0 bytes=32768 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_STAGE_FINAL backend=nvme id=3 stage=nvme_write stage_id=8 dispatch_callback=4 dispatch_kfunc_ok=4 dispatch_kfunc_errors=0 complete_callback=4 complete_kfunc_ok=4 complete_kfunc_errors=0 result_ok=4 result_errors=0 bytes=32768 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_STAGE_FINAL backend=iaa id=4 stage=iaa_compress stage_id=10 dispatch_callback=2 dispatch_kfunc_ok=2 dispatch_kfunc_errors=0 complete_callback=2 complete_kfunc_ok=2 complete_kfunc_errors=0 result_ok=2 result_errors=0 bytes=20 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_STAGE_FINAL backend=iaa id=4 stage=iaa_decompress stage_id=11 dispatch_callback=3 dispatch_kfunc_ok=3 dispatch_kfunc_errors=0 complete_callback=3 complete_kfunc_ok=3 complete_kfunc_errors=0 result_ok=3 result_errors=0 bytes=30 last_result=0\n"
		"XDEV_EXT_REFERENCE_POLICY_STAGE_FINAL backend=gpu id=5 stage=gpu_copy stage_id=3 dispatch_callback=1 dispatch_kfunc_ok=1 dispatch_kfunc_errors=0 complete_callback=1 complete_kfunc_ok=1 complete_kfunc_errors=0 result_ok=1 result_errors=0 bytes=7 last_result=0\n";
	struct xdev_ext_reference_policy_stats stats;
	struct snapshot_capture capture;
	int ret;

	/* Distinct values per row expose a printer that reads the wrong row,
	 * e.g. the descriptor index instead of the UAPI stage id.
	 */
	memset(&stats, 0, sizeof(stats));
	set_row(&stats.backend[XDEV_EXT_BINDING_BACKEND_SOCKET], 3, 25);
	set_row(&stats.backend[XDEV_EXT_BINDING_BACKEND_AFXDP], 48, 69472);
	set_row(&stats.backend[XDEV_EXT_BINDING_BACKEND_NVME], 8, 65536);
	set_row(&stats.backend[XDEV_EXT_BINDING_BACKEND_IAA], 5, 50);
	set_row(&stats.backend[XDEV_EXT_BINDING_BACKEND_GPU], 1, 7);
	set_row(&stats.stage[XDEV_EXT_BINDING_STAGE_SEND], 3, 25);
	set_row(&stats.stage[XDEV_EXT_BINDING_STAGE_AFXDP_TX], 24, 34000);
	set_row(&stats.stage[XDEV_EXT_BINDING_STAGE_AFXDP_RX], 24, 35472);
	set_row(&stats.stage[XDEV_EXT_BINDING_STAGE_NVME_READ], 4, 32768);
	set_row(&stats.stage[XDEV_EXT_BINDING_STAGE_NVME_WRITE], 4, 32768);
	set_row(&stats.stage[XDEV_EXT_BINDING_STAGE_IAA_COMPRESS], 2, 20);
	set_row(&stats.stage[XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS], 3, 30);
	set_row(&stats.stage[XDEV_EXT_BINDING_STAGE_GPU_COPY], 1, 7);
	/* Rows no backend owns are never printed. */
	set_row(&stats.stage[XDEV_EXT_BINDING_STAGE_NONE], 99, 99);
	set_row(&stats.stage[XDEV_EXT_BINDING_STAGE_FILE_WRITE], 99, 99);

	memset(&capture, 0, sizeof(capture));
	capture.fail_at = -1;
	ret = xdev_ext_reference_policy_emit_snapshot(&stats, capture_line,
						 &capture);
	CHECK(ret == 0, "full snapshot emits successfully");
	CHECK(capture.lines ==
	      XDEV_EXT_REFERENCE_POLICY_COUNT + XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT,
	      "snapshot is five backend lines plus eight stage lines");
	CHECK(!strcmp(capture.text, expected),
	      "backend lines are unchanged and stage lines follow them");
	if (strcmp(capture.text, expected))
		fprintf(stderr, "got:\n%s", capture.text);

	memset(&capture, 0, sizeof(capture));
	capture.fail_at = 6;
	CHECK(xdev_ext_reference_policy_emit_snapshot(&stats, capture_line,
						 &capture) == -EIO,
	      "an emit failure is returned to the caller");
	CHECK(capture.lines == 6, "emission stops at the first failure");
	CHECK(xdev_ext_reference_policy_emit_snapshot(NULL, capture_line,
						 &capture) == -EINVAL,
	      "null statistics are rejected");
	CHECK(xdev_ext_reference_policy_emit_snapshot(&stats, NULL, &capture) ==
	      -EINVAL, "null emitter is rejected");
}

static void test_stats_map_value_size_is_exact(void)
{
	CHECK(xdev_ext_reference_policy_stats_value_size_valid(
		      sizeof(struct xdev_ext_reference_policy_stats)),
	      "the exact statistics map layout is accepted");
	CHECK(!xdev_ext_reference_policy_stats_value_size_valid(
		       sizeof(struct xdev_ext_reference_policy_stats) - 1),
	      "a smaller statistics map layout is rejected");
	CHECK(!xdev_ext_reference_policy_stats_value_size_valid(
		       sizeof(struct xdev_ext_reference_policy_stats) + 1),
	      "a larger statistics map layout is rejected before lookup");
}

static void test_stop_is_idempotent(void)
{
	struct xdev_ext_reference_policy_runtime runtime = {};

	reset_fake();
	xdev_ext_reference_policy_stop(&runtime, &fake_ops);
	CHECK(event_count == 0, "stopping an empty runtime is a no-op");
}

int main(void)
{
	test_attaches_all_backends_and_stops_in_reverse();
	test_partial_failure_rolls_back_and_closes();
	test_every_partial_failure_rolls_back();
	test_success_with_null_link_is_protocol_error();
	test_busy_runtime_is_unchanged();
	test_invalid_start_arguments();
	test_backend_descriptor_contract();
	test_final_stats_format();
	test_stage_descriptor_contract();
	test_stage_stats_format();
	test_worst_case_lines_fit();
	test_snapshot_keeps_final_lines_and_appends_stage_lines();
	test_stats_map_value_size_is_exact();
	test_stop_is_idempotent();

	printf("xdev_ext_reference_policy_core: %u checks, %u failures\n",
	       checks, failures);
	return failures ? 1 : 0;
}
