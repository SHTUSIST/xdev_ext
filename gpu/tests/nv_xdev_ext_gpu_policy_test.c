/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel-open/nvidia/nv-xdev_ext-gpu-policy.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static unsigned int checks;
static unsigned int failures;

#define EXPECT_TRUE(expr)                                                       \
	do {                                                                     \
		checks++;                                                        \
		if (!(expr)) {                                                   \
			fprintf(stderr, "%s:%d: EXPECT_TRUE(%s) failed\n",       \
				__FILE__, __LINE__, #expr);                         \
			failures++;                                               \
		}                                                                \
	} while (0)

#define EXPECT_EQ(expected, actual)                                             \
	do {                                                                     \
		uint64_t _expected = (uint64_t)(expected);                       \
		uint64_t _actual = (uint64_t)(actual);                           \
		checks++;                                                        \
		if (_expected != _actual) {                                     \
			fprintf(stderr, "%s:%d: expected 0x%" PRIx64             \
				", got 0x%" PRIx64 "\n", __FILE__, __LINE__,      \
				_expected, _actual);                               \
			failures++;                                               \
		}                                                                \
	} while (0)

enum fake_event {
	FAKE_EVENT_DISPATCH = 1,
	FAKE_EVENT_SUBMIT,
	FAKE_EVENT_COMPLETE,
	FAKE_EVENT_PUT,
};

struct fake_env {
	struct nv_xdev_ext_gpu_plan dispatch_plan;
	struct nv_xdev_ext_gpu_plan complete_plan;
	int dispatch_rc;
	int complete_rc;
	int mapped_errno;
	uint32_t native_status;
	unsigned int dispatches;
	unsigned int submits;
	unsigned int completes;
	unsigned int puts;
	unsigned int events[8];
	unsigned int event_count;
	int token_live;
	int close_during_submit;
	int registry_refs;
	int buffer_freed;
	struct nv_xdev_ext_gpu_result seen_result;
	struct nv_xdev_ext_gpu_request seen_request;
};

static void record_event(struct fake_env *env, unsigned int event)
{
	if (env->event_count < ARRAY_SIZE(env->events))
		env->events[env->event_count++] = event;
}

static int fake_dispatch(void *private,
			 const struct nv_xdev_ext_gpu_request *request,
			 struct nv_xdev_ext_gpu_plan *plan)
{
	struct fake_env *env = private;

	env->dispatches++;
	record_event(env, FAKE_EVENT_DISPATCH);
	env->seen_request = *request;
	*plan = env->dispatch_plan;
	if (!env->dispatch_rc &&
	    plan->action != NV_XDEV_EXT_GPU_ACTION_TERMINAL)
		env->token_live = 1;
	return env->dispatch_rc;
}

static uint32_t fake_submit(void *private,
			    const struct nv_xdev_ext_gpu_request *request)
{
	struct fake_env *env = private;

	(void)request;
	env->submits++;
	record_event(env, FAKE_EVENT_SUBMIT);
	if (env->close_during_submit) {
		EXPECT_EQ(2, env->registry_refs);
		env->registry_refs--;
		EXPECT_TRUE(!env->buffer_freed);
	}
	return env->native_status;
}

static int fake_complete(void *private,
			 const struct nv_xdev_ext_gpu_request *request,
			 const struct nv_xdev_ext_gpu_result *result,
			 struct nv_xdev_ext_gpu_plan *plan)
{
	struct fake_env *env = private;

	(void)request;
	env->completes++;
	record_event(env, FAKE_EVENT_COMPLETE);
	env->seen_result = *result;
	*plan = env->complete_plan;
	EXPECT_TRUE(env->token_live);
	env->token_live = 0;
	return env->complete_rc;
}

static void fake_put(void *private)
{
	struct fake_env *env = private;

	env->puts++;
	record_event(env, FAKE_EVENT_PUT);
	env->token_live = 0;
}

static int32_t fake_normalize(void *private, uint32_t status)
{
	struct fake_env *env = private;

	(void)status;
	return env->mapped_errno;
}

static const struct nv_xdev_ext_gpu_ops fake_ops = {
	.dispatch = fake_dispatch,
	.submit = fake_submit,
	.complete = fake_complete,
	.token_put = fake_put,
	.normalize_status = fake_normalize,
};

static struct nv_xdev_ext_gpu_request valid_request(uint32_t direction,
					       uint32_t gpu_page_size)
{
	struct nv_xdev_ext_gpu_request request = {
		.request_id = 0x101,
		.chain_id = 0x102,
		.endpoint_id = 0x103,
		.umem_buffer_id = 0x104,
		.gpu_buffer_id = 0x105,
		.direction = direction,
		.umem_offset = 4096,
		.gpu_offset = gpu_page_size / 2,
		.length = gpu_page_size,
		.umem_capacity = 1024 * 1024,
		.umem_page_size = 4096,
		.umem_page_count = 256,
		.gpu_page_size = gpu_page_size,
		.gpu_page_count = 2,
	};

	return request;
}

static struct fake_env valid_env(uint32_t action, uint32_t native_status)
{
	struct fake_env env = {
		.dispatch_plan = { .action = action },
		.complete_plan = { .action = NV_XDEV_EXT_GPU_ACTION_FALLBACK },
		.native_status = native_status,
		.mapped_errno = -EIO,
	};

	return env;
}

static void expect_run_order(const struct fake_env *env)
{
	EXPECT_EQ(3, env->event_count);
	EXPECT_EQ(FAKE_EVENT_DISPATCH, env->events[0]);
	EXPECT_EQ(FAKE_EVENT_SUBMIT, env->events[1]);
	EXPECT_EQ(FAKE_EVENT_COMPLETE, env->events[2]);
}

static void test_page_coverage_and_overflow(void)
{
	const uint32_t page_sizes[] = { 4096, 65536, 131072 };
	struct nv_xdev_ext_gpu_request request;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(page_sizes); i++) {
		request = valid_request(NV_XDEV_EXT_GPU_UMEM_TO_GPU, page_sizes[i]);
		EXPECT_EQ(0, nv_xdev_ext_gpu_validate_request(&request));
	}

	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.umem_offset = request.umem_capacity - 1024;
	request.length = 2048;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));

	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.umem_offset = UINT64_MAX - 1024;
	request.umem_capacity = UINT64_MAX;
	request.length = 2048;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));

	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.umem_page_count = 1;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));

	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.gpu_page_count = 1;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));

	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 8192);
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));

	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.direction = 2;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));

	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.length = 0;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));

	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.length = (uint64_t)UINT32_MAX + 1;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));

	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.request_id = 0;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));
	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.chain_id = 0;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));
	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.endpoint_id = 0;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));
	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.umem_buffer_id = 0;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));
	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	request.gpu_buffer_id = 0;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_gpu_validate_request(&request));
}

static void test_direction_routes_only_relative_offsets(void)
{
	struct nv_xdev_ext_gpu_request request;
	struct nv_xdev_ext_gpu_route route;

	request = valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 65536);
	EXPECT_EQ(0, nv_xdev_ext_gpu_make_route(&request, &route));
	EXPECT_EQ(NV_XDEV_EXT_GPU_FROM_DEVICE, route.device_direction);
	EXPECT_EQ(request.gpu_offset, route.src_offset);
	EXPECT_EQ(request.umem_offset, route.dst_offset);
	EXPECT_EQ(request.gpu_buffer_id, route.src_buffer_id);
	EXPECT_EQ(request.umem_buffer_id, route.dst_buffer_id);

	request = valid_request(NV_XDEV_EXT_GPU_UMEM_TO_GPU, 65536);
	EXPECT_EQ(0, nv_xdev_ext_gpu_make_route(&request, &route));
	EXPECT_EQ(NV_XDEV_EXT_GPU_TO_DEVICE, route.device_direction);
	EXPECT_EQ(request.umem_offset, route.src_offset);
	EXPECT_EQ(request.gpu_offset, route.dst_offset);
	EXPECT_EQ(request.umem_buffer_id, route.src_buffer_id);
	EXPECT_EQ(request.gpu_buffer_id, route.dst_buffer_id);
}

static void test_fallback_and_use_plan_submit(void)
{
	const uint32_t actions[] = {
		NV_XDEV_EXT_GPU_ACTION_FALLBACK,
		NV_XDEV_EXT_GPU_ACTION_USE_PLAN,
	};
	struct nv_xdev_ext_gpu_request request =
		valid_request(NV_XDEV_EXT_GPU_UMEM_TO_GPU, 65536);
	struct nv_xdev_ext_gpu_outcome outcome;
	struct fake_env env;
	uint32_t status;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(actions); i++) {
		env = valid_env(actions[i], 0);
		memset(&outcome, 0xa5, sizeof(outcome));
		status = nv_xdev_ext_gpu_run(&request, &fake_ops, &env,
					0x1001, 0x1002, &outcome);
		EXPECT_EQ(0, status);
		EXPECT_EQ(1, env.dispatches);
		EXPECT_EQ(1, env.submits);
		EXPECT_EQ(1, env.completes);
		EXPECT_EQ(0, env.puts);
		EXPECT_EQ(0, env.token_live);
		EXPECT_EQ(0, env.seen_result.result);
		EXPECT_EQ(request.length, env.seen_result.bytes_done);
		EXPECT_EQ(actions[i], outcome.dispatch_action);
		EXPECT_EQ(0, outcome.dispatch_error);
		EXPECT_EQ(0, outcome.completion_error);
		expect_run_order(&env);
	}
}

static void test_terminal_and_invalid_do_not_submit(void)
{
	struct nv_xdev_ext_gpu_request request =
		valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 4096);
	struct nv_xdev_ext_gpu_outcome outcome;
	struct fake_env env;
	uint32_t status;

	env = valid_env(NV_XDEV_EXT_GPU_ACTION_TERMINAL, 0);
	status = nv_xdev_ext_gpu_run(&request, &fake_ops, &env,
				0x1001, 0x1002, &outcome);
	EXPECT_EQ(0x1002, status);
	EXPECT_EQ(1, env.dispatches);
	EXPECT_EQ(0, env.submits);
	EXPECT_EQ(0, env.completes);
	EXPECT_EQ(1, env.puts);
	EXPECT_EQ(0, env.token_live);
	EXPECT_EQ(NV_XDEV_EXT_GPU_ACTION_TERMINAL, outcome.dispatch_action);

	env = valid_env(99, 0);
	status = nv_xdev_ext_gpu_run(&request, &fake_ops, &env,
				0x1001, 0x1002, &outcome);
	EXPECT_EQ(0x1001, status);
	EXPECT_EQ(1, env.dispatches);
	EXPECT_EQ(0, env.submits);
	EXPECT_EQ(0, env.completes);
	EXPECT_EQ(1, env.puts);

	env = valid_env(NV_XDEV_EXT_GPU_ACTION_FALLBACK, 0);
	env.dispatch_rc = -EPROTO;
	env.token_live = 1;
	status = nv_xdev_ext_gpu_run(&request, &fake_ops, &env,
				0x1001, 0x1002, &outcome);
	EXPECT_EQ(0x1001, status);
	EXPECT_EQ(-EPROTO, outcome.dispatch_error);
	EXPECT_EQ(0, env.submits);
	EXPECT_EQ(0, env.completes);
	EXPECT_EQ(1, env.puts);
	EXPECT_EQ(0, env.token_live);
}

static void test_native_status_normalization_and_preservation(void)
{
	struct nv_xdev_ext_gpu_request request =
		valid_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM, 131072);
	struct nv_xdev_ext_gpu_outcome outcome;
	struct fake_env env = valid_env(NV_XDEV_EXT_GPU_ACTION_USE_PLAN, 0x56ab);
	uint32_t status;

	env.mapped_errno = -ENOMEM;
	status = nv_xdev_ext_gpu_run(&request, &fake_ops, &env,
				0x1001, 0x1002, &outcome);
	EXPECT_EQ(0x56ab, status);
	EXPECT_EQ(-ENOMEM, env.seen_result.result);
	EXPECT_EQ(0, env.seen_result.bytes_done);
	EXPECT_EQ(1, env.completes);
	expect_run_order(&env);

	env = valid_env(NV_XDEV_EXT_GPU_ACTION_USE_PLAN, 0x56ab);
	env.mapped_errno = 0;
	status = nv_xdev_ext_gpu_run(&request, &fake_ops, &env,
				0x1001, 0x1002, &outcome);
	EXPECT_EQ(0x56ab, status);
	EXPECT_EQ(-EIO, env.seen_result.result);

	env = valid_env(NV_XDEV_EXT_GPU_ACTION_USE_PLAN, 0x56ab);
	env.mapped_errno = EINVAL;
	status = nv_xdev_ext_gpu_run(&request, &fake_ops, &env,
				0x1001, 0x1002, &outcome);
	EXPECT_EQ(0x56ab, status);
	EXPECT_EQ(-EIO, env.seen_result.result);

	env = valid_env(NV_XDEV_EXT_GPU_ACTION_USE_PLAN, 0x56ab);
	env.mapped_errno = -4096;
	status = nv_xdev_ext_gpu_run(&request, &fake_ops, &env,
				0x1001, 0x1002, &outcome);
	EXPECT_EQ(0x56ab, status);
	EXPECT_EQ(-EIO, env.seen_result.result);
}

static void test_completion_result_never_changes_native_status(void)
{
	struct nv_xdev_ext_gpu_request request =
		valid_request(NV_XDEV_EXT_GPU_UMEM_TO_GPU, 4096);
	struct nv_xdev_ext_gpu_outcome outcome;
	struct fake_env env = valid_env(NV_XDEV_EXT_GPU_ACTION_FALLBACK, 0x7777);
	uint32_t status;

	env.complete_rc = -EPROTO;
	env.complete_plan.action = NV_XDEV_EXT_GPU_ACTION_TERMINAL;
	status = nv_xdev_ext_gpu_run(&request, &fake_ops, &env,
				0x1001, 0x1002, &outcome);
	EXPECT_EQ(0x7777, status);
	EXPECT_EQ(1, env.completes);
	EXPECT_EQ(-EPROTO, outcome.completion_error);
	EXPECT_EQ(NV_XDEV_EXT_GPU_ACTION_TERMINAL, outcome.completion_action);
}

static void fake_registry_put(struct fake_env *env)
{
	EXPECT_TRUE(env->registry_refs > 0);
	env->registry_refs--;
	if (!env->registry_refs)
		env->buffer_freed = 1;
}

static void test_close_unpin_waits_for_synchronous_call(void)
{
	struct nv_xdev_ext_gpu_request request =
		valid_request(NV_XDEV_EXT_GPU_UMEM_TO_GPU, 4096);
	struct nv_xdev_ext_gpu_outcome outcome;
	struct fake_env env = valid_env(NV_XDEV_EXT_GPU_ACTION_USE_PLAN, 0);

	/* Registry reference plus the ioctl's nv_p2p_umem_ioctl_handle_get(). */
	env.registry_refs = 2;
	env.close_during_submit = 1;
	EXPECT_EQ(0, nv_xdev_ext_gpu_run(&request, &fake_ops, &env,
					0x1001, 0x1002, &outcome));
	EXPECT_EQ(1, env.registry_refs);
	EXPECT_TRUE(!env.buffer_freed);
	EXPECT_EQ(1, env.completes);

	/* Mirrors nv_p2p_umem_ioctl_handle_put() after the xfer returns. */
	fake_registry_put(&env);
	EXPECT_EQ(0, env.registry_refs);
	EXPECT_TRUE(env.buffer_freed);
}

static void test_bad_admission_never_touches_policy_or_rm(void)
{
	struct nv_xdev_ext_gpu_request request =
		valid_request(NV_XDEV_EXT_GPU_UMEM_TO_GPU, 4096);
	struct nv_xdev_ext_gpu_outcome outcome;
	struct fake_env env = valid_env(NV_XDEV_EXT_GPU_ACTION_USE_PLAN, 0);

	request.gpu_page_count = 0;
	EXPECT_EQ(0x1001, nv_xdev_ext_gpu_run(&request, &fake_ops, &env,
					     0x1001, 0x1002, &outcome));
	EXPECT_EQ(-EINVAL, outcome.dispatch_error);
	EXPECT_EQ(0, env.dispatches);
	EXPECT_EQ(0, env.submits);
	EXPECT_EQ(0, env.completes);
	EXPECT_EQ(0, env.puts);
}

int main(void)
{
	test_page_coverage_and_overflow();
	test_direction_routes_only_relative_offsets();
	test_fallback_and_use_plan_submit();
	test_terminal_and_invalid_do_not_submit();
	test_native_status_normalization_and_preservation();
	test_completion_result_never_changes_native_status();
	test_close_unpin_waits_for_synchronous_call();
	test_bad_admission_never_touches_policy_or_rm();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks failed\n", failures, checks);
		return 1;
	}
	printf("PASS: %u checks\n", checks);
	return 0;
}
