/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel-open/nvidia/nv-xdev_ext-gpu.h"

#define ASSERT_CTX_OFFSET(member, expected)                                    \
	_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, member) == (expected), \
		       "XDEV_EXT v2 " #member " offset drifted")

_Static_assert(sizeof(struct xdev_ext_binding_ctx_v2) == 136,
	       "XDEV_EXT v2 context size drifted");
_Static_assert(_Alignof(struct xdev_ext_binding_ctx_v2) == 8,
	       "XDEV_EXT v2 context alignment drifted");
ASSERT_CTX_OFFSET(abi_version, 0);
ASSERT_CTX_OFFSET(ctx_size, 4);
ASSERT_CTX_OFFSET(event, 8);
ASSERT_CTX_OFFSET(backend, 12);
ASSERT_CTX_OFFSET(current_stage, 16);
ASSERT_CTX_OFFSET(direction, 20);
ASSERT_CTX_OFFSET(frame_state, 24);
ASSERT_CTX_OFFSET(capabilities, 28);
ASSERT_CTX_OFFSET(allowed_recipe_mask, 32);
ASSERT_CTX_OFFSET(allowed_next_mask, 36);
ASSERT_CTX_OFFSET(allowed_profile_mask, 40);
ASSERT_CTX_OFFSET(reserved0, 44);
ASSERT_CTX_OFFSET(request_id, 48);
ASSERT_CTX_OFFSET(chain_id, 56);
ASSERT_CTX_OFFSET(endpoint_id, 64);
ASSERT_CTX_OFFSET(src_buffer_id, 72);
ASSERT_CTX_OFFSET(dst_buffer_id, 80);
ASSERT_CTX_OFFSET(src_offset, 88);
ASSERT_CTX_OFFSET(dst_offset, 96);
ASSERT_CTX_OFFSET(logical_offset, 104);
ASSERT_CTX_OFFSET(length, 112);
ASSERT_CTX_OFFSET(bytes_done, 120);
ASSERT_CTX_OFFSET(result, 128);
ASSERT_CTX_OFFSET(reserved1, 132);

#undef ASSERT_CTX_OFFSET

_Static_assert(XDEV_EXT_BINDING_ABI_VERSION == 2,
	       "XDEV_EXT ABI version drifted");
_Static_assert(XDEV_EXT_BINDING_EVENT_DISPATCH == 1 &&
	       XDEV_EXT_BINDING_EVENT_COMPLETE == 2,
	       "XDEV_EXT event ABI drifted");
_Static_assert(XDEV_EXT_BINDING_BACKEND_GPU == 5,
	       "XDEV_EXT GPU backend ABI drifted");
_Static_assert(XDEV_EXT_BINDING_DIRECTION_TO_DEVICE == 1 &&
	       XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE == 2,
	       "XDEV_EXT direction ABI drifted");
_Static_assert(XDEV_EXT_BINDING_RECIPE_GPU_COPY == 6,
	       "XDEV_EXT GPU recipe ABI drifted");
_Static_assert(XDEV_EXT_BINDING_STAGE_GPU_COPY == 3 &&
	       XDEV_EXT_BINDING_STAGE_COMPLETE == 6,
	       "XDEV_EXT stage ABI drifted");
_Static_assert(XDEV_EXT_BINDING_ACTION_FALLBACK == 0 &&
	       XDEV_EXT_BINDING_ACTION_USE_PLAN == 1 &&
	       XDEV_EXT_BINDING_ACTION_TERMINAL == 2,
	       "XDEV_EXT action ABI drifted");
_Static_assert(XDEV_EXT_BINDING_PROFILE_NATIVE == 1,
	       "XDEV_EXT profile ABI drifted");
_Static_assert(XDEV_EXT_BINDING_CAP_ZERO_COPY == (1U << 4),
	       "XDEV_EXT capability ABI drifted");
_Static_assert(sizeof(struct xdev_ext_binding_plan) == 16,
	       "XDEV_EXT plan layout drifted");

static unsigned int checks;
static unsigned int failures;
static unsigned int dispatches;
static unsigned int completes;
static unsigned int token_puts;
static int dispatch_rc;
static int complete_rc;
static struct xdev_ext_binding_plan next_dispatch_plan;
static struct xdev_ext_binding_plan next_complete_plan;
static struct xdev_ext_binding_ctx_v2 dispatch_ctx;
static struct xdev_ext_binding_ctx_v2 complete_ctx;
static const int token_marker;

#define EXPECT_EQ(expected, actual)                                             \
	do {                                                                     \
		long long _expected = (long long)(expected);                       \
		long long _actual = (long long)(actual);                           \
		checks++;                                                        \
		if (_expected != _actual) {                                     \
			fprintf(stderr, "%s:%d: expected %lld, got %lld\n",      \
				__FILE__, __LINE__, _expected, _actual);             \
			failures++;                                               \
		}                                                                \
	} while (0)

int xdev_ext_binding_dispatch(const struct xdev_ext_binding_ctx_v2 *ctx,
			 struct xdev_ext_binding_token *token,
			 struct xdev_ext_binding_plan *plan)
{
	dispatches++;
	dispatch_ctx = *ctx;
	*plan = next_dispatch_plan;
	if (!dispatch_rc && plan->action != XDEV_EXT_BINDING_ACTION_TERMINAL)
		token->private = &token_marker;
	else
		token->private = NULL;
	return dispatch_rc;
}

int xdev_ext_binding_complete(const struct xdev_ext_binding_ctx_v2 *ctx,
			 struct xdev_ext_binding_token *token,
			 struct xdev_ext_binding_plan *plan)
{
	completes++;
	complete_ctx = *ctx;
	*plan = next_complete_plan;
	EXPECT_EQ((uintptr_t)&token_marker, (uintptr_t)token->private);
	token->private = NULL;
	return complete_rc;
}

void xdev_ext_binding_token_put(struct xdev_ext_binding_token *token)
{
	token_puts++;
	token->private = NULL;
}

static void reset_fake(void)
{
	dispatches = 0;
	completes = 0;
	token_puts = 0;
	dispatch_rc = 0;
	complete_rc = 0;
	next_dispatch_plan = (struct xdev_ext_binding_plan){};
	next_complete_plan = (struct xdev_ext_binding_plan){};
	dispatch_ctx = (struct xdev_ext_binding_ctx_v2){};
	complete_ctx = (struct xdev_ext_binding_ctx_v2){};
}

static struct nv_xdev_ext_gpu_request make_request(uint32_t direction)
{
	struct nv_xdev_ext_gpu_request request = {
		.request_id = 0x101,
		.chain_id = 0x102,
		.endpoint_id = 0x103,
		.umem_buffer_id = 0x104,
		.gpu_buffer_id = 0x105,
		.direction = direction,
		.umem_page_size = 4096,
		.umem_page_count = 32,
		.gpu_page_size = 65536,
		.gpu_page_count = 1,
		.umem_offset = 8192,
		.gpu_offset = 2048,
		.length = 4096,
		.umem_capacity = 32 * 4096,
	};

	return request;
}

static void test_dispatch_context_contains_only_relative_metadata(void)
{
	struct nv_xdev_ext_gpu_binding binding = {};
	struct nv_xdev_ext_gpu_plan plan;
	struct nv_xdev_ext_gpu_request request;

	reset_fake();
	next_dispatch_plan.action = XDEV_EXT_BINDING_ACTION_USE_PLAN;
	request = make_request(NV_XDEV_EXT_GPU_UMEM_TO_GPU);
	EXPECT_EQ(0, nv_xdev_ext_gpu_binding_dispatch(&binding, &request, &plan));
	EXPECT_EQ(NV_XDEV_EXT_GPU_ACTION_USE_PLAN, plan.action);
	EXPECT_EQ(1, dispatches);
	EXPECT_EQ(XDEV_EXT_BINDING_ABI_VERSION, dispatch_ctx.abi_version);
	EXPECT_EQ(sizeof(dispatch_ctx), dispatch_ctx.ctx_size);
	EXPECT_EQ(XDEV_EXT_BINDING_EVENT_DISPATCH, dispatch_ctx.event);
	EXPECT_EQ(XDEV_EXT_BINDING_BACKEND_GPU, dispatch_ctx.backend);
	EXPECT_EQ(XDEV_EXT_BINDING_STAGE_GPU_COPY, dispatch_ctx.current_stage);
	EXPECT_EQ(XDEV_EXT_BINDING_DIRECTION_TO_DEVICE, dispatch_ctx.direction);
	EXPECT_EQ(XDEV_EXT_BINDING_FRAME_UNTRACKED, dispatch_ctx.frame_state);
	EXPECT_EQ(request.umem_offset, dispatch_ctx.src_offset);
	EXPECT_EQ(request.gpu_offset, dispatch_ctx.dst_offset);
	EXPECT_EQ(request.length, dispatch_ctx.length);
	EXPECT_EQ(XDEV_EXT_BINDING_CAP_ZERO_COPY, dispatch_ctx.capabilities);
	EXPECT_EQ(1U << XDEV_EXT_BINDING_RECIPE_GPU_COPY,
		  dispatch_ctx.allowed_recipe_mask);
	EXPECT_EQ(1U << XDEV_EXT_BINDING_STAGE_COMPLETE,
		  dispatch_ctx.allowed_next_mask);
	EXPECT_EQ(1U << XDEV_EXT_BINDING_PROFILE_NATIVE,
		  dispatch_ctx.allowed_profile_mask);
	EXPECT_EQ(0, dispatch_ctx.reserved0);
	EXPECT_EQ(request.request_id, dispatch_ctx.request_id);
	EXPECT_EQ(request.chain_id, dispatch_ctx.chain_id);
	EXPECT_EQ(request.endpoint_id, dispatch_ctx.endpoint_id);
	EXPECT_EQ(request.umem_buffer_id, dispatch_ctx.src_buffer_id);
	EXPECT_EQ(request.gpu_buffer_id, dispatch_ctx.dst_buffer_id);
	EXPECT_EQ(0, dispatch_ctx.logical_offset);
	EXPECT_EQ(0, dispatch_ctx.bytes_done);
	EXPECT_EQ(0, dispatch_ctx.result);
	EXPECT_EQ(0, dispatch_ctx.reserved1);

	nv_xdev_ext_gpu_binding_put(&binding);
	EXPECT_EQ(1, token_puts);

	reset_fake();
	next_dispatch_plan.action = XDEV_EXT_BINDING_ACTION_FALLBACK;
	request = make_request(NV_XDEV_EXT_GPU_GPU_TO_UMEM);
	EXPECT_EQ(0, nv_xdev_ext_gpu_binding_dispatch(&binding, &request, &plan));
	EXPECT_EQ(NV_XDEV_EXT_GPU_ACTION_FALLBACK, plan.action);
	EXPECT_EQ(XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE, dispatch_ctx.direction);
	EXPECT_EQ(request.gpu_offset, dispatch_ctx.src_offset);
	EXPECT_EQ(request.umem_offset, dispatch_ctx.dst_offset);
	EXPECT_EQ(request.gpu_buffer_id, dispatch_ctx.src_buffer_id);
	EXPECT_EQ(request.umem_buffer_id, dispatch_ctx.dst_buffer_id);
	nv_xdev_ext_gpu_binding_put(&binding);
}

static void test_completion_consumes_same_token_once(void)
{
	struct nv_xdev_ext_gpu_binding binding = {};
	struct nv_xdev_ext_gpu_request request =
		make_request(NV_XDEV_EXT_GPU_UMEM_TO_GPU);
	struct nv_xdev_ext_gpu_result result = {
		.result = -EIO,
		.bytes_done = 0,
	};
	struct nv_xdev_ext_gpu_plan plan;

	reset_fake();
	next_dispatch_plan.action = XDEV_EXT_BINDING_ACTION_USE_PLAN;
	next_complete_plan.action = XDEV_EXT_BINDING_ACTION_TERMINAL;
	EXPECT_EQ(0, nv_xdev_ext_gpu_binding_dispatch(&binding, &request, &plan));
	EXPECT_EQ(0, nv_xdev_ext_gpu_binding_complete(&binding, &request,
						 &result, &plan));
	EXPECT_EQ(1, completes);
	EXPECT_EQ(NV_XDEV_EXT_GPU_ACTION_TERMINAL, plan.action);
	EXPECT_EQ(XDEV_EXT_BINDING_EVENT_COMPLETE, complete_ctx.event);
	EXPECT_EQ(-EIO, complete_ctx.result);
	EXPECT_EQ(0, complete_ctx.bytes_done);
	EXPECT_EQ(0, (uintptr_t)binding.token.private);

	/* Empty-token completion is a no-op and cannot notify a later plugin. */
	EXPECT_EQ(0, nv_xdev_ext_gpu_binding_complete(&binding, &request,
						 &result, &plan));
	EXPECT_EQ(1, completes);
}

static void test_errors_and_unknown_actions_leave_no_token(void)
{
	struct nv_xdev_ext_gpu_binding binding = {};
	struct nv_xdev_ext_gpu_request request =
		make_request(NV_XDEV_EXT_GPU_UMEM_TO_GPU);
	struct nv_xdev_ext_gpu_plan plan;

	reset_fake();
	dispatch_rc = -EPROTO;
	EXPECT_EQ(-EPROTO,
		  nv_xdev_ext_gpu_binding_dispatch(&binding, &request, &plan));
	EXPECT_EQ(0, (uintptr_t)binding.token.private);

	reset_fake();
	next_dispatch_plan.action = 99;
	EXPECT_EQ(-EPROTO,
		  nv_xdev_ext_gpu_binding_dispatch(&binding, &request, &plan));
	EXPECT_EQ(1, token_puts);
	EXPECT_EQ(0, (uintptr_t)binding.token.private);

	/* The runner's common unwind must not release an already-empty token. */
	nv_xdev_ext_gpu_binding_put(&binding);
	EXPECT_EQ(1, token_puts);
}

int main(void)
{
	test_dispatch_context_contains_only_relative_metadata();
	test_completion_consumes_same_token_once();
	test_errors_and_unknown_actions_leave_no_token();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks failed\n", failures, checks);
		return 1;
	}
	printf("PASS: %u checks\n", checks);
	return 0;
}
