// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../../../../include/linux/xdev_ext_binding.h"

_Static_assert(XDEV_EXT_BINDING_ABI_VERSION == 2, "unexpected binding ABI");
_Static_assert(XDEV_EXT_BINDING_EVENT_UNSPEC == 0, "unspecified event changed");
_Static_assert(XDEV_EXT_BINDING_EVENT_DISPATCH == 1, "dispatch event changed");
_Static_assert(XDEV_EXT_BINDING_EVENT_COMPLETE == 2, "complete event changed");
_Static_assert(XDEV_EXT_BINDING_EVENT_MAX == 3, "event sentinel changed");

/* Keep the shipped v1 recipe and stage numbers stable. */
_Static_assert(XDEV_EXT_BINDING_RECIPE_DEFAULT == 0, "default recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_FILE_READ == 1, "file-read recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_FILE_WRITE == 2, "file-write recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_SOCKET_SEND == 3, "socket recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_AFXDP_COPY == 4, "AF_XDP recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_CPU_CALC == 5, "CPU recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_GPU_COPY == 6, "GPU recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_COMPLETE == 7, "complete recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_NVME_PT_READ == 8, "NVMe read recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE == 9, "NVMe write recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS == 10, "IAA compress recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS == 11, "IAA decompress recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX == 12,
	       "AF_XDP native TX recipe changed");
_Static_assert(XDEV_EXT_BINDING_RECIPE_AFXDP_RX == 13,
	       "AF_XDP RX recipe must be appended");
_Static_assert(XDEV_EXT_BINDING_RECIPE_MAX <= 32, "recipe mask exceeds 32 bits");

_Static_assert(XDEV_EXT_BINDING_STAGE_NONE == 0, "none stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_FILE_READ == 1, "file-read stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_CPU_CALC == 2, "CPU stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_GPU_COPY == 3, "GPU stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_SEND == 4, "send stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_FILE_WRITE == 5, "file-write stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_COMPLETE == 6, "complete stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_NVME_READ == 7, "NVMe read stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_NVME_WRITE == 8, "NVMe write stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_AFXDP_TX == 9, "AF_XDP TX stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_IAA_COMPRESS == 10, "IAA compress stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS == 11, "IAA decompress stage changed");
_Static_assert(XDEV_EXT_BINDING_STAGE_AFXDP_RX == 12,
	       "AF_XDP RX stage must be appended");
_Static_assert(XDEV_EXT_BINDING_STAGE_MAX <= 32, "stage mask exceeds 32 bits");

_Static_assert(XDEV_EXT_BINDING_BACKEND_UNSPEC == 0, "unspecified backend changed");
_Static_assert(XDEV_EXT_BINDING_BACKEND_SOCKET == 1, "socket backend changed");
_Static_assert(XDEV_EXT_BINDING_BACKEND_AFXDP == 2, "AF_XDP backend changed");
_Static_assert(XDEV_EXT_BINDING_BACKEND_NVME == 3, "NVMe backend changed");
_Static_assert(XDEV_EXT_BINDING_BACKEND_IAA == 4, "IAA backend changed");
_Static_assert(XDEV_EXT_BINDING_BACKEND_GPU == 5, "GPU backend changed");
_Static_assert(XDEV_EXT_BINDING_BACKEND_MAX <= 32, "backend enum exceeds 32 values");

_Static_assert(XDEV_EXT_BINDING_DIRECTION_UNSPEC == 0, "unspecified direction changed");
_Static_assert(XDEV_EXT_BINDING_DIRECTION_TO_DEVICE == 1, "to-device direction changed");
_Static_assert(XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE == 2, "from-device direction changed");
_Static_assert(XDEV_EXT_BINDING_DIRECTION_INTERNAL == 3, "internal direction changed");
_Static_assert(XDEV_EXT_BINDING_DIRECTION_MAX <= 32,
	       "direction enum exceeds 32 values");

_Static_assert(XDEV_EXT_BINDING_ACTION_FALLBACK == 0, "fallback action changed");
_Static_assert(XDEV_EXT_BINDING_ACTION_USE_PLAN == 1, "use-plan action changed");
_Static_assert(XDEV_EXT_BINDING_ACTION_TERMINAL == 2, "terminal action changed");
_Static_assert(XDEV_EXT_BINDING_ACTION_MAX <= 32, "action enum exceeds 32 values");
_Static_assert(XDEV_EXT_BINDING_PROFILE_NONE == 0, "none profile changed");
_Static_assert(XDEV_EXT_BINDING_PROFILE_NATIVE == 1, "native profile changed");
_Static_assert(XDEV_EXT_BINDING_PROFILE_MAX <= 32, "profile mask exceeds 32 bits");
_Static_assert(XDEV_EXT_BINDING_EVENT_MAX <= 32, "event enum exceeds 32 values");

_Static_assert(XDEV_EXT_BINDING_CAP_ASYNC == UINT32_C(0x00000001),
	       "async capability bit changed");
_Static_assert(XDEV_EXT_BINDING_CAP_POLL == UINT32_C(0x00000002),
	       "poll capability bit changed");
_Static_assert(XDEV_EXT_BINDING_CAP_FIXED_FILE == UINT32_C(0x00000004),
	       "fixed-file capability bit changed");
_Static_assert(XDEV_EXT_BINDING_CAP_FIXED_BUFFER == UINT32_C(0x00000008),
	       "fixed-buffer capability bit changed");
_Static_assert(XDEV_EXT_BINDING_CAP_ZERO_COPY == UINT32_C(0x00000010),
	       "zero-copy capability bit changed");
_Static_assert(XDEV_EXT_BINDING_CAP_MULTIBUFFER == UINT32_C(0x00000020),
	       "multi-buffer capability bit changed");
_Static_assert(XDEV_EXT_BINDING_CAP_SHARED_UMEM == UINT32_C(0x00000040),
	       "shared-UMEM capability bit changed");
_Static_assert(XDEV_EXT_BINDING_OPS_F_AFXDP_RX == UINT32_C(0x00000001),
	       "AF_XDP RX opt-in flag changed");
_Static_assert(XDEV_EXT_BINDING_KNOWN_OPS_FLAG_MASK == UINT32_C(0x00000001),
	       "known policy flag mask changed");

_Static_assert(XDEV_EXT_BINDING_FRAME_UNTRACKED == 0,
	       "untracked frame state must remain zero-initializable");
_Static_assert(sizeof(struct xdev_ext_binding_ctx_v2) == 136,
	       "binding context layout changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, abi_version) == 0,
	       "ABI version offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, ctx_size) == 4,
	       "context size offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, event) == 8,
	       "event ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, backend) == 12,
	       "backend ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, current_stage) == 16,
	       "current stage ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, direction) == 20,
	       "direction ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, frame_state) == 24,
	       "frame state ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, capabilities) == 28,
	       "capabilities ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, allowed_recipe_mask) == 32,
	       "recipe mask ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, allowed_next_mask) == 36,
	       "next-stage mask ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, allowed_profile_mask) == 40,
	       "profile mask ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, reserved0) == 44,
	       "first reserved ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, request_id) == 48,
	       "request ID ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, chain_id) == 56,
	       "chain ID ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, endpoint_id) == 64,
	       "endpoint ID ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, src_buffer_id) == 72,
	       "source buffer ID ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, dst_buffer_id) == 80,
	       "destination buffer ID ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, src_offset) == 88,
	       "source offset ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, dst_offset) == 96,
	       "destination offset ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, logical_offset) == 104,
	       "logical offset ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, length) == 112,
	       "length ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, bytes_done) == 120,
	       "completed bytes ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, result) == 128,
	       "result ABI offset changed");
_Static_assert(offsetof(struct xdev_ext_binding_ctx_v2, reserved1) == 132,
	       "trailing reserved ABI offset changed");

_Static_assert(XDEV_EXT_BINDING_KNOWN_RECIPE_MASK == UINT32_C(0x00003ffe),
	       "known recipe mask must remain a constant expression");
_Static_assert(XDEV_EXT_BINDING_KNOWN_STAGE_MASK == UINT32_C(0x00001ffe),
	       "known stage mask must remain a constant expression");
_Static_assert(XDEV_EXT_BINDING_KNOWN_PROFILE_MASK == UINT32_C(0x00000002),
	       "known profile mask must remain a constant expression");
_Static_assert(XDEV_EXT_BINDING_KNOWN_CAPABILITY_MASK == UINT32_C(0x0000007f),
	       "known capability mask must remain a constant expression");

static unsigned int tests_run;
static unsigned int tests_failed;

#define EXPECT_EQ(actual_expr, expected_expr) do {                         \
	long long actual_ = (long long)(actual_expr);                       \
	long long expected_ = (long long)(expected_expr);                   \
	tests_run++;                                                        \
	if (actual_ != expected_) {                                         \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",     \
			__FILE__, __LINE__, #actual_expr, actual_, expected_); \
		tests_failed++;                                               \
	}                                                                   \
} while (0)

static struct xdev_ext_binding_ctx_v2 base_ctx(void)
{
	return xdev_ext_binding_make_socket_send_ctx(UINT64_C(4096));
}

static struct xdev_ext_binding_plan use_plan(uint32_t recipe, uint32_t next,
					uint32_t profile)
{
	struct xdev_ext_binding_plan plan = {
		.action = XDEV_EXT_BINDING_ACTION_USE_PLAN,
		.recipe = recipe,
		.next_stage = next,
		.profile = profile,
	};

	return plan;
}

static struct xdev_ext_binding_plan zero_arg_plan(uint32_t action)
{
	struct xdev_ext_binding_plan plan = { .action = action };

	return plan;
}

static void expect_common_builder_fields(const struct xdev_ext_binding_ctx_v2 *ctx,
					 uint32_t backend, uint32_t stage,
					 uint32_t direction, uint64_t length)
{
	EXPECT_EQ(ctx->abi_version, XDEV_EXT_BINDING_ABI_VERSION);
	EXPECT_EQ(ctx->ctx_size, sizeof(*ctx));
	EXPECT_EQ(ctx->event, XDEV_EXT_BINDING_EVENT_DISPATCH);
	EXPECT_EQ(ctx->backend, backend);
	EXPECT_EQ(ctx->current_stage, stage);
	EXPECT_EQ(ctx->direction, direction);
	EXPECT_EQ(ctx->frame_state, XDEV_EXT_BINDING_FRAME_UNTRACKED);
	EXPECT_EQ(ctx->capabilities, 0);
	EXPECT_EQ(ctx->allowed_next_mask,
		  xdev_ext_binding_stage_bit(XDEV_EXT_BINDING_STAGE_COMPLETE));
	EXPECT_EQ(ctx->allowed_profile_mask,
		  xdev_ext_binding_profile_bit(XDEV_EXT_BINDING_PROFILE_NATIVE));
	EXPECT_EQ(ctx->request_id, 0);
	EXPECT_EQ(ctx->chain_id, 0);
	EXPECT_EQ(ctx->endpoint_id, 0);
	EXPECT_EQ(ctx->src_buffer_id, 0);
	EXPECT_EQ(ctx->dst_buffer_id, 0);
	EXPECT_EQ(ctx->length, length);
	EXPECT_EQ(ctx->bytes_done, 0);
	EXPECT_EQ(ctx->result, 0);
	EXPECT_EQ(ctx->reserved0, 0);
	EXPECT_EQ(ctx->reserved1, 0);
}

static void test_safe_dynamic_bit_helpers(void)
{
	uint32_t recipe = XDEV_EXT_BINDING_RECIPE_NVME_PT_READ;
	uint32_t stage = XDEV_EXT_BINDING_STAGE_AFXDP_TX;
	uint32_t profile = XDEV_EXT_BINDING_PROFILE_NATIVE;

	EXPECT_EQ(xdev_ext_binding_recipe_bit(recipe++),
		  UINT32_C(1) << XDEV_EXT_BINDING_RECIPE_NVME_PT_READ);
	EXPECT_EQ(recipe, XDEV_EXT_BINDING_RECIPE_NVME_PT_READ + 1);
	EXPECT_EQ(xdev_ext_binding_recipe_bit(UINT32_C(32)), 0);
	EXPECT_EQ(xdev_ext_binding_recipe_bit(UINT32_MAX), 0);

	EXPECT_EQ(xdev_ext_binding_stage_bit(stage++),
		  UINT32_C(1) << XDEV_EXT_BINDING_STAGE_AFXDP_TX);
	EXPECT_EQ(stage, XDEV_EXT_BINDING_STAGE_AFXDP_TX + 1);
	EXPECT_EQ(xdev_ext_binding_stage_bit(UINT32_C(32)), 0);
	EXPECT_EQ(xdev_ext_binding_stage_bit(UINT32_MAX), 0);

	EXPECT_EQ(xdev_ext_binding_profile_bit(profile++),
		  UINT32_C(1) << XDEV_EXT_BINDING_PROFILE_NATIVE);
	EXPECT_EQ(profile, XDEV_EXT_BINDING_PROFILE_NATIVE + 1);
	EXPECT_EQ(xdev_ext_binding_profile_bit(UINT32_C(32)), 0);
	EXPECT_EQ(xdev_ext_binding_profile_bit(UINT32_MAX), 0);
}

static void test_socket_builder(void)
{
	const uint64_t length = UINT64_C(0x1122334455667788);
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_socket_send_ctx(length);

	expect_common_builder_fields(&ctx, XDEV_EXT_BINDING_BACKEND_SOCKET,
				     XDEV_EXT_BINDING_STAGE_SEND,
				     XDEV_EXT_BINDING_DIRECTION_TO_DEVICE, length);
	EXPECT_EQ(ctx.allowed_recipe_mask,
		  xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_SOCKET_SEND));
	EXPECT_EQ(ctx.src_offset, 0);
	EXPECT_EQ(ctx.dst_offset, 0);
	EXPECT_EQ(ctx.logical_offset, 0);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);
}

static void test_afxdp_builder(void)
{
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_afxdp_tx_ctx(UINT64_C(2048));

	expect_common_builder_fields(&ctx, XDEV_EXT_BINDING_BACKEND_AFXDP,
				     XDEV_EXT_BINDING_STAGE_AFXDP_TX,
				     XDEV_EXT_BINDING_DIRECTION_TO_DEVICE, 2048);
	EXPECT_EQ(ctx.allowed_recipe_mask,
		  xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_AFXDP_COPY));
	EXPECT_EQ(ctx.src_offset, 0);
	EXPECT_EQ(ctx.dst_offset, 0);
	EXPECT_EQ(ctx.logical_offset, 0);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);
}

static void test_afxdp_native_tx_builder(void)
{
	const uint32_t capabilities = XDEV_EXT_BINDING_CAP_ASYNC |
		XDEV_EXT_BINDING_CAP_ZERO_COPY | XDEV_EXT_BINDING_CAP_MULTIBUFFER |
		XDEV_EXT_BINDING_CAP_SHARED_UMEM;
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_afxdp_native_tx_ctx(UINT64_C(0x12340000),
						     UINT64_C(8192),
						     capabilities);
	struct xdev_ext_binding_ctx_v2 common = ctx;

	common.capabilities = 0;
	expect_common_builder_fields(&common, XDEV_EXT_BINDING_BACKEND_AFXDP,
				     XDEV_EXT_BINDING_STAGE_AFXDP_TX,
				     XDEV_EXT_BINDING_DIRECTION_TO_DEVICE, 8192);
	EXPECT_EQ(ctx.allowed_recipe_mask,
		  xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX));
	EXPECT_EQ(ctx.src_offset, UINT64_C(0x12340000));
	EXPECT_EQ(ctx.capabilities, capabilities);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);
}

static void test_afxdp_rx_builder(void)
{
	const uint32_t capabilities = XDEV_EXT_BINDING_CAP_ZERO_COPY |
		XDEV_EXT_BINDING_CAP_MULTIBUFFER | XDEV_EXT_BINDING_CAP_SHARED_UMEM;
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_afxdp_rx_ctx(UINT64_C(0x56780000),
					  UINT64_C(12288), capabilities);
	struct xdev_ext_binding_ctx_v2 common = ctx;

	common.capabilities = 0;
	expect_common_builder_fields(&common, XDEV_EXT_BINDING_BACKEND_AFXDP,
				     XDEV_EXT_BINDING_STAGE_AFXDP_RX,
				     XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE, 12288);
	EXPECT_EQ(ctx.allowed_recipe_mask,
		  xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_AFXDP_RX));
	EXPECT_EQ(ctx.dst_offset, UINT64_C(0x56780000));
	EXPECT_EQ(ctx.src_offset, 0);
	EXPECT_EQ(ctx.capabilities, capabilities);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);
}

static void test_policy_flag_validation(void)
{
	struct xdev_ext_binding_ctx_v2 rx =
		xdev_ext_binding_make_afxdp_rx_ctx(0, 4096, 0);
	struct xdev_ext_binding_ctx_v2 tx = xdev_ext_binding_make_afxdp_tx_ctx(4096);
	struct xdev_ext_binding_ctx_v2 send = base_ctx();

	EXPECT_EQ(xdev_ext_binding_ops_flags_valid(XDEV_EXT_BINDING_BACKEND_AFXDP, 0), 1);
	EXPECT_EQ(xdev_ext_binding_ops_flags_valid(
			  XDEV_EXT_BINDING_BACKEND_AFXDP,
			  XDEV_EXT_BINDING_OPS_F_AFXDP_RX), 1);
	EXPECT_EQ(xdev_ext_binding_ops_flags_valid(
			  XDEV_EXT_BINDING_BACKEND_SOCKET,
			  XDEV_EXT_BINDING_OPS_F_AFXDP_RX), 0);
	EXPECT_EQ(xdev_ext_binding_ops_flags_valid(
			  XDEV_EXT_BINDING_BACKEND_AFXDP,
			  UINT32_C(0x80000000)), 0);
	EXPECT_EQ(xdev_ext_binding_ops_flags_valid(XDEV_EXT_BINDING_BACKEND_MAX, 0), 0);
	EXPECT_EQ(xdev_ext_binding_ops_accepts_ctx(XDEV_EXT_BINDING_BACKEND_AFXDP, 0,
					      &rx), 0);
	EXPECT_EQ(xdev_ext_binding_ops_accepts_ctx(
			  XDEV_EXT_BINDING_BACKEND_AFXDP,
			  XDEV_EXT_BINDING_OPS_F_AFXDP_RX, &rx), 1);
	EXPECT_EQ(xdev_ext_binding_ops_accepts_ctx(XDEV_EXT_BINDING_BACKEND_AFXDP, 0,
					      &tx), 1);
	EXPECT_EQ(xdev_ext_binding_ops_accepts_ctx(XDEV_EXT_BINDING_BACKEND_SOCKET, 0,
					      &send), 1);
	EXPECT_EQ(xdev_ext_binding_ops_accepts_ctx(XDEV_EXT_BINDING_BACKEND_SOCKET, 0,
					      &rx), 0);
}

static void test_nvme_builders(void)
{
	const uint64_t offset = UINT64_C(0x123456789abcdef0);
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_nvme_ctx(0, offset, UINT64_C(4096));

	expect_common_builder_fields(&ctx, XDEV_EXT_BINDING_BACKEND_NVME,
				     XDEV_EXT_BINDING_STAGE_NVME_READ,
				     XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE, 4096);
	EXPECT_EQ(ctx.allowed_recipe_mask,
		  xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_NVME_PT_READ));
	EXPECT_EQ(ctx.src_offset, 0);
	EXPECT_EQ(ctx.dst_offset, 0);
	EXPECT_EQ(ctx.logical_offset, offset);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);

	ctx = xdev_ext_binding_make_nvme_ctx(1, offset, UINT64_C(8192));
	expect_common_builder_fields(&ctx, XDEV_EXT_BINDING_BACKEND_NVME,
				     XDEV_EXT_BINDING_STAGE_NVME_WRITE,
				     XDEV_EXT_BINDING_DIRECTION_TO_DEVICE, 8192);
	EXPECT_EQ(ctx.allowed_recipe_mask,
		  xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE));
	EXPECT_EQ(ctx.src_offset, 0);
	EXPECT_EQ(ctx.dst_offset, 0);
	EXPECT_EQ(ctx.logical_offset, offset);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);
}

static void test_iaa_builders(void)
{
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_iaa_ctx(0, UINT64_C(64), UINT64_C(128),
					 UINT64_C(4096));

	expect_common_builder_fields(&ctx, XDEV_EXT_BINDING_BACKEND_IAA,
				     XDEV_EXT_BINDING_STAGE_IAA_COMPRESS,
				     XDEV_EXT_BINDING_DIRECTION_INTERNAL, 4096);
	EXPECT_EQ(ctx.allowed_recipe_mask,
		  xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS));
	EXPECT_EQ(ctx.src_offset, 64);
	EXPECT_EQ(ctx.dst_offset, 128);
	EXPECT_EQ(ctx.logical_offset, 0);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);

	ctx = xdev_ext_binding_make_iaa_ctx(1, UINT64_C(128), UINT64_C(64),
				       UINT64_C(2048));
	expect_common_builder_fields(&ctx, XDEV_EXT_BINDING_BACKEND_IAA,
				     XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS,
				     XDEV_EXT_BINDING_DIRECTION_INTERNAL, 2048);
	EXPECT_EQ(ctx.allowed_recipe_mask,
		  xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS));
	EXPECT_EQ(ctx.src_offset, 128);
	EXPECT_EQ(ctx.dst_offset, 64);
	EXPECT_EQ(ctx.logical_offset, 0);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);
}

static void test_gpu_builders(void)
{
	struct xdev_ext_binding_ctx_v2 ctx = xdev_ext_binding_make_gpu_ctx(
		XDEV_EXT_BINDING_DIRECTION_TO_DEVICE, UINT64_C(256),
		UINT64_C(512), UINT64_C(65536));

	expect_common_builder_fields(&ctx, XDEV_EXT_BINDING_BACKEND_GPU,
				     XDEV_EXT_BINDING_STAGE_GPU_COPY,
				     XDEV_EXT_BINDING_DIRECTION_TO_DEVICE, 65536);
	EXPECT_EQ(ctx.allowed_recipe_mask,
		  xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_GPU_COPY));
	EXPECT_EQ(ctx.src_offset, 256);
	EXPECT_EQ(ctx.dst_offset, 512);
	EXPECT_EQ(ctx.logical_offset, 0);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);

	ctx = xdev_ext_binding_make_gpu_ctx(XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
				       512, 256, 4096);
	EXPECT_EQ(ctx.direction, XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE);
	EXPECT_EQ(ctx.logical_offset, 0);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);

	ctx = xdev_ext_binding_make_gpu_ctx(XDEV_EXT_BINDING_DIRECTION_INTERNAL,
				       0, 0, 4096);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
}

static void test_context_enum_validation(void)
{
	struct xdev_ext_binding_ctx_v2 ctx = base_ctx();

	ctx.event = XDEV_EXT_BINDING_EVENT_UNSPEC;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = base_ctx();
	ctx.event = XDEV_EXT_BINDING_EVENT_MAX;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);

	ctx = base_ctx();
	ctx.backend = XDEV_EXT_BINDING_BACKEND_UNSPEC;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = base_ctx();
	ctx.backend = XDEV_EXT_BINDING_BACKEND_MAX;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);

	ctx = base_ctx();
	ctx.direction = XDEV_EXT_BINDING_DIRECTION_UNSPEC;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = base_ctx();
	ctx.direction = XDEV_EXT_BINDING_DIRECTION_MAX;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);

	ctx = base_ctx();
	ctx.current_stage = XDEV_EXT_BINDING_STAGE_NONE;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = base_ctx();
	ctx.current_stage = XDEV_EXT_BINDING_STAGE_MAX;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
}

static void test_context_header_and_reserved_validation(void)
{
	struct xdev_ext_binding_ctx_v2 ctx = base_ctx();

	ctx.abi_version++;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EPROTO);
	ctx = base_ctx();
	ctx.ctx_size--;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EPROTO);

	ctx = base_ctx();
	ctx.frame_state = 1;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = base_ctx();
	ctx.reserved0 = 1;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = base_ctx();
	ctx.reserved1 = 1;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
}

static void test_unknown_mask_bits(void)
{
	struct xdev_ext_binding_ctx_v2 ctx = base_ctx();

	ctx.allowed_recipe_mask |= UINT32_C(1) << 31;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = base_ctx();
	ctx.allowed_next_mask |= UINT32_C(1) << 31;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = base_ctx();
	ctx.allowed_profile_mask |= UINT32_C(1) << 31;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = base_ctx();
	ctx.capabilities |= UINT32_C(1) << 31;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
}

static void test_backend_direction_validation(void)
{
	struct xdev_ext_binding_ctx_v2 ctx = base_ctx();

	ctx.direction = XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);

	ctx = xdev_ext_binding_make_afxdp_tx_ctx(4096);
	ctx.direction = XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);

	ctx = xdev_ext_binding_make_afxdp_rx_ctx(0, 4096, 0);
	ctx.direction = XDEV_EXT_BINDING_DIRECTION_TO_DEVICE;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);

	ctx = xdev_ext_binding_make_nvme_ctx(0, 0, 4096);
	ctx.direction = XDEV_EXT_BINDING_DIRECTION_TO_DEVICE;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);

	ctx = xdev_ext_binding_make_nvme_ctx(1, 0, 4096);
	ctx.direction = XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);

	ctx = xdev_ext_binding_make_iaa_ctx(0, 0, 0, 4096);
	ctx.direction = XDEV_EXT_BINDING_DIRECTION_TO_DEVICE;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
}

static void test_backend_recipe_matrix(void)
{
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_SOCKET,
			  XDEV_EXT_BINDING_RECIPE_SOCKET_SEND), 1);
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_SOCKET,
			  XDEV_EXT_BINDING_RECIPE_AFXDP_COPY), 0);
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_AFXDP,
			  XDEV_EXT_BINDING_RECIPE_AFXDP_COPY), 1);
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_AFXDP,
			  XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX), 1);
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_AFXDP,
			  XDEV_EXT_BINDING_RECIPE_AFXDP_RX), 1);
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_NVME,
			  XDEV_EXT_BINDING_RECIPE_NVME_PT_READ), 1);
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_NVME,
			  XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE), 1);
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_NVME,
			  XDEV_EXT_BINDING_RECIPE_FILE_READ), 0);
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_IAA,
			  XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS), 1);
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_IAA,
			  XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS), 1);
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_GPU,
			  XDEV_EXT_BINDING_RECIPE_GPU_COPY), 1);
	EXPECT_EQ(xdev_ext_binding_backend_allows_recipe(
			  XDEV_EXT_BINDING_BACKEND_UNSPEC,
			  XDEV_EXT_BINDING_RECIPE_GPU_COPY), 0);

	/* A trusted-C mask that crosses backend boundaries is itself invalid. */
	{
		struct xdev_ext_binding_ctx_v2 ctx = base_ctx();

		ctx.allowed_recipe_mask |=
			xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_GPU_COPY);
		EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	}
}

static void test_stage_recipe_matrix(void)
{
	struct xdev_ext_binding_ctx_v2 ctx;

	EXPECT_EQ(xdev_ext_binding_stage_allows_recipe(
			  XDEV_EXT_BINDING_STAGE_AFXDP_TX,
			  XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX), 1);
	EXPECT_EQ(xdev_ext_binding_stage_allows_recipe(
			  XDEV_EXT_BINDING_STAGE_AFXDP_RX,
			  XDEV_EXT_BINDING_RECIPE_AFXDP_RX), 1);
	EXPECT_EQ(xdev_ext_binding_stage_allows_recipe(
			  XDEV_EXT_BINDING_STAGE_AFXDP_RX,
			  XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX), 0);
	EXPECT_EQ(xdev_ext_binding_stage_allows_recipe(
			  XDEV_EXT_BINDING_STAGE_NVME_READ,
			  XDEV_EXT_BINDING_RECIPE_NVME_PT_READ), 1);
	EXPECT_EQ(xdev_ext_binding_stage_allows_recipe(
			  XDEV_EXT_BINDING_STAGE_NVME_READ,
			  XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE), 0);
	EXPECT_EQ(xdev_ext_binding_stage_allows_recipe(
			  XDEV_EXT_BINDING_STAGE_NVME_WRITE,
			  XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE), 1);
	EXPECT_EQ(xdev_ext_binding_stage_allows_recipe(
			  XDEV_EXT_BINDING_STAGE_NVME_WRITE,
			  XDEV_EXT_BINDING_RECIPE_NVME_PT_READ), 0);
	EXPECT_EQ(xdev_ext_binding_stage_allows_recipe(
			  XDEV_EXT_BINDING_STAGE_IAA_COMPRESS,
			  XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS), 1);
	EXPECT_EQ(xdev_ext_binding_stage_allows_recipe(
			  XDEV_EXT_BINDING_STAGE_IAA_COMPRESS,
			  XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS), 0);
	EXPECT_EQ(xdev_ext_binding_stage_allows_recipe(
			  XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS,
			  XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS), 1);
	EXPECT_EQ(xdev_ext_binding_stage_allows_recipe(
			  XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS,
			  XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS), 0);

	ctx = xdev_ext_binding_make_nvme_ctx(0, 0, 4096);
	ctx.allowed_recipe_mask =
		xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = xdev_ext_binding_make_nvme_ctx(1, 0, 4096);
	ctx.allowed_recipe_mask =
		xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_NVME_PT_READ);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);

	ctx = xdev_ext_binding_make_iaa_ctx(0, 0, 0, 4096);
	ctx.allowed_recipe_mask =
		xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = xdev_ext_binding_make_iaa_ctx(1, 0, 0, 4096);
	ctx.allowed_recipe_mask =
		xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS);
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
}

static void test_zero_argument_actions(void)
{
	struct xdev_ext_binding_ctx_v2 ctx = base_ctx();
	struct xdev_ext_binding_plan plan =
		zero_arg_plan(XDEV_EXT_BINDING_ACTION_FALLBACK);

	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), 0);
	plan.action = XDEV_EXT_BINDING_ACTION_TERMINAL;
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), 0);

	plan = zero_arg_plan(XDEV_EXT_BINDING_ACTION_FALLBACK);
	plan.recipe = XDEV_EXT_BINDING_RECIPE_SOCKET_SEND;
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EINVAL);
	plan = zero_arg_plan(XDEV_EXT_BINDING_ACTION_FALLBACK);
	plan.next_stage = XDEV_EXT_BINDING_STAGE_COMPLETE;
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EINVAL);
	plan = zero_arg_plan(XDEV_EXT_BINDING_ACTION_TERMINAL);
	plan.profile = XDEV_EXT_BINDING_PROFILE_NATIVE;
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EINVAL);
}

static void test_use_plan_validation(void)
{
	struct xdev_ext_binding_ctx_v2 ctx = base_ctx();
	struct xdev_ext_binding_plan plan = use_plan(
		XDEV_EXT_BINDING_RECIPE_SOCKET_SEND, XDEV_EXT_BINDING_STAGE_COMPLETE,
		XDEV_EXT_BINDING_PROFILE_NATIVE);

	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), 0);

	plan.action = XDEV_EXT_BINDING_ACTION_MAX;
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EINVAL);
	plan = use_plan(XDEV_EXT_BINDING_RECIPE_DEFAULT,
			XDEV_EXT_BINDING_STAGE_COMPLETE, XDEV_EXT_BINDING_PROFILE_NATIVE);
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EINVAL);
	plan = use_plan(XDEV_EXT_BINDING_RECIPE_MAX,
			XDEV_EXT_BINDING_STAGE_COMPLETE, XDEV_EXT_BINDING_PROFILE_NATIVE);
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EINVAL);
	plan = use_plan(XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
			XDEV_EXT_BINDING_STAGE_NONE, XDEV_EXT_BINDING_PROFILE_NATIVE);
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EINVAL);
	plan = use_plan(XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
			XDEV_EXT_BINDING_STAGE_MAX, XDEV_EXT_BINDING_PROFILE_NATIVE);
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EINVAL);
	plan = use_plan(XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
			XDEV_EXT_BINDING_STAGE_COMPLETE, XDEV_EXT_BINDING_PROFILE_NONE);
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EINVAL);
	plan = use_plan(XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
			XDEV_EXT_BINDING_STAGE_COMPLETE, XDEV_EXT_BINDING_PROFILE_MAX);
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EINVAL);

	plan = use_plan(XDEV_EXT_BINDING_RECIPE_FILE_READ,
			XDEV_EXT_BINDING_STAGE_COMPLETE, XDEV_EXT_BINDING_PROFILE_NATIVE);
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EPERM);
	plan = use_plan(XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
			XDEV_EXT_BINDING_STAGE_GPU_COPY, XDEV_EXT_BINDING_PROFILE_NATIVE);
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EPERM);
	plan = use_plan(XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
			XDEV_EXT_BINDING_STAGE_COMPLETE, XDEV_EXT_BINDING_PROFILE_NATIVE);
	ctx.allowed_profile_mask = 0;
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -EPERM);

	ctx = base_ctx();
	ctx.allowed_next_mask = xdev_ext_binding_stage_bit(XDEV_EXT_BINDING_STAGE_SEND);
	plan.next_stage = XDEV_EXT_BINDING_STAGE_SEND;
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &plan), -ELOOP);
}

static void test_dispatch_is_pristine(void)
{
	struct xdev_ext_binding_ctx_v2 ctx = base_ctx();

	ctx.result = -EIO;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx = base_ctx();
	ctx.bytes_done = 1;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
}

static void test_completion_rules(void)
{
	struct xdev_ext_binding_ctx_v2 ctx = base_ctx();
	struct xdev_ext_binding_plan fallback =
		zero_arg_plan(XDEV_EXT_BINDING_ACTION_FALLBACK);
	struct xdev_ext_binding_plan terminal =
		zero_arg_plan(XDEV_EXT_BINDING_ACTION_TERMINAL);
	struct xdev_ext_binding_plan continue_plan = use_plan(
		XDEV_EXT_BINDING_RECIPE_SOCKET_SEND, XDEV_EXT_BINDING_STAGE_COMPLETE,
		XDEV_EXT_BINDING_PROFILE_NATIVE);

	ctx.event = XDEV_EXT_BINDING_EVENT_COMPLETE;
	ctx.result = -EIO;
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &fallback), 0);
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &terminal), 0);
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &continue_plan), -EPERM);

	ctx.result = 0;
	ctx.bytes_done = ctx.length + 1;
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, &continue_plan), 0);

	ctx = base_ctx();
	ctx.event = XDEV_EXT_BINDING_EVENT_COMPLETE;
	ctx.result = 1;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx.result = -4096;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
	ctx.result = -4095;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);
	ctx.result = -EIO;
	ctx.bytes_done = 1;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), -EINVAL);
}

static void test_byte_result_normalization(void)
{
	struct xdev_ext_binding_normalized_result normalized;
	int64_t native_result;

	native_result = 0;
	normalized = xdev_ext_binding_normalize_byte_result(native_result);
	EXPECT_EQ(native_result, 0);
	EXPECT_EQ(normalized.result, 0);
	EXPECT_EQ(normalized.bytes_done, 0);

	native_result = 4096;
	normalized = xdev_ext_binding_normalize_byte_result(native_result);
	EXPECT_EQ(native_result, 4096);
	EXPECT_EQ(normalized.result, 0);
	EXPECT_EQ(normalized.bytes_done, 4096);

	native_result = -EAGAIN;
	normalized = xdev_ext_binding_normalize_byte_result(native_result);
	EXPECT_EQ(native_result, -EAGAIN);
	EXPECT_EQ(normalized.result, -EAGAIN);
	EXPECT_EQ(normalized.bytes_done, 0);

	native_result = -4095;
	normalized = xdev_ext_binding_normalize_byte_result(native_result);
	EXPECT_EQ(normalized.result, -4095);
	EXPECT_EQ(normalized.bytes_done, 0);

	native_result = -4096;
	normalized = xdev_ext_binding_normalize_byte_result(native_result);
	EXPECT_EQ(normalized.result, -EIO);
	EXPECT_EQ(normalized.bytes_done, 0);
}

static void test_status_result_normalization(void)
{
	struct xdev_ext_binding_normalized_result normalized;
	int64_t native_status;

	native_status = 0;
	normalized = xdev_ext_binding_normalize_status_result(native_status, 8192);
	EXPECT_EQ(native_status, 0);
	EXPECT_EQ(normalized.result, 0);
	EXPECT_EQ(normalized.bytes_done, 8192);

	native_status = -EIO;
	normalized = xdev_ext_binding_normalize_status_result(native_status, 8192);
	EXPECT_EQ(native_status, -EIO);
	EXPECT_EQ(normalized.result, -EIO);
	EXPECT_EQ(normalized.bytes_done, 0);

	native_status = -4095;
	normalized = xdev_ext_binding_normalize_status_result(native_status, 8192);
	EXPECT_EQ(normalized.result, -4095);
	EXPECT_EQ(normalized.bytes_done, 0);

	/* Positive NVMe or NVIDIA device statuses are not Linux errnos. */
	native_status = 1;
	normalized = xdev_ext_binding_normalize_status_result(native_status, 8192);
	EXPECT_EQ(native_status, 1);
	EXPECT_EQ(normalized.result, -EIO);
	EXPECT_EQ(normalized.bytes_done, 0);

	native_status = UINT16_MAX;
	normalized = xdev_ext_binding_normalize_status_result(native_status, 8192);
	EXPECT_EQ(normalized.result, -EIO);
	EXPECT_EQ(normalized.bytes_done, 0);

	native_status = -4096;
	normalized = xdev_ext_binding_normalize_status_result(native_status, 8192);
	EXPECT_EQ(normalized.result, -EIO);
	EXPECT_EQ(normalized.bytes_done, 0);
}

static void test_capabilities(void)
{
	struct xdev_ext_binding_ctx_v2 ctx = base_ctx();

	ctx.capabilities = XDEV_EXT_BINDING_CAP_ASYNC |
			   XDEV_EXT_BINDING_CAP_POLL |
			   XDEV_EXT_BINDING_CAP_FIXED_FILE |
			   XDEV_EXT_BINDING_CAP_FIXED_BUFFER |
			   XDEV_EXT_BINDING_CAP_ZERO_COPY;
	EXPECT_EQ(xdev_ext_binding_validate_ctx(&ctx), 0);
}

static void test_bounded_window(void)
{
	EXPECT_EQ(xdev_ext_binding_window_valid(0, 0, 0), 1);
	EXPECT_EQ(xdev_ext_binding_window_valid(0, 4096, 4096), 1);
	EXPECT_EQ(xdev_ext_binding_window_valid(4096, 0, 4096), 1);
	EXPECT_EQ(xdev_ext_binding_window_valid(1, 4095, 4096), 1);
	EXPECT_EQ(xdev_ext_binding_window_valid(4097, 0, 4096), 0);
	EXPECT_EQ(xdev_ext_binding_window_valid(1, 4096, 4096), 0);
	EXPECT_EQ(xdev_ext_binding_window_valid(UINT64_MAX, 1, UINT64_MAX), 0);
	EXPECT_EQ(xdev_ext_binding_window_valid(UINT64_MAX - 1, 2,
					   UINT64_MAX), 0);
	EXPECT_EQ(xdev_ext_binding_window_valid(UINT64_MAX - 1, 1,
					   UINT64_MAX), 1);
}

static void test_null_inputs(void)
{
	struct xdev_ext_binding_ctx_v2 ctx = base_ctx();
	struct xdev_ext_binding_plan plan =
		zero_arg_plan(XDEV_EXT_BINDING_ACTION_FALLBACK);

	EXPECT_EQ(xdev_ext_binding_validate_ctx(NULL), -EINVAL);
	EXPECT_EQ(xdev_ext_binding_validate_plan(NULL, &plan), -EINVAL);
	EXPECT_EQ(xdev_ext_binding_validate_plan(&ctx, NULL), -EINVAL);
}

int main(void)
{
	test_safe_dynamic_bit_helpers();
	test_socket_builder();
	test_afxdp_builder();
	test_afxdp_native_tx_builder();
	test_afxdp_rx_builder();
	test_policy_flag_validation();
	test_nvme_builders();
	test_iaa_builders();
	test_gpu_builders();
	test_context_enum_validation();
	test_context_header_and_reserved_validation();
	test_unknown_mask_bits();
	test_backend_direction_validation();
	test_backend_recipe_matrix();
	test_stage_recipe_matrix();
	test_zero_argument_actions();
	test_use_plan_validation();
	test_dispatch_is_pristine();
	test_completion_rules();
	test_byte_result_normalization();
	test_status_result_normalization();
	test_capabilities();
	test_bounded_window();
	test_null_inputs();

	if (tests_failed) {
		fprintf(stderr, "FAIL: %u of %u checks failed\n",
			tests_failed, tests_run);
		return 1;
	}

	printf("PASS: %u binding ABI v2 validator checks\n", tests_run);
	return 0;
}
