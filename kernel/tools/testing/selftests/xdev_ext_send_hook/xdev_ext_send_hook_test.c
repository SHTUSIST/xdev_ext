// SPDX-License-Identifier: GPL-2.0

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifndef ERESTARTSYS
#define ERESTARTSYS 512
#endif

#include "../../../../include/uapi/linux/io_uring.h"
#include "../../../../io_uring/xdev_ext_send_hook.h"

static_assert(sizeof(struct io_uring_sqe) == 64,
	      "io_uring base SQE layout changed");
static_assert(offsetof(struct io_uring_sqe, off) == 8,
	      "io_uring off offset changed");
static_assert(offsetof(struct io_uring_sqe, off) ==
	      offsetof(struct io_uring_sqe, addr2),
	      "io_uring off/addr2 alias changed");
static_assert(offsetof(struct io_uring_sqe, addr3) == 48,
	      "io_uring addr3 offset changed");

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual, expected) do {                                      \
	long long _actual = (long long)(actual);                               \
	long long _expected = (long long)(expected);                           \
	checks++;                                                               \
	if (_actual != _expected) {                                             \
		fprintf(stderr, "%s:%d: got %lld, expected %lld\n",             \
			__FILE__, __LINE__, _actual, _expected);                    \
		failures++;                                                        \
	}                                                                        \
} while (0)

struct fake_send {
	struct xdev_ext_send_hook_state hook;
	int dispatch_ret;
	uint32_t action;
	long native_ret;
	bool native_called;
	unsigned int native_calls;
	unsigned int token_puts;
	unsigned int completes;
};

static long fake_native_call(bool *native_called, unsigned int *native_calls,
			     long native_ret)
{
	EXPECT_EQ(*native_called, true);
	(*native_calls)++;
	return native_ret;
}

static void test_native_call_boundary(void)
{
	unsigned int native_calls = 0;
	bool native_called = false;
	long ret;

	ret = xdev_ext_send_hook_call_native(&native_called,
					fake_native_call(&native_called, &native_calls,
							 -ENXIO));
	EXPECT_EQ(ret, -ENXIO);
	EXPECT_EQ(native_called, true);
	EXPECT_EQ(native_calls, 1);

	native_called = false;
	ret = xdev_ext_send_hook_call_native(&native_called,
					fake_native_call(&native_called, &native_calls,
							 -ENETDOWN));
	EXPECT_EQ(ret, -ENETDOWN);
	EXPECT_EQ(native_called, true);
	EXPECT_EQ(native_calls, 2);
}

static void test_restart_is_user_visible_eintr_and_completes_once(void)
{
	struct xdev_ext_binding_normalized_result normalized;
	struct xdev_ext_binding_ctx_v2 ctx = {};
	struct xdev_ext_send_hook_state hook = {};
	unsigned int native_calls = 0;
	bool native_called = false;
	enum xdev_ext_send_hook_finish finish;
	long ret;

	EXPECT_EQ(xdev_ext_send_hook_after_dispatch(
			  &hook, 0, XDEV_EXT_BINDING_ACTION_FALLBACK), 0);
	ret = xdev_ext_send_hook_call_native(
		&native_called,
		fake_native_call(&native_called, &native_calls, -ERESTARTSYS));
	EXPECT_EQ(ret, -EINTR);
	EXPECT_EQ(native_called, true);
	EXPECT_EQ(native_calls, 1);
	normalized = xdev_ext_binding_normalize_byte_result(ret);
	ctx.event = XDEV_EXT_BINDING_EVENT_COMPLETE;
	ctx.result = normalized.result;
	ctx.bytes_done = normalized.bytes_done;
	EXPECT_EQ(ctx.event, XDEV_EXT_BINDING_EVENT_COMPLETE);
	EXPECT_EQ(ctx.result, -EINTR);
	EXPECT_EQ(ctx.bytes_done, 0);
	finish = xdev_ext_send_hook_finish(&hook, native_called);
	EXPECT_EQ(finish, XDEV_EXT_SEND_HOOK_COMPLETE);
	EXPECT_EQ(xdev_ext_send_hook_finish(&hook, native_called),
		  XDEV_EXT_SEND_HOOK_FINISH_NONE);
}

static void test_umem_compatibility_preflight(void)
{
	EXPECT_EQ(xdev_ext_send_hook_check_umem_compat(false, false, false), 0);
	EXPECT_EQ(xdev_ext_send_hook_check_umem_compat(true, false, false), 0);
	EXPECT_EQ(xdev_ext_send_hook_check_umem_compat(false, true, false), 0);
	EXPECT_EQ(xdev_ext_send_hook_check_umem_compat(true, true, false),
		  -EOPNOTSUPP);
	EXPECT_EQ(xdev_ext_send_hook_check_umem_compat(false, true, true),
		  -EOPNOTSUPP);
}

static void test_send_buffer_source_preflight(void)
{
	/* A zero userspace pointer is invalid for an ordinary socket SEND. */
	EXPECT_EQ(xdev_ext_send_hook_check_buffer_source(false, false, 0), -EINVAL);

	/* AF_XDP and registered UMEM both use zero as a valid frame offset. */
	EXPECT_EQ(xdev_ext_send_hook_check_buffer_source(true, false, 0), 0);
	EXPECT_EQ(xdev_ext_send_hook_check_buffer_source(false, true, 0), 0);
	EXPECT_EQ(xdev_ext_send_hook_check_buffer_source(false, false, 1), 0);
}

static void test_send_flags_preflight(void)
{
	const uint32_t internal_flags = UINT32_C(0x08110000);
	const uint32_t allowed_flags = UINT32_MAX & ~internal_flags;
	const uint32_t nopolicy_flag = UINT32_C(0x00010000);
	const uint32_t decrypted_flag = UINT32_C(0x00100000);
	const uint32_t splice_flag = UINT32_C(0x08000000);
	const uint64_t wide_flags = UINT64_C(1) << 32;
	int ret;

	ret = xdev_ext_send_hook_check_flags_masked(false, 0, internal_flags);
	EXPECT_EQ(ret, 0);
	ret = xdev_ext_send_hook_check_flags_masked(false, allowed_flags,
					       internal_flags);
	EXPECT_EQ(ret, 0);
	ret = xdev_ext_send_hook_check_flags_masked(false, wide_flags,
					       internal_flags);
	EXPECT_EQ(ret, -EINVAL);

	/* Match MSG_INTERNAL_SENDMSG_FLAGS from include/linux/socket.h. */
	ret = xdev_ext_send_hook_check_flags_masked(false, nopolicy_flag,
					       internal_flags);
	EXPECT_EQ(ret, -EINVAL);
	ret = xdev_ext_send_hook_check_flags_masked(false, decrypted_flag,
					       internal_flags);
	EXPECT_EQ(ret, -EINVAL);
	ret = xdev_ext_send_hook_check_flags_masked(false, splice_flag,
					       internal_flags);
	EXPECT_EQ(ret, -EINVAL);
	ret = xdev_ext_send_hook_check_flags_masked(false, internal_flags,
					       internal_flags);
	EXPECT_EQ(ret, -EINVAL);

	/* The in-kernel AF_XDP COPY entry has no descriptor-option ABI. */
	ret = xdev_ext_send_hook_check_flags_masked(true, 0, internal_flags);
	EXPECT_EQ(ret, 0);
	ret = xdev_ext_send_hook_check_flags_masked(true, decrypted_flag,
					       internal_flags);
	EXPECT_EQ(ret, -EINVAL);
	ret = xdev_ext_send_hook_check_flags_masked(true, 1, internal_flags);
	EXPECT_EQ(ret, -EOPNOTSUPP);
}

static void test_effective_socket_flags(void)
{
	const uint32_t requested = UINT32_C(0x4000);
	const uint32_t dontwait = UINT32_C(0x0040);

	EXPECT_EQ(xdev_ext_send_hook_effective_flags(requested, false, dontwait),
		  requested);
	EXPECT_EQ(xdev_ext_send_hook_effective_flags(requested, true, dontwait),
		  requested | dontwait);
	EXPECT_EQ(xdev_ext_send_hook_effective_flags(requested | dontwait, true,
						dontwait),
		  requested | dontwait);
}

static void test_send_sqe_field_encoding(void)
{
	const uint64_t shared = UINT64_C(0x123456789abcdef0);
	const uint64_t flags = UINT64_C(0x4000);
	struct xdev_ext_send_sqe_fields fields;

	/* New encoding: addr3 carries stats, leaving all of off for flags. */
	fields = xdev_ext_send_sqe_fields_from_words(false, flags, shared);
	EXPECT_EQ(fields.shared_addr, shared);
	EXPECT_EQ(fields.send_flags, flags);

	/* Legacy non-UMEM encoding: off/addr2 carries stats and no flags. */
	fields = xdev_ext_send_sqe_fields_from_words(false, shared, 0);
	EXPECT_EQ(fields.shared_addr, shared);
	EXPECT_EQ(fields.send_flags, 0);

	/* Registered UMEM owns stats; off remains the SEND flags word. */
	fields = xdev_ext_send_sqe_fields_from_words(true, flags, shared);
	EXPECT_EQ(fields.shared_addr, 0);
	EXPECT_EQ(fields.send_flags, flags);
}

static void test_send_context_construction(void)
{
	struct xdev_ext_binding_ctx_v2 ctx;

	ctx = xdev_ext_send_hook_make_ctx(true, false, 73, 512);
	EXPECT_EQ(ctx.backend, XDEV_EXT_BINDING_BACKEND_AFXDP);
	EXPECT_EQ(ctx.event, XDEV_EXT_BINDING_EVENT_DISPATCH);
	EXPECT_EQ(ctx.current_stage, XDEV_EXT_BINDING_STAGE_AFXDP_TX);
	EXPECT_EQ(ctx.direction, XDEV_EXT_BINDING_DIRECTION_TO_DEVICE);
	EXPECT_EQ(ctx.src_offset, 73);
	EXPECT_EQ(ctx.length, 512);

	ctx = xdev_ext_send_hook_make_ctx(false, true, 91, 1024);
	EXPECT_EQ(ctx.backend, XDEV_EXT_BINDING_BACKEND_SOCKET);
	EXPECT_EQ(ctx.current_stage, XDEV_EXT_BINDING_STAGE_SEND);
	EXPECT_EQ(ctx.src_offset, 91);
	EXPECT_EQ(ctx.length, 1024);

	ctx = xdev_ext_send_hook_make_ctx(false, false, 117, 2048);
	EXPECT_EQ(ctx.backend, XDEV_EXT_BINDING_BACKEND_SOCKET);
	EXPECT_EQ(ctx.src_offset, 0);
	EXPECT_EQ(ctx.length, 2048);
}

static long fake_run(struct fake_send *fake)
{
	enum xdev_ext_send_hook_finish finish;
	int ret;

	ret = xdev_ext_send_hook_after_dispatch(&fake->hook, fake->dispatch_ret,
					   fake->action);
	if (!ret) {
		if (fake->native_called)
			fake->native_calls++;
		ret = fake->native_ret;
	}

	finish = xdev_ext_send_hook_finish(&fake->hook, fake->native_called);
	if (finish == XDEV_EXT_SEND_HOOK_PUT_TOKEN)
		fake->token_puts++;
	else if (finish == XDEV_EXT_SEND_HOOK_COMPLETE)
		fake->completes++;
	return ret;
}

static void expect_one_case(int dispatch_ret, uint32_t action,
			    long native_ret, bool native_called,
			    long expected_ret, unsigned int native_calls,
			    unsigned int puts, unsigned int completes)
{
	struct fake_send fake = {
		.dispatch_ret = dispatch_ret,
		.action = action,
		.native_ret = native_ret,
		.native_called = native_called,
	};

	EXPECT_EQ(fake_run(&fake), expected_ret);
	EXPECT_EQ(fake.native_calls, native_calls);
	EXPECT_EQ(fake.token_puts, puts);
	EXPECT_EQ(fake.completes, completes);
	EXPECT_EQ(xdev_ext_send_hook_finish(&fake.hook, native_called),
		  XDEV_EXT_SEND_HOOK_FINISH_NONE);
}

int main(void)
{
	struct xdev_ext_send_hook_state inactive = {};

	test_native_call_boundary();
	test_restart_is_user_visible_eintr_and_completes_once();
	test_umem_compatibility_preflight();
	test_send_buffer_source_preflight();
	test_send_flags_preflight();
	test_effective_socket_flags();
	test_send_sqe_field_encoding();
	test_send_context_construction();

	/* No active policy: the native path runs without a token finalizer. */
	EXPECT_EQ(xdev_ext_send_hook_finish(&inactive, true),
		  XDEV_EXT_SEND_HOOK_FINISH_NONE);

	/* Dispatch rejection and terminal/invalid plans call no native path. */
	expect_one_case(-EACCES, XDEV_EXT_BINDING_ACTION_FALLBACK, 0, false,
			-EACCES, 0, 1, 0);
	expect_one_case(0, XDEV_EXT_BINDING_ACTION_TERMINAL, 0, false,
			-EPERM, 0, 1, 0);
	expect_one_case(0, 99, 0, false, -EPROTO, 0, 1, 0);

	/* A pre-native failure unwinds the pinned generation. */
	expect_one_case(0, XDEV_EXT_BINDING_ACTION_FALLBACK, -EINVAL, false,
			-EINVAL, 0, 1, 0);

	/* Once native was called, success, short write, and errno all complete. */
	expect_one_case(0, XDEV_EXT_BINDING_ACTION_FALLBACK, 4096, true,
			4096, 1, 0, 1);
	expect_one_case(0, XDEV_EXT_BINDING_ACTION_USE_PLAN, 17, true,
			17, 1, 0, 1);
	expect_one_case(0, XDEV_EXT_BINDING_ACTION_FALLBACK, -EPIPE, true,
			-EPIPE, 1, 0, 1);

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks\n", failures, checks);
		return 1;
	}
	printf("PASS: %u send-hook checks\n", checks);
	return 0;
}
