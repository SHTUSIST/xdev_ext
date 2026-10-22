/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_SEND_HOOK_H
#define IO_URING_XDEV_EXT_SEND_HOOK_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/xdev_ext_binding.h>
#else
#include <errno.h>
#include <stdbool.h>
#include "../include/linux/xdev_ext_binding.h"
#endif

/*
 * Small pure state machine shared by the socket and AF_XDP send hooks.  It
 * makes token ownership explicit across policy rejection, failures before the
 * native function is entered, and native completion.
 */
struct xdev_ext_send_hook_state {
	bool policy_attempted;
	bool policy_dispatched;
	bool finalized;
};

struct xdev_ext_send_sqe_fields {
	__u64 shared_addr;
	__u64 send_flags;
};

/*
 * addr2 aliases off in the SQE.  A non-UMEM SEND therefore uses addr3 for
 * the stats pointer when it also needs flags.  An all-zero addr3 selects the
 * original addr2/off stats encoding, whose flags are necessarily zero.
 * Registered UMEM supplies its own stats pointer and always leaves off for
 * SEND flags.
 */
static inline struct xdev_ext_send_sqe_fields
xdev_ext_send_sqe_fields_from_words(bool use_umem, __u64 off, __u64 addr3)
{
	struct xdev_ext_send_sqe_fields fields = {
		.shared_addr = 0,
		.send_flags = off,
	};

	if (use_umem)
		return fields;
	if (addr3) {
		fields.shared_addr = addr3;
	} else {
		fields.shared_addr = off;
		fields.send_flags = 0;
	}
	return fields;
}

enum xdev_ext_send_hook_finish {
	XDEV_EXT_SEND_HOOK_FINISH_NONE = 0,
	XDEV_EXT_SEND_HOOK_PUT_TOKEN,
	XDEV_EXT_SEND_HOOK_COMPLETE,
};

/*
 * Mark the native boundary before evaluating the call expression.  Keeping
 * the ordering in one helper prevents an immediate native errno from being
 * mistaken for a pre-native failure and dropping the completion callback.
 * Kernel-private restart results must not escape through an io_uring CQE.
 */
#define xdev_ext_send_hook_call_native(native_called, native_call) ({ \
	__s64 __native_result; \
	*(native_called) = true; \
	__native_result = (native_call); \
	__native_result == -ERESTARTSYS ? -EINTR : __native_result; \
})

static inline struct xdev_ext_binding_ctx_v2
xdev_ext_send_hook_make_ctx(bool afxdp, bool use_umem, __u64 src_offset,
		       __u64 length)
{
	struct xdev_ext_binding_ctx_v2 ctx;

	ctx = afxdp ? xdev_ext_binding_make_afxdp_tx_ctx(length) :
		      xdev_ext_binding_make_socket_send_ctx(length);
	if (afxdp || use_umem)
		ctx.src_offset = src_offset;
	return ctx;
}

static inline int
xdev_ext_send_hook_check_umem_compat(bool afxdp, bool use_umem,
				bool msg_zerocopy)
{
	if (!use_umem)
		return 0;
	if (afxdp || msg_zerocopy)
		return -EOPNOTSUPP;
	return 0;
}

/*
 * A normal non-UMEM socket SEND needs a userspace buffer pointer.  AF_XDP and
 * registered UMEM instead interpret addr as a byte offset, where zero names
 * the first frame.  Run this after the socket has been classified and before
 * policy dispatch.
 */
static inline int
xdev_ext_send_hook_check_buffer_source(bool afxdp, bool use_umem, __u64 addr)
{
	return !afxdp && !use_umem && !addr ? -EINVAL : 0;
}

/*
 * sock_sendmsg() consumes a 32-bit flag word.  Reject bits that would be
 * truncated rather than silently changing the request, and reject internal
 * flags that normal sendmsg entry points strip before reaching a protocol.
 * The mask parameter keeps the state machine directly testable outside the
 * kernel without copying private socket flag definitions into UAPI.
 */
static inline int
xdev_ext_send_hook_check_flags_masked(bool afxdp, __u64 flags,
				 __u32 internal_flags)
{
	if (flags > (__u64)(__u32)~0U)
		return -EINVAL;
	if ((__u32)flags & internal_flags)
		return -EINVAL;
	return afxdp && flags ? -EOPNOTSUPP : 0;
}

static inline __u32
xdev_ext_send_hook_effective_flags(__u32 requested_flags, bool file_nonblock,
			      __u32 dontwait_flag)
{
	/* Preserve every validated caller flag and add descriptor nonblocking. */
	return requested_flags | (file_nonblock ? dontwait_flag : 0);
}

#ifdef __KERNEL__
static inline int xdev_ext_send_hook_check_flags(bool afxdp, __u64 flags)
{
	return xdev_ext_send_hook_check_flags_masked(afxdp, flags,
						(__u32)MSG_INTERNAL_SENDMSG_FLAGS);
}
#endif

static inline int
xdev_ext_send_hook_after_dispatch(struct xdev_ext_send_hook_state *state,
			     int dispatch_ret, __u32 action)
{
	if (!state)
		return -EINVAL;
	if (state->policy_attempted)
		return -EALREADY;

	state->policy_attempted = true;
	if (dispatch_ret)
		return dispatch_ret;

	switch (action) {
	case XDEV_EXT_BINDING_ACTION_FALLBACK:
	case XDEV_EXT_BINDING_ACTION_USE_PLAN:
		state->policy_dispatched = true;
		return 0;
	case XDEV_EXT_BINDING_ACTION_TERMINAL:
		return -EPERM;
	default:
		return -EPROTO;
	}
}

#ifdef __KERNEL__
static inline int
xdev_ext_send_hook_dispatch_binding(struct xdev_ext_send_hook_state *state,
			       struct xdev_ext_binding_ctx_v2 *ctx,
			       struct xdev_ext_binding_token *token,
			       struct xdev_ext_binding_plan *plan,
			       int *binding_ret)
{
	int ret;

	ret = xdev_ext_binding_dispatch(ctx, token, plan);
	if (binding_ret)
		*binding_ret = ret;
	return xdev_ext_send_hook_after_dispatch(state, ret, plan->action);
}
#endif

static inline enum xdev_ext_send_hook_finish
xdev_ext_send_hook_finish(struct xdev_ext_send_hook_state *state, bool native_called)
{
	if (!state || !state->policy_attempted || state->finalized)
		return XDEV_EXT_SEND_HOOK_FINISH_NONE;

	state->finalized = true;
	if (!state->policy_dispatched || !native_called)
		return XDEV_EXT_SEND_HOOK_PUT_TOKEN;
	return XDEV_EXT_SEND_HOOK_COMPLETE;
}

#ifdef __KERNEL__
static inline int
xdev_ext_send_hook_finish_binding(struct xdev_ext_send_hook_state *state,
			     struct xdev_ext_binding_ctx_v2 *ctx,
			     struct xdev_ext_binding_token *token,
			     bool native_called, __s64 native_result,
			     struct xdev_ext_binding_plan *plan)
{
	struct xdev_ext_binding_normalized_result normalized;
	enum xdev_ext_send_hook_finish finish;

	finish = xdev_ext_send_hook_finish(state, native_called);
	if (finish == XDEV_EXT_SEND_HOOK_FINISH_NONE)
		return 0;
	if (finish == XDEV_EXT_SEND_HOOK_PUT_TOKEN) {
		xdev_ext_binding_token_put(token);
		return 0;
	}

	normalized = xdev_ext_binding_normalize_byte_result(native_result);
	ctx->event = XDEV_EXT_BINDING_EVENT_COMPLETE;
	ctx->result = normalized.result;
	ctx->bytes_done = normalized.bytes_done;
	return xdev_ext_binding_complete(ctx, token, plan);
}
#endif

#endif /* IO_URING_XDEV_EXT_SEND_HOOK_H */
