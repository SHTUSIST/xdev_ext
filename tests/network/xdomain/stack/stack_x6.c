/* SPDX-License-Identifier: GPL-2.0 */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"
#include "../../../../../tools/xdev_ext_mech/xdomain_peer.bpf.c"

/* Host invocation storage supplies class-sized views to the complete actual
 * program above. The production identity/kfunc and verifier gates run apart.
 * Faulted verdicts are recorded before the current callback returns. */
static const struct xdev_ext_mech_call_args *active;
static const struct xdev_ext_mech_ctx *active_ctx;
static unsigned active_endpoint;
static int active_fault;

__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx, size_t size)
{
	return active && ctx == active_ctx && size == active->info_size ?
		(__u8 *)active->info : NULL;
}

__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 slot, size_t size)
{
	return active && ctx == active_ctx && size == active->desc_size &&
		slot < active->desc_cap ? active->scratch + slot * size : NULL;
}

__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx, __u32 slot, size_t size)
{
	return active && ctx == active_ctx && size == active->cqe_size &&
		slot < active->cqe_cap ? (__u8 *)active->cqe + slot * size : NULL;
}

int bpf_xdev_ext_xdomain_info(const struct xdev_ext_mech_ctx *ctx, void *out, __u32 size)
{
	if (!active || ctx != active_ctx || !active->xdomain || size != active->info_size)
		return -EINVAL;
	memcpy(out, active->info, size);
	return 0;
}

int bpf_xdev_ext_xdomain_verdict(const struct xdev_ext_mech_ctx *ctx,
			       const void *in, __u32 size)
{
	struct xdev_ext_xdomain_proto_verdict verdict;

	if (!active || ctx != active_ctx || !active->xdomain || size != sizeof(verdict))
		return -EINVAL;
	memcpy(&verdict, in, sizeof(verdict));
	switch (active_fault) {
	case 1:
		verdict.action = UINT32_MAX;
		break;
	case 3:
		verdict.epoch++;
		break;
	case 4:
		return 0; /* Deliberately omit the current invocation's verdict. */
	case 5:
		verdict.action = XDEV_EXT_XDP_ACT_PUBLISH;
		verdict.status = 0;
		verdict.wake_ns = verdict.credit = 0;
		break;
	case 6:
		verdict.event_id++;
		break;
	case 7:
		verdict.action = XDEV_EXT_XDP_ACT_WAIT;
		verdict.status = 0;
		verdict.credit = 0;
		verdict.wake_ns = ktime_get_boottime_ns() + 1000000;
		break;
	}
	active->xdomain->calls++;
	memcpy(&active->xdomain->verdict, &verdict, sizeof(verdict));
	if (active_fault == 2) {
		/* Duplicate in this invocation: the actual BPF callback observes
		 * the bridge error before returning; X5 applies neither intent. */
		active->xdomain->calls++;
		return -EALREADY;
	}
	return 0;
}

int stack_x6_call(struct xdev_ext_mech_stage *stage,
		  const struct xdev_ext_mech_call_args *args, s32 *result)
{
	struct xdev_ext_mech_ctx ctx = {
		.base = *args->base,
		.callsite = args->callsite,
		.batch_id = args->b ? args->b->ticket : args->batch_id,
	};
	bool protocol = args->callsite == XDEV_EXT_MECH_SITE_WORKER_PROTOCOL;

	assert(!active && !stack_spins && !stack_mutexes);
	active = args;
	active_ctx = &ctx;
	active_endpoint = stack_endpoint_stage(stage);
	active_fault = protocol ? stack_policy_fault(active_endpoint,
		((const struct xdev_ext_xdomain_proto_info *)args->info)->event) : 0;
	if (args->member == XDEV_EXT_MECH_MEMBER_BUILD)
		*result = xdomain_peer_build(NULL, &ctx);
	else if (args->member == XDEV_EXT_MECH_MEMBER_PREPARE)
		*result = xdomain_peer_prepare(NULL, &ctx);
	else
		*result = xdomain_peer_complete(NULL, &ctx);
	if (protocol) {
		const struct xdev_ext_xdomain_proto_info *info = args->info;
		struct stack_event event = {
			.kind = STACK_EV_PROTOCOL, .endpoint = active_endpoint,
			.session_id = stage->s->id,
			.direction = stage->direction, .stage_index = stage->index,
			.group = info->group, .seq = info->data_seq,
			.flags = info->facts, .status = *result,
			.control_type = info->event,
			.length = args->xdomain->verdict.action,
			.raw_len = sizeof(*info),
		};
		memcpy(event.raw, info, sizeof(*info));
		stack_record(event);
	}
	active = NULL;
	active_ctx = NULL;
	active_fault = 0;
	return 0;
}
