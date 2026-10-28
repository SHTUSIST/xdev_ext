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
	if (!active || ctx != active_ctx || !active->xdomain || !out ||
	    size != sizeof(struct xdev_ext_xdomain_proto_info) || size != active->info_size)
		return -EINVAL;
	memcpy(out, active->info, size);
	return 0;
}

static int stack_x6_record_verdict(const struct xdev_ext_mech_ctx *ctx,
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

/* Versioned host invocation storage only. Private kfunc identity and verifier
 * gates remain covered by their separate actual-source suite. */
static bool stack_x6_protocol_view(void)
{
 const struct xdev_ext_xdomain_proto_info *info;
 if(!active||!active->xdomain||!active->info)return false;
 info=active->info;
 return info->size==active->info_size&&
  ((active->info_size==sizeof(*info)&&info->version==XDEV_EXT_XDOMAIN_PROTO_VERSION)||
   (active->info_size==sizeof(struct xdev_ext_xdomain_proto_info_v2)&&
    info->version==XDEV_EXT_XDOMAIN_PROTO_V2_VERSION));
}

int bpf_xdev_ext_xdomain_verdict(const struct xdev_ext_mech_ctx *ctx,
                               const void *in,__u32 size)
{
 if(!active||active->info_size!=sizeof(struct xdev_ext_xdomain_proto_info))return -EINVAL;
 return stack_x6_record_verdict(ctx,in,size);
}

int bpf_xdev_ext_xdomain_info_v2(const struct xdev_ext_mech_ctx *ctx,void *out,__u32 size)
{
 struct xdev_ext_xdomain_proto_info_v2 *info=out;
 if(!active||ctx!=active_ctx||!stack_x6_protocol_view()||!out||size!=sizeof(*info))return -EINVAL;
 memset(out,0,sizeof(*info));memcpy(out,active->info,active->info_size);
 info->base.size=sizeof(*info);info->base.version=XDEV_EXT_XDOMAIN_PROTO_V2_VERSION;
 return 0;
}

static int stack_x6_v2_verdict_decode(const struct xdev_ext_mech_ctx *ctx,
                                    const void *in,__u32 size,
                                    struct xdev_ext_xdomain_proto_verdict *verdict)
{
 const struct xdev_ext_xdomain_proto_info *info;
 if(!active||ctx!=active_ctx||!stack_x6_protocol_view()||!in||size!=sizeof(*verdict))return -EINVAL;
 memcpy(verdict,in,sizeof(*verdict));info=active->info;
 if(verdict->size!=sizeof(*verdict)||verdict->version!=XDEV_EXT_XDOMAIN_PROTO_V2_VERSION||
    verdict->action<=XDEV_EXT_XDP_ACT_INVALID||
    verdict->action>(info->version==XDEV_EXT_XDOMAIN_PROTO_VERSION?
       XDEV_EXT_XDP_ACT_CANCEL_ARMED:XDEV_EXT_XDP_ACT_TX_POST_EARLY)||
    verdict->flags||verdict->reserved0||verdict->reserved1||
    verdict->event_id!=info->event_id||verdict->epoch!=info->epoch)return -EINVAL;
 if(info->version==XDEV_EXT_XDOMAIN_PROTO_VERSION)verdict->version=XDEV_EXT_XDOMAIN_PROTO_VERSION;
 return 0;
}

int bpf_xdev_ext_xdomain_verdict_v2(const struct xdev_ext_mech_ctx *ctx,const void *in,__u32 size)
{
 struct xdev_ext_xdomain_proto_verdict verdict;
 int ret=stack_x6_v2_verdict_decode(ctx,in,size,&verdict);
 if(ret)return ret;
 return stack_x6_record_verdict(ctx,&verdict,sizeof(verdict));
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
