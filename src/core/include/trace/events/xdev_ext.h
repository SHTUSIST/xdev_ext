/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM xdev_ext
#if !defined(_TRACE_XDEV_EXT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_XDEV_EXT_H
#include <linux/tracepoint.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/xdev_ext_mech.h>
/* ABI marker declares source hook coverage, not physical path verification. */
#ifndef _XDEV_EXT_NATIVE_EVENT_DATA
#define _XDEV_EXT_NATIVE_EVENT_DATA
struct xdev_ext_native_event {
	const char *phase, *origin;
	u64 session_id, batch_id, batch_key;
	u32 frame_id;
	u64 generation;
	u32 stage;
	u64 ticket;
	u32 class_id;
	int accepted, status;
	u64 cookie, address;
	u32 bytes;
	u64 aux, sequence;
	u32 origin_tgid, frame_ordinal, frame_offset, frame_length;
	u64 process_start_ticks, native_user_data;
};
#endif
TRACE_EVENT(native_event,
	TP_PROTO(const struct xdev_ext_native_event *e),
	TP_ARGS(e),
	TP_STRUCT__entry(
		__string(phase, e->phase)
		__string(origin, e->origin)
		__field(u64, session_id) __field(u64, batch_id)
		__field(u64, batch_key) __field(u32, frame_id)
		__field(u64, generation) __field(u32, stage)
		__field(u64, ticket) __field(u32, class_id)
		__field(int, accepted) __field(int, status)
		__field(u64, cookie) __field(u64, address)
		__field(u32, bytes) __field(u64, aux) __field(u64, sequence) __field(u64, ts_ns)
		__field(u32, origin_tgid) __field(u64, process_start_ticks)
		__field(u64, native_user_data)
		__field(u32, frame_ordinal) __field(u32, frame_offset) __field(u32, frame_length)
	),
	TP_fast_assign(
		__entry->ts_ns = ktime_get_ns();
		__entry->origin_tgid = e->origin_tgid;
		__entry->process_start_ticks = e->process_start_ticks;
		__entry->native_user_data = e->native_user_data;
		__entry->frame_ordinal = e->frame_ordinal;
		__entry->frame_offset = e->frame_offset;
		__entry->frame_length = e->frame_length;
		__assign_str(phase); __assign_str(origin);
		__entry->session_id = e->session_id;
		__entry->batch_id = e->batch_id;
		__entry->batch_key = e->batch_key;
		__entry->frame_id = e->frame_id;
		__entry->generation = e->generation;
		__entry->stage = e->stage;
		__entry->ticket = e->ticket;
		__entry->class_id = e->class_id;
		__entry->accepted = e->accepted;
		__entry->status = e->status;
		__entry->cookie = e->cookie;
		__entry->address = e->address;
		__entry->bytes = e->bytes;
		__entry->aux = e->aux;
		__entry->sequence = e->sequence;
	),
	TP_printk("abi=xdev-native-v1-nvme-xsk-batch phase=%s origin=%s session_id=%llu batch_id=%llu batch_key=%llu frame_id=%u generation=%llu stage=%u ticket=%llu class_id=%u accepted=%d status=%d cookie=%llu address=%llu bytes=%u aux=%llu sequence=%llu ts_ns=%llu origin_tgid=%u process_start_ticks=%llu native_user_data=%llu frame_ordinal=%u frame_offset=%u frame_length=%u",
		__get_str(phase), __get_str(origin), __entry->session_id,
		__entry->batch_id, __entry->batch_key, __entry->frame_id,
		__entry->generation, __entry->stage, __entry->ticket,
		__entry->class_id, __entry->accepted, __entry->status,
		__entry->cookie, __entry->address, __entry->bytes,
		__entry->aux, __entry->sequence, __entry->ts_ns,
		__entry->origin_tgid, __entry->process_start_ticks, __entry->native_user_data,
		__entry->frame_ordinal, __entry->frame_offset, __entry->frame_length)
);
/* Local monotonic observations, not hardware first-byte timestamps. */
TRACE_EVENT(xdomain_event,
	TP_PROTO(u64 session_id, u32 stage, u32 direction,
		 const struct xdev_ext_xdomain_trace *e),
	TP_ARGS(session_id, stage, direction, e),
	TP_STRUCT__entry(
		__string(phase, e->phase)
		__field(u64, session_id) __field(u32, stage)
		__field(u32, direction) __field(u32, early)
		__field(u64, local_inc) __field(u64, remote_inc)
		__field(u64, tx_bind) __field(u64, rx_bind)
		__field(u64, group) __field(u64, key)
		__field(u64, ticket) __field(u64, pool_generation)
		__field(int, status) __field(bool, quiesced)
		__field(u64, ts_ns)
	),
	TP_fast_assign(
		__entry->ts_ns = ktime_get_ns();
		__assign_str(phase);
		__entry->session_id = session_id;
		__entry->stage = stage;
		__entry->direction = direction;
		__entry->early = e->early;
		__entry->local_inc = e->local_inc;
		__entry->remote_inc = e->remote_inc;
		__entry->tx_bind = e->tx_bind;
		__entry->rx_bind = e->rx_bind;
		__entry->group = e->group;
		__entry->key = e->key;
		__entry->ticket = e->ticket;
		__entry->pool_generation = e->pool_generation;
		__entry->status = e->status;
		__entry->quiesced = e->quiesced;
	),
	TP_printk("abi=xdev-xdomain-v1 phase=%s session_id=%llu stage=%u direction=%u early=%u local_inc=%llu remote_inc=%llu tx_bind=%llu rx_bind=%llu group=%llu key=%llu ticket=%llu pool_generation=%llu status=%d quiesced=%u ts_ns=%llu",
		__get_str(phase), __entry->session_id, __entry->stage,
		__entry->direction, __entry->early, __entry->local_inc,
		__entry->remote_inc, __entry->tx_bind, __entry->rx_bind,
		__entry->group, __entry->key, __entry->ticket,
		__entry->pool_generation, __entry->status,
		__entry->quiesced, __entry->ts_ns)
);
#endif
#include <trace/define_trace.h>

#ifndef _XDEV_EXT_NATIVE_EVENT_EMIT
#define _XDEV_EXT_NATIVE_EVENT_EMIT
static inline void xdev_ext_native_event_emit(const char *phase, const char *origin,
		u64 session_id, u64 batch_id, u64 batch_key, u32 frame_id,
		u64 generation, u32 stage, u64 ticket, u32 class_id, int accepted,
		int status, u64 cookie, u64 address, u32 bytes, u64 aux, u64 sequence,
		u32 frame_ordinal, u32 frame_offset, u32 frame_length)
{
	struct xdev_ext_native_event e = {
		.phase = phase, .origin = origin, .session_id = session_id,
		.batch_id = batch_id, .batch_key = batch_key, .frame_id = frame_id,
		.generation = generation, .stage = stage, .ticket = ticket,
		.class_id = class_id, .accepted = accepted, .status = status,
		.cookie = cookie, .address = address, .bytes = bytes,
		.aux = aux, .sequence = sequence,
		.frame_ordinal = frame_ordinal, .frame_offset = frame_offset,
		.frame_length = frame_length,
	};
	trace_native_event(&e);
}
#endif
