/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_TP_H
#define XDEV_TP_H
#include <cuda.h>
#include <stddef.h>
#include <stdint.h>
#include "../../../kernel/tools/xdev_ext_mech/lib/libxdev_ext_peer_message.h"
#include "../../../kernel/tools/xdev_ext_mech/lib/libxdev_ext_cuda.h"
#include "xdev_tp_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define XDEV_TP_ABI_VERSION 1U
typedef struct xdev_tp_comm xdev_tp_comm;
typedef struct xdev_tp_work xdev_tp_work;
enum xdev_tp_dtype { XDEV_TP_F16 = 1, XDEV_TP_BF16 = 2, XDEV_TP_F32 = 3 };
enum xdev_tp_mode { XDEV_TP_D1_EAGER = 1, XDEV_TP_D2_GPU = 2 };
enum xdev_tp_operation { XDEV_TP_SUM = 1, XDEV_TP_GATHER = 2, XDEV_TP_ALL_GATHER = 3 };
enum xdev_tp_work_state {
	XDEV_TP_WORK_PREPARED = 0,
	XDEV_TP_WORK_ACCEPTED = 1,
	XDEV_TP_WORK_PRODUCED = 2,
	XDEV_TP_WORK_RX_READY = 3,
	XDEV_TP_WORK_RESULT_READY = 4,
	XDEV_TP_WORK_RELEASED = 5,
	XDEV_TP_WORK_FAILED_RETAINED = 6,
};
enum xdev_tp_clock { XDEV_TP_CLOCK_HOST_MONOTONIC = 1, XDEV_TP_CLOCK_GPU_GLOBALTIMER = 2 };
enum xdev_tp_trace_kind {
	XDEV_TP_TRACE_SLOT_ACQUIRED = 1,
	XDEV_TP_TRACE_TX_PRODUCED = 2,
	XDEV_TP_TRACE_RX_DELIVERED = 3,
	XDEV_TP_TRACE_RESULT_READY = 4,
	XDEV_TP_TRACE_LAST_USE_RELEASED = 5,
	XDEV_TP_TRACE_FAILED_RETAINED = 6,
};
struct xdev_tp_config {
	size_t size;
	uint32_t version, rank, world_size, mode;
	CUcontext context;
	/* Borrowed admitted endpoints. Each has its own registered allocation. */
	struct xdev_ext_peer_endpoint *tx_endpoint, *rx_endpoint;
	CUdeviceptr tx_va, rx_va;
	uint64_t tx_bytes, rx_bytes;
	uint32_t frame_size, logical_depth;
	uint64_t max_payload_bytes, first_sequence, communicator_id, epoch;
	uint64_t timeout_ns;
	const char *ptx_path;
	/* Open/attach before endpoint_create; required in d2, NULL in d1. */
	struct xdev_ext_cuda_user *d2_tx_producer, *d2_tx_terminal, *d2_rx_consumer;
	uint32_t trace_capacity, flags; /* flags=0; trace_capacity0 disables tracing */
};
struct xdev_tp_stats {
	size_t size;
	uint32_t version, rank;
	uint64_t api_attempts, preflight_rejected;
	uint64_t attempts, submitted, completed, failed;
	uint64_t tx_done, rx_delivered, last_use_released;
	uint64_t first_sequence, last_sequence;
	uint64_t payload_tx_bytes, payload_rx_bytes, wire_tx_bytes, wire_rx_bytes;
	uint64_t logical_inflight, logical_inflight_high_water;
	uint64_t gpu_invocations, host_control_calls, trace_dropped;
	uint64_t fallback_calls; /* strict implementation keeps this zero */
	int32_t error;
	uint32_t retained;
};
struct xdev_tp_work_stats {
	size_t size;
	uint32_t version, state;
	uint64_t invocations, completed, failed, first_sequence, last_sequence;
	uint64_t payload_bytes, wire_bytes;
	int32_t error;
	uint32_t retained;
};
struct xdev_tp_trace_record {
	uint64_t sequence, timestamp, payload_bytes, wire_bytes;
	uint64_t logical_inflight;
	uint32_t rank, kind, clock, operation;
	int32_t error;
	uint32_t reserved;
};
int xdev_tp_create(const struct xdev_tp_config *, xdev_tp_comm **);
int xdev_tp_allreduce_sum(xdev_tp_comm *, CUdeviceptr input, CUdeviceptr output,
	uint64_t numel, enum xdev_tp_dtype, CUstream caller_stream,
	uint64_t collective_seq, xdev_tp_work **);
int xdev_tp_logits_gather(xdev_tp_comm *, CUdeviceptr input, CUdeviceptr output,
	uint64_t rows, uint64_t local_width, enum xdev_tp_dtype, int dst_rank,
	int all_gather, CUstream caller_stream, uint64_t collective_seq, xdev_tp_work **);
/* query: 0 complete, 1 pending, negative stable error. Wait timeout neither
 * revokes accepted work nor proves native/GPU quiescence. */
int xdev_tp_work_query(xdev_tp_work *);
int xdev_tp_work_wait(xdev_tp_work *, uint64_t timeout_ns);
int xdev_tp_work_get_stats(xdev_tp_work *, struct xdev_tp_work_stats *);
int xdev_tp_work_destroy(xdev_tp_work *);
int xdev_tp_get_stats(xdev_tp_comm *, struct xdev_tp_stats *);
int xdev_tp_trace_read(xdev_tp_comm *, struct xdev_tp_trace_record *,
	size_t capacity, size_t *written);
int xdev_tp_destroy(xdev_tp_comm *, uint64_t timeout_ns);
#ifdef __cplusplus
}
#endif
#endif
