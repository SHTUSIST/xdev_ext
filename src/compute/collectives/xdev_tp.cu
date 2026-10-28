// SPDX-License-Identifier: GPL-2.0
#include "xdev_tp_device.h"
using namespace xdev_tp_native;

static __device__ int message_spans(xdev_ext_cuda_message *message,
 Span *spans, bool tx)
{
 if (message->status) return message->status;
 if (!message->nr_frames || message->nr_frames > XDEV_EXT_MECH_MAX_FRAMES)
  return -EPROTO;
 for (unsigned i = 0; i < message->nr_frames; ++i) {
  if (!message->device_address[i] || !message->f[i].data_len ||
      message->f[i].data_len > message->f[i].capacity) return -EPROTO;
  spans[i] = {message->device_address[i], message->f[i].data_len};
  if (tx) message->f[i].out_len = message->f[i].data_len;
 }
 return 0;
}

static __device__ void runtime_trace(DeviceWork *work, Runtime *runtime,
 uint32_t kind, int error = 0)
{
 if (work->mode != XDEV_TP_D2_GPU || !runtime->trace_address ||
     !runtime->trace_capacity) return;
 if (runtime->trace_count >= runtime->trace_capacity) {
  if (runtime->trace_dropped != UINT64_MAX) ++runtime->trace_dropped;
  return;
 }
 uint64_t timestamp = 0;
#ifdef __CUDA_ARCH__
 asm volatile("mov.u64 %0, %%globaltimer;" : "=l"(timestamp));
#endif
 auto *records = reinterpret_cast<TraceRecord *>(runtime->trace_address);
 records[runtime->trace_count] = {
  work->core.sequence ? work->core.sequence : work->producer.key,
  timestamp, work->shape.payload_bytes, work->shape.wire_bytes,
  runtime->inflight, work->shape.rank, kind, XDEV_TP_CLOCK_GPU_GLOBALTIMER,
  work->shape.operation, error, 0,
 };
 ++runtime->trace_count;
}

static __device__ int device_failure(DeviceWork *work, Runtime *runtime, int error)
{
 bool first = work->core.state != XDEV_TP_WORK_FAILED_RETAINED;
 int rc = fail(runtime, &work->core, error);
 if (first) {
  ++work->failed;
  runtime_trace(work, runtime, XDEV_TP_TRACE_FAILED_RETAINED, rc);
 }
 return rc;
}

extern "C" __global__ void xdev_tp_pack_begin(DeviceWork *work, Runtime *runtime,
 Shape shape, uint64_t input, uint64_t output, uint32_t mode, uint64_t owner_cookie)
{
 if (blockIdx.x || threadIdx.x) return;
 work->mode = mode;
 work->phase_error = 0;
 if (mode == XDEV_TP_D2_GPU) {
  if (work->owner_cookie != owner_cookie) {
   work->core = {};
   work->invocations = work->completed = work->failed = 0;
   work->first_sequence = work->last_sequence = 0;
   work->tx_done = work->rx_delivered = work->last_use_released = 0;
   work->payload_tx_bytes = work->payload_rx_bytes = 0;
   work->wire_tx_bytes = work->wire_rx_bytes = 0;
   work->owner_cookie = owner_cookie;
  }
  work->shape = shape;
  work->input = input;
  work->output = output;
  int rc = work->producer.status;
  if (!rc) rc = begin_invocation(runtime, &work->core, work->producer.key);
  if (!rc) {
   work->shape.sequence = work->core.sequence;
   ++work->invocations;
   if (!work->first_sequence) work->first_sequence = work->core.sequence;
   work->last_sequence = work->core.sequence;
   runtime_trace(work, runtime, XDEV_TP_TRACE_SLOT_ACQUIRED);
   rc = message_spans(&work->producer, work->tx, true);
   work->tx_count = work->producer.nr_frames;
  }
  if (rc) {
   work->phase_error = device_failure(work, runtime, rc);
   work->producer.status = work->phase_error;
   return;
  }
 }
 work->phase_error = prepare_pack(work->shape,
  reinterpret_cast<const unsigned char *>(work->input), work->tx,
  work->tx_count, &work->tx_index);
 if (work->phase_error) {
  device_failure(work, runtime, work->phase_error);
  if (mode == XDEV_TP_D2_GPU) work->producer.status = work->core.error;
 }
}

/* All control validation and the small fixed header precede this kernel on
 * the same caller stream. No global barrier or cross-block state mutation. */
extern "C" __global__ void xdev_tp_pack_payload(DeviceWork *work)
{
 if (work->phase_error || work->core.error) return;
 uint64_t lane = uint64_t(blockIdx.x) * blockDim.x + threadIdx.x;
 uint64_t lanes = uint64_t(gridDim.x) * blockDim.x;
 pack_partition(work->shape, reinterpret_cast<const unsigned char *>(work->input),
  work->tx, work->tx_index, lane, lanes);
}

extern "C" __global__ void xdev_tp_pack_commit(DeviceWork *work, Runtime *runtime)
{
 if (blockIdx.x || threadIdx.x || work->phase_error || work->core.error) return;
 if (work->mode == XDEV_TP_D2_GPU) {
  int rc = advance(runtime, &work->core, XDEV_TP_WORK_PRODUCED, 0);
  work->producer.status = rc;
  if (rc) device_failure(work, runtime, rc);
  else runtime_trace(work, runtime, XDEV_TP_TRACE_TX_PRODUCED);
 }
}

extern "C" __global__ void xdev_tp_result_begin(DeviceWork *work, Runtime *runtime)
{
 if (blockIdx.x || threadIdx.x) return;
 int rc = runtime->error;
 if (work->mode == XDEV_TP_D2_GPU) {
  if (!rc) rc = work->producer.status;
  if (!rc) rc = message_spans(&work->receiver, work->rx, false);
  if (!rc) rc = receive(runtime, &work->core, work->receiver.key,
                         work->receiver.ticket);
  work->rx_count = work->receiver.nr_frames;
  if (!rc) {
   ++work->rx_delivered;
   runtime_trace(work, runtime, XDEV_TP_TRACE_RX_DELIVERED);
  }
 }
 if (!rc) rc = prepare_result(work->shape,
  reinterpret_cast<const unsigned char *>(work->input),
  reinterpret_cast<unsigned char *>(work->output), work->rx, work->rx_count,
  work->mode == XDEV_TP_D2_GPU ? work->receiver.key : work->shape.sequence,
  &work->rx_index);
 work->phase_error = rc;
 if (rc) device_failure(work, runtime, rc);
 if (work->mode == XDEV_TP_D2_GPU) work->receiver.status = rc;
}

extern "C" __global__ void xdev_tp_result_payload(DeviceWork *work)
{
 if (work->phase_error || work->core.error) return;
 uint64_t lane = uint64_t(blockIdx.x) * blockDim.x + threadIdx.x;
 uint64_t lanes = uint64_t(gridDim.x) * blockDim.x;
 result_partition(work->shape, reinterpret_cast<const unsigned char *>(work->input),
  reinterpret_cast<unsigned char *>(work->output), work->rx, work->rx_index,
  lane, lanes);
}

extern "C" __global__ void xdev_tp_result_commit(DeviceWork *work, Runtime *runtime)
{
 if (blockIdx.x || threadIdx.x || work->phase_error || work->core.error) return;
 int rc = advance(runtime, &work->core, XDEV_TP_WORK_RESULT_READY, 0);
 if (rc) device_failure(work, runtime, rc);
 else runtime_trace(work, runtime, XDEV_TP_TRACE_RESULT_READY);
 if (work->mode == XDEV_TP_D2_GPU) work->receiver.status = rc;
}

/* A terminal wrapper is validated before its real USER done publication. */
extern "C" __global__ void xdev_tp_terminal_begin(DeviceWork *work, Runtime *runtime)
{
 if (blockIdx.x || threadIdx.x) return;
 int rc = runtime->error;
 if (!rc) rc = work->producer.status;
 if (!rc) rc = work->receiver.status;
 if (!rc) ++work->last_use_released;
 if (!rc) rc = work->terminal.status;
 if (!rc && work->terminal.key != work->core.sequence) rc = -EPROTO;
 if (rc) rc = device_failure(work, runtime, rc);
 work->terminal.status = rc;
}

extern "C" __global__ void xdev_tp_release(DeviceWork *work, Runtime *runtime)
{
 if (blockIdx.x || threadIdx.x) return;
 int rc = runtime->error;
 if (!rc) rc = work->receiver.status;
 if (!rc) rc = work->terminal.status;
 if (!rc && work->terminal.key != work->core.sequence) rc = -EPROTO;
 if (rc) device_failure(work, runtime, rc);
 else {
  rc = advance(runtime, &work->core, XDEV_TP_WORK_RELEASED, 0);
  if (rc) device_failure(work, runtime, rc);
  else {
   ++work->completed;
   ++work->tx_done;
   work->payload_tx_bytes += work->shape.payload_bytes;
   work->payload_rx_bytes += work->shape.payload_bytes;
   work->wire_tx_bytes += work->tx_index.bytes;
   work->wire_rx_bytes += work->rx_index.bytes;
   runtime_trace(work, runtime, XDEV_TP_TRACE_LAST_USE_RELEASED);
  }
 }
}
