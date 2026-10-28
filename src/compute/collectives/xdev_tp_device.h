/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_TP_DEVICE_H
#define XDEV_TP_DEVICE_H
#include "xdev_tp.h"
#include "xdev_tp_algorithms.h"
namespace xdev_tp_native {
static_assert(max_spans == XDEV_EXT_MECH_MAX_FRAMES, "native frame bound");
static_assert(sizeof(TraceRecord) == sizeof(xdev_tp_trace_record), "trace record ABI");
static_assert(offsetof(TraceRecord, error) == offsetof(xdev_tp_trace_record, error),
 "trace error offset ABI");
struct DeviceWork {
 Shape shape;
 WorkCore core;
 uint64_t input, output;
 xdev_ext_cuda_message producer, receiver, terminal;
 Span tx[XDEV_EXT_MECH_MAX_FRAMES], rx[XDEV_EXT_MECH_MAX_FRAMES];
 SpanIndex tx_index, rx_index;
 uint32_t tx_count, rx_count, mode;
 int32_t phase_error;
 uint64_t owner_cookie;
 uint64_t invocations, completed, failed, first_sequence, last_sequence;
 uint64_t tx_done, rx_delivered, last_use_released;
 uint64_t payload_tx_bytes, payload_rx_bytes, wire_tx_bytes, wire_rx_bytes;
};
}
#endif
