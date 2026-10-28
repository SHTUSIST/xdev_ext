/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_TP_DEVICE_H
#define XDEV_TP_DEVICE_H
#include "xdev_tp.h"
#include "xdev_tp_algorithms.h"
namespace xdev_tp_native {
struct DeviceWork {
 Shape shape;
 WorkCore core;
 uint64_t input, output;
 xdev_ext_cuda_message producer, receiver, terminal;
 Span tx[XDEV_EXT_MECH_MAX_FRAMES], rx[XDEV_EXT_MECH_MAX_FRAMES];
 uint32_t tx_count, rx_count, mode;
 uint64_t invocations, completed, failed, first_sequence, last_sequence;
 uint64_t tx_done, rx_delivered, last_use_released;
};
}
#endif
