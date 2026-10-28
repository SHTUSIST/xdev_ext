/* SPDX-License-Identifier: GPL-2.0 */
#ifndef DMA_REFERENCE_HOST_BPF_TRACING_H
#define DMA_REFERENCE_HOST_BPF_TRACING_H
#define BPF_PROG(name, args...) name(unsigned long long *ctx, args)
#endif
