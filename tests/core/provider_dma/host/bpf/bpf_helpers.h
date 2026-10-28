/* SPDX-License-Identifier: GPL-2.0 */
#ifndef DMA_REFERENCE_HOST_BPF_HELPERS_H
#define DMA_REFERENCE_HOST_BPF_HELPERS_H
#define SEC(name)
#define __ksym
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
/* Host semantics only: this does not model kernel iterator verification. */
#define bpf_for(i, start, end) for ((i) = (start); (i) < (end); ++(i))
#endif
