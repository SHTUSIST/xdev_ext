/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_CREF_HOST_BPF_TRACING_H
#define XDEV_EXT_MECH_CREF_HOST_BPF_TRACING_H

/*
 * Host stand-in for libbpf's BPF_PROG(): the program keeps its raw ctx
 * parameter and receives its typed argument directly.
 */
#define BPF_PROG(name, args...)	name(unsigned long long *ctx, args)

#endif /* XDEV_EXT_MECH_CREF_HOST_BPF_TRACING_H */
