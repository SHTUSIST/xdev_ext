/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_REL_GLUE_HOST_VMLINUX_H
#define XDEV_EXT_REL_GLUE_HOST_VMLINUX_H
/*
 * Host stand-in for the target vmlinux.h of tools/xdev_ext_mech/nxp_reliable.bpf.c:
 * the cref host stand-in plus the policy UAPI type, which the kernel emits to
 * BTF (BTF_TYPE_EMIT) because only the program dereferences it. With
 * XDEV_EXT_REL_GLUE_BPF_TARGET it also declares the open-coded iterator type
 * that libbpf's bpf_for() needs when compiling with -target bpf.
 */
#include "tools/testing/selftests/xdev_ext_mech/cref/host/vmlinux.h"
#if __has_include("include/uapi/linux/xdev_ext_policy.h")
#include "include/uapi/linux/xdev_ext_policy.h"
#endif
#ifdef XDEV_EXT_REL_GLUE_BPF_TARGET
struct bpf_iter_num { __u64 __opaque[1]; } __attribute__((aligned(8)));
#endif
#endif
