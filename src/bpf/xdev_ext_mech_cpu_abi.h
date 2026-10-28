/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_CPU_ABI_H
#define XDEV_EXT_MECH_CPU_ABI_H

/*
 * Fixed scratch wire layout of UAPI xdev_ext_cpu_desc (CPU ABI v1).
 * CONFIG_XDEV_EXT_MECH_CPU=n can omit that type from vmlinux BTF even
 * though the shared CPU struct_ops type remains. Use a distinct local name
 * so this also builds when vmlinux.h contains the UAPI type. This is a byte
 * view returned by bpf_xdev_ext_desc, not a kernel object for CO-RE access.
 * xdev_ext_cpu_bpf_test.py pins every field's type, offset, size and alignment
 * to the current UAPI and exercises the actual BPF program.
 */
struct xdev_ext_mp_cpu_desc {
	__u32 xform;
	__u32 flags;
	__u64 param __attribute__((aligned(8)));
};

#endif /* XDEV_EXT_MECH_CPU_ABI_H */
