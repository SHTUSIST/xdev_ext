/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_CREF_HOST_BPF_HELPERS_H
#define XDEV_EXT_MECH_CREF_HOST_BPF_HELPERS_H

/*
 * Host stand-in for libbpf's bpf_helpers.h: sections and kfunc linkage mean
 * nothing on the host, bpf_for() is a counted loop, and the clock is the
 * test's.
 */

#define SEC(name)
#define __ksym
#ifndef __always_inline
#define __always_inline	inline __attribute__((always_inline))
#endif

#define bpf_for(i, start, end)	for ((i) = (start); (i) < (end); (i)++)

__u64 bpf_ktime_get_ns(void);

#endif /* XDEV_EXT_MECH_CREF_HOST_BPF_HELPERS_H */
