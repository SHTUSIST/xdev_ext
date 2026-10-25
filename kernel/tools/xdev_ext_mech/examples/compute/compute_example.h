/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_COMPUTE_EXAMPLE_H
#define XDEV_EXT_COMPUTE_EXAMPLE_H

/*
 * The one piece every compute example shares: names for the compute kfuncs
 * (Documentation/userspace-api/xdev_ext-compute.rst) that let the algorithm
 * headers of this directory compile both as BPF and as host C.
 *
 * BPF (clang -target bpf, after vmlinux.h, bpf_helpers.h and
 * ../../xdev_ext_mech_kfunc.h): the names map onto the kfuncs and bpf_for().
 *
 * Host C (tests only): the includer first defines the type ex_ctx and the
 * functions ex_nr_frames(), ex_frame_len(), ex_frame_rw() and
 * ex_frame_set_len() with the kernel's semantics, for example the mock in
 * tools/testing/selftests/xdev_ext_mech/compute_examples/compute_examples_host_test.c.
 *
 *   ex_frame_len(c, pos)            valid length L of frame pos on entry
 *   ex_frame_rw(c, pos, off, SIZE)  writable view of bytes [off, off + SIZE)
 *                                   counted from the first valid byte; SIZE a
 *                                   constant; NULL outside the frame capacity
 *   ex_frame_set_len(c, pos, len)   record the output length, only L + D
 */

#if defined(__bpf__)
/*
 * A macro, not a typedef: vmlinux.h makes field accesses CO-RE relocations,
 * and a relocation recorded against a local typedef name does not resolve
 * against the kernel's BTF.
 */
#define ex_ctx const struct xdev_ext_mech_ctx
#define ex_nr_frames(c)			((c)->nr_frames)
#define ex_frame_len(c, pos)		bpf_xdev_ext_frame_len(c, pos)
#define ex_frame_rw(c, pos, off, size)	bpf_xdev_ext_frame_rw(c, pos, off, size)
#define ex_frame_set_len(c, pos, len)	bpf_xdev_ext_frame_set_len(c, pos, len)
/*
 * An open-coded iterator: bounded at run time, verified without unrolling.
 * The bounds are int, as bpf_iter_num_new() takes them.
 */
#define ex_for(i, start, end)		bpf_for(i, (int)(start), (int)(end))
/* Constant-trip inner loops become straight-line code ... */
#define EX_UNROLL			_Pragma("unroll")
/*
 * ... or stay a bounded loop that the verifier walks iteration by iteration,
 * where unrolled code would keep more values live than the 512-byte stack
 * holds.
 */
#define EX_NOUNROLL			_Pragma("clang loop unroll(disable)")
#else
#define ex_for(i, start, end)		for ((i) = (start); (i) < (int)(end); (i)++)
#define EX_UNROLL
#define EX_NOUNROLL
#endif

#define EX_INLINE static inline __attribute__((always_inline))

/* Hide @x's origin from the compiler (not from the verifier). */
#define EX_OPAQUE(x)	__asm__ volatile("" : "+r"(x))

/* errno values; vmlinux.h carries none. */
#define EX_EFAULT	14
#define EX_EINVAL	22
#define EX_EBADMSG	74

EX_INLINE __u32 ex_le32(const __u8 *p)
{
	return (__u32)p[0] | (__u32)p[1] << 8 | (__u32)p[2] << 16 | (__u32)p[3] << 24;
}

EX_INLINE __u64 ex_le64(const __u8 *p)
{
	return (__u64)ex_le32(p) | (__u64)ex_le32(p + 4) << 32;
}

EX_INLINE void ex_put_le32(__u8 *p, __u32 v)
{
	p[0] = (__u8)v;
	p[1] = (__u8)(v >> 8);
	p[2] = (__u8)(v >> 16);
	p[3] = (__u8)(v >> 24);
}

EX_INLINE void ex_put_be64(__u8 *p, __u64 v)
{
	int i;

	EX_UNROLL
	for (i = 0; i < 8; i++)
		p[i] = (__u8)(v >> (56 - 8 * i));
}

#endif
