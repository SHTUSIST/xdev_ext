/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_KFUNC_H
#define XDEV_EXT_MECH_KFUNC_H

/*
 * Mechanism-layer kfuncs (include/linux/xdev_ext_mech.h), for the BPF objects of
 * tools/xdev_ext_mech.  Each takes the callback's own ctx (KF_TRUSTED_ARGS).  A
 * view is valid during this callback only and may be NULL (KF_RET_NULL);
 * its size argument must be a compile-time constant equal to the size C
 * allows for that view, or C returns NULL.
 */

/* The class info structure; any member. */
extern __u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx,
			  const size_t rdonly_buf_size) __ksym;
/* Scratch descriptor @slot; build only. */
extern __u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 slot,
			  const size_t rdwr_buf_size) __ksym;
/* Completion copy @slot; complete only. */
extern __u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx, __u32 slot,
			 const size_t rdonly_buf_size) __ksym;
/* Chunk bytes [off, off + size) of batch frame @pos; build and complete. */
extern __u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *ctx, __u32 pos,
			   __u32 off, const size_t rdonly_buf_size) __ksym;
/* crc32c() without pre- or post-inversion over chunk bytes of frame @pos. */
extern __u32 bpf_xdev_ext_frame_crc32c(const struct xdev_ext_mech_ctx *ctx, __u32 pos,
				  __u32 off, __u32 len, __u32 seed) __ksym;
/* crc32c() without pre- or post-inversion over a stack buffer. */
extern __u32 bpf_xdev_ext_crc32c(const void *buf, __u32 buf__sz,
			    __u32 seed) __ksym;
/* Private stage state; AF_XDP RX complete only, size in [1, 256]. */
extern __u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *ctx,
				 const size_t rdwr_buf_size) __ksym;
/* Header room bytes [off, off + size) of frame @pos; AF_XDP TX build only. */
extern __u8 *bpf_xdev_ext_afxdp_hdr(const struct xdev_ext_mech_ctx *ctx, __u32 pos,
			       __u32 off, const size_t rdwr_buf_size) __ksym;
/*
 * Record the hold intent, once per AF_XDP RX complete: frame @pos of the
 * batch keyed @key, payload [span_off, span_off + span_len) of the chunk.
 * C takes the frames per batch from the session layout and applies the
 * intent only when the callback returns HOLD.
 */
extern int bpf_xdev_ext_afxdp_hold(const struct xdev_ext_mech_ctx *ctx, __u64 key,
			      __u32 pos, __u32 span_off,
			      __u32 span_len) __ksym;

#endif /* XDEV_EXT_MECH_KFUNC_H */
