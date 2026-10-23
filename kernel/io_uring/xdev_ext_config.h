/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_CONFIG_H
#define IO_URING_XDEV_EXT_CONFIG_H

/*
 * XDEV_EXT Feature Flags — comment out to disable.
 * When disabled, the code compiles as if the feature doesn't exist.
 */

/*
 * UMEM zero-copy path for unified_ops (Approach 3).
 *
 * The effective definition is the -DXDEV_EXT_UMEM_ZEROCOPY in io_uring/Makefile,
 * which reaches every io_uring object, including files that never include this
 * header; keep that -D.  This define must use the SAME value (1): a bare
 * "#define XDEV_EXT_UMEM_ZEROCOPY" here would redefine the macro to empty, and
 * -Werror turns the redefinition warning against the -D's implicit 1 into a
 * build failure.  struct io_ring_ctx declares ->xdev_ext_umem unconditionally
 * (include/linux/io_uring_types.h), so the macro gates only io_uring/ code.
 */
#define XDEV_EXT_UMEM_ZEROCOPY 1

/*
 * In-kernel COPY-mode AF_XDP send (Plan Y) is selected by
 * CONFIG_IO_URING_XDEV_EXT_AFXDP_COPY.  io_uring/Makefile translates that Kconfig
 * symbol into XDEV_EXT_AFXDP_SEND for the io_uring compilation unit.
 */

/*
 * Per-frame 4-state lifecycle state machine (FREE/IO_PENDING/READY/
 * TX_PENDING; see xdev_ext_frame_sm.h) — compile-time switch, default OFF.
 * When undefined, no SM code exists anywhere: xdev_ext_umem has no frames
 * array and unified_ops keeps today's synchronous behavior byte-
 * identically. Define (to 1) to compile in the per-frame state word and
 * the async UMEM READ whose I/O completion publishes the frame from
 * IRQ/softirq context. Requires XDEV_EXT_UMEM_ZEROCOPY.
 *
 * Kconfig builds do not use the line below: io_uring/Makefile passes
 * -DXDEV_EXT_LIFECYCLE_SM=1 to every io_uring object when
 * CONFIG_IO_URING_XDEV_EXT_IAA=y, so enabling IAA also switches unified_ops
 * UMEM READ from the synchronous path to the asynchronous lifecycle variant.
 * This state word has no generation token; the mechanism session lifecycle
 * (xdev_ext_mech_lifecycle.h) is a separate implementation.
 */
/* #define XDEV_EXT_LIFECYCLE_SM 1 */

/* Chain scheduler — currently disabled */
/* #define XDEV_EXT_ENABLE_CHAIN_SCHED */

#endif /* IO_URING_XDEV_EXT_CONFIG_H */
