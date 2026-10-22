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
 * Must be defined with the SAME value (1) as the global -DXDEV_EXT_UMEM_ZEROCOPY in
 * io_uring/Makefile: that -D is what include/linux/io_uring_types.h sees to gate
 * the ->xdev_ext_umem member (this header is NOT included there). A bare
 * "#define XDEV_EXT_UMEM_ZEROCOPY" here would redefine the macro to empty and, under
 * -Werror, trip a redefinition warning vs the -D's implicit 1. See
 * afxdp_work/reports/FINDINGS.md PRE-2.
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
 */
/* #define XDEV_EXT_LIFECYCLE_SM 1 */

/* Chain scheduler — currently disabled */
/* #define XDEV_EXT_ENABLE_CHAIN_SCHED */

#endif /* IO_URING_XDEV_EXT_CONFIG_H */
