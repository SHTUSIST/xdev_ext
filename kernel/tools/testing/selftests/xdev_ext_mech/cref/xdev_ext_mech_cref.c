// SPDX-License-Identifier: GPL-2.0
/*
 * xdev_ext_mech_cref: measurement arm C (plan section 6.1).  While loaded, the
 * AF_XDP and NVMe classes run the C reference callbacks of xdev_ext_mech_cref.h,
 * the programs of tools/xdev_ext_mech/nxp_mech.bpf.c line for line, instead of
 * BPF, for every session created afterwards (xdev_ext_mech_set_c_ops(), kernels
 * with CONFIG_XDEV_EXT_MECH_C_REFERENCE=y).  Unloading restores BPF; a session
 * still on these callbacks holds the module.
 *
 * Parameters (read only, set at insmod), the program globals:
 *   nxp_session	NXP session id the peer stamps (the sender's -e)
 *   key_base		key of batch 0 (default 1)
 *   nvme_mode		0 window slot, 1 past the window (C must refuse)
 * calls (read only): how often each callback ran since the load.
 */
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/if_xdp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/stddef.h>
#include <linux/sysfs.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/xdev_ext_mech.h>

#include "net/xdp/xsk_xdev_ext_mech_core.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_prog.h"

#ifndef CONFIG_XDEV_EXT_MECH_C_REFERENCE
#error "xdev_ext_mech_cref needs a kernel with CONFIG_XDEV_EXT_MECH_C_REFERENCE=y"
#endif

#define XDEV_EXT_MECH_CREF_CALL_OF(ctx)	xdev_ext_mech_call_of(ctx)

/* The clock bpf_ktime_get_ns() reads. */
static __u64 xdev_ext_mech_cref_now_ns(void)
{
	return ktime_get_mono_fast_ns();
}

#include "xdev_ext_mech_cref.h"

static struct xdev_ext_mech_cref_state xdev_ext_mech_cref = { .key_base = 1 };

module_param_named(nxp_session, xdev_ext_mech_cref.nxp_session, ullong, 0444);
MODULE_PARM_DESC(nxp_session, "NXP session id the peer stamps");
module_param_named(key_base, xdev_ext_mech_cref.key_base, ullong, 0444);
MODULE_PARM_DESC(key_base, "key of batch 0");
module_param_named(nvme_mode, xdev_ext_mech_cref.nvme_mode, uint, 0444);
MODULE_PARM_DESC(nvme_mode, "0: window slot, 1: past the window");

enum {
	XDEV_EXT_MECH_CREF_AFXDP_BUILD,
	XDEV_EXT_MECH_CREF_AFXDP_COMPLETE,
	XDEV_EXT_MECH_CREF_NVME_BUILD,
	XDEV_EXT_MECH_CREF_NVME_COMPLETE,
	XDEV_EXT_MECH_CREF_NR,
};

static atomic64_t xdev_ext_mech_cref_calls[XDEV_EXT_MECH_CREF_NR];

static int xdev_ext_mech_cref_calls_get(char *buf, const struct kernel_param *kp)
{
	return sysfs_emit(buf,
		"afxdp_build=%lld afxdp_complete=%lld nvme_build=%lld nvme_complete=%lld\n",
		atomic64_read(&xdev_ext_mech_cref_calls[XDEV_EXT_MECH_CREF_AFXDP_BUILD]),
		atomic64_read(&xdev_ext_mech_cref_calls[XDEV_EXT_MECH_CREF_AFXDP_COMPLETE]),
		atomic64_read(&xdev_ext_mech_cref_calls[XDEV_EXT_MECH_CREF_NVME_BUILD]),
		atomic64_read(&xdev_ext_mech_cref_calls[XDEV_EXT_MECH_CREF_NVME_COMPLETE]));
}

static int xdev_ext_mech_cref_calls_set(const char *val,
				   const struct kernel_param *kp)
{
	return -EPERM;
}

static const struct kernel_param_ops xdev_ext_mech_cref_calls_ops = {
	.set = xdev_ext_mech_cref_calls_set,
	.get = xdev_ext_mech_cref_calls_get,
};
module_param_cb(calls, &xdev_ext_mech_cref_calls_ops, NULL, 0444);
MODULE_PARM_DESC(calls, "callbacks run since the load");

/*
 * RX complete callbacks run under their pool's rx_lock; protocol state
 * belongs to each bound AF_XDP stage, just as in the BPF program.
 */
static __s32 xdev_ext_mech_cref_afxdp_complete_cb(const struct xdev_ext_mech_ctx *ctx)
{
	atomic64_inc(&xdev_ext_mech_cref_calls[XDEV_EXT_MECH_CREF_AFXDP_COMPLETE]);
	return xdev_ext_mech_cref_afxdp_complete(&xdev_ext_mech_cref, ctx);
}

static __s32 xdev_ext_mech_cref_afxdp_build_cb(const struct xdev_ext_mech_ctx *ctx)
{
	atomic64_inc(&xdev_ext_mech_cref_calls[XDEV_EXT_MECH_CREF_AFXDP_BUILD]);
	return xdev_ext_mech_cref_afxdp_build(&xdev_ext_mech_cref, ctx);
}

static __s32 xdev_ext_mech_cref_nvme_build_cb(const struct xdev_ext_mech_ctx *ctx)
{
	atomic64_inc(&xdev_ext_mech_cref_calls[XDEV_EXT_MECH_CREF_NVME_BUILD]);
	return xdev_ext_mech_cref_nvme_build(&xdev_ext_mech_cref, ctx);
}

static __s32 xdev_ext_mech_cref_nvme_complete_cb(const struct xdev_ext_mech_ctx *ctx)
{
	atomic64_inc(&xdev_ext_mech_cref_calls[XDEV_EXT_MECH_CREF_NVME_COMPLETE]);
	return xdev_ext_mech_cref_nvme_complete(ctx);
}

/* nxp_afxdp_ops and nxp_nvme_ops of nxp_mech.bpf.c; neither has prepare. */
static const struct xdev_ext_mech_c_ops xdev_ext_mech_cref_afxdp_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = xdev_ext_mech_cref_afxdp_build_cb,
	.complete = xdev_ext_mech_cref_afxdp_complete_cb,
};

static const struct xdev_ext_mech_c_ops xdev_ext_mech_cref_nvme_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = xdev_ext_mech_cref_nvme_build_cb,
	.complete = xdev_ext_mech_cref_nvme_complete_cb,
};

static int __init xdev_ext_mech_cref_init(void)
{
	int err;

	err = xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_AFXDP, &xdev_ext_mech_cref_afxdp_ops);
	if (err)
		return err;
	err = xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_NVME, &xdev_ext_mech_cref_nvme_ops);
	if (err)
		xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_AFXDP, NULL);
	return err;
}

static void __exit xdev_ext_mech_cref_exit(void)
{
	xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_NVME, NULL);
	xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_AFXDP, NULL);
}

module_init(xdev_ext_mech_cref_init);
module_exit(xdev_ext_mech_cref_exit);
MODULE_DESCRIPTION("XDEV_EXT mechanism C reference callbacks (measurement arm C)");
MODULE_LICENSE("GPL");
