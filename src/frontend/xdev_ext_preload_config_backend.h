/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_CONFIG_BACKEND_H
#define XDEV_EXT_PRELOAD_CONFIG_BACKEND_H

/*
 * The configuration spellings that name one backend.  xdev_ext_preload_config.h
 * is device-neutral; it parses these knobs through the names below, so a new
 * backend adds its spellings here and nothing in the core changes.
 */

/* Receive source: how the per-flow program is attached (auto, drv, skb). */
#define XDEV_EXT_CFG_VAR_RX_ATTACH_MODE "XDEV_EXT_PRELOAD_RX_XDP_MODE"

/* Write sink served by NVMe passthrough on a whole namespace. */
#define XDEV_EXT_CFG_SPELLING_SINK_PASSTHRU "nvme-pt"

/* Test builds only: <regular file>:<nsid>:<lba_shift> stands in for one
 * namespace, so the passthrough sink can run against a model. */
#define XDEV_EXT_CFG_VAR_TEST_NS_MAP "XDEV_EXT_PRELOAD_TEST_NVME_MAP"

#endif /* XDEV_EXT_PRELOAD_CONFIG_BACKEND_H */
