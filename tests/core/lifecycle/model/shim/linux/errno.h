/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The errno values the lifecycle header returns are the userspace ones.
 * <errno.h> itself reaches <linux/errno.h>, so pass through to the system
 * header rather than back to <errno.h>.
 */
#ifndef XDEV_EXT_LIFE_MODEL_SHIM_ERRNO_H
#define XDEV_EXT_LIFE_MODEL_SHIM_ERRNO_H
#include_next <linux/errno.h>
#endif
