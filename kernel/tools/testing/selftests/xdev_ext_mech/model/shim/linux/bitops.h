/* SPDX-License-Identifier: GPL-2.0 */
/* Host-model hweight32 only. Kernel linkage is checked separately by
 * kernel_popcount/run.py against the real kernel headers and Kbuild flags.
 */
#ifndef XDEV_EXT_LIFE_MODEL_SHIM_BITOPS_H
#define XDEV_EXT_LIFE_MODEL_SHIM_BITOPS_H
#define hweight32(v) __builtin_popcount(v)
#endif
