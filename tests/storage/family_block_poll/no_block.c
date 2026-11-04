/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/xdev_ext_storfam_block.h>
/* A leaking new-only public view conflicts; legitimate noBLOCK is opaque. */
struct xdev_ext_stor_poll_view {unsigned fixture_no_block_guard;};
int main(void){return 0;}
