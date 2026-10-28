/* SPDX-License-Identifier: GPL-2.0 */
/* This fixture exercises selectors -1 only. Never manufacture private identity. */
static int xdev_ext_mech_instance_get_from_fd(u32 class_id, int fd,
 struct xdev_ext_mech_instance **out)
{ (void)class_id;(void)fd;(void)out;abort(); }
static bool xdev_ext_mech_instance_current(const struct xdev_ext_mech_instance *p)
{ (void)p;abort(); }
static void xdev_ext_mech_instance_put(struct xdev_ext_mech_instance *p)
{ (void)p;abort(); }
