/* SPDX-License-Identifier: GPL-2.0 */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"
#define pci_dev_put stack_x3_pci_put
#include "../../../../../io_uring/xdomain/xdev_ext_xdomain_main.c"
int stack_x3_init(void){
	return xdev_ext_xd_init();
}
void stack_x3_exit(void){
	xdev_ext_xd_exit();
}
int stack_x3_probe(struct tb_service*s){
	return xdev_ext_xd_probe(s,NULL);
}
void stack_x3_remove(struct tb_service*s){
	xdev_ext_xd_remove(s);
}
int stack_x3_suspend(struct tb_service*s){
	return xdev_ext_xd_suspend(&s->dev);
}
int stack_x3_resume(struct tb_service*s){
	return xdev_ext_xd_resume(&s->dev);
}
