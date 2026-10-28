/* SPDX-License-Identifier: GPL-2.0 */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"
void production_poll_parameter(const char *, bool *, unsigned);
#define PP_CAT_(a,b) a##b
#define PP_CAT(a,b) PP_CAT_(a,b)
#define PP_PARAM(name,value,perm,id) \
 static void __attribute__((constructor)) PP_CAT(pp_register_,id)(void) \
 { production_poll_parameter(name,&(value),perm); }
#undef module_param
#undef module_param_named
#define module_param(name,type,perm) PP_PARAM(#name,name,perm,__COUNTER__)
#define module_param_named(name,value,type,perm) PP_PARAM(#name,value,perm,__COUNTER__)
struct ring_frame *production_poll_ring(struct tb_ring *);
void production_poll_complete(struct tb_ring *);
#define tb_ring_poll_complete production_poll_complete
#define tb_ring_poll production_poll_ring
#include "stack_x3.c"
