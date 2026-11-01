/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <stdint.h>
#include "peer_endpoint_owner.h"
#define OFF(field,value) _Static_assert(offsetof(struct xdev_ext_cuda_peer_owner_opts,field)==value,"old owner ABI " #field)
_Static_assert(sizeof(void*)==8,"LP64 test fixture");
_Static_assert(sizeof(struct xdev_ext_cuda_peer_owner_opts)==112,"old owner options ABI");
OFF(size,0);OFF(version,8);OFF(mode,12);OFF(context_mode,16);OFF(device,20);
OFF(context,24);OFF(stream,32);OFF(nvidia_node,40);OFF(bpf_object,48);
OFF(link_token,56);OFF(allocation_bytes,64);OFF(nr_batches,72);OFF(first_sequence,80);
OFF(timeout_ns,88);OFF(group_bytes,96);OFF(depth,100);OFF(user_bpf_object,104);
_Static_assert(sizeof(struct xdev_ext_cuda_peer_owner_view)==96,"old view ABI");
_Static_assert(offsetof(struct xdev_ext_cuda_peer_owner_view,context)==8,"old view context");
_Static_assert(offsetof(struct xdev_ext_cuda_peer_owner_view,tx_endpoint)==24,"old view endpoints");
_Static_assert(offsetof(struct xdev_ext_cuda_peer_owner_view,tx_va)==40,"old view VA");
_Static_assert(offsetof(struct xdev_ext_cuda_peer_owner_view,tx_producer)==64,"old view controllers");
_Static_assert(offsetof(struct xdev_ext_cuda_peer_owner_view,frame_size)==88,"old view frame");
static int (*old_open)(const struct xdev_ext_cuda_peer_owner_opts*,struct xdev_ext_cuda_peer_owner**)=xdev_ext_cuda_peer_owner_open;
static int (*old_flags)(const struct xdev_ext_cuda_peer_owner_opts*,uint32_t,struct xdev_ext_cuda_peer_owner**)=xdev_ext_cuda_peer_owner_open_flags;
static int (*old_view)(struct xdev_ext_cuda_peer_owner*,struct xdev_ext_cuda_peer_owner_view*)=xdev_ext_cuda_peer_owner_get_view;
static int (*old_start)(struct xdev_ext_cuda_peer_owner*)=xdev_ext_cuda_peer_owner_start;
static int (*old_close)(struct xdev_ext_cuda_peer_owner**)=xdev_ext_cuda_peer_owner_close;
#ifdef CUDA_PRIVATE_NEW
_Static_assert(sizeof(struct xdev_ext_cuda_peer_programs_opts)==56,"new additive options shape");
_Static_assert(sizeof(((struct xdev_ext_cuda_peer_programs_opts*)0)->tx_stage_pins)/sizeof(const char*)==3,"TX3");
_Static_assert(sizeof(((struct xdev_ext_cuda_peer_programs_opts*)0)->rx_stage_pins)/sizeof(const char*)==2,"RX2");
static struct xdev_ext_cuda_peer_programs_opts programs=XDEV_EXT_CUDA_PEER_PROGRAMS_OPTS_INIT;
static int (*new_open)(const struct xdev_ext_cuda_peer_owner_opts*,uint32_t,const struct xdev_ext_cuda_peer_programs_opts*,struct xdev_ext_cuda_peer_owner**)=xdev_ext_cuda_peer_owner_open_programs;
static int (*new_endpoint)(struct xdev_ext_peer_endpoint*,const int*,__u32,struct xdev_ext_mech_create_report*)=xdev_ext_peer_endpoint_create_programs;
#endif
int declarations_c(void)
{
 int result=!old_open||!old_flags||!old_view||!old_close||!old_start;
#ifdef CUDA_PRIVATE_NEW
 result|=!new_open||!new_endpoint||programs.size!=sizeof(programs)||programs.version!=1||programs.flags;
 for(unsigned i=0;i<3;i++)result|=programs.tx_stage_pins[i]!=NULL;
 for(unsigned i=0;i<2;i++)result|=programs.rx_stage_pins[i]!=NULL;
#endif
 return result;
}
