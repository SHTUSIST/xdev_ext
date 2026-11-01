/* SPDX-License-Identifier: GPL-2.0 */
#include <type_traits>
#include "peer_endpoint_owner.h"
#ifdef CUDA_PRIVATE_NEW
static_assert(std::is_aggregate<xdev_ext_cuda_peer_programs_opts>::value,"positional C-compatible aggregate");
static_assert(std::is_standard_layout<xdev_ext_cuda_peer_programs_opts>::value,"C-compatible options");
static xdev_ext_cuda_peer_programs_opts programs=XDEV_EXT_CUDA_PEER_PROGRAMS_OPTS_INIT;
#endif
int declarations_cpp()
{
#ifdef CUDA_PRIVATE_NEW
 if(programs.size!=sizeof(programs)||programs.version!=1||programs.flags)return 1;
 for(auto p:programs.tx_stage_pins)if(p)return 1;
 for(auto p:programs.rx_stage_pins)if(p)return 1;
#endif
 return 0;
}
