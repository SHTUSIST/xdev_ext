// SPDX-License-Identifier: GPL-2.0
// Host lane invocation of actual CUDA source, never a payload implementation.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <vector>
#define __device__
#define __global__
struct TestDim {unsigned x=0,y=0,z=0;};
static TestDim blockIdx,threadIdx,gridDim,blockDim;
#include TP_KERNEL_SOURCE
int main(){
 constexpr unsigned lanes=64,payload=4096;
 std::vector<unsigned char> input(payload,0),target(64+payload,0xaa);
 std::vector<unsigned> coverage(payload,0);
 uint64_t largest=0,total=0;
 xdev_tp_native::Shape shape{};shape.communicator_id=7;shape.epoch=9;shape.sequence=23;
 shape.rows=1;shape.width=payload/4;shape.operation=1;shape.dtype=3;shape.rank=0;shape.world_size=2;
 int rc=xdev_tp_native::shape_validate(&shape,payload,64+payload);
 if(rc)return 2;
 for(unsigned lane=0;lane<lanes;lane++){
  std::fill(target.begin(),target.end(),0xaa);
  xdev_tp_native::Runtime runtime{};runtime.next_sequence=23;
  xdev_tp_native::DeviceWork work{};work.shape=shape;work.mode=1;
  work.input=reinterpret_cast<uint64_t>(input.data());
  work.tx[0]={reinterpret_cast<uint64_t>(target.data()),target.size()};work.tx_count=1;
  gridDim.x=2;blockDim.x=32;blockIdx.x=lane/32;threadIdx.x=lane%32;
#ifdef TP_PHASED_KERNELS
  blockIdx.x=threadIdx.x=0;
  xdev_tp_pack_begin(&work,&runtime,shape,work.input,0,1,1);
  std::fill(target.begin(),target.end(),0xaa);
  blockIdx.x=lane/32;threadIdx.x=lane%32;
  xdev_tp_pack_payload(&work);
#else
  xdev_tp_pack(&work,&runtime,shape,work.input,0,1);
#endif
  unsigned wrote=0;
  for(unsigned i=0;i<payload;i++)if(target[64+i]!=0xaa){wrote++;coverage[i]++;}
  largest=std::max<uint64_t>(largest,wrote);total+=wrote;
 }
 unsigned missing=0,overlap=0;for(unsigned n:coverage){missing+=n==0;overlap+=n>1;}
 bool okay=missing==0 && overlap==0 && largest<=(payload+lanes-1)/lanes;
 std::printf("TP_PAYLOAD_PARTITION lanes=%u payload=%u total_writes=%llu largest_lane=%llu missing=%u overlap=%u failures=%u\n",
  lanes,payload,(unsigned long long)total,(unsigned long long)largest,missing,overlap,!okay);
 return !okay;
}
