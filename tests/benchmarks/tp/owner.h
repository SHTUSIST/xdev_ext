// SPDX-License-Identifier: GPL-2.0
#ifndef TP_EVAL_OWNER_H
#define TP_EVAL_OWNER_H
#include "options.h"
#include "../../../src/compute/collectives/xdev_tp.h"
#include "../../../src/compute/cuda/peer_endpoint_owner.h"
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
inline void native_check(int rc,const char *what) {
 if(rc)throw std::runtime_error(std::string(what)+": "+std::to_string(rc));
}
inline void cuda_check(CUresult rc,const char *what) {
 if(rc!=CUDA_SUCCESS)throw std::runtime_error(std::string(what)+": CUDA "+std::to_string(int(rc)));
}
#define CU(call) cuda_check((call),#call)
#define NATIVE(call) native_check((call),#call)
struct tp_eval_owner {
 xdev_ext_cuda_peer_owner *bootstrap=nullptr;
 CUcontext context=nullptr;
 CUstream stream=nullptr;
 CUmodule oracle=nullptr;
 CUfunction fill=nullptr,check=nullptr;
 xdev_tp_comm *comm=nullptr;
 bool started=false;
 std::vector<CUdeviceptr> inputs,outputs,bad;
 void open(const tp_eval_options &o,const char *node,const char *bpf,const char *user_bpf,const char *oracle_ptx,const char *tp_ptx) {
  xdev_ext_cuda_peer_owner_opts options{};
  options.size=sizeof(options);options.version=1;options.mode=o.mode;
  options.context_mode=XDEV_EXT_CUDA_PEER_CREATE_OWN;options.device=o.device;
  options.nvidia_node=node;options.bpf_object=bpf;options.user_bpf_object=user_bpf;options.link_token=o.link;
  options.allocation_bytes=o.allocation_bytes;options.nr_batches=o.iterations*o.depth;
  options.first_sequence=o.first_sequence;options.timeout_ns=o.timeout_ns;
  options.group_bytes=o.group_bytes;options.depth=o.depth;
  int rc=xdev_ext_cuda_peer_owner_open_flags(&options,o.early_cts?XDEV_EXT_PEER_ENDPOINT_F_EARLY:0,&bootstrap);
  started=bootstrap!=nullptr; // Retain partial owner as well as accepted work.
  NATIVE(rc);
  xdev_ext_cuda_peer_owner_view view{};view.size=sizeof(view);
  NATIVE(xdev_ext_cuda_peer_owner_get_view(bootstrap,&view));
  context=view.context;stream=view.stream;
  CU(cuModuleLoad(&oracle,oracle_ptx));
  CU(cuModuleGetFunction(&fill,oracle,"tp_eval_fill"));
  CU(cuModuleGetFunction(&check,oracle,"tp_eval_check"));
  xdev_tp_config c{};c.size=sizeof(c);c.version=XDEV_TP_ABI_VERSION;c.rank=o.rank;c.world_size=2;
  c.mode=o.mode;c.context=context;c.tx_endpoint=view.tx_endpoint;c.rx_endpoint=view.rx_endpoint;
  c.tx_va=view.tx_va;c.rx_va=view.rx_va;c.tx_bytes=c.rx_bytes=view.allocation_bytes;c.frame_size=view.frame_size;
  c.logical_depth=o.depth;c.max_payload_bytes=o.payload_bytes;c.first_sequence=o.first_sequence;
  c.communicator_id=o.communicator;c.epoch=o.epoch;c.timeout_ns=o.timeout_ns;c.ptx_path=tp_ptx;
  c.d2_tx_producer=view.tx_producer;c.d2_tx_terminal=view.tx_terminal;c.d2_rx_consumer=view.rx_consumer;c.trace_capacity=o.trace_capacity;
  if(o.operation!=4)NATIVE(xdev_tp_create(&c,&comm));
  for(unsigned i=0;i<o.depth;++i) {
   CUdeviceptr in=0,out=0,mismatch=0;
   CU(cuMemAlloc(&in,o.payload_bytes?o.payload_bytes:1));inputs.push_back(in);
   CU(cuMemAlloc(&out,o.payload_bytes?(o.operation==1?o.payload_bytes:2*o.payload_bytes):1));outputs.push_back(out);
   CU(cuMemAlloc(&mismatch,sizeof(unsigned)));bad.push_back(mismatch);
  }
  NATIVE(xdev_ext_cuda_peer_owner_start(bootstrap));
 }
 void fill_inputs(const tp_eval_options &o,uint64_t iteration) {
  for(unsigned j=0;j<o.depth;++j) {
   uint64_t n=o.rows*o.elements,seed=iteration+j;
   unsigned dtype=o.dtype,rank=o.rank;
   void *args[]={&inputs[j],&n,&dtype,&rank,&seed};
   CU(cuLaunchKernel(fill,32,1,1,256,1,1,0,stream,args,nullptr));
  }
  CU(cuStreamSynchronize(stream));
 }
 bool validate(const tp_eval_options &o,unsigned j,uint64_t iteration) {
  CU(cuMemsetD32Async(bad[j],0,1,stream));
  uint64_t rows=o.rows,width=o.elements,seed=iteration+j;
  unsigned dtype=o.dtype,op=o.operation;
  void *args[]={&outputs[j],&rows,&width,&dtype,&op,&seed,&bad[j]};
  CU(cuLaunchKernel(check,32,1,1,256,1,1,0,stream,args,nullptr));
  CU(cuStreamSynchronize(stream));unsigned mismatches=0;
  CU(cuMemcpyDtoH(&mismatches,bad[j],sizeof(mismatches)));
  return mismatches==0;
 }
 void close(uint64_t timeout) {
  // Comm and graph borrowers release first; the production owner separately
  // proves last use and native drain before authority/allocation/context free.
  if(comm) {NATIVE(xdev_tp_destroy(comm,timeout));comm=nullptr;}
  CU(cuStreamSynchronize(stream));
  for(auto p:inputs)CU(cuMemFree(p));
  for(auto p:outputs)CU(cuMemFree(p));
  for(auto p:bad)CU(cuMemFree(p));
  CU(cuModuleUnload(oracle));oracle=nullptr;
  NATIVE(xdev_ext_cuda_peer_owner_close(&bootstrap));
  started=false;
 }
};
#endif
