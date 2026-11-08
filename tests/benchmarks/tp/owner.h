// SPDX-License-Identifier: GPL-2.0
#ifndef TP_EVAL_OWNER_H
#define TP_EVAL_OWNER_H
#include "options.h"
#include "../../../src/compute/collectives/xdev_tp.h"
#include "../../../src/compute/cuda/peer_endpoint_owner.h"
#include "../../../src/compute/cuda/frame_endpoint_owner.h"
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
 xdev_ext_cuda_frame_owner *frames=nullptr; // --frames host
 CUcontext context=nullptr;
 CUstream stream=nullptr;
 CUmodule oracle=nullptr;
 CUfunction fill=nullptr,check=nullptr;
 xdev_tp_comm *comm=nullptr;
 bool started=false;
 std::vector<CUdeviceptr> inputs,outputs,bad;
 void open(const tp_eval_options &o,const char *node,const char *bpf,const char *user_bpf,const char *oracle_ptx,const char *tp_ptx,
           const xdev_ext_cuda_peer_programs_opts *programs=nullptr) {
  if(o.frames){open_frames(o,node,bpf,oracle_ptx,tp_ptx);return;}
  xdev_ext_cuda_peer_owner_opts options{};
  options.size=sizeof(options);options.version=1;options.mode=o.mode;
  options.context_mode=XDEV_EXT_CUDA_PEER_CREATE_OWN;options.device=o.device;
  options.nvidia_node=node;options.bpf_object=bpf;options.user_bpf_object=user_bpf;options.link_token=o.link;
  options.allocation_bytes=o.allocation_bytes;options.nr_batches=o.iterations*o.depth;
  options.first_sequence=o.first_sequence;options.timeout_ns=o.timeout_ns;
  options.group_bytes=o.group_bytes;options.depth=o.depth;
  uint32_t endpoint_flags=o.early_cts?XDEV_EXT_PEER_ENDPOINT_F_EARLY:0;
  int rc=programs?xdev_ext_cuda_peer_owner_open_programs(&options,endpoint_flags,programs,&bootstrap):
                  xdev_ext_cuda_peer_owner_open_flags(&options,endpoint_flags,&bootstrap);
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
 // Host frames plus the GPU copy engine (GPU without GPUDirect RDMA): the
 // owner creates both host-frame endpoints; each collective posts its own
 // batches, so there is no START here.
 void open_frames(const tp_eval_options &o,const char *node,const char *bpf,const char *oracle_ptx,const char *tp_ptx) {
  xdev_ext_cuda_frame_owner_opts options{};
  options.size=sizeof(options);options.version=XDEV_EXT_CUDA_FRAME_OWNER_VERSION;
  options.context_mode=XDEV_EXT_CUDA_PEER_CREATE_OWN;options.device=o.device;
  options.nvidia_node=node;options.bpf_object=bpf;options.ce_bpf_object=o.ce_bpf_object;
  options.link_token=o.link;options.timeout_ns=o.timeout_ns;options.group_bytes=o.group_bytes;
  options.receive_groups=1;options.endpoint_flags=o.early_cts?XDEV_EXT_FRAME_ENDPOINT_F_EARLY:0;
  int rc=xdev_ext_cuda_frame_owner_open(&options,&frames);
  started=frames!=nullptr; // Retain a partial owner as well as accepted work.
  NATIVE(rc);
  xdev_ext_cuda_frame_owner_view view{};view.size=sizeof(view);
  NATIVE(xdev_ext_cuda_frame_owner_get_view(frames,&view));
  context=view.context;stream=view.stream;
  CU(cuModuleLoad(&oracle,oracle_ptx));
  CU(cuModuleGetFunction(&fill,oracle,"tp_eval_fill"));
  CU(cuModuleGetFunction(&check,oracle,"tp_eval_check"));
  xdev_tp_config c{};c.size=sizeof(c);c.version=XDEV_TP_ABI_VERSION;c.rank=o.rank;c.world_size=2;
  c.mode=o.mode;c.context=context;c.flags=XDEV_TP_F_HOST_FRAMES;c.tx_frames=view.tx_frames;c.rx_frames=view.rx_frames;
  c.tx_va=view.tx_va;c.rx_va=view.rx_va;c.tx_bytes=view.tx_bytes;c.rx_bytes=view.rx_bytes;c.frame_size=4096;
  c.logical_depth=o.depth;c.max_payload_bytes=o.payload_bytes;c.first_sequence=o.first_sequence;
  c.communicator_id=o.communicator;c.epoch=o.epoch;c.timeout_ns=o.timeout_ns;c.ptx_path=tp_ptx;
  c.trace_capacity=o.trace_capacity;
  NATIVE(xdev_tp_create(&c,&comm));
  CUdeviceptr in=0,out=0,mismatch=0;
  CU(cuMemAlloc(&in,o.payload_bytes?o.payload_bytes:1));inputs.push_back(in);
  CU(cuMemAlloc(&out,o.payload_bytes?(o.operation==1?o.payload_bytes:2*o.payload_bytes):1));outputs.push_back(out);
  CU(cuMemAlloc(&mismatch,sizeof(unsigned)));bad.push_back(mismatch);
 }
 // Session identities recorded in the run metadata, after CREATE.
 void session_ids(tp_eval_options &o) {
  if(frames) {
   xdev_ext_cuda_frame_owner_view view{};view.size=sizeof(view);
   NATIVE(xdev_ext_cuda_frame_owner_get_view(frames,&view));
   o.tx_session_id=xdev_ext_session_id(xdev_ext_frame_endpoint_session(view.tx_frames));
   o.rx_session_id=xdev_ext_session_id(xdev_ext_frame_endpoint_session(view.rx_frames));
  } else {
   xdev_ext_cuda_peer_owner_view identity{};identity.size=sizeof(identity);
   NATIVE(xdev_ext_cuda_peer_owner_get_view(bootstrap,&identity));
   o.tx_session_id=xdev_ext_session_id(xdev_ext_peer_endpoint_session(identity.tx_endpoint));
   o.rx_session_id=xdev_ext_session_id(xdev_ext_peer_endpoint_session(identity.rx_endpoint));
  }
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
  if(frames)NATIVE(xdev_ext_cuda_frame_owner_close(&frames));
  else NATIVE(xdev_ext_cuda_peer_owner_close(&bootstrap));
  started=false;
 }
};
#endif
