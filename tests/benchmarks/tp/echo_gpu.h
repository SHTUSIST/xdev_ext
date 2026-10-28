// SPDX-License-Identifier: GPL-2.0
#ifndef TP_EVAL_ECHO_GPU_H
#define TP_EVAL_ECHO_GPU_H
#include "echo.h"
#include "echo_device.h"
#include <cstddef>

struct tp_eval_echo_gpu {
 tp_eval_owner &owner;
 const tp_eval_options &options;
 xdev_ext_cuda_peer_owner_view view{};
 CUdeviceptr state=0;
 CUfunction begin=nullptr,produce=nullptr,consume=nullptr,terminal=nullptr;
 CUgraph graph=nullptr;
 CUgraphExec exec=nullptr;
 bool captured=false, safe=false;
 uint64_t completed=0;
 tp_eval_echo_gpu(tp_eval_owner &o,const tp_eval_options &cfg):owner(o),options(cfg) {
  if(cfg.mode!=2 || cfg.operation!=4 || cfg.depth!=1)NATIVE(-EINVAL);
  view.size=sizeof(view);NATIVE(xdev_ext_cuda_peer_owner_get_view(owner.bootstrap,&view));
  if(!view.tx_producer || !view.tx_terminal || !view.rx_consumer)NATIVE(-EINVAL);
  CU(cuModuleGetFunction(&begin,owner.oracle,"tp_eval_echo_gpu_begin"));
  CU(cuModuleGetFunction(&produce,owner.oracle,"tp_eval_echo_gpu_produce"));
  CU(cuModuleGetFunction(&consume,owner.oracle,"tp_eval_echo_gpu_consume"));
  CU(cuModuleGetFunction(&terminal,owner.oracle,"tp_eval_echo_gpu_terminal"));
  tp_eval_echo_gpu_state initial{};
  initial.first_sequence=cfg.first_sequence;
  initial.tx_base=view.tx_va;initial.rx_base=view.rx_va;initial.allocation_bytes=view.allocation_bytes;
  initial.group_bytes=cfg.group_bytes;initial.frame_size=view.frame_size;initial.rank=cfg.rank;
  CU(cuMemAlloc(&state,sizeof(initial)));
  CU(cuMemcpyHtoD(state,&initial,sizeof(initial)));
 }
 xdev_ext_cuda_message *message(size_t offset) {
  return reinterpret_cast<xdev_ext_cuda_message *>(state+offset);
 }
 void kernel(CUfunction function) {
  void *args[]={&state};
  CU(cuLaunchKernel(function,1,1,1,1,1,1,0,owner.stream,args,nullptr));
 }
 void capture() {
  if(captured || graph || exec || !state)NATIVE(-EINVAL);
  // A capture error preserves all borrowed controls/state for explicit recovery.
  safe=false;
  CU(cuStreamBeginCapture(owner.stream,CU_STREAM_CAPTURE_MODE_THREAD_LOCAL));
  kernel(begin);
  auto *tx=message(offsetof(tp_eval_echo_gpu_state,tx));
  auto *rx=message(offsetof(tp_eval_echo_gpu_state,rx));
  auto *end=message(offsetof(tp_eval_echo_gpu_state,terminal));
  if(options.rank==0) {
   NATIVE(xdev_ext_cuda_user_wait(view.tx_producer,owner.stream,tx));kernel(produce);
   NATIVE(xdev_ext_cuda_user_done(view.tx_producer,owner.stream,tx));
   NATIVE(xdev_ext_cuda_user_wait(view.rx_consumer,owner.stream,rx));
   NATIVE(xdev_ext_cuda_receive_visible(view.rx_consumer,owner.stream));kernel(consume);
   NATIVE(xdev_ext_cuda_user_done(view.rx_consumer,owner.stream,rx));
  } else {
   NATIVE(xdev_ext_cuda_user_wait(view.rx_consumer,owner.stream,rx));
   NATIVE(xdev_ext_cuda_receive_visible(view.rx_consumer,owner.stream));
   NATIVE(xdev_ext_cuda_user_wait(view.tx_producer,owner.stream,tx));kernel(consume);
   NATIVE(xdev_ext_cuda_user_done(view.rx_consumer,owner.stream,rx));
   NATIVE(xdev_ext_cuda_user_done(view.tx_producer,owner.stream,tx));
  }
  NATIVE(xdev_ext_cuda_user_wait(view.tx_terminal,owner.stream,end));kernel(terminal);
  NATIVE(xdev_ext_cuda_user_done(view.tx_terminal,owner.stream,end));
  CU(cuStreamEndCapture(owner.stream,&graph));CU(cuGraphInstantiate(&exec,graph,0));
  captured=true;safe=true;
 }
 void wait_native_complete(uint64_t target) {
  const uint64_t start=tp_eval_echo::monotonic_ns();
  bool done[2]={false,false};
  while(!done[0] || !done[1]) {
   for(unsigned i=0;i<2;++i) {
    if(done[i])continue;
    if(tp_eval_echo::monotonic_ns()-start>=options.timeout_ns)NATIVE(-ETIMEDOUT);
    xdev_ext_mech_stats stats{};
    auto *session=xdev_ext_peer_endpoint_session(i?view.rx_endpoint:view.tx_endpoint);
    NATIVE(xdev_ext_session_stats(session,&stats));
    if(stats.last_err)NATIVE(stats.last_err);
    if(stats.batches_abort || stats.held || stats.sequestered || stats.timeouts || stats.protocol_err || stats.rejects)
     throw std::runtime_error("GPU echo native END failed or retained custody");
    if(tp_eval_echo::monotonic_ns()-start>=options.timeout_ns)NATIVE(-ETIMEDOUT);
    done[i]=stats.batches_done>=target;
   }
   if(!done[0] || !done[1])sched_yield();
  }
 }
 bool exchange(uint64_t iteration) {
  if(!captured || !exec || !safe || iteration!=completed || iteration==UINT64_MAX)NATIVE(-EINVAL);
  safe=false;
  CU(cuGraphLaunch(exec,owner.stream));CU(cuStreamSynchronize(owner.stream));
  tp_eval_echo_gpu_state observed{};
  CU(cuMemcpyDtoH(&observed,state,sizeof(observed)));
  if(observed.error || observed.mismatch || observed.tx.status || observed.rx.status || observed.terminal.status ||
     observed.invocation!=iteration+1)
   throw std::runtime_error("GPU echo independent validation/control failure");
  wait_native_complete(iteration+1);
  completed=iteration+1;safe=true;return true;
 }
 void close() {
  if(!safe || !captured)throw std::runtime_error("GPU echo usage remains unknown");
  // Future replay references disappear before last-use proof and storage free.
  safe=false;
  if(exec){CU(cuGraphExecDestroy(exec));exec=nullptr;}
  if(graph){CU(cuGraphDestroy(graph));graph=nullptr;}
  CU(cuStreamSynchronize(owner.stream));
  if(state){CU(cuMemFree(state));state=0;}
  captured=false;
 }
};
#endif
