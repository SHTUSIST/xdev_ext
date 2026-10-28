// SPDX-License-Identifier: GPL-2.0
#ifndef TP_EVAL_ECHO_H
#define TP_EVAL_ECHO_H
#include "owner.h"
struct tp_eval_echo {
 tp_eval_owner &owner;
 const tp_eval_options &options;
 xdev_ext_cuda_peer_owner_view view{};
 CUfunction produce=nullptr,verify=nullptr;
 CUevent complete_event=nullptr;
 tp_eval_echo(tp_eval_owner &o,const tp_eval_options &cfg):owner(o),options(cfg) {
  view.size=sizeof(view);NATIVE(xdev_ext_cuda_peer_owner_get_view(o.bootstrap,&view));
  CU(cuModuleGetFunction(&produce,owner.oracle,"tp_eval_echo_fill"));
  CU(cuModuleGetFunction(&verify,owner.oracle,"tp_eval_echo_check"));
  CU(cuEventCreate(&complete_event,CU_EVENT_DISABLE_TIMING));
 }
 xdev_ext_peer_message next(bool tx,xdev_ext_peer_role role,uint64_t sequence) {
  xdev_ext_peer_message m{};
  NATIVE(xdev_ext_peer_endpoint_next(tx?view.tx_endpoint:view.rx_endpoint,int(options.timeout_ns/1000000),&m));
  if(m.role!=role || m.batch.key!=sequence)throw std::runtime_error("echo role/key mismatch");
  return m;
 }
 xdev_ext_peer_span span(xdev_ext_peer_message &m,unsigned i,bool tx) {
  xdev_ext_peer_span s{};
  NATIVE(xdev_ext_user_batch_peer_span(&m.batch,i,tx?view.tx_va:view.rx_va,
         view.allocation_bytes,view.frame_size,&s));return s;
 }
 void done(bool tx,xdev_ext_peer_message &m) {
  CU(cuEventRecord(complete_event,owner.stream));CU(cuEventSynchronize(complete_event));
  NATIVE(xdev_ext_peer_endpoint_complete(tx?view.tx_endpoint:view.rx_endpoint,&m,0));
 }
 void fill(xdev_ext_peer_message &tx,uint64_t seed) {
  uint64_t offset=0;
  for(unsigned i=0;i<tx.batch.nr_frames;++i) {
   auto s=span(tx,i,true);CUdeviceptr ptr=s.device_address;uint64_t n=s.data_len;
   void *args[]={&ptr,&n,&offset,&seed};
   CU(cuLaunchKernel(produce,16,1,1,256,1,1,0,owner.stream,args,nullptr));offset+=n;
  }
  if(offset!=options.group_bytes)throw std::runtime_error("echo short TX message");
 }
 void copy(xdev_ext_peer_message &rx,xdev_ext_peer_message &tx) {
  NATIVE(xdev_ext_cuda_host_receive_visible(view.context));
  if(rx.batch.nr_frames!=tx.batch.nr_frames)throw std::runtime_error("echo frame geometry mismatch");
  uint64_t total=0;
  for(unsigned i=0;i<rx.batch.nr_frames;++i) {
   auto r=span(rx,i,false),t=span(tx,i,true);
   if(r.data_len!=t.data_len)throw std::runtime_error("echo span length mismatch");
   CU(cuMemcpyDtoDAsync(t.device_address,r.device_address,r.data_len,owner.stream));total+=r.data_len;
  }
  if(total!=options.group_bytes)throw std::runtime_error("echo short RX message");
 }
 bool check(xdev_ext_peer_message &rx,uint64_t seed) {
  NATIVE(xdev_ext_cuda_host_receive_visible(view.context));
  CU(cuMemsetD32Async(owner.bad[0],0,1,owner.stream));
  uint64_t offset=0;
  for(unsigned i=0;i<rx.batch.nr_frames;++i) {
   auto s=span(rx,i,false);CUdeviceptr ptr=s.device_address;uint64_t n=s.data_len;
   void *args[]={&ptr,&n,&offset,&seed,&owner.bad[0]};
   CU(cuLaunchKernel(verify,16,1,1,256,1,1,0,owner.stream,args,nullptr));offset+=n;
  }
  if(offset!=options.group_bytes)throw std::runtime_error("echo short return message");
  CU(cuEventRecord(complete_event,owner.stream));CU(cuEventSynchronize(complete_event));
  unsigned bad=0;CU(cuMemcpyDtoH(&bad,owner.bad[0],sizeof(bad)));return bad==0;
 }
 bool exchange(uint64_t iteration) {
  uint64_t sequence=options.first_sequence+iteration;
  if(options.rank==0) {
   auto tx=next(true,XDEV_EXT_PEER_PRODUCER,sequence);fill(tx,iteration);done(true,tx);
   auto rx=next(false,XDEV_EXT_PEER_RX_CONSUMER,sequence);bool valid=check(rx,iteration);
   // A failed independent consumer is UNKNOWN, never a fabricated done0.
   if(!valid)throw std::runtime_error("echo GPU payload mismatch");
   done(false,rx);
  } else {
   auto rx=next(false,XDEV_EXT_PEER_RX_CONSUMER,sequence);
   auto tx=next(true,XDEV_EXT_PEER_PRODUCER,sequence);
   // Check request independently as well as checking the returned bytes on0.
   if(!check(rx,iteration))throw std::runtime_error("echo request GPU mismatch");
   copy(rx,tx);done(false,rx);done(true,tx);
  }
  auto terminal=next(true,XDEV_EXT_PEER_TX_TERMINAL,sequence);done(true,terminal);
  return true;
 }
 void close() {CU(cuEventDestroy(complete_event));complete_event=nullptr;}
};
#endif
