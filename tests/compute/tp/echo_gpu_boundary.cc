// SPDX-License-Identifier: GPL-2.0
// Execute real benchmark graph assembly and CUDA kernel bodies at native/CUDA
// boundaries. Host branch arithmetic only; no GPU memory-model/DMA evidence.
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>
#include <cuda.h>
#include <peer_endpoint_owner.h>
#include TP_ECHO_OPTIONS
struct dim {unsigned x=0;};
static dim blockIdx,threadIdx,blockDim{1},gridDim{1};
static unsigned atomicAdd(unsigned *p,unsigned n){auto old=*p;*p+=n;return old;}
static int atomicCAS(int *p,int old,int n){auto v=*p;if(v==old)*p=n;return v;}
static int atomicExch(int *p,int n){auto old=*p;*p=n;return old;}
#define __host__
#define __device__
#define __global__
#include TP_ECHO_DEVICE
#include TP_ECHO_GPU_KERNELS
#undef __global__
#undef __device__
#undef __host__
static std::string scenario;
static unsigned rank_, failures, replay, intervals, premature_interval, native_reads[2];
static unsigned completed_prefix[2], successes[4], negatives[4], waits[4];
static unsigned frees_, graph_live, exec_live, launches, captures;
static bool recording, visible, gpu_pending, observed, consumed, produced;
static uint64_t ticks;
static std::vector<std::string> calls;
static std::vector<std::function<CUresult()>> nodes;
static std::vector<unsigned char> tx_bytes(16384,0xa5),rx_bytes(16384,0xc7);
static std::vector<void *> allocations;
struct xdev_ext_cuda_user {unsigned role;};
struct xdev_ext_peer_endpoint {unsigned index;};
struct xdev_ext_session {unsigned index;};
static xdev_ext_cuda_user controls[3]={{1},{2},{3}};
static xdev_ext_peer_endpoint endpoints[2]={{0},{1}};
static xdev_ext_session sessions[2]={{0},{1}};
static void expect(bool ok,const char *why){if(!ok){std::cerr<<"FAIL "<<why<<"\n";failures++;}}
static bool fault(const char *s){return scenario==s;}
static CUresult queue(std::function<CUresult()> f){if(recording){nodes.push_back(f);return 0;}return f();}
static unsigned char byte_at(uint64_t offset,unsigned seed){return static_cast<unsigned char>((offset%251+seed%251)%251);}
static const unsigned lens[2]={3072,19};
static const unsigned offsets[2]={512,256};
static bool guards_intact(const std::vector<unsigned char> &data,unsigned char poison){
 for(unsigned pos=0;pos<data.size();pos++){
  bool payload=false;for(unsigned i=0;i<2;i++)payload|=pos>=4096*i+offsets[i]&&pos<4096*i+offsets[i]+lens[i];
  if(!payload&&data[pos]!=poison)return false;
 }return true;
}
static void input_bytes(){for(unsigned i=0;i<2;i++)for(unsigned j=0;j<lens[i];j++)rx_bytes[4096*i+offsets[i]+j]=byte_at((i?3072:0)+j,replay);}
static bool bytes_match(const std::vector<unsigned char>&data){for(unsigned i=0;i<2;i++)for(unsigned j=0;j<lens[i];j++)if(data[4096*i+offsets[i]+j]!=byte_at((i?3072:0)+j,replay))return false;return true;}
static void native_check(int n,const char *s){if(n)throw std::runtime_error(s);}
static void cuda_check(CUresult n,const char *s){if(n)throw std::runtime_error(s);}
#define NATIVE(c) native_check((c),#c)
#define CU(c) cuda_check((c),#c)
#define TP_EVAL_OWNER_H
struct tp_eval_owner {
 xdev_ext_cuda_peer_owner *bootstrap=reinterpret_cast<xdev_ext_cuda_peer_owner *>(1);
 CUcontext context=reinterpret_cast<void *>(1);
 CUstream stream=reinterpret_cast<void *>(2);
 CUmodule oracle=reinterpret_cast<void *>(3);
 std::vector<CUdeviceptr> bad;
 void close(uint64_t){expect(!graph_live&&!exec_live&&!gpu_pending,"owner close follows graph destruction and last use");calls.push_back("owner_close");}
};
CUresult cuStreamBeginCapture(CUstream,int);
CUresult cuStreamEndCapture(CUstream,CUgraph *);
CUresult cuGraphInstantiate(CUgraphExec *,CUgraph,unsigned long long);
CUresult cuGraphLaunch(CUgraphExec,CUstream);
CUresult cuGraphDestroy(CUgraph);
CUresult cuGraphExecDestroy(CUgraphExec);
CUresult cuStreamSynchronize(CUstream);
CUresult cuMemsetD32Async(CUdeviceptr,unsigned,size_t,CUstream);
CUresult cuMemsetD8Async(CUdeviceptr,unsigned char,size_t,CUstream);
CUresult cuMemcpyDtoDAsync(CUdeviceptr,CUdeviceptr,size_t,CUstream);
#include TP_ECHO_SOURCE
#include TP_ECHO_GPU_SOURCE
extern "C" int xdev_ext_cuda_peer_owner_get_view(xdev_ext_cuda_peer_owner *,xdev_ext_cuda_peer_owner_view *v){
 v->tx_endpoint=&endpoints[0];v->rx_endpoint=&endpoints[1];
 v->context=reinterpret_cast<void *>(1);v->stream=reinterpret_cast<void *>(2);
 v->tx_va=reinterpret_cast<CUdeviceptr>(tx_bytes.data());v->rx_va=reinterpret_cast<CUdeviceptr>(rx_bytes.data());
 v->allocation_bytes=16384;v->frame_size=4096;
 v->tx_producer=&controls[0];v->rx_consumer=&controls[1];v->tx_terminal=&controls[2];
 if(fault("alias_allocation"))v->rx_va=v->tx_va;
 return 0;
}
extern "C" int xdev_ext_peer_endpoint_next(xdev_ext_peer_endpoint *,int,xdev_ext_peer_message *){expect(false,"d2 never consumes ready on host");return -EIO;}
extern "C" int xdev_ext_peer_endpoint_complete(xdev_ext_peer_endpoint *,const xdev_ext_peer_message *,int){expect(false,"d2 never publishes done on host");return -EIO;}
extern "C" int xdev_ext_cuda_host_receive_visible(CUcontext){expect(false,"d2 uses captured native receive visibility");return -EIO;}
extern "C" int xdev_ext_user_batch_peer_span(const xdev_ext_user_batch *,__u32,__u64,__u64,__u32,xdev_ext_peer_span *){return -EIO;}
extern "C" xdev_ext_session *xdev_ext_peer_endpoint_session(xdev_ext_peer_endpoint *e){return &sessions[e->index];}
extern "C" int xdev_ext_session_stats(xdev_ext_session *s,xdev_ext_mech_stats *out){
 calls.push_back("stats"+std::to_string(s->index));*out={};
 unsigned seen=++native_reads[s->index];
 // Two observations per replay force the real loop to wait for each END.
 completed_prefix[s->index]=seen/2;out->batches_done=completed_prefix[s->index];
 out->inflight=7; // Future work is allowed; current END prefix is sufficient.
 if(fault("end_timeout"))out->batches_done=0;
 if(fault("end_abort"))out->batches_abort=1;
 if(fault("end_held"))out->held=1;
 if(fault("end_sequestered"))out->sequestered=1;
 if(fault("end_error"))out->last_err=-EIO;
 return 0;
}
extern "C" int xdev_ext_session_wait(xdev_ext_session *,int,xdev_ext_mech_stats *){expect(false,"echo END is cumulative-prefix stats");return -EIO;}
extern "C" int xdev_ext_cuda_user_wait(xdev_ext_cuda_user *u,CUstream,xdev_ext_cuda_message *m){
 expect(recording,"native wait is captured once");unsigned role=u->role;
 return queue([=](){
  calls.push_back("wait"+std::to_string(role));waits[role]++;*m={};
  m->ticket=100*role+replay+1;m->key=23+replay;m->nr_frames=2;
  for(unsigned i=0;i<2;i++){auto &f=m->f[i];f.umem_addr=4096*i;f.data_off=offsets[i];f.capacity=4096-offsets[i];f.data_len=lens[i];f.out_len=lens[i];m->device_address[i]=reinterpret_cast<CUdeviceptr>((role==2?rx_bytes:tx_bytes).data()+4096*i+offsets[i]);}
  if(role==2){visible=false;input_bytes();
   if(fault("bad_payload")||fault("bad_short_tail"))rx_bytes[role==2&&fault("bad_short_tail")?4096+256+18:512]^=1;
   if(fault("bad_key"))m->key++;
   if(fault("zero_ticket"))m->ticket=0;
   if(fault("duplicate_key")&&replay)m->key--;
   if(fault("stale_ticket")&&replay)m->ticket--;
   if(fault("ready_status"))m->status=-EIO;
   if(fault("zero_span"))m->f[1].data_len=0;
   if(fault("zero_frames"))m->nr_frames=0;
   if(fault("too_many_frames"))m->nr_frames=XDEV_EXT_MECH_MAX_FRAMES+1;
   if(fault("span_bounds"))m->f[1].data_len=4096;
   if(fault("address_bounds"))m->device_address[1]=reinterpret_cast<CUdeviceptr>(rx_bytes.data())+16384+256;
   if(fault("geometry"))m->f[1].data_len=18;
  }
  if(role==1&&fault("producer_key"))m->key++;
  if(role==1&&fault("producer_status"))m->status=-EIO;
  if(role==1&&fault("tx_geometry"))m->f[1].data_len=18;
  if(role==3&&fault("terminal_key"))m->key++;
  if(role==3&&fault("terminal_status"))m->status=-EIO;
  if(role==3&&fault("terminal_ticket")&&replay)m->ticket--;
  return CUresult(0);
 });
}
extern "C" int xdev_ext_cuda_receive_visible(xdev_ext_cuda_user *u,CUstream){
 expect(recording&&u->role==2,"receive visibility captured on RX controller");
 if(fault("visibility_failure"))return -EIO;
 return queue([](){visible=true;calls.push_back("visible");return CUresult(0);});
}
extern "C" int xdev_ext_cuda_user_done(xdev_ext_cuda_user *u,CUstream,xdev_ext_cuda_message *m){
 expect(recording,"native done is captured once");unsigned role=u->role;
 return queue([=](){
  calls.push_back("done"+std::to_string(role)+":"+std::to_string(m->status));
  expect(guards_intact(tx_bytes,0xa5)&&guards_intact(rx_bytes,0xc7),"device algorithm never writes outside verified payload spans");
  if(m->status<0)negatives[role]++;else {
   expect(m->status==0,"done has zero or negative status");successes[role]++;
   expect(m->key==23+replay&&m->ticket==100*role+replay+1,"done uses this replay fresh ready authority");
   if(role==1){expect(rank_?consumed:produced,"TX done follows the actual device payload algorithm");expect(bytes_match(tx_bytes),"every TX byte includes fresh seed and short tail");}
   if(role==2){expect(consumed,"RX done follows actual device validation/copy kernel");expect(visible,"RX visibility precedes successful consumer release");
    if(rank_)expect(bytes_match(tx_bytes),"rank1 copies all RX bytes before RX done");}
  }
  return CUresult(0);
 });
}
CUresult cuMemAlloc(CUdeviceptr *p,size_t n){void *v=std::calloc(1,n);allocations.push_back(v);*p=reinterpret_cast<CUdeviceptr>(v);calls.push_back("alloc");return 0;}
CUresult cuMemFree(CUdeviceptr p){expect(!graph_live&&!exec_live&&!gpu_pending,"device state not freed while graph or GPU owns it");frees_++;calls.push_back("free");for(void *&v:allocations)if(v==reinterpret_cast<void *>(p)){std::free(v);v=nullptr;return 0;}expect(false,"free owned allocation");return 0;}
CUresult cuMemcpyHtoD(CUdeviceptr p,const void *v,size_t n){expect(!recording,"initial controls copied outside graph");expect(n<=sizeof(tp_eval_echo_gpu_state),"HtoD is control state, never payload");std::memcpy(reinterpret_cast<void *>(p),v,n);return 0;}
CUresult cuMemcpyHtoDAsync(CUdeviceptr p,const void *v,size_t n,CUstream){expect(!recording,"capture-time host constants cannot set replay seed");return cuMemcpyHtoD(p,v,n);}
CUresult cuMemcpyDtoH(void *v,CUdeviceptr p,size_t n){expect(!recording&&!gpu_pending,"host observation follows GPU completion");expect(n<=sizeof(tp_eval_echo_gpu_state),"DtoH observes control state only");if(fault("observe_failure"))return CUDA_ERROR_UNKNOWN;observed=true;std::memcpy(v,reinterpret_cast<void *>(p),n);return 0;}
CUresult cuMemsetD8(CUdeviceptr p,unsigned char v,size_t n){std::memset(reinterpret_cast<void *>(p),v,n);return 0;}
CUresult cuMemsetD8Async(CUdeviceptr p,unsigned char v,size_t n,CUstream){return queue([=](){std::memset(reinterpret_cast<void *>(p),v,n);return CUresult(0);});}
CUresult cuMemsetD32Async(CUdeviceptr p,unsigned v,size_t n,CUstream){return queue([=](){for(size_t i=0;i<n;i++)reinterpret_cast<unsigned *>(p)[i]=v;return CUresult(0);});}
CUresult cuMemcpyDtoDAsync(CUdeviceptr p,CUdeviceptr q,size_t n,CUstream){return queue([=](){expect(visible,"copy follows RX visibility");std::memcpy(reinterpret_cast<void *>(p),reinterpret_cast<void *>(q),n);return CUresult(0);});}
CUresult cuModuleGetFunction(CUfunction *f,CUmodule,const char *name){
 static const char *names[]={"tp_eval_echo_gpu_begin","tp_eval_echo_gpu_produce","tp_eval_echo_gpu_consume","tp_eval_echo_gpu_terminal","tp_eval_echo_fill","tp_eval_echo_check"};
 for(unsigned i=0;i<6;i++)if(std::strcmp(name,names[i])==0){*f=reinterpret_cast<void *>(uintptr_t(i+1));return 0;}expect(false,"known kernel function");return CUDA_ERROR_UNKNOWN;
}
CUresult cuLaunchKernel(CUfunction f,unsigned gx,unsigned,unsigned,unsigned bx,unsigned,unsigned,unsigned,CUstream,void **a,void **){
 unsigned kernel=unsigned(reinterpret_cast<uintptr_t>(f));
 expect(kernel>=1&&kernel<=4,"d2 executes graph-aware device algorithms");
 auto state=*static_cast<CUdeviceptr *>(a[0]);
 return queue([=](){
  auto *s=reinterpret_cast<tp_eval_echo_gpu_state *>(state);
  if(kernel==3)expect(visible,"actual consume kernel follows RX visibility");
  gridDim.x=gx;blockDim.x=bx;
  for(blockIdx.x=0;blockIdx.x<gx;blockIdx.x++)for(threadIdx.x=0;threadIdx.x<bx;threadIdx.x++){
   if(kernel==1)tp_eval_echo_gpu_begin(s);
   else if(kernel==2)tp_eval_echo_gpu_produce(s);
   else if(kernel==3)tp_eval_echo_gpu_consume(s);
   else if(kernel==4)tp_eval_echo_gpu_terminal(s);
  }
  if(kernel==1){produced=false;consumed=false;}
  if(kernel==2)produced=true;
  if(kernel==3)consumed=true;
  calls.push_back("kernel"+std::to_string(kernel));return CUresult(0);
 });
}
CUresult cuStreamBeginCapture(CUstream,int){captures++;calls.push_back("capture");if(fault("capture_failure"))return CUDA_ERROR_UNKNOWN;recording=true;nodes.clear();return 0;}
CUresult cuStreamEndCapture(CUstream,CUgraph *g){recording=false;*g=reinterpret_cast<void *>(4);graph_live++;return 0;}
CUresult cuGraphInstantiate(CUgraphExec *e,CUgraph,unsigned long long){if(fault("instantiate_failure"))return CUDA_ERROR_UNKNOWN;*e=reinterpret_cast<void *>(5);exec_live++;return 0;}
CUresult cuGraphLaunch(CUgraphExec,CUstream){launches++;observed=false;if(fault("launch_failure")){gpu_pending=true;return CUDA_ERROR_UNKNOWN;}gpu_pending=true;for(auto &n:nodes){auto e=n();if(e)return e;}return 0;}
CUresult cuGraphExecDestroy(CUgraphExec){calls.push_back("destroy_exec");if(fault("destroy_failure"))return CUDA_ERROR_UNKNOWN;exec_live--;return 0;}
CUresult cuGraphDestroy(CUgraph){expect(!exec_live,"exec destroyed before graph");calls.push_back("destroy_graph");if(fault("graph_destroy_failure"))return CUDA_ERROR_UNKNOWN;graph_live--;return 0;}
CUresult cuStreamSynchronize(CUstream){if(fault("sync_failure"))return CUDA_ERROR_UNKNOWN;gpu_pending=false;return 0;}
CUresult cuStreamQuery(CUstream){return gpu_pending?CUDA_ERROR_NOT_READY:CUDA_SUCCESS;}
CUresult cuEventCreate(CUevent *e,unsigned){*e=reinterpret_cast<void *>(6);return 0;}
CUresult cuEventRecord(CUevent,CUstream){return 0;}
CUresult cuEventSynchronize(CUevent){return cuStreamSynchronize(nullptr);}
CUresult cuEventQuery(CUevent){return cuStreamQuery(nullptr);}
CUresult cuEventDestroy(CUevent){return 0;}
CUresult cuStreamIsCapturing(CUstream,CUstreamCaptureStatus *s){*s=recording?CU_STREAM_CAPTURE_STATUS_ACTIVE:CU_STREAM_CAPTURE_STATUS_NONE;return 0;}
static uint64_t now_ns(){expect(captures==1&&graph_live&&exec_live&&!recording,"capture and instantiate complete before interval clock starts");return ++ticks;}
struct barrier {int fd=-1;void exchange(const std::string &){calls.push_back("barrier");}};
static int boundary_printf(const char *fmt,...){
 if(std::strstr(fmt,"\"interval\"")){intervals++;premature_interval+=completed_prefix[0]<intervals||completed_prefix[1]<intervals;expect(observed,"interval follows GPU error observation");calls.push_back("interval");replay++;}
 return 0;
}
#define printf boundary_printf
static int actual_driver_echo(tp_eval_owner &owner,const tp_eval_options &o){barrier control;
#include TP_ECHO_DRIVER
 return -1;
}
#undef printf
int main(int argc,char **argv){
 assert(argc==3);scenario=argv[1];rank_=unsigned(std::stoul(argv[2]));
 // This host fixture uses the production monotonic clock. A successful case
 // must tolerate CI scheduling; end_timeout below separately checks expiry.
 tp_eval_options o;o.rank=rank_;o.mode=2;o.operation=4;o.depth=1;o.iterations=2;o.first_sequence=23;o.group_bytes=3091;o.allocation_bytes=16384;o.timeout_ns=1000000000;
 if(fault("end_timeout"))o.timeout_ns=1;
 tp_eval_owner owner;bool threw=false;
 if(fault("destroy_failure")||fault("graph_destroy_failure")){
  try{tp_eval_echo_gpu e(owner,o);e.capture();e.exchange(0);e.close();}catch(const std::exception&){threw=true;}
 }else try{actual_driver_echo(owner,o);}catch(const std::exception&){threw=true;}
 bool invalid=scenario!="success";
 expect(threw==invalid,"exception matches independent invalid-evidence scenario");
 if(invalid){expect(frees_==0,"failure retains device state");expect(intervals==(fault("duplicate_key")||fault("stale_ticket")||fault("terminal_ticket")?1U:0U),"failure produces no successful interval");
  if(fault("bad_payload")||fault("bad_short_tail")||fault("bad_key")||fault("zero_ticket")||fault("ready_status")||fault("zero_span")||fault("zero_frames")||fault("too_many_frames")||fault("span_bounds")||fault("address_bounds")||fault("geometry")){
   expect(negatives[2]>0,"real device validation publishes negative RX status");expect(successes[2]==0,"invalid RX never publishes done0");
   if(rank_)expect(negatives[1]>0&&successes[1]==0,"rank1 GPU error propagates to TX status");
   expect(negatives[3]>0&&successes[3]==0,"GPU error reaches terminal status");
  }
 }else{
  expect(captures==1&&launches==2,"one captured graph replayed twice");
  expect(intervals==2&&premature_interval==0,"both replay intervals follow both native END prefixes");
  expect(successes[1]==2&&successes[2]==2&&successes[3]==2,"every fresh ready role completed exactly once per replay");
  expect(waits[1]==2&&waits[2]==2&&waits[3]==2,"each replay consumes new native ready messages");
  expect(frees_>0&&!graph_live&&!exec_live,"successful close releases graph before device state");
 }
 std::cout<<"case="<<scenario<<" rank="<<rank_<<" failures="<<failures<<" intervals="<<intervals<<" premature_intervals="<<premature_interval<<" captures="<<captures<<" launches="<<launches<<" frees="<<frees_<<" calls=";
 for(auto &c:calls)std::cout<<c<<",";std::cout<<"\n";
 // Process teardown is not a production cleanup receipt. Keep production
 // calls observable; release fixture allocations only after all assertions.
 for(auto p:allocations)std::free(p);
 return failures?1:0;
}
