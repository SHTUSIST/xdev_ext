// SPDX-License-Identifier: GPL-2.0
// Complete production library is included unchanged. Only CUDA/endpoint calls
// below are controlled host boundaries; no TP validation is replaced.
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include TP_LIBRARY_SOURCE
#define __device__
#define __global__
struct BoundaryDim {unsigned x=0,y=0,z=0;};
static BoundaryDim blockIdx,threadIdx,gridDim,blockDim;
#include TP_KERNEL_SOURCE
#ifndef TP_HAS_BATCH
struct BoundaryBatchRequest {
 CUdeviceptr input,output;uint64_t rows,local_width;uint32_t operation,dtype;int32_t dst_rank;uint32_t flags;
};
extern "C" int xdev_tp_submit_batch(xdev_tp_comm *,const BoundaryBatchRequest *,size_t,CUstream,uint64_t,xdev_tp_work **) __attribute__((weak));
#else
using BoundaryBatchRequest=xdev_tp_request;
#endif
struct xdev_ext_peer_endpoint { unsigned direction; };
struct xdev_ext_cuda_user { uint64_t stream;unsigned role; };
namespace boundary {
uint64_t context=1,stream_context=1,memory_context=1;
bool managed=false,host_memory=false,capturing=false;
uint64_t input=4096,output=8192,input_bytes=16,output_bytes=16;
uint64_t tx=0x100000,rx=0x200000,tx_bytes=4096,rx_bytes=4096;
unsigned ready=0,completes=0,enqueued=0,writes=0,closed=0;
unsigned next_calls=0,ready_fault=0;
bool execute_kernels=false;
unsigned tx_next=0;
struct Function {std::string name;};
bool graph_mode=false,recording=false,producer_ready=false,receiver_ready=false,terminal_ready=false,result_allowed=false,graph_complete=false;
bool graph_started=false;
CUresult graph_error=CUDA_SUCCESS;
uint64_t replay_key=23;
unsigned producer_done0=0,receiver_done0=0,terminal_done0=0;
unsigned role_counts[4]{},batch_width=1,enqueue_calls=0,enqueue_fail_at=0;
std::map<uint64_t,uint64_t> tensor_regions;
std::vector<unsigned> wait_order;
std::vector<std::function<CUresult()>> graph_nodes;
size_t graph_cursor=0;
std::vector<std::function<void()>> graph_releases;
std::vector<uint64_t> producer_keys,receiver_keys,terminal_keys;
void progress_graph(){
 graph_started=true;
 while(graph_cursor<graph_nodes.size()){
  CUresult rc=graph_nodes[graph_cursor]();if(rc==CUDA_ERROR_NOT_READY)return;
  if(rc){graph_error=rc;graph_complete=true;return;}
  graph_cursor++;
 }
}
std::map<CUdeviceptr,size_t> allocations;
struct Memory { uint64_t base,bytes;bool external; };
Memory memory(CUdeviceptr p) {
 if(p==tx)return {tx,tx_bytes,true};if(p==rx)return {rx,rx_bytes,true};
 for(auto r:allocations)if(p>=r.first && p-r.first<r.second)return {r.first,r.second,false};
 for(auto r:tensor_regions)if(p>=r.first && p-r.first<r.second)return {r.first,r.second,true};
 if(p==input)return {input,input_bytes,true};if(p==output)return {output,output_bytes,true};
 if(p>input && p-input<input_bytes)return {input,input_bytes,true};
 return {p,0,true};
}
}
CUresult cuCtxGetCurrent(CUcontext *p){*p=reinterpret_cast<void *>(boundary::context);return CUDA_SUCCESS;}
CUresult cuStreamGetCtx(CUstream,CUcontext *p){*p=reinterpret_cast<void *>(boundary::stream_context);return CUDA_SUCCESS;}
CUresult cuStreamIsCapturing(CUstream,CUstreamCaptureStatus *p){*p=(boundary::graph_mode?boundary::recording:boundary::capturing)?CU_STREAM_CAPTURE_STATUS_ACTIVE:CU_STREAM_CAPTURE_STATUS_NONE;return CUDA_SUCCESS;}
CUresult cuStreamQuery(CUstream){return boundary::graph_mode&&boundary::graph_started&&!boundary::graph_complete?CUDA_ERROR_NOT_READY:CUDA_SUCCESS;}
CUresult cuStreamGetId(CUstream s,unsigned long long *p){*p=reinterpret_cast<uintptr_t>(s);return CUDA_SUCCESS;}
CUresult cuPointerGetAttribute(void *p,int attribute,CUdeviceptr address){
 auto m=boundary::memory(address);bool tensor=address!=boundary::tx && address!=boundary::rx;
 if(attribute==CU_POINTER_ATTRIBUTE_CONTEXT)*static_cast<CUcontext *>(p)=reinterpret_cast<void *>(tensor?boundary::memory_context:boundary::context);
 else if(attribute==CU_POINTER_ATTRIBUTE_MEMORY_TYPE)*static_cast<CUmemorytype *>(p)=tensor&&boundary::host_memory?CU_MEMORYTYPE_HOST:CU_MEMORYTYPE_DEVICE;
 else if(attribute==CU_POINTER_ATTRIBUTE_IS_MANAGED)*static_cast<unsigned *>(p)=tensor&&boundary::managed;
 else return CUDA_ERROR_UNKNOWN;
 (void)m;return CUDA_SUCCESS;
}
CUresult cuMemGetAddressRange(CUdeviceptr *base,size_t *bytes,CUdeviceptr p){auto m=boundary::memory(p);*base=m.base;*bytes=m.bytes;return CUDA_SUCCESS;}
CUresult cuMemAlloc(CUdeviceptr *p,size_t n){void *m=std::calloc(1,n);if(!m)return CUDA_ERROR_UNKNOWN;*p=reinterpret_cast<uintptr_t>(m);boundary::allocations[*p]=n;return CUDA_SUCCESS;}
CUresult cuMemFree(CUdeviceptr p){auto i=boundary::allocations.find(p);assert(i!=boundary::allocations.end());std::free(reinterpret_cast<void *>(p));boundary::allocations.erase(i);return CUDA_SUCCESS;}
CUresult cuMemcpyHtoD(CUdeviceptr p,const void *s,size_t n){std::memcpy(reinterpret_cast<void *>(p),s,n);return CUDA_SUCCESS;}
CUresult cuMemcpyHtoDAsync(CUdeviceptr p,const void *s,size_t n,CUstream){return cuMemcpyHtoD(p,s,n);}
CUresult cuMemcpyDtoH(void *p,CUdeviceptr s,size_t n){std::memcpy(p,reinterpret_cast<void *>(s),n);return CUDA_SUCCESS;}
CUresult cuMemsetD8(CUdeviceptr p,unsigned char v,size_t n){std::memset(reinterpret_cast<void *>(p),v,n);return CUDA_SUCCESS;}
CUresult cuModuleLoad(CUmodule *m,const char *){*m=reinterpret_cast<void *>(1);return CUDA_SUCCESS;}
CUresult cuModuleGetFunction(CUfunction *f,CUmodule,const char *name){*f=new boundary::Function{name};return CUDA_SUCCESS;}
CUresult cuModuleUnload(CUmodule){return CUDA_SUCCESS;}
CUresult cuEventCreate(CUevent *e,unsigned){*e=reinterpret_cast<void *>(1);return CUDA_SUCCESS;}
CUresult cuEventDestroy(CUevent){return CUDA_SUCCESS;}
CUresult cuEventQuery(CUevent){return !boundary::graph_mode||!boundary::graph_started?CUDA_SUCCESS:boundary::graph_complete?boundary::graph_error:CUDA_ERROR_NOT_READY;}
CUresult cuEventRecord(CUevent,CUstream){if(boundary::recording)boundary::graph_nodes.push_back([](){boundary::graph_complete=true;return CUDA_SUCCESS;});return CUDA_SUCCESS;}
CUresult cuLaunchKernel(CUfunction function,unsigned gx,unsigned,unsigned,unsigned bx,unsigned,unsigned,unsigned,CUstream,void **args,void **){
 // Qualification must reject before this boundary. A mistakenly accepted call
 // becomes a visible retained error; it never dereferences synthetic tensor VAs.
 boundary::enqueued++;
 if(!boundary::execute_kernels)return CUDA_ERROR_UNKNOWN;
 auto *work=reinterpret_cast<xdev_tp_native::DeviceWork *>(*static_cast<CUdeviceptr *>(args[0]));
 const auto &name=static_cast<boundary::Function *>(function)->name;
 bool payload=name=="xdev_tp_pack_payload"||name=="xdev_tp_result_payload";
 auto *runtime=payload?nullptr:reinterpret_cast<xdev_tp_native::Runtime *>(*static_cast<CUdeviceptr *>(args[1]));
 bool pack_begin=name=="xdev_tp_pack"||name=="xdev_tp_pack_begin";
 xdev_tp_native::Shape shape{};uint64_t input=0,output=0,cookie=0;uint32_t mode=0;
 if(pack_begin){shape=*static_cast<xdev_tp_native::Shape *>(args[2]);input=*static_cast<uint64_t *>(args[3]);output=*static_cast<uint64_t *>(args[4]);mode=*static_cast<uint32_t *>(args[5]);
#ifdef TP_PHASED_KERNELS
  cookie=*static_cast<uint64_t *>(args[6]);
#endif
 }
 auto invoke=[=]()->CUresult{
  if(boundary::graph_mode && name.find("xdev_tp_result")==0 && !boundary::result_allowed)return CUresult(CUDA_ERROR_NOT_READY);
  gridDim.x=gx;blockDim.x=bx;
  for(unsigned block=0;block<gx;block++)for(unsigned thread=0;thread<bx;thread++){
  blockIdx.x=block;threadIdx.x=thread;
#ifdef TP_PHASED_KERNELS
  if(name=="xdev_tp_pack_begin")xdev_tp_pack_begin(work,runtime,shape,input,output,mode,cookie);
  else if(name=="xdev_tp_pack_payload")xdev_tp_pack_payload(work);
  else if(name=="xdev_tp_pack_commit")xdev_tp_pack_commit(work,runtime);
  else if(name=="xdev_tp_result_begin")xdev_tp_result_begin(work,runtime);
  else if(name=="xdev_tp_result_payload")xdev_tp_result_payload(work);
  else if(name=="xdev_tp_result_commit")xdev_tp_result_commit(work,runtime);
  else if(name=="xdev_tp_terminal_begin")xdev_tp_terminal_begin(work,runtime);
#else
  if(name=="xdev_tp_pack")xdev_tp_pack(work,runtime,shape,input,output,mode);
  else if(name=="xdev_tp_result")xdev_tp_result(work,runtime);
#endif
  else if(name=="xdev_tp_release")xdev_tp_release(work,runtime);
  else return CUDA_ERROR_UNKNOWN;
  }
  return CUresult(CUDA_SUCCESS);
 };
 if(boundary::recording){boundary::graph_nodes.push_back(invoke);return CUDA_SUCCESS;}
 return invoke();
}
CUresult cuStreamGetCaptureInfo(CUstream,CUstreamCaptureStatus *s,cuuint64_t *,CUgraph *g,const CUgraphNode **,size_t *,const void **){*s=boundary::capturing?1:0;if(g)*g=reinterpret_cast<void *>(1);return CUDA_SUCCESS;}
CUresult cuUserObjectCreate(CUuserObject *o,void *data,void (*release)(void *),unsigned,unsigned){*o=data;boundary::graph_releases.push_back([=](){release(data);});return CUDA_SUCCESS;}
CUresult cuGraphRetainUserObject(CUgraph,CUuserObject,unsigned,unsigned){return CUDA_SUCCESS;}
CUresult cuUserObjectRelease(CUuserObject,unsigned){return CUDA_SUCCESS;}
extern "C" int xdev_ext_peer_endpoint_next(xdev_ext_peer_endpoint *ep,int,xdev_ext_peer_message *m){
 boundary::next_calls++;
 if(boundary::ready_fault==3)return -ETIMEDOUT;
 boundary::ready++;*m={};m->role=ep->direction?XDEV_EXT_PEER_RX_CONSUMER:boundary::tx_next++?XDEV_EXT_PEER_TX_TERMINAL:XDEV_EXT_PEER_PRODUCER;
 if(boundary::ready_fault==1)m->role=XDEV_EXT_PEER_TX_TERMINAL;
 m->batch.key=boundary::ready_fault==2?24:23;m->batch.ticket=31;m->batch.nr_frames=1;m->batch.f[0].data_len=128;m->batch.f[0].capacity=4096;return 0;
}
extern "C" int xdev_ext_peer_endpoint_complete(xdev_ext_peer_endpoint *,const xdev_ext_peer_message *,int){boundary::completes++;return 0;}
extern "C" int xdev_ext_peer_endpoint_close(xdev_ext_peer_endpoint *){boundary::closed++;return 0;}
#include TP_PEER_SPAN_SOURCE
extern "C" int xdev_ext_cuda_host_receive_visible(CUcontext){return 0;}
extern "C" int xdev_ext_cuda_user_wait(xdev_ext_cuda_user *u,CUstream s,xdev_ext_cuda_message *m){
 if(u->stream!=reinterpret_cast<uintptr_t>(s))return -EXDEV;
 if(++boundary::enqueue_calls==boundary::enqueue_fail_at)return -EIO;
 if(boundary::recording){
  boundary::enqueued++;
  boundary::wait_order.push_back(u->role);
  boundary::graph_nodes.push_back([=](){
   bool ready=u->role==1?boundary::producer_ready:u->role==2?boundary::receiver_ready:boundary::terminal_ready;
   if(!ready)return CUresult(CUDA_ERROR_NOT_READY);
   unsigned ordinal=boundary::role_counts[u->role]++;
   *m={};m->key=boundary::replay_key+ordinal;m->ticket=m->key+100;m->nr_frames=1;
   m->device_address[0]=(u->role==2?boundary::rx:boundary::tx)+(ordinal%boundary::batch_width)*4096;
   m->f[0].data_len=128;m->f[0].capacity=4096;
   if(boundary::batch_width>1 && u->role==2){
    xdev_tp_native::Shape peer{};peer.communicator_id=7;peer.epoch=9;peer.sequence=m->key;peer.rows=1;peer.width=4;
    peer.operation=1;peer.dtype=3;peer.rank=1;peer.world_size=2;
    if(xdev_tp_native::shape_validate(&peer,4096,4096))return CUresult(CUDA_ERROR_UNKNOWN);
    xdev_tp_native::encode_header(peer,reinterpret_cast<unsigned char *>(m->device_address[0]));
    std::memset(reinterpret_cast<void *>(m->device_address[0]+64),0,16);
   }
   (u->role==1?boundary::producer_keys:u->role==2?boundary::receiver_keys:boundary::terminal_keys).push_back(m->key);
   boundary::ready++;return CUresult(CUDA_SUCCESS);
  });return 0;
 }
 boundary::enqueued++;boundary::ready++;return 0;
}
extern "C" int xdev_ext_cuda_user_done(xdev_ext_cuda_user *u,CUstream,xdev_ext_cuda_message *m){
 boundary::enqueued++;
 if(boundary::recording)boundary::graph_nodes.push_back([=](){
  if(!m->status){if(u->role==1)boundary::producer_done0++;else if(u->role==2)boundary::receiver_done0++;else boundary::terminal_done0++;}
  return CUresult(CUDA_SUCCESS);
 });return 0;
}
extern "C" int xdev_ext_cuda_receive_visible(xdev_ext_cuda_user *,CUstream){boundary::enqueued++;if(boundary::recording)boundary::graph_nodes.push_back([](){return CUresult(CUDA_SUCCESS);});return 0;}
static void script_observations(xdev_tp_comm *comm,xdev_tp_work *work,const char *script){
 using namespace boundary;
 std::vector<int> queries;std::vector<std::string> snapshots;
 int wait_result=0,destroy_work_result=0,destroy_comm_result=0,second_submit_result=0;
 CUdeviceptr arena=comm->arena;
 std::istringstream steps(script);std::string step;
 while(std::getline(steps,step,',')){
  if(step.find("accept:")==0)continue;
  if(step=="query")queries.push_back(xdev_tp_work_query(work));
  else if(step.find("wait:")==0)wait_result=xdev_tp_work_wait(work,1);
  else if(step=="destroy_work")destroy_work_result=xdev_tp_work_destroy(work);
  else if(step.find("destroy_comm:")==0)destroy_comm_result=xdev_tp_destroy(comm,1);
  else if(step.find("submit:")==0){xdev_tp_work *other=nullptr;second_submit_result=xdev_tp_allreduce_sum(comm,input,output,4,XDEV_TP_F32,reinterpret_cast<void *>(1),24,&other);}
  else if(step.find("producer_event_failure:")==0){graph_started=true;graph_error=CUDA_ERROR_UNKNOWN;graph_complete=true;}
  else if(step.find("producer_event_success:")==0){producer_ready=true;progress_graph();}
  else if(step.find("rx_ready:")==0){receiver_ready=true;progress_graph();}
  else if(step.find("result_event_success:")==0){result_allowed=true;progress_graph();}
  else if(step.find("tx_terminal_ready:")==0){terminal_ready=true;progress_graph();}
  if(step.find("result_event_success:")==0||step.find("tx_terminal_ready:")==0){
   int state=xdev_tp_work_query(work);std::ostringstream s;
   s<<"{\"after\":\""<<step<<"\",\"rx_done0_count\":"<<receiver_done0<<",\"tx_terminal_done0_count\":"<<terminal_done0
    <<",\"released\":"<<(state==0?"true":"false")<<",\"tx_storage_freed\":"<<(allocations.count(arena)?"false":"true")
    <<",\"rx_storage_freed\":"<<(allocations.count(arena)?"false":"true")<<"}";snapshots.push_back(s.str());
  }
 }
 std::cout<<"{\"query_results\":[";for(size_t i=0;i<queries.size();i++){if(i)std::cout<<',';std::cout<<queries[i];}
 std::cout<<"],\"snapshots\":[";for(size_t i=0;i<snapshots.size();i++){if(i)std::cout<<',';std::cout<<snapshots[i];}
 bool alive=allocations.count(arena);
 std::cout<<"],\"wait_result\":"<<wait_result<<",\"wait_timeout\":"<<(wait_result==-ETIMEDOUT?"true":"false")
  <<",\"destroy_work_negative\":"<<(destroy_work_result<0?"true":"false")<<",\"destroy_comm_negative\":"<<(destroy_comm_result<0?"true":"false")
  <<",\"second_submit_result\":"<<second_submit_result<<",\"retained\":"<<(alive?"true":"false")
  <<",\"tx_storage_freed\":"<<(alive?"false":"true")<<",\"rx_storage_freed\":"<<(alive?"false":"true")<<",\"storage_freed\":"<<(alive?"false":"true")
  <<",\"borrowed_endpoints_closed\":"<<closed<<",\"tx_done0_count\":"<<producer_done0<<",\"rx_done0_count\":"<<receiver_done0
  <<",\"accepted_count\":"<<(work&&work->accepted?1:0)<<"}\n";
}
static void bytes_from_hex(const std::string &text,unsigned char *out,size_t capacity){
 assert(text.size()%2==0&&text.size()/2<=capacity);
 for(size_t i=0;i<text.size()/2;i++)out[i]=std::stoul(text.substr(i*2,2),nullptr,16);
}
static std::string bits_json(const unsigned char *p,size_t bytes,unsigned item){
 static const char digits[]="0123456789abcdef";std::ostringstream out;out<<'[';
 for(size_t i=0;i<bytes;i+=item){if(i)out<<',';out<<'"';for(unsigned j=item;j>0;j--){unsigned b=p[i+j-1];out<<digits[b>>4]<<digits[b&15];}out<<'"';}out<<']';return out.str();
}
static void stats_json(const xdev_tp_stats &s){
 std::cout<<"{\"completed\":"<<s.completed<<",\"tx_done\":"<<s.tx_done<<",\"rx_delivered\":"<<s.rx_delivered
  <<",\"last_use_released\":"<<s.last_use_released<<",\"payload_tx_bytes\":"<<s.payload_tx_bytes<<",\"payload_rx_bytes\":"<<s.payload_rx_bytes
  <<",\"wire_tx_bytes\":"<<s.wire_tx_bytes<<",\"wire_rx_bytes\":"<<s.wire_rx_bytes<<"}";
}
static void replay_observations(xdev_tp_comm *comm,xdev_tp_work *work,const char *replays,
 std::vector<unsigned char> &in,std::vector<unsigned char> &out,std::vector<unsigned char> &tx_bytes,std::vector<unsigned char> &rx_bytes){
 using namespace boundary;
 int before=xdev_tp_work_query(work);std::vector<uint64_t> keys,wire_sequences;std::vector<std::string> outputs;
 std::istringstream all(replays);std::string replay;int last_query=before;
 while(std::getline(all,replay,';')){
  auto first=replay.find(':'),second=replay.find(':',first+1);assert(first!=std::string::npos&&second!=std::string::npos);
  replay_key=std::stoull(replay.substr(0,first));keys.push_back(replay_key);
  bytes_from_hex(replay.substr(first+1,second-first-1),in.data(),in.size());
  xdev_tp_native::Shape remote=work->image.shape;remote.sequence=replay_key;remote.rank^=1U;
  xdev_tp_native::encode_header(remote,rx_bytes.data());
  bytes_from_hex(replay.substr(second+1),rx_bytes.data()+64,rx_bytes.size()-64);
  graph_cursor=0;graph_complete=false;graph_error=CUDA_SUCCESS;
  std::memset(role_counts,0,sizeof(role_counts));
  producer_ready=receiver_ready=terminal_ready=result_allowed=true;progress_graph();
  last_query=xdev_tp_work_query(work);
  wire_sequences.push_back(xdev_tp_native::get_le(tx_bytes.data()+24,8));
  outputs.push_back(bits_json(out.data(),work->image.shape.output_bytes,xdev_tp_native::item_size(work->image.shape.dtype)));
 }
 xdev_tp_stats stats{};stats.size=sizeof(stats);xdev_tp_get_stats(comm,&stats);
 std::vector<xdev_tp_trace_record> records(64);size_t written=0;
 int trace_result=xdev_tp_trace_read(comm,records.data(),records.size(),&written);
 CUdeviceptr arena=comm->arena;int live_destroy=xdev_tp_work_destroy(work);
 bool kept=live_destroy<0 && allocations.count(arena);
 for(auto &release:graph_releases)release();graph_releases.clear();
 int destroy=xdev_tp_work_destroy(work);
 xdev_tp_stats after{};after.size=sizeof(after);xdev_tp_get_stats(comm,&after);
 std::cout<<"{\"query_before_replay\":"<<before<<",\"last_query\":"<<last_query;
 for(const char *field:{"producer_keys","rx_keys","terminal_keys","wire_sequences"}){
  std::string which=field;
  std::cout<<",\""<<field<<"\":[";const auto &values=which=="wire_sequences"?wire_sequences:which=="producer_keys"?producer_keys:which=="rx_keys"?receiver_keys:terminal_keys;
  for(size_t i=0;i<values.size();i++){if(i)std::cout<<',';std::cout<<values[i];}std::cout<<']';
 }
 std::cout<<",\"output_bits_per_replay\":[";for(size_t i=0;i<outputs.size();i++){if(i)std::cout<<',';std::cout<<outputs[i];}
 std::cout<<"],\"gpu_invocations\":"<<stats.gpu_invocations<<",\"completed\":"<<stats.completed<<",\"api_attempts\":"<<stats.api_attempts
  <<",\"storage_alive_until_graph_destroy\":"<<(kept?"true":"false")<<",\"destroy_after_graph\":"<<destroy
  <<",\"trace_result\":"<<trace_result<<",\"trace_dropped\":"<<stats.trace_dropped<<",\"trace_records\":[";
 for(size_t i=0;i<written;i++){
  if(i)std::cout<<',';auto &r=records[i];
  std::cout<<"{\"sequence\":"<<r.sequence<<",\"kind\":"<<r.kind<<",\"clock\":"<<r.clock<<",\"rank\":"<<r.rank
   <<",\"timestamp\":"<<r.timestamp<<",\"logical_inflight\":"<<r.logical_inflight<<",\"error\":"<<r.error<<"}";
 }
 std::cout<<"],\"stats_before_destroy\":";
 stats_json(stats);std::cout<<",\"stats_after_destroy\":";stats_json(after);std::cout<<"}\n";
}
static void batch_observations(xdev_tp_comm *comm,const char *scenario){
 using namespace boundary;
#ifdef TP_HAS_BATCH
 constexpr unsigned count=2;
 std::vector<unsigned char> inputs[count],outputs[count];BoundaryBatchRequest requests[count]{};
 for(unsigned i=0;i<count;i++){
  inputs[i].resize(16,0);outputs[i].resize(16,0xcd);
  requests[i]={reinterpret_cast<CUdeviceptr>(inputs[i].data()),reinterpret_cast<CUdeviceptr>(outputs[i].data()),1,4,1,3,0,0};
  tensor_regions[requests[i].input]=16;tensor_regions[requests[i].output]=16;
 }
 if(std::string(scenario)=="invalid_later")requests[1].dtype=99;
 if(std::string(scenario)=="partial_enqueue")enqueue_fail_at=2;
 xdev_tp_work *work[count]{};batch_width=count;
 int rc=xdev_tp_submit_batch(comm,requests,count,reinterpret_cast<void *>(1),23,work);
 recording=false;
 unsigned handles=0;for(auto *w:work)handles+=w!=nullptr;
 unsigned nodes_before_retry=enqueued;
 if(!rc){
  graph_cursor=0;graph_complete=false;producer_ready=receiver_ready=terminal_ready=result_allowed=true;progress_graph();
  for(auto *w:work)if(w)(void)xdev_tp_work_query(w);
 }
 xdev_tp_stats stats{};stats.size=sizeof(stats);xdev_tp_get_stats(comm,&stats);
 int second=0;if(std::string(scenario)=="partial_enqueue"){
  recording=true;xdev_tp_work *retry[count]{};second=xdev_tp_submit_batch(comm,requests,count,reinterpret_cast<void *>(1),23,retry);recording=false;
 }
 std::cout<<"{\"status\":"<<rc<<",\"handles\":"<<handles<<",\"nodes_before_retry\":"<<nodes_before_retry<<",\"nodes_after_retry\":"<<enqueued
  <<",\"ready_consumed_count\":"<<ready<<",\"completed\":"<<stats.completed<<",\"logical_high_water\":"<<stats.logical_inflight_high_water
  <<",\"logical_inflight\":"<<stats.logical_inflight<<",\"error\":"<<stats.error<<",\"second_submit_result\":"<<second<<",\"wait_order\":[";
 for(size_t i=0;i<wait_order.size();i++){if(i)std::cout<<',';std::cout<<wait_order[i];}std::cout<<"]}\n";
#else
 (void)comm;(void)scenario;std::cout<<"{\"missing_batch_feature\":true}\n";
#endif
}
static void storage_observations(xdev_tp_comm *comm,xdev_tp_work *work,const char *script){
 using namespace boundary;
 std::vector<std::string> snapshots;std::istringstream steps(script);std::string step;
 bool graph_destroy_pending=false;
 while(std::getline(steps,step,',')){
  if(step=="replay_complete"){
   graph_cursor=0;producer_ready=receiver_ready=terminal_ready=result_allowed=true;progress_graph();
   if(xdev_tp_work_query(work))throw std::runtime_error("storage precondition replay did not complete");
  }else if(step=="drop_python_work"||step=="graph_destroy"){
   // Model CUDA user-object destructor deferral until the separately injected
   // final-use completion. The production graph callback is not invoked early.
   if(step=="graph_destroy")graph_destroy_pending=true;
   int rc=xdev_tp_work_destroy(work);std::ostringstream snapshot;
   snapshot<<"{\"after\":\""<<step<<"\",\"storage_retained\":"<<(rc<0&&allocations.count(comm->arena)?"true":"false")<<"}";
   snapshots.push_back(snapshot.str());
  }else if(step=="query"){(void)xdev_tp_work_query(work);}
  else if(step=="final_last_use_complete"){
   if(!graph_destroy_pending)throw std::runtime_error("final graph callback before graph destruction");
   for(auto &release:graph_releases)release();graph_releases.clear();
   int rc=xdev_tp_work_destroy(work);std::ostringstream snapshot;
   snapshot<<"{\"after\":\""<<step<<"\",\"storage_releasable\":"<<(rc==0?"true":"false")<<"}";snapshots.push_back(snapshot.str());
  }
 }
 std::cout<<"{\"scope\":\"native work graph refs only; no Python Tensor execution\",\"snapshots\":[";
 for(size_t i=0;i<snapshots.size();i++){if(i)std::cout<<',';std::cout<<snapshots[i];}std::cout<<"]}\n";
}
static uint64_t num(char **a,unsigned n){return std::stoull(a[n],nullptr,0);}
int main(int argc,char **argv){
 if(argc<33||argc>36)return 64;using namespace boundary;
 bool replaying=std::string(argv[1])=="replay",storage=std::string(argv[1])=="storage",batching=std::string(argv[1])=="batch";
 bool scripting=std::string(argv[1])=="script"||replaying||storage||batching;
 bool creating=std::string(argv[1])=="create",completing=std::string(argv[1])=="complete"||scripting;
 xdev_ext_peer_endpoint tx_endpoint{0},rx_endpoint{1};
 xdev_ext_cuda_user producer{1,1},terminal{1,3},consumer{1,2};
 xdev_tp_config cfg{};cfg.size=sizeof(cfg);cfg.version=1;
 cfg.communicator_id=num(argv,2);cfg.epoch=num(argv,3);cfg.first_sequence=num(argv,4);
 cfg.rank=num(argv,5);cfg.world_size=num(argv,6);tx=num(argv,7);rx=num(argv,8);tx_bytes=num(argv,9);rx_bytes=num(argv,10);
 cfg.flags=num(argv,11);cfg.tx_va=tx;cfg.rx_va=rx;cfg.tx_bytes=tx_bytes;cfg.rx_bytes=rx_bytes;
 std::vector<unsigned char> tx_storage,rx_storage,input_storage,output_storage;
 if(completing){
  tx_storage.resize(tx_bytes,0xaa);rx_storage.resize(rx_bytes,0xbb);
  input_storage.resize(std::max<uint64_t>(num(argv,19),1),0);output_storage.resize(std::max<uint64_t>(num(argv,20)*2,1),0xcd);
  tx=cfg.tx_va=reinterpret_cast<uintptr_t>(tx_storage.data());rx=cfg.rx_va=reinterpret_cast<uintptr_t>(rx_storage.data());
  execute_kernels=true;
 }
 context=num(argv,21);stream_context=num(argv,22);memory_context=num(argv,23);
 cfg.context=reinterpret_cast<void *>(context);cfg.tx_endpoint=&tx_endpoint;cfg.rx_endpoint=&rx_endpoint;
 cfg.mode=num(argv,31);cfg.d2_tx_producer=&producer;cfg.d2_tx_terminal=&terminal;cfg.d2_rx_consumer=&consumer;
 cfg.frame_size=4096;cfg.logical_depth=num(argv,28);cfg.max_payload_bytes=tx_bytes>=64?tx_bytes-64:0;
 cfg.timeout_ns=100000;cfg.ptx_path="host-boundary-never-PTX";
 if(std::string(argv[1])=="trace_capability")cfg.trace_capacity=8;
 if(argc==36)cfg.trace_capacity=num(argv,35);
 xdev_tp_comm *comm=nullptr;xdev_tp_work *work=nullptr;
 int rc=xdev_tp_create(&cfg,&comm);
 input=num(argv,17);output=num(argv,18);input_bytes=num(argv,19);output_bytes=num(argv,20);
 if(completing){
  input=reinterpret_cast<uintptr_t>(input_storage.data());output=output?reinterpret_cast<uintptr_t>(output_storage.data()):0;
  xdev_tp_native::Shape remote{};remote.communicator_id=cfg.communicator_id;remote.epoch=cfg.epoch;remote.sequence=num(argv,29);
  remote.rows=std::string(argv[12])=="sum"?1:num(argv,15);remote.width=std::string(argv[12])=="sum"?num(argv,14):num(argv,16);
  remote.operation=std::string(argv[12])=="sum"?1:2;remote.dtype=num(argv,13);remote.rank=cfg.rank^1U;remote.world_size=2;remote.dst_rank=num(argv,30);
  if(xdev_tp_native::shape_validate(&remote,UINT64_MAX,UINT64_MAX))return 65;
  xdev_tp_native::encode_header(remote,rx_storage.data());
  std::fill(rx_storage.begin()+64,rx_storage.end(),0);
 }
 managed=num(argv,24);host_memory=num(argv,25);capturing=num(argv,27);
 ready_fault=argc>=34?num(argv,33):0;
 graph_mode=recording=scripting;
 if(std::string(argv[1])=="batch_capability"){
  bool present=!!xdev_tp_submit_batch;
  std::cout<<"{\"batch_entry_available\":"<<(present?"true":"false")<<",\"ready_consumed_count\":"<<ready<<"}\n";
  if(comm)xdev_tp_destroy(comm,1);return 0;
 }
 if(std::string(argv[1])=="trace_capability"){
  xdev_tp_trace_record record{};size_t written=99;int status=rc?rc:xdev_tp_trace_read(comm,&record,1,&written);
  std::cout<<"{\"status\":"<<status<<",\"written\":"<<written<<",\"ready_consumed_count\":"<<ready<<"}\n";return 0;
 }
 if(batching){if(rc)return 67;batch_observations(comm,argv[34]);return 0;}
 if(!rc && !creating){
  if(std::string(argv[12])=="sum")rc=xdev_tp_allreduce_sum(comm,input,output,num(argv,14),xdev_tp_dtype(num(argv,13)),reinterpret_cast<void *>(num(argv,32)),num(argv,29),&work);
  else rc=xdev_tp_logits_gather(comm,input,output,num(argv,15),num(argv,16),xdev_tp_dtype(num(argv,13)),int(num(argv,30)),0,reinterpret_cast<void *>(num(argv,32)),num(argv,29),&work);
 }
 recording=false;
 if(scripting){if(rc||!work)return 66;
  if(replaying)replay_observations(comm,work,argv[34],input_storage,output_storage,tx_storage,rx_storage);
  else if(storage)storage_observations(comm,work,argv[34]);
  else script_observations(comm,work,argv[34]);return 0;}
 xdev_tp_stats stats{};stats.size=sizeof(stats);if(comm)xdev_tp_get_stats(comm,&stats);
 unsigned first_ready=ready,first_calls=next_calls;int second_result=0;
 if(comm&&ready_fault){xdev_tp_work *second=nullptr;second_result=xdev_tp_allreduce_sum(comm,input,output,num(argv,14),xdev_tp_dtype(num(argv,13)),reinterpret_cast<void *>(num(argv,32)),num(argv,29),&second);}
 std::cout<<"{\"status\":"<<rc<<",\"submit_count\":"<<first_calls<<",\"ready_consumed_count\":"<<first_ready
  <<",\"accepted_count\":"<<(work&&work->accepted?1:0)<<",\"output_write_count\":"<<writes
  <<",\"endpoint_mutation_count\":"<<ready+completes<<",\"borrowed_endpoints_closed\":"<<closed<<",\"enqueued_nodes\":"<<enqueued
  <<",\"work_handle_nonnull\":"<<(work?"true":"false")<<",\"communicator_poisoned\":"<<(stats.error?"true":"false")
  <<",\"retained\":"<<(stats.retained?"true":"false")<<",\"error\":"<<stats.error
  <<",\"second_submit_result\":"<<second_result<<",\"ready_after_second\":"<<ready<<",\"next_calls_after_second\":"<<next_calls;
 if(completing){
  std::cout<<",\"submitted\":"<<stats.submitted<<",\"completed\":"<<stats.completed<<",\"first_sequence\":"<<stats.first_sequence<<",\"last_sequence\":"<<stats.last_sequence
   <<",\"next_sequence\":"<<(comm?comm->runtime.next_sequence:0)<<",\"wire_header_bytes\":64,\"payload_bytes\":"<<(work?work->image.shape.payload_bytes:0)
   <<",\"wire_rows\":"<<xdev_tp_native::get_le(tx_storage.data()+32,8)<<",\"wire_local_width\":"<<xdev_tp_native::get_le(tx_storage.data()+40,8);
 }
 std::cout<<"}\n";
 if(comm&&!work)xdev_tp_destroy(comm,1);
 return 0;
}
