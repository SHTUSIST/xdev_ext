// SPDX-License-Identifier: GPL-2.0
#include "xdev_tp_device.h"
#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <deque>
#include <mutex>
#include <new>
#include <thread>
#include <vector>
using namespace xdev_tp_native;
namespace {
constexpr unsigned template_capacity=256;
struct GraphLifetime { std::atomic<bool> released{false}; };
void CUDA_CB graph_release(void *p) { static_cast<GraphLifetime *>(p)->released.store(true,std::memory_order_release); }
uint64_t now_ns() { return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
int drv(CUresult rc) { return rc==CUDA_SUCCESS?0:rc==CUDA_ERROR_NOT_SUPPORTED || rc==CUDA_ERROR_NO_DEVICE || rc==CUDA_ERROR_STUB_LIBRARY?-EOPNOTSUPP:-EIO; }
}
struct xdev_tp_comm {
 xdev_tp_config cfg{};
 Runtime runtime{};
 CUdeviceptr device_runtime=0, arena=0;
 CUmodule module=nullptr;
 CUfunction pack=nullptr,result=nullptr,release=nullptr;
 CUstream stream=nullptr;
 bool bound=false;
 uint64_t stream_id=0;
 xdev_tp_stats stats{};
 std::mutex mutex;
 std::vector<xdev_tp_work *> works;
 bool occupied[template_capacity]{};
 std::deque<xdev_tp_trace_record> trace;
};
struct xdev_tp_work {
 xdev_tp_comm *comm=nullptr;
 unsigned slot=0;
 DeviceWork image{};
 CUdeviceptr device=0;
 CUevent event=nullptr;
 CUstream stream=nullptr;
 GraphLifetime *graph=nullptr;
 bool accepted=false;
 xdev_ext_peer_message producer{},receiver{},terminal{};
};
static int context_check(CUcontext expected) {
 CUcontext current=nullptr;
 int rc=drv(cuCtxGetCurrent(&current));
 return rc?rc:current!=expected?-EINVAL:0;
}
static int stream_check(xdev_tp_comm *c, CUstream stream, CUstreamCaptureStatus *capture) {
 int rc=context_check(c->cfg.context);CUcontext owner=nullptr;
 if(!rc)rc=drv(cuStreamGetCtx(stream,&owner));
 if(!rc && owner!=c->cfg.context)rc=-EINVAL;
 if(!rc)rc=drv(cuStreamIsCapturing(stream,capture));
 unsigned long long id=0;
 if(!rc)rc=drv(cuStreamGetId(stream,&id));
 if(!rc && c->bound && id!=c->stream_id)rc=-EXDEV;
 return rc;
}
static int memory_facts(CUdeviceptr pointer, uint64_t bytes, CUcontext context, MemoryFacts *facts) {
 *facts={pointer,bytes,0,0,uint64_t(reinterpret_cast<uintptr_t>(context)),0,0};
 if(!bytes)return 0;
 CUcontext owner=nullptr;CUmemorytype type;unsigned managed;CUdeviceptr base;size_t allocation;
 int rc=drv(cuPointerGetAttribute(&owner,CU_POINTER_ATTRIBUTE_CONTEXT,pointer));
 if(!rc)rc=drv(cuPointerGetAttribute(&type,CU_POINTER_ATTRIBUTE_MEMORY_TYPE,pointer));
 if(!rc)rc=drv(cuPointerGetAttribute(&managed,CU_POINTER_ATTRIBUTE_IS_MANAGED,pointer));
 if(!rc)rc=drv(cuMemGetAddressRange(&base,&allocation,pointer));
 if(rc)return rc;
 *facts={pointer,bytes,base,allocation,uint64_t(reinterpret_cast<uintptr_t>(owner)),uint32_t(type==CU_MEMORYTYPE_DEVICE),managed};
 return memory_validate(*facts,bytes,uint64_t(reinterpret_cast<uintptr_t>(context)));
}
static void trace(xdev_tp_comm *c,xdev_tp_work *w,unsigned kind,int error=0) {
 if(!c->cfg.trace_capacity)return;
 if(c->trace.size()==c->cfg.trace_capacity){++c->stats.trace_dropped;return;}
 c->trace.push_back({w->image.core.sequence,now_ns(),w->image.shape.payload_bytes,w->image.shape.wire_bytes,
  c->runtime.inflight,c->cfg.rank,kind,XDEV_TP_CLOCK_HOST_MONOTONIC,w->image.shape.operation,error,0});
}
static int retain(xdev_tp_work *w,int error) {
 auto *c=w->comm;
 int rc=fail(&c->runtime,&w->image.core,error);
 c->stats.error=rc;c->stats.retained=1;
 trace(c,w,XDEV_TP_TRACE_FAILED_RETAINED,rc);
 return rc;
}
static int event_wait(xdev_tp_work *w,uint64_t timeout_ns) {
 uint64_t start=now_ns();
 for(;;) {
  CUresult rc=cuEventQuery(w->event);
  if(rc==CUDA_SUCCESS)return 0;
  if(rc!=CUDA_ERROR_NOT_READY)return drv(rc);
  if(timeout_ns && now_ns()-start>=timeout_ns)return -ETIMEDOUT;
  std::this_thread::yield();
 }
}
static int kernel(CUfunction f,xdev_tp_work *w,bool pack=false) {
 CUdeviceptr runtime=w->comm->device_runtime;
 void *args[]={&w->device,&runtime,&w->image.shape,&w->image.input,&w->image.output,&w->image.mode};
 (void)pack;
 return drv(cuLaunchKernel(f,1,1,1,1,1,1,0,w->stream,args,nullptr));
}
static int upload(xdev_tp_work *w) {
 int rc=drv(cuMemcpyHtoDAsync(w->device,&w->image,sizeof(w->image),w->stream));
 if(!rc)rc=drv(cuMemcpyHtoDAsync(w->comm->device_runtime,&w->comm->runtime,sizeof(Runtime),w->stream));
 return rc;
}
static int complete_event(xdev_tp_work *w) {
 int rc=drv(cuEventRecord(w->event,w->stream));
 if(!rc)rc=event_wait(w,w->comm->cfg.timeout_ns);
 return rc;
}
static int spans(xdev_tp_work *w,xdev_ext_peer_message *m,bool tx) {
 auto *c=w->comm;unsigned count=m->batch.nr_frames;
 if(!count || count>XDEV_EXT_MECH_MAX_FRAMES)return -EPROTO;
 auto *target=tx?w->image.tx:w->image.rx;
 for(unsigned i=0;i<count;++i) {
  xdev_ext_peer_span span{};
  int rc=xdev_ext_user_batch_peer_span(&m->batch,i,tx?c->cfg.tx_va:c->cfg.rx_va,
   tx?c->cfg.tx_bytes:c->cfg.rx_bytes,c->cfg.frame_size,&span);
  if(rc)return rc;
  target[i]={span.device_address,span.data_len};
  if(tx)m->batch.f[i].out_len=span.data_len;
 }
 uint64_t bytes;int rc=span_capacity(target,count,&bytes);
 if(!rc && bytes<w->image.shape.wire_bytes)rc=-EMSGSIZE;
 if(tx)w->image.tx_count=count;else w->image.rx_count=count;
 return rc;
}
static int next(xdev_tp_work *w,bool tx,xdev_ext_peer_role role,xdev_ext_peer_message *out) {
 auto *c=w->comm;
 ++c->stats.host_control_calls;
 uint64_t ns=c->cfg.timeout_ns;
 int ms=ns?int(std::min<uint64_t>((ns+999999)/1000000,INT32_MAX)):-1;
 int rc=xdev_ext_peer_endpoint_next(tx?c->cfg.tx_endpoint:c->cfg.rx_endpoint,ms,out);
 if(!rc && (out->role!=role || out->batch.key!=w->image.shape.sequence))rc=-EPROTO;
 return rc;
}
static int done(xdev_tp_work *w,bool tx,xdev_ext_peer_message *m,int status) {
 ++w->comm->stats.host_control_calls;
 return xdev_ext_peer_endpoint_complete(tx?w->comm->cfg.tx_endpoint:w->comm->cfg.rx_endpoint,m,status);
}
static int eager(xdev_tp_work *w) {
 auto *c=w->comm;int rc=next(w,true,XDEV_EXT_PEER_PRODUCER,&w->producer);
 if(rc)return rc;
 w->accepted=true;
 rc=begin_invocation(&c->runtime,&w->image.core,w->producer.batch.key);
 if(rc)return retain(w,rc);
 trace(c,w,XDEV_TP_TRACE_SLOT_ACQUIRED);
 if(!(rc=spans(w,&w->producer,true)))rc=upload(w);
 if(!rc)rc=kernel(c->pack,w,true);
 if(!rc)rc=complete_event(w);
 if(!rc)rc=drv(cuMemcpyDtoH(&w->image,w->device,sizeof(w->image)));
 if(!rc && w->image.core.error)rc=w->image.core.error;
 if(rc) { done(w,true,&w->producer,rc);return retain(w,rc); }
 if((rc=done(w,true,&w->producer,0)))return retain(w,rc);
 advance(&c->runtime,&w->image.core,2,0);trace(c,w,XDEV_TP_TRACE_TX_PRODUCED);
 if((rc=next(w,false,XDEV_EXT_PEER_RX_CONSUMER,&w->receiver)))return retain(w,rc);
 if((rc=receive(&c->runtime,&w->image.core,w->receiver.batch.key,w->receiver.batch.ticket)))return retain(w,rc);
 trace(c,w,XDEV_TP_TRACE_RX_DELIVERED);++c->stats.rx_delivered;
 if(!(rc=spans(w,&w->receiver,false)))rc=xdev_ext_cuda_host_receive_visible(c->cfg.context);
 if(!rc)rc=upload(w);
 if(!rc)rc=kernel(c->result,w);
 if(!rc)rc=complete_event(w);
 if(!rc)rc=drv(cuMemcpyDtoH(&w->image,w->device,sizeof(w->image)));
 if(!rc)rc=drv(cuMemcpyDtoH(&c->runtime,c->device_runtime,sizeof(Runtime)));
 if(!rc && w->image.core.error)rc=w->image.core.error;
 if(rc){done(w,false,&w->receiver,rc);return retain(w,rc);}
 trace(c,w,XDEV_TP_TRACE_RESULT_READY);
 if((rc=done(w,false,&w->receiver,0)))return retain(w,rc);
 ++c->stats.last_use_released;trace(c,w,XDEV_TP_TRACE_LAST_USE_RELEASED);
 if((rc=next(w,true,XDEV_EXT_PEER_TX_TERMINAL,&w->terminal)))return retain(w,rc);
 if((rc=done(w,true,&w->terminal,0)))return retain(w,rc);
 ++c->stats.tx_done;advance(&c->runtime,&w->image.core,5,0);
 w->image.invocations=1;w->image.completed=1;w->image.first_sequence=w->image.last_sequence=w->image.core.sequence;
 c->stats.payload_tx_bytes+=w->image.shape.payload_bytes;c->stats.payload_rx_bytes+=w->image.shape.payload_bytes;
 uint64_t tx=0,rx=0;span_capacity(w->image.tx,w->image.tx_count,&tx);span_capacity(w->image.rx,w->image.rx_count,&rx);
 c->stats.wire_tx_bytes+=tx;c->stats.wire_rx_bytes+=rx;
 return 0;
}
static xdev_ext_cuda_message *device_message(xdev_tp_work *w,size_t offset) {
 return reinterpret_cast<xdev_ext_cuda_message *>(w->device+offset);
}
static int graph_lifetime(xdev_tp_work *w) {
 CUstreamCaptureStatus status;cuuint64_t id;CUgraph graph;
 int rc=drv(cuStreamGetCaptureInfo(w->stream,&status,&id,&graph,nullptr,nullptr,nullptr));
 if(rc)return rc;
 if(status!=CU_STREAM_CAPTURE_STATUS_ACTIVE)return 0;
 w->graph=new(std::nothrow) GraphLifetime;
 if(!w->graph)return -ENOMEM;
 CUuserObject object;
 rc=drv(cuUserObjectCreate(&object,w->graph,graph_release,1,CU_USER_OBJECT_NO_DESTRUCTOR_SYNC));
 if(rc){delete w->graph;w->graph=nullptr;return rc;}
 rc=drv(cuGraphRetainUserObject(graph,object,1,CU_GRAPH_USER_OBJECT_MOVE));
 if(rc){cuUserObjectRelease(object,1);return rc;}
 return 0;
}
static int gpu(xdev_tp_work *w,CUstreamCaptureStatus capture) {
 auto *c=w->comm;
 int rc=graph_lifetime(w);
 if(rc)return rc;
 // This enqueue is the first possible external ready-consumption operation.
 auto *p=device_message(w,offsetof(DeviceWork,producer));
 auto *r=device_message(w,offsetof(DeviceWork,receiver));
 auto *t=device_message(w,offsetof(DeviceWork,terminal));
 rc=xdev_ext_cuda_user_wait(c->cfg.d2_tx_producer,w->stream,p);
 if(rc)return rc;
 w->accepted=true;
 if(!(rc=kernel(c->pack,w,true)))rc=xdev_ext_cuda_user_done(c->cfg.d2_tx_producer,w->stream,p);
 if(!rc)rc=xdev_ext_cuda_user_wait(c->cfg.d2_rx_consumer,w->stream,r);
 if(!rc)rc=xdev_ext_cuda_receive_visible(c->cfg.d2_rx_consumer,w->stream);
 if(!rc)rc=kernel(c->result,w);
 if(!rc)rc=xdev_ext_cuda_user_done(c->cfg.d2_rx_consumer,w->stream,r);
 if(!rc)rc=xdev_ext_cuda_user_wait(c->cfg.d2_tx_terminal,w->stream,t);
 if(!rc)rc=xdev_ext_cuda_user_done(c->cfg.d2_tx_terminal,w->stream,t);
 if(!rc)rc=kernel(c->release,w);
 if(!rc)rc=drv(cuEventRecord(w->event,w->stream));
 if(rc)return retain(w,rc);
 (void)capture;
 return 0;
}
extern "C" int xdev_tp_create(const xdev_tp_config *cfg,xdev_tp_comm **out) {
 if(out)*out=nullptr;
 if(!out || !cfg || cfg->size!=sizeof(*cfg) || cfg->version!=1 || cfg->flags ||
 cfg->rank>1 || cfg->world_size!=2 || !cfg->context || !cfg->tx_endpoint || !cfg->rx_endpoint ||
 cfg->tx_endpoint==cfg->rx_endpoint || !cfg->first_sequence || !cfg->communicator_id || !cfg->epoch ||
 !cfg->logical_depth || cfg->logical_depth>XDEV_EXT_USER_RING_MAX || !cfg->frame_size ||
 !cfg->tx_bytes || !cfg->rx_bytes || cfg->max_payload_bytes>UINT32_MAX ||
 cfg->max_payload_bytes>UINT64_MAX-64 || cfg->max_payload_bytes+64>std::min(cfg->tx_bytes,cfg->rx_bytes) ||
 !cfg->ptx_path || !*cfg->ptx_path || (cfg->mode!=1 && cfg->mode!=2))return -EINVAL;
 if(cfg->mode==1 && cfg->logical_depth!=1)return -EOPNOTSUPP;
 if(cfg->mode==2 && (!cfg->d2_tx_producer || !cfg->d2_rx_consumer || !cfg->d2_tx_terminal))return -EINVAL;
 int rc=context_check(cfg->context);MemoryFacts tx{},rx{};
 if(!rc)rc=memory_facts(cfg->tx_va,cfg->tx_bytes,cfg->context,&tx);
 if(!rc)rc=memory_facts(cfg->rx_va,cfg->rx_bytes,cfg->context,&rx);
 if(!rc && cfg->tx_va<cfg->rx_va+cfg->rx_bytes && cfg->rx_va<cfg->tx_va+cfg->tx_bytes)rc=-EINVAL;
 if(rc)return rc;
 xdev_tp_comm *c=new(std::nothrow) xdev_tp_comm;
 if(!c)return -ENOMEM;
 c->cfg=*cfg;c->runtime.next_sequence=cfg->first_sequence;
 c->stats.size=sizeof(c->stats);c->stats.version=1;c->stats.rank=cfg->rank;
 rc=drv(cuModuleLoad(&c->module,cfg->ptx_path));
 if(!rc)rc=drv(cuModuleGetFunction(&c->pack,c->module,"xdev_tp_pack"));
 if(!rc)rc=drv(cuModuleGetFunction(&c->result,c->module,"xdev_tp_result"));
 if(!rc)rc=drv(cuModuleGetFunction(&c->release,c->module,"xdev_tp_release"));
 if(!rc)rc=drv(cuMemAlloc(&c->device_runtime,sizeof(Runtime)));
 if(!rc)rc=drv(cuMemAlloc(&c->arena,sizeof(DeviceWork)*template_capacity));
 if(!rc)rc=drv(cuMemcpyHtoD(c->device_runtime,&c->runtime,sizeof(Runtime)));
 if(!rc)rc=drv(cuMemsetD8(c->arena,0,sizeof(DeviceWork)*template_capacity));
 if(rc) {
  if(c->arena)cuMemFree(c->arena);if(c->device_runtime)cuMemFree(c->device_runtime);if(c->module)cuModuleUnload(c->module);
  delete c;return rc;
 }
 *out=c;return 0;
}
static int submit(xdev_tp_comm *c,CUdeviceptr input,CUdeviceptr output,Shape shape,
 CUstream stream,uint64_t sequence,xdev_tp_work **out) {
 if(out)*out=nullptr;if(!c || !out)return -EINVAL;
 std::lock_guard<std::mutex> lock(c->mutex);++c->stats.api_attempts;
 if(c->runtime.error)return c->runtime.error;
 CUstreamCaptureStatus capture=CU_STREAM_CAPTURE_STATUS_NONE;
 int rc=stream_check(c,stream,&capture);
 if(!rc && c->cfg.mode==1 && capture!=CU_STREAM_CAPTURE_STATUS_NONE)rc=-EOPNOTSUPP;
 shape.communicator_id=c->cfg.communicator_id;shape.epoch=c->cfg.epoch;shape.sequence=sequence;
 shape.rank=c->cfg.rank;shape.world_size=2;
 Qualification q{};q.context=uint64_t(reinterpret_cast<uintptr_t>(c->cfg.context));q.stream_context=q.context;
 q.sequence=sequence;q.next_sequence=c->runtime.next_sequence;q.max_payload=c->cfg.max_payload_bytes;
 q.slot_capacity=std::min(c->cfg.tx_bytes,c->cfg.rx_bytes);q.mode=c->cfg.mode;q.depth=c->cfg.logical_depth;
 q.capturing=capture!=CU_STREAM_CAPTURE_STATUS_NONE;
 if(!rc)rc=shape_validate(&shape,q.max_payload,q.slot_capacity);
 if(!rc)rc=memory_facts(input,shape.payload_bytes,c->cfg.context,&q.input);
 bool needs=shape.operation!=2 || shape.rank==shape.dst_rank;
 if(!rc)rc=memory_facts(output,needs || output?shape.output_bytes:0,c->cfg.context,&q.output);
 if(!rc)rc=qualify(&shape,q);
 unsigned slot=0;while(slot<template_capacity && c->occupied[slot])++slot;
 if(!rc && slot==template_capacity)rc=-ENOSPC;
 if(rc){++c->stats.preflight_rejected;return rc;}
 auto *w=new(std::nothrow) xdev_tp_work;
 if(!w)return -ENOMEM;
 w->comm=c;w->slot=slot;w->device=c->arena+slot*sizeof(DeviceWork);w->stream=stream;
 w->image.shape=shape;w->image.input=input;w->image.output=output;w->image.mode=c->cfg.mode;
 rc=drv(cuEventCreate(&w->event,CU_EVENT_DISABLE_TIMING));
 if(rc){delete w;return rc;}
 if(!c->bound){unsigned long long id;rc=drv(cuStreamGetId(stream,&id));if(!rc){c->bound=true;c->stream=stream;c->stream_id=id;}}
 if(rc){cuEventDestroy(w->event);delete w;return rc;}
 c->occupied[slot]=true;c->works.push_back(w);
 if(c->cfg.mode==1)rc=eager(w);
 else {
  // Set fixed mode once, outside captured graph nodes. The pool was allocated
  // and zeroed at communicator creation; only this field needs setup.
  // Every pack node receives shape/input/output by value, never capture-time H2D.
  rc=gpu(w,capture);
 }
 if(!w->accepted && !w->graph) {
  c->works.pop_back();c->occupied[slot]=false;cuEventDestroy(w->event);delete w;
  if(rc)++c->stats.preflight_rejected;
  return rc;
 }
 *out=w;return rc;
}
extern "C" int xdev_tp_allreduce_sum(xdev_tp_comm *c,CUdeviceptr input,CUdeviceptr output,uint64_t numel,
 xdev_tp_dtype dtype,CUstream stream,uint64_t sequence,xdev_tp_work **out) {
 Shape s{};s.rows=1;s.width=numel;s.operation=1;s.dtype=dtype;
 return submit(c,input,output,s,stream,sequence,out);
}
extern "C" int xdev_tp_logits_gather(xdev_tp_comm *c,CUdeviceptr input,CUdeviceptr output,uint64_t rows,
 uint64_t width,xdev_tp_dtype dtype,int dst,int all,CUstream stream,uint64_t sequence,xdev_tp_work **out) {
 if((all!=0 && all!=1) || dst<0 || dst>1){if(out)*out=nullptr;return -EINVAL;}
 Shape s{};s.rows=rows;s.width=width;s.operation=all?3:2;s.dtype=dtype;s.dst_rank=dst;
 return submit(c,input,output,s,stream,sequence,out);
}
static int refresh(xdev_tp_work *w) {
 auto *c=w->comm;
 if(w->image.core.error)return w->image.core.error;
 if(c->cfg.mode==1)return query(w->image.core);
 int rc=context_check(c->cfg.context);if(rc)return rc;
 CUresult ready=cuEventQuery(w->event);
 if(ready==CUDA_ERROR_NOT_READY)return 1;
 if(ready!=CUDA_SUCCESS)return retain(w,drv(ready));
 rc=drv(cuMemcpyDtoH(&w->image,w->device,sizeof(w->image)));
 if(!rc)rc=drv(cuMemcpyDtoH(&c->runtime,c->device_runtime,sizeof(Runtime)));
 if(rc)return retain(w,rc);
 if(!w->image.invocations)return 1;
 if(w->image.core.error)return retain(w,w->image.core.error);
 return query(w->image.core);
}
extern "C" int xdev_tp_work_query(xdev_tp_work *w) {
 if(!w)return -EINVAL;std::lock_guard<std::mutex> lock(w->comm->mutex);return refresh(w);
}
extern "C" int xdev_tp_work_wait(xdev_tp_work *w,uint64_t timeout) {
 if(!w)return -EINVAL;uint64_t start=now_ns();
 for(;;){int rc=xdev_tp_work_query(w);if(rc!=1)return rc;if(timeout && now_ns()-start>=timeout)return -ETIMEDOUT;std::this_thread::yield();}
}
extern "C" int xdev_tp_work_get_stats(xdev_tp_work *w,xdev_tp_work_stats *out) {
 if(!w || !out || out->size!=sizeof(*out))return -EINVAL;
 std::lock_guard<std::mutex> lock(w->comm->mutex);int rc=refresh(w);if(rc<0 && !w->image.core.error)return rc;
 *out={sizeof(*out),1,w->image.core.state,w->image.invocations,w->image.completed,w->image.failed,
  w->image.first_sequence,w->image.last_sequence,w->image.shape.payload_bytes,w->image.shape.wire_bytes,
  w->image.core.error,uint32_t(w->image.core.state==6)};return 0;
}
extern "C" int xdev_tp_get_stats(xdev_tp_comm *c,xdev_tp_stats *out) {
 if(!c || !out || out->size!=sizeof(*out))return -EINVAL;
 std::lock_guard<std::mutex> lock(c->mutex);
 if(c->cfg.mode==2)for(auto *w:c->works){int rc=refresh(w);if(rc<0 && !c->runtime.error)return rc;}
 auto s=c->stats;s.attempts=c->runtime.invocations;s.submitted=c->runtime.invocations;s.completed=c->runtime.completed;
 s.failed=c->runtime.failed;s.first_sequence=c->runtime.first_sequence;s.last_sequence=c->runtime.last_sequence;
 s.logical_inflight=c->runtime.inflight;s.logical_inflight_high_water=c->runtime.high_water;
 s.error=c->runtime.error;s.retained=!!c->runtime.error;
 if(c->cfg.mode==2){s.gpu_invocations=c->runtime.invocations;s.tx_done=s.rx_delivered=s.last_use_released=0;
  s.payload_tx_bytes=s.payload_rx_bytes=s.wire_tx_bytes=s.wire_rx_bytes=0;
  for(auto *w:c->works){s.tx_done+=w->image.tx_done;s.rx_delivered+=w->image.rx_delivered;s.last_use_released+=w->image.last_use_released;
   s.payload_tx_bytes+=w->image.completed*w->image.shape.payload_bytes;s.payload_rx_bytes+=w->image.completed*w->image.shape.payload_bytes;
   uint64_t tx=0,rx=0;if(w->image.tx_count)span_capacity(w->image.tx,w->image.tx_count,&tx);if(w->image.rx_count)span_capacity(w->image.rx,w->image.rx_count,&rx);
   s.wire_tx_bytes+=w->image.completed*tx;s.wire_rx_bytes+=w->image.completed*rx;}}
 *out=s;return 0;
}
extern "C" int xdev_tp_trace_read(xdev_tp_comm *c,xdev_tp_trace_record *out,size_t capacity,size_t *written) {
 if(!c || !written || (capacity && !out))return -EINVAL;
 std::lock_guard<std::mutex> lock(c->mutex);*written=0;
 if(c->cfg.mode==2 && c->cfg.trace_capacity)return -EOPNOTSUPP;
 while(*written<capacity && !c->trace.empty()){out[(*written)++]=c->trace.front();c->trace.pop_front();}return 0;
}
extern "C" int xdev_tp_work_destroy(xdev_tp_work *w) {
 if(!w)return -EINVAL;auto *c=w->comm;std::lock_guard<std::mutex> lock(c->mutex);
 int rc=refresh(w);if(rc)return rc==1?-EBUSY:rc;
 if(w->graph && !w->graph->released.load(std::memory_order_acquire))return -EBUSY;
 rc=drv(cuEventDestroy(w->event));if(rc)return rc;
 c->occupied[w->slot]=false;c->works.erase(std::find(c->works.begin(),c->works.end(),w));delete w->graph;delete w;return 0;
}
extern "C" int xdev_tp_destroy(xdev_tp_comm *c,uint64_t timeout) {
 if(!c)return -EINVAL;uint64_t start=now_ns();
 for(;;){xdev_tp_work *w=nullptr;{std::lock_guard<std::mutex> lock(c->mutex);if(!c->works.empty())w=c->works.front();}
  if(!w)break;int rc=xdev_tp_work_destroy(w);if(!rc)continue;if(rc!=-EBUSY)return rc;
  if(!timeout || now_ns()-start>=timeout)return -ETIMEDOUT;std::this_thread::yield();}
 if(c->runtime.error)return c->runtime.error;
 int rc=context_check(c->cfg.context);if(rc)return rc;
 if((rc=drv(cuMemFree(c->arena))))return rc;c->arena=0;
 if((rc=drv(cuMemFree(c->device_runtime))))return rc;c->device_runtime=0;
 if((rc=drv(cuModuleUnload(c->module))))return rc;delete c;return 0;
}
