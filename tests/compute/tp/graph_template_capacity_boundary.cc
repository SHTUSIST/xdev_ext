// SPDX-License-Identifier: GPL-2.0
// TODO.54 / G0-f: one CUDA graph must be able to hold more than 256 native
// work templates (a vLLM decode step of a 64-layer TP=2 model records 129
// all-reduces per captured batch size, and the default capture keeps one graph
// per size alive). Reuses the frozen complete-source boundary unchanged.
#include TP_LIBRARY_SOURCE
#undef TP_LIBRARY_SOURCE
#define TP_LIBRARY_SOURCE TP_EMPTY_SOURCE
#define main tp_frozen_boundary_main
#include "native_library_boundary.cc"
#undef main
#include <array>
#include <memory>
static unsigned failures;
static void check(bool ok,const std::string &message) {if(!ok){std::cerr<<"FAIL "<<message<<"\n";failures++;}}
namespace {
constexpr unsigned element_count=4;
struct Fixture {
 std::vector<unsigned char> tx_storage,rx_storage;
 xdev_ext_peer_endpoint tx_endpoint{0},rx_endpoint{1};
 xdev_ext_cuda_user producer{1,1},terminal{1,3},consumer{1,2};
 xdev_tp_config cfg{};
 explicit Fixture(uint32_t capacity,uint32_t depth=1) {
  using namespace boundary;
  // Two 4 KiB frames per direction: the boundary places ordinal%2 frames.
  tx_storage.assign(8192,0);rx_storage.assign(8192,0);
  tx=reinterpret_cast<uintptr_t>(tx_storage.data());rx=reinterpret_cast<uintptr_t>(rx_storage.data());
  tx_bytes=rx_bytes=8192;execute_kernels=true;graph_mode=true;batch_width=2;
  cfg.size=sizeof(cfg);cfg.version=1;cfg.communicator_id=7;cfg.epoch=9;cfg.first_sequence=23;
  cfg.world_size=2;cfg.mode=XDEV_TP_D2_GPU;cfg.context=reinterpret_cast<void *>(1);
  cfg.tx_endpoint=&tx_endpoint;cfg.rx_endpoint=&rx_endpoint;cfg.tx_va=tx;cfg.rx_va=rx;cfg.tx_bytes=cfg.rx_bytes=8192;
  cfg.frame_size=4096;cfg.logical_depth=depth;cfg.max_payload_bytes=4032;cfg.timeout_ns=100000;
  cfg.ptx_path="host-source-boundary-only";cfg.d2_tx_producer=&producer;cfg.d2_tx_terminal=&terminal;cfg.d2_rx_consumer=&consumer;
  cfg.template_capacity=capacity;
 }
};
struct Tensors {
 // One separately registered 16-byte F32 input and output per template.
 std::vector<std::array<float,element_count>> in,out;
 explicit Tensors(size_t n):in(n),out(n) {
  for(size_t i=0;i<n;++i) {
   boundary::tensor_regions[reinterpret_cast<uintptr_t>(in[i].data())]=sizeof(in[i]);
   boundary::tensor_regions[reinterpret_cast<uintptr_t>(out[i].data())]=sizeof(out[i]);
  }
 }
 ~Tensors() {
  for(size_t i=0;i<in.size();++i) {
   boundary::tensor_regions.erase(reinterpret_cast<uintptr_t>(in[i].data()));
   boundary::tensor_regions.erase(reinterpret_cast<uintptr_t>(out[i].data()));
  }
 }
 CUdeviceptr input(size_t i) {return reinterpret_cast<uintptr_t>(in[i].data());}
 CUdeviceptr output(size_t i) {return reinterpret_cast<uintptr_t>(out[i].data());}
 // Fresh values per replay; remote payload is zero, so a correct sum equals input.
 void fill(unsigned replay) {
  for(size_t i=0;i<in.size();++i)for(unsigned e=0;e<element_count;++e){in[i][e]=float(1+replay*7+i*3+e);out[i][e]=-1.0f;}
 }
 size_t mismatches() const {
  size_t bad=0;for(size_t i=0;i<in.size();++i)for(unsigned e=0;e<element_count;++e)bad+=out[i][e]!=in[i][e];return bad;
 }
};
void begin_capture() {
 using namespace boundary;
 capturing=recording=true;graph_nodes.clear();graph_cursor=0;graph_started=graph_complete=false;graph_error=CUDA_SUCCESS;
 std::memset(role_counts,0,sizeof(role_counts));producer_keys.clear();receiver_keys.clear();terminal_keys.clear();
}
void end_capture() {boundary::recording=boundary::capturing=false;}
// One replay of the whole recorded graph. Keys start at the device sequence
// counter; the boundary issues key+100 as the ready ticket for every message.
bool replay(uint64_t first_key) {
 using namespace boundary;
 replay_key=first_key;graph_cursor=0;graph_complete=false;graph_error=CUDA_SUCCESS;
 std::memset(role_counts,0,sizeof(role_counts));
 producer_ready=receiver_ready=terminal_ready=result_allowed=true;progress_graph();
 producer_ready=receiver_ready=terminal_ready=result_allowed=false;
 return graph_cursor==graph_nodes.size()&&graph_error==CUDA_SUCCESS;
}
bool contiguous(const std::vector<uint64_t> &keys,uint64_t first,size_t count) {
 if(keys.size()!=count)return false;
 for(size_t i=0;i<count;++i)if(keys[i]!=first+i)return false;
 return true;
}
size_t arena_bytes(xdev_tp_comm *comm) {
 auto i=boundary::allocations.find(comm->arena);return i==boundary::allocations.end()?0:i->second;
}
void release_graph() {for(auto &release:boundary::graph_releases)release();boundary::graph_releases.clear();}
int destroy_all(std::vector<xdev_tp_work *> &works) {
 int first=0;for(auto *w:works){int rc=xdev_tp_work_destroy(w);if(rc&&!first)first=rc;}works.clear();return first;
}
uint32_t usage(xdev_tp_comm *comm,uint32_t *in_use) {
 uint32_t capacity=0;*in_use=UINT32_MAX;
 int rc=xdev_tp_get_template_usage(comm,&capacity,in_use);
 check(rc==0,"template usage query succeeds (rc="+std::to_string(rc)+")");
 return capacity;
}
// Capture N single all-reduces into one graph, replay it R times with fresh
// tickets and fresh inputs, then retire every template and the communicator.
int capture_replay(unsigned capacity,unsigned n,unsigned replays) {
 Fixture f(capacity);xdev_tp_comm *comm=nullptr;
 int rc=xdev_tp_create(&f.cfg,&comm);
 if(rc||!comm){std::cerr<<"create setup failed "<<rc<<"\n";return 2;}
 check(arena_bytes(comm)==size_t(capacity)*sizeof(xdev_tp_native::DeviceWork),
       "arena holds exactly template_capacity device templates");
 Tensors t(n);std::vector<xdev_tp_work *> works;
 begin_capture();
 unsigned ready_before=boundary::ready;
 for(unsigned i=0;i<n;++i) {
  xdev_tp_work *w=nullptr;
  rc=xdev_tp_allreduce_sum(comm,t.input(i),t.output(i),element_count,XDEV_TP_F32,reinterpret_cast<void *>(1),23,&w);
  if(rc||!w){check(false,"capture of template "+std::to_string(i)+" accepted (rc="+std::to_string(rc)+")");break;}
  works.push_back(w);
 }
 end_capture();
 check(works.size()==n,"all "+std::to_string(n)+" templates captured in one graph");
 check(boundary::ready==ready_before,"capture consumes no native ready message");
 uint32_t in_use=0;check(usage(comm,&in_use)==capacity&&in_use==works.size(),"usage reports capacity and captured templates");
 if(works.size()==n) {
  for(unsigned r=0;r<replays;++r) {
   t.fill(r);uint64_t first=23+uint64_t(r)*n;
   check(replay(first),"replay "+std::to_string(r)+" runs every captured node");
   check(t.mismatches()==0,"replay "+std::to_string(r)+" writes every template's fresh sum");
   check(contiguous(boundary::producer_keys,23,size_t(r+1)*n)&&contiguous(boundary::receiver_keys,23,size_t(r+1)*n)&&
         contiguous(boundary::terminal_keys,23,size_t(r+1)*n),"replay "+std::to_string(r)+" took fresh contiguous keys/tickets");
  }
  for(auto *w:works)check(xdev_tp_work_query(w)==0,"replayed template reports complete");
  xdev_tp_work_stats ws{};ws.size=sizeof(ws);
  check(xdev_tp_work_get_stats(works.back(),&ws)==0&&ws.invocations==replays&&ws.completed==replays&&
        ws.last_sequence==23+uint64_t(replays)*n-1,"last template counts one invocation per replay");
  xdev_tp_stats s{};s.size=sizeof(s);
  check(xdev_tp_get_stats(comm,&s)==0&&s.completed==uint64_t(n)*replays&&s.gpu_invocations==uint64_t(n)*replays&&
        s.error==0&&s.last_sequence==23+uint64_t(replays)*n-1,"communicator totals match N x replays");
 }
 if(!works.empty())check(xdev_tp_work_destroy(works.front())==-EBUSY,"a template stays held while its CUDA graph lives");
 release_graph();
 check(destroy_all(works)==0,"every template retires after graph release");
 check(usage(comm,&in_use)==capacity&&in_use==0,"all templates returned");
 CUdeviceptr arena=comm->arena;
 check(xdev_tp_destroy(comm,1)==0,"communicator shutdown succeeds");
 check(!boundary::allocations.count(arena),"shutdown frees the template arena");
 return failures?1:0;
}
// Capacity C admits exactly C live captured templates; C+1 is refused before
// any native ready take or graph node.
int exhaust(unsigned capacity) {
 Fixture f(capacity);xdev_tp_comm *comm=nullptr;
 if(xdev_tp_create(&f.cfg,&comm)||!comm)return 2;
 unsigned effective=capacity?capacity:XDEV_TP_TEMPLATE_CAPACITY;
 Tensors t(effective+1);std::vector<xdev_tp_work *> works;
 begin_capture();
 for(unsigned i=0;i<effective;++i){xdev_tp_work *w=nullptr;
  if(xdev_tp_allreduce_sum(comm,t.input(i),t.output(i),element_count,XDEV_TP_F32,reinterpret_cast<void *>(1),23,&w)||!w)break;
  works.push_back(w);}
 check(works.size()==effective,"capacity "+std::to_string(effective)+" templates admitted, got "+std::to_string(works.size()));
 size_t nodes=boundary::graph_nodes.size();unsigned calls=boundary::enqueue_calls;
 xdev_tp_stats before{};before.size=sizeof(before);xdev_tp_get_stats(comm,&before);
 xdev_tp_work *extra=reinterpret_cast<xdev_tp_work *>(1);
 int rc=xdev_tp_allreduce_sum(comm,t.input(effective),t.output(effective),element_count,XDEV_TP_F32,reinterpret_cast<void *>(1),23,&extra);
 end_capture();
 xdev_tp_stats after{};after.size=sizeof(after);xdev_tp_get_stats(comm,&after);
 check(rc==-ENOSPC&&extra==nullptr,"template beyond capacity is refused with -ENOSPC (rc="+std::to_string(rc)+")");
 check(boundary::graph_nodes.size()==nodes&&boundary::enqueue_calls==calls,"refusal records no graph node");
 check(after.preflight_rejected==before.preflight_rejected+1&&after.error==0,"refusal is a preflight reject, not a stable error");
 uint32_t in_use=0;check(usage(comm,&in_use)==effective&&in_use==effective,"usage reports a full template pool");
 release_graph();
 check(destroy_all(works)==0,"captured templates retire after graph release");
 check(usage(comm,&in_use)==effective&&in_use==0,"pool empty after retirement");
 CUdeviceptr arena=comm->arena;
 check(xdev_tp_destroy(comm,1)==0&&!boundary::allocations.count(arena),"shutdown frees arena");
 return failures?1:0;
}
// Segmented windows (T6b) captured through submit_batch: many windows of
// logical_depth items in one graph, more than 256 templates in total.
int batch_capture(unsigned capacity,unsigned depth,unsigned windows,unsigned replays) {
 Fixture f(capacity,depth);xdev_tp_comm *comm=nullptr;
 if(xdev_tp_create(&f.cfg,&comm)||!comm)return 2;
 unsigned n=depth*windows;Tensors t(n);std::vector<xdev_tp_work *> works(n,nullptr);
 begin_capture();
 for(unsigned wdx=0;wdx<windows;++wdx) {
  std::vector<xdev_tp_request> requests(depth);
  for(unsigned i=0;i<depth;++i)requests[i]={t.input(wdx*depth+i),t.output(wdx*depth+i),1,element_count,XDEV_TP_SUM,XDEV_TP_F32,0,0};
  int rc=xdev_tp_submit_batch(comm,requests.data(),depth,reinterpret_cast<void *>(1),23,works.data()+wdx*depth);
  if(rc){check(false,"window "+std::to_string(wdx)+" captured (rc="+std::to_string(rc)+")");break;}
 }
 end_capture();
 size_t held=0;for(auto *w:works)held+=w!=nullptr;
 check(held==n,"all "+std::to_string(n)+" batch templates captured in one graph, got "+std::to_string(held));
 if(held==n)for(unsigned r=0;r<replays;++r) {
  t.fill(r);
  check(replay(23+uint64_t(r)*n),"batch replay "+std::to_string(r)+" runs every node");
  check(t.mismatches()==0,"batch replay "+std::to_string(r)+" writes every fresh sum");
  check(contiguous(boundary::producer_keys,23,size_t(r+1)*n),"batch replay "+std::to_string(r)+" took fresh producer keys");
 }
 xdev_tp_stats s{};s.size=sizeof(s);
 check(xdev_tp_get_stats(comm,&s)==0&&s.completed==uint64_t(held==n?n:0)*replays&&s.error==0,"batch totals match");
 release_graph();
 std::vector<xdev_tp_work *> live;for(auto *w:works)if(w)live.push_back(w);
 check(destroy_all(live)==0,"batch templates retire");
 CUdeviceptr arena=comm->arena;
 check(xdev_tp_destroy(comm,1)==0&&!boundary::allocations.count(arena),"shutdown frees arena");
 return failures?1:0;
}
// Creation bounds: above the maximum or a nonzero reserved word is refused
// without any device allocation; a caller built against the original
// struct (size without the appended fields) keeps the default.
int limits() {
 {
  Fixture f(XDEV_TP_TEMPLATE_CAPACITY_MAX+1);xdev_tp_comm *comm=reinterpret_cast<xdev_tp_comm *>(1);
  size_t allocations=boundary::allocations.size();
  int rc=xdev_tp_create(&f.cfg,&comm);
  check(rc==-EINVAL&&comm==nullptr,"capacity above maximum is refused (rc="+std::to_string(rc)+")");
  check(boundary::allocations.size()==allocations,"refused capacity allocates nothing");
 }
 {
  Fixture f(300);f.cfg.reserved=1;xdev_tp_comm *comm=nullptr;
  check(xdev_tp_create(&f.cfg,&comm)==-EINVAL&&!comm,"nonzero reserved word is refused");
 }
 {
  // Original-ABI caller: bytes after its struct are not part of its config.
  Fixture f(0);
  auto buffer=std::make_unique<unsigned char[]>(sizeof(xdev_tp_config));
  std::memset(buffer.get(),0xff,sizeof(xdev_tp_config));
  std::memcpy(buffer.get(),&f.cfg,XDEV_TP_CONFIG_SIZE_V1_BASE);
  auto *legacy=reinterpret_cast<xdev_tp_config *>(buffer.get());legacy->size=XDEV_TP_CONFIG_SIZE_V1_BASE;
  xdev_tp_comm *comm=nullptr;int rc=xdev_tp_create(legacy,&comm);
  check(rc==0&&comm,"original-size config is accepted (rc="+std::to_string(rc)+")");
  if(comm){uint32_t in_use=0;check(usage(comm,&in_use)==XDEV_TP_TEMPLATE_CAPACITY&&in_use==0,"original-size config keeps 256 templates");
   check(arena_bytes(comm)==size_t(XDEV_TP_TEMPLATE_CAPACITY)*sizeof(xdev_tp_native::DeviceWork),"default arena size");
   check(xdev_tp_destroy(comm,1)==0,"legacy communicator shutdown");}
 }
 {
  /* A caller compiled with graph-cap fields but no host endpoints keeps
   * its requested capacity. Poisoned appended pointers are never read. */
  Fixture f(300);
  const size_t graph_size=offsetof(xdev_tp_config,tx_frames);
  auto buffer=std::make_unique<unsigned char[]>(sizeof(xdev_tp_config));
  std::memset(buffer.get(),0xff,sizeof(xdev_tp_config));
  std::memcpy(buffer.get(),&f.cfg,graph_size);
  auto *legacy=reinterpret_cast<xdev_tp_config *>(buffer.get());legacy->size=graph_size;
  xdev_tp_comm *comm=nullptr;int rc=xdev_tp_create(legacy,&comm);
  check(rc==0&&comm,"graph-size config is accepted (rc="+std::to_string(rc)+")");
  if(comm){uint32_t in_use=0;check(usage(comm,&in_use)==300&&in_use==0,"graph-size config keeps its requested capacity");
   check(xdev_tp_destroy(comm,1)==0,"graph-size communicator shutdown");}
 }
 {
  Fixture f(0);f.cfg.size=XDEV_TP_CONFIG_SIZE_V1_BASE+4;xdev_tp_comm *comm=nullptr;
  check(xdev_tp_create(&f.cfg,&comm)==-EINVAL&&!comm,"unknown config size is refused");
 }
 return failures?1:0;
}
}
int main(int argc,char **argv) {
 if(argc!=2)return 64;std::string scenario=argv[1];int rc=64;
 if(scenario=="capture_replay")rc=capture_replay(1024,300,3);
 else if(scenario=="capture_large")rc=capture_replay(4096,4096,1);
 else if(scenario=="exhaust")rc=exhaust(300);
 else if(scenario=="default_exhaust")rc=exhaust(0);
 else if(scenario=="batch_capture")rc=batch_capture(512,4,75,2);
 else if(scenario=="limits")rc=limits();
 std::cout<<"case="<<scenario<<" failures="<<failures<<" exit="<<rc<<"\n";
 return rc==2?2:rc;
}
