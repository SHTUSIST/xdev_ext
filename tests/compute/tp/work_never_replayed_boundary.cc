// SPDX-License-Identifier: GPL-2.0
// Reuse the frozen complete-source adapter; override only two Driver results.
#include TP_LIBRARY_SOURCE
#undef TP_LIBRARY_SOURCE
#define TP_LIBRARY_SOURCE TP_EMPTY_SOURCE
#define main tp_frozen_boundary_main
#define cuStreamQuery tp_frozen_stream_query
#define cuMemcpyDtoH tp_frozen_device_read
#include "native_library_boundary.cc"
#undef cuMemcpyDtoH
#undef cuStreamQuery
#undef main
static CUresult injected_stream_result=CUDA_SUCCESS;
static bool fail_device_read=false;
CUresult cuStreamQuery(CUstream s) {
 if(injected_stream_result!=CUDA_SUCCESS)return injected_stream_result;
 return tp_frozen_stream_query(s);
}
CUresult cuMemcpyDtoH(void *p,CUdeviceptr s,size_t n) {
 if(fail_device_read)return CUDA_ERROR_UNKNOWN;
 return tp_frozen_device_read(p,s,n);
}
static unsigned failures;
static void check(bool ok,const char *message) {if(!ok){std::cerr<<"FAIL "<<message<<"\n";failures++;}}
static void release_graph_references() {
 check(!boundary::graph_releases.empty(),"capture actually retained a CUDA user object");
 for(auto &release:boundary::graph_releases)release();
 boundary::graph_releases.clear();
}
static bool no_new_totals(const xdev_tp_stats &a,const xdev_tp_stats &b) {
 return a.completed==b.completed&&a.submitted==b.submitted&&a.tx_done==b.tx_done&&a.rx_delivered==b.rx_delivered&&
  a.last_use_released==b.last_use_released&&a.payload_tx_bytes==b.payload_tx_bytes&&a.payload_rx_bytes==b.payload_rx_bytes&&
  a.wire_tx_bytes==b.wire_tx_bytes&&a.wire_rx_bytes==b.wire_rx_bytes;
}
int main(int argc,char **argv) {
 if(argc!=2)return 64;using namespace boundary;std::string scenario=argv[1];
 std::vector<unsigned char> tx_storage(4096),rx_storage(4096),inputs(16),outputs(16);
 tx=reinterpret_cast<uintptr_t>(tx_storage.data());rx=reinterpret_cast<uintptr_t>(rx_storage.data());
 input=reinterpret_cast<uintptr_t>(inputs.data());output=reinterpret_cast<uintptr_t>(outputs.data());
 tx_bytes=rx_bytes=4096;input_bytes=output_bytes=16;execute_kernels=true;graph_mode=true;
 xdev_ext_peer_endpoint tx_endpoint{0},rx_endpoint{1};
 xdev_ext_cuda_user producer{1,1},terminal{1,3},consumer{1,2};
 xdev_tp_config cfg{};cfg.size=sizeof(cfg);cfg.version=1;cfg.communicator_id=7;cfg.epoch=9;cfg.first_sequence=23;
 cfg.world_size=2;cfg.mode=XDEV_TP_D2_GPU;cfg.context=reinterpret_cast<void *>(1);
 cfg.tx_endpoint=&tx_endpoint;cfg.rx_endpoint=&rx_endpoint;cfg.tx_va=tx;cfg.rx_va=rx;cfg.tx_bytes=cfg.rx_bytes=4096;
 cfg.frame_size=4096;cfg.logical_depth=1;cfg.max_payload_bytes=4032;cfg.timeout_ns=100000;
 cfg.ptx_path="host-source-boundary-only";cfg.d2_tx_producer=&producer;cfg.d2_tx_terminal=&terminal;cfg.d2_rx_consumer=&consumer;
 xdev_tp_comm *comm=nullptr;xdev_tp_work *work=nullptr;int rc=xdev_tp_create(&cfg,&comm);
 if(rc||!comm){std::cerr<<"create setup failed "<<rc<<"\n";return 2;}
 auto capture=[&](uint64_t sequence) {
  capturing=recording=true;graph_nodes.clear();graph_cursor=0;graph_started=graph_complete=false;
  ready=producer_done0=receiver_done0=terminal_done0=0;
  role_counts[1]=role_counts[2]=role_counts[3]=0;
  int status=xdev_tp_allreduce_sum(comm,input,output,4,XDEV_TP_F32,reinterpret_cast<void *>(1),sequence,&work);
  recording=capturing=false;return status;
 };
 auto remote=[&](uint64_t sequence) {
  xdev_tp_native::Shape shape{};shape.communicator_id=7;shape.epoch=9;shape.sequence=sequence;shape.rows=1;shape.width=4;
  shape.operation=1;shape.dtype=3;shape.rank=1;shape.world_size=2;
  if(xdev_tp_native::shape_validate(&shape,4096,4096))throw std::runtime_error("remote shape setup");
  xdev_tp_native::encode_header(shape,rx_storage.data());
 };
 unsigned prior_replays=scenario=="foreign_older"?2:scenario=="slot_reuse"?1:0;
 for(unsigned prior=0;prior<prior_replays;prior++) {
  uint64_t previous_sequence=23+prior;replay_key=previous_sequence;
  if(capture(previous_sequence)||!work)return 2;remote(previous_sequence);
  producer_ready=receiver_ready=terminal_ready=result_allowed=true;progress_graph();
  if(xdev_tp_work_query(work))return 2;
  release_graph_references();if(xdev_tp_work_destroy(work))return 2;work=nullptr;
  producer_ready=receiver_ready=terminal_ready=result_allowed=false;
 }
 if(scenario=="partial_capture")enqueue_fail_at=enqueue_calls+2;
 uint64_t sequence=23+prior_replays;rc=capture(sequence);
 if(!work || (scenario=="partial_capture"?(rc!=-EIO):(rc!=0))) {std::cerr<<"capture setup "<<rc<<"\n";return 2;}
 auto arena=comm->arena;auto slot=work->slot;auto *device=reinterpret_cast<xdev_tp_native::DeviceWork *>(work->device);
 if(scenario=="stream_pending")injected_stream_result=CUDA_ERROR_NOT_READY;
 if(scenario=="stream_unknown")injected_stream_result=CUDA_ERROR_UNKNOWN;
 if(scenario=="read_unknown")fail_device_read=true;
 if(scenario=="begun_pending") {producer_ready=true;progress_graph();check(device->invocations==1&&device->completed==0,"actual pack began but never completed");}
 if(scenario=="wrong_key") {replay_key=24;remote(24);producer_ready=receiver_ready=terminal_ready=result_allowed=true;progress_graph();check(device->invocations==0&&device->core.error!=0,"actual invalid ready key rejected");}
 // CUDA defers a graph user-object destructor until final graph use ends.
 // An already-running incomplete graph therefore still holds its reference.
 if(scenario!="graph_held"&&scenario!="begun_pending")release_graph_references();
 if(scenario=="foreign_older") {check(work->owner_cookie>2,"two real previous retirements establish cookie history");device->owner_cookie=work->owner_cookie-2;}
 if(scenario=="foreign_newer")device->owner_cookie=work->owner_cookie+1;
 bool allowed=scenario=="never_replayed"||scenario=="slot_reuse";
 bool retained_before=allocations.count(arena);uint64_t cookie=device->owner_cookie;
 xdev_tp_stats before{};before.size=sizeof(before);int stats_rc=xdev_tp_get_stats(comm,&before);
 // UNKNOWN/read failures may legitimately make the public stats query fail;
 // only successful never-invoked cleanup is checked for zero fabrication.
 if(allowed&&stats_rc)return 2;
 unsigned ready_before=ready,producer_before=producer_done0,receiver_before=receiver_done0,terminal_before=terminal_done0;
 int destroy=xdev_tp_work_destroy(work);
 check(allowed?destroy==0:destroy<0,"destroy respects never-invoked versus retained custody");
 check(retained_before&&allocations.count(arena),"work retirement keeps communicator arena authority alive");
 check(ready==ready_before&&producer_done0==producer_before&&receiver_done0==receiver_before&&terminal_done0==terminal_before,"destroy never submits or fabricates native done0");
 int comm_destroy=999;
 if(destroy==0) {
  work=nullptr;check(!comm->occupied[slot]&&comm->works.empty(),"template slot and host work are retired");
  xdev_tp_stats after{};after.size=sizeof(after);check(xdev_tp_get_stats(comm,&after)==0,"post-retirement stats readable");
  check(no_new_totals(before,after),"never-replayed template contributes no completions or bytes");
  check(after.completed==(scenario=="slot_reuse"?1:0),"only genuinely completed previous replay remains accounted");
  comm_destroy=xdev_tp_destroy(comm,1);check(comm_destroy==0,"communicator shutdown succeeds after unused template retirement");
  check(!allocations.count(arena),"shutdown frees native metadata after all graph refs and templates end");
 } else check(comm->occupied[slot]&&!comm->works.empty(),"refused destroy retains work and occupied slot");
 std::cout<<"case="<<scenario<<" failures="<<failures<<" setup="<<rc<<" destroy="<<destroy<<" comm_destroy="<<comm_destroy
  <<" cookie="<<cookie<<" ready="<<ready<<" producer_done0="<<producer_done0<<" rx_done0="<<receiver_done0<<" terminal_done0="<<terminal_done0<<"\n";
 return failures?1:0;
}
