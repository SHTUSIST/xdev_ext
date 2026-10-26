// SPDX-License-Identifier: GPL-2.0
// Actual PhysicalOwner/guard; metadata-only priming, fail-stop GPU boundary.
// -fno-access-control is confined to this independent test compilation.
#define main xdomain_production_main_unused
#include "xdomain_agent.cc"
#undef main
#define main native_filesystem_fixture_main_unused
#include "native_trace_owner_test.cc"
#undef main
#include <iostream>
static tb_guard *probe_guard=nullptr;
static std::string scenario;
static fs::path owned_path;
static bool gpu_edge=false, cleanup_admission=false;
static uint32_t edge_permissions=0;
extern "C" int __real_tb_guard_begin(tb_guard *,tb_operation,uint64_t *);
extern "C" int __wrap_tb_guard_begin(tb_guard *g,tb_operation op,uint64_t *ticket) {
 if(g==probe_guard && op==TB_OP_EPOCH_CLOSE) {
  cleanup_admission=true;
  if(scenario=="trace-held")tb_guard_hold(g,TB_HOLD_CANCEL);
 }
 return __real_tb_guard_begin(g,op,ticket);
}
// These are terminal traps, never successful CUDA/resource implementations.
extern "C" int tb_gpu_close(tb_gpu *) {
 gpu_edge=true;edge_permissions=tb_guard_cleanup_permissions(probe_guard);
 throw std::runtime_error("test stopped before GPU device entry");
}
extern "C" int tb_gpu_open(tb_gpu **,tb_guard *,const tb_gpu_request *){_exit(94);}
extern "C" int tb_gpu_fill(tb_gpu *,uint64_t,bool){_exit(94);}
extern "C" int tb_gpu_registration(const tb_gpu *,struct tb_gpu_registration *){_exit(94);}
extern "C" int tb_gpu_receive_visible(tb_gpu *){_exit(94);}
extern "C" int tb_gpu_verify(tb_gpu *,const tb_verify_extent *,size_t,uint64_t,tb_verify_result *){_exit(94);}
extern "C" int tb_gpu_last_diagnostic(tb_gpu_diagnostic *){_exit(94);}
extern "C" CUresult CUDAAPI cuInit(unsigned int){_exit(95);}
extern "C" CUresult CUDAAPI cuDeviceGetByPCIBusId(CUdevice *,const char *){_exit(95);}
extern "C" CUresult CUDAAPI cuDeviceGetAttribute(int *,CUdevice_attribute,CUdevice){_exit(95);}
static void advance(tb_guard *g,tb_operation op,tb_phase phase,bool safe) {
 uint64_t ticket=0;need(tb_guard_begin(g,op,&ticket)==0,"guard prime begin");
 need(tb_guard_end(g,ticket,phase,safe,true)==0,"guard prime end");
}
int main(int argc,char **argv) {
 try {
  need(argc==4,"usage scenario directory wire");scenario=argv[1];fs::path directory(argv[2]);
  auto wire=read_file(argv[3]);tb::Identity id{"pair-close-regression",std::string(40,'a'),"tx","bringup","a-to-b",3};
  tb_guard *g=nullptr;need(tb_guard_new(TB_BACKING_GPU,&g)==0,"guard new");
  advance(g,TB_OP_GPU_OPEN,TB_PHASE_GPU_READY,true);advance(g,TB_OP_GPU_FILL,TB_PHASE_GPU_READY,true);
  advance(g,TB_OP_CREATE,TB_PHASE_SESSION_CREATED,false);advance(g,TB_OP_START,TB_PHASE_START_ACCEPTED,false);advance(g,TB_OP_STOP,TB_PHASE_DRAINED_SAFE,true);
  // Negative cases start with pair permission already present: rejection must
  // arise from actual receipt validation, not accidentally missing permission.
  if(scenario!="pair-valid")need(tb_guard_pair_stopped(g)==0,"prime pair permission");
  int durable=tb::open_durable_record(directory.string(),id,nullptr);need(durable>=0,"durable");
  PhysicalOwner owner(g,id,"unused-kernel",true,durable,"unused-log","unused-receipt","unused-helpers",directory.string());
  owner.epoch_.session_id=101;owner.epoch_.created=true;owner.epoch_.start_accepted=true;owner.epoch_.stop_proved=true;owner.local_stop_request_=5;owner.groups_=1;
  if(scenario=="trace-safe"||scenario=="trace-held") {
   auto root=directory/"tracefs";auto evidence=directory/"trace-evidence";
   fs::create_directories(root/"instances/other");fs::create_directories(evidence);
   put(root/"trace","SHARED TRACE MUST SURVIVE\n");put(root/"tracing_on","1\n");put(root/"instances/other/trace","OTHER INSTANCE\n");
   owner.native_trace_.reset(new tb::NativeTraceCapture(root.string(),evidence.string(),"owned"));
   need(owner.native_trace_->start()==0,"real private capture start");owned_path=root/"instances/owned";
  }
  probe_guard=g;
  tb::Command command{id,6,mono_ns()+2000000000ULL,"close",wire};
  auto result=owner.execute(command);
  if(scenario=="pair-valid") {
   need(gpu_edge,"valid paired STOP did not reach cleanup boundary");
   need((edge_permissions & 15)==15,"valid paired STOP failed to grant actual cleanup permissions");
  }else if(scenario=="trace-safe") {
   need(gpu_edge,"safe close did not reach GPU boundary");need(cleanup_admission,"trace close omitted actual cleanup admission");
   need(!fs::exists(owned_path),"safe close did not remove private trace before final GPU close");unchanged(directory/"tracefs");
  }else if(scenario=="trace-held") {
   need(cleanup_admission,"trace close omitted actual cleanup admission");need(!gpu_edge,"HELD cleanup continued to GPU boundary");
   need(fs::exists(owned_path),"HELD-before-admission removed private trace");
   struct tb_guard_snapshot s{};tb_guard_snapshot(g,&s);need(s.held&&s.cleanup_permissions==0,"HELD guard lost retention");unchanged(directory/"tracefs");
  }else {
   need(!gpu_edge,"invalid/missing paired receipt reached resource cleanup");need(!cleanup_admission,"invalid/missing pair reached cleanup admission");need(result.error!=0,"invalid pair accepted");
  }
  std::cout<<"PASS "<<scenario<<" metadata-only; no GPU/native call; result_error="<<result.error<<"\n";return 0;
 }catch(const std::exception &e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}
}
