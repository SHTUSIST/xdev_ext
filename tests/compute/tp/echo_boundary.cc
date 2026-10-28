// SPDX-License-Identifier: GPL-2.0
// Actual echo control flow and kernels; CUDA/endpoint/session call boundaries.
// The owner fixture is already qualified. This is no GPU/DMA/timing evidence.
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <deque>
#include <iostream>
#include <memory>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>
#include <cuda.h>
#include <libxdev_ext_peer_message.h>
#include <peer_endpoint_owner.h>
#include TP_ECHO_OPTIONS
struct dim { unsigned x=0; };
static dim blockIdx,threadIdx,blockDim{1},gridDim{1};
static unsigned atomicAdd(unsigned *p,unsigned n) {unsigned old=*p;*p+=n;return old;}
#define __global__
#include TP_ECHO_KERNELS
#undef __global__
extern "C" {
#include TP_ECHO_SPAN
}
static std::vector<std::string> calls;
static unsigned terminal_publications, interval_pending, intervals, failures;
static bool drained[2];
static unsigned stats_reads[2];
static uint64_t ticks;
struct xdev_ext_peer_endpoint {unsigned index;};
struct xdev_ext_session {unsigned index;};
static xdev_ext_peer_endpoint endpoints[2]={{0},{1}};
static xdev_ext_session sessions[2]={{0},{1}};
static std::deque<xdev_ext_peer_message> ready[2];
static std::vector<unsigned char> tx_bytes(8192),rx_bytes(8192);
static unsigned mismatch;
static std::string scenario;
static void native_check(int n,const char *s) {if(n)throw std::runtime_error(s);}
static void cuda_check(CUresult n,const char *s) {if(n)throw std::runtime_error(s);}
#define NATIVE(c) native_check((c),#c)
#define CU(c) cuda_check((c),#c)
// Only the already-qualified owner fields consumed by echo.h are fixtures.
#define TP_EVAL_OWNER_H
struct tp_eval_owner {
 xdev_ext_cuda_peer_owner *bootstrap=reinterpret_cast<xdev_ext_cuda_peer_owner *>(1);
 CUstream stream=reinterpret_cast<void *>(2);
 CUmodule oracle=reinterpret_cast<void *>(3);
 std::vector<CUdeviceptr> bad{reinterpret_cast<CUdeviceptr>(&mismatch)};
 void close(uint64_t) {calls.push_back("owner_close");}
};
CUresult cuMemcpyDtoDAsync(CUdeviceptr,CUdeviceptr,size_t,CUstream);
CUresult cuMemsetD32Async(CUdeviceptr,unsigned,size_t,CUstream);
#include TP_ECHO_SOURCE
extern "C" int xdev_ext_cuda_peer_owner_get_view(xdev_ext_cuda_peer_owner *,xdev_ext_cuda_peer_owner_view *v) {
 v->tx_endpoint=&endpoints[0];v->rx_endpoint=&endpoints[1];
 v->tx_va=reinterpret_cast<CUdeviceptr>(tx_bytes.data());v->rx_va=reinterpret_cast<CUdeviceptr>(rx_bytes.data());
 v->allocation_bytes=8192;v->frame_size=4096;v->context=reinterpret_cast<void *>(1);return 0;
}
extern "C" int xdev_ext_cuda_host_receive_visible(CUcontext) {calls.push_back("visible");return 0;}
extern "C" int xdev_ext_peer_endpoint_next(xdev_ext_peer_endpoint *e,int,xdev_ext_peer_message *m) {
 assert(!ready[e->index].empty());*m=ready[e->index].front();ready[e->index].pop_front();
 calls.push_back("take"+std::to_string(m->role));return 0;
}
extern "C" int xdev_ext_peer_endpoint_complete(xdev_ext_peer_endpoint *,const xdev_ext_peer_message *m,int status) {
 assert(status==0);calls.push_back("done"+std::to_string(m->role));
 // A USER done is publication, not a synchronous native END. Real library
 // body publishes done_prod/KICK and returns; the session observer is separate.
 if(m->role==XDEV_EXT_PEER_TX_TERMINAL) {terminal_publications++;drained[0]=drained[1]=false;}
 return 0;
}
extern "C" xdev_ext_session *xdev_ext_peer_endpoint_session(xdev_ext_peer_endpoint *e) {return &sessions[e->index];}
extern "C" int xdev_ext_session_wait(xdev_ext_session *s,int,xdev_ext_mech_stats *out) {
 calls.push_back("native_wait"+std::to_string(s->index));drained[s->index]=true;*out={};out->batches_done=terminal_publications;return 0;
}
extern "C" int xdev_ext_session_stats(xdev_ext_session *s,xdev_ext_mech_stats *out) {
 calls.push_back("native_stats"+std::to_string(s->index));
 drained[s->index]=++stats_reads[s->index]>1;*out={};
 out->batches_done=drained[s->index]?terminal_publications:0;return 0;
}
CUresult cuModuleGetFunction(CUfunction *f,CUmodule,const char *name) {*f=reinterpret_cast<void *>(std::strcmp(name,"tp_eval_echo_fill")==0?1:2);return 0;}
CUresult cuEventCreate(CUevent *e,unsigned) {*e=reinterpret_cast<void *>(1);return 0;}
CUresult cuEventRecord(CUevent,CUstream) {calls.push_back("record");return 0;}
CUresult cuEventSynchronize(CUevent) {calls.push_back("sync");return 0;}
CUresult cuEventDestroy(CUevent) {return 0;}
CUresult cuMemcpyDtoH(void *to,CUdeviceptr from,size_t n) {std::memcpy(to,reinterpret_cast<void *>(from),n);return 0;}
CUresult cuMemcpyDtoDAsync(CUdeviceptr to,CUdeviceptr from,size_t n,CUstream) {
 assert(to!=from);calls.push_back("d2d");std::memcpy(reinterpret_cast<void *>(to),reinterpret_cast<void *>(from),n);return 0;
}
CUresult cuMemsetD32Async(CUdeviceptr p,unsigned value,size_t n,CUstream) {assert(n==1);*reinterpret_cast<unsigned *>(p)=value;return 0;}
CUresult cuLaunchKernel(CUfunction f,unsigned gx,unsigned,unsigned,unsigned bx,unsigned,unsigned,unsigned,CUstream,void **a,void **) {
 calls.push_back(f==reinterpret_cast<void *>(1)?"fill":"check");gridDim.x=gx;blockDim.x=bx;
 auto p=*static_cast<CUdeviceptr *>(a[0]);auto n=*static_cast<uint64_t *>(a[1]);auto off=*static_cast<uint64_t *>(a[2]);auto seed=*static_cast<uint64_t *>(a[3]);
 for(blockIdx.x=0;blockIdx.x<gx;blockIdx.x++)for(threadIdx.x=0;threadIdx.x<bx;threadIdx.x++) {
  if(f==reinterpret_cast<void *>(1))tp_eval_echo_fill(reinterpret_cast<unsigned char *>(p),n,off,seed);
  else tp_eval_echo_check(reinterpret_cast<unsigned char *>(p),n,off,seed,reinterpret_cast<unsigned *>(*static_cast<CUdeviceptr *>(a[4])));
 }
 return 0;
}
static uint64_t now_ns() {return ++ticks;}
struct barrier {int fd=-1;void exchange(const std::string &) {calls.push_back("barrier");}};
static int boundary_printf(const char *fmt,...) {
 if(std::strstr(fmt,"\"interval\"")) {intervals++;interval_pending+=!drained[0]||!drained[1];calls.push_back("interval");}
 return 0;
}
#define printf boundary_printf
// The actual driver branch now names a d2 type. Its implementation and real
// kernels are exercised by echo_gpu_boundary.cc. Any accidental d2 invocation
// in these unchanged d1-only cases aborts instead of supplying fake behavior.
struct tp_eval_echo_gpu {
 tp_eval_echo_gpu(tp_eval_owner &,const tp_eval_options &) {std::abort();}
 void capture() {std::abort();}
 bool exchange(uint64_t) {std::abort();}
 void close() {std::abort();}
};
static int actual_driver_echo(tp_eval_owner &owner,const tp_eval_options &o) {
 barrier control;
#include TP_ECHO_DRIVER
 return -1;
}
#undef printf
static void expect(bool ok,const char *what) {if(!ok){std::cerr<<"FAIL "<<what<<"\n";failures++;}}
static size_t at(const std::string &s) {for(size_t i=0;i<calls.size();i++)if(calls[i]==s)return i;return calls.size();}
static unsigned count(const std::string &s) {unsigned n=0;for(const auto &v:calls)n+=v==s;return n;}
static xdev_ext_peer_message message(xdev_ext_peer_role role) {
 xdev_ext_peer_message m{};m.role=role;m.batch.key=23;m.batch.nr_frames=2;
 for(unsigned i=0;i<2;i++) {auto &f=m.batch.f[i];f.umem_addr=4096*i;f.data_off=512;f.capacity=3072;f.data_len=3000;}
 return m;
}
int main(int argc,char **argv) {
 assert(argc==2);scenario=argv[1];tp_eval_options o;o.rank=scenario.find("rank1")!=std::string::npos?1:0;
 o.operation=4;o.iterations=1;o.first_sequence=23;o.group_bytes=6000;
 auto tx=message(XDEV_EXT_PEER_PRODUCER),rx=message(XDEV_EXT_PEER_RX_CONSUMER),terminal=message(XDEV_EXT_PEER_TX_TERMINAL);
 // Seed the peer's request/return through the actual source kernel. This is
 // qualified incoming data, not a second implementation of its byte formula.
 gridDim.x=blockDim.x=1;blockIdx.x=threadIdx.x=0;
 for(unsigned i=0;i<2;i++)tp_eval_echo_fill(rx_bytes.data()+4096*i+512,3000,3000*i,0);
 if(scenario.find("bad_payload")!=std::string::npos)rx_bytes[512]^=1;
 if(scenario.find("bad_key")!=std::string::npos)rx.batch.key++;
 if(scenario.find("geometry")!=std::string::npos)tx.batch.nr_frames=1;
 ready[0].push_back(tx);ready[0].push_back(terminal);ready[1].push_back(rx);
 tp_eval_owner owner;bool threw=false;
 try {if(scenario=="cutoff_rank0"||scenario=="cutoff_rank1")actual_driver_echo(owner,o);else {tp_eval_echo e(owner,o);e.exchange(0);e.close();}}
 catch(const std::exception &) {threw=true;}
 bool invalid=scenario.find("bad_")!=std::string::npos||scenario.find("geometry")!=std::string::npos;
 expect(threw==invalid,"exception matches invalid evidence");
 if(invalid) {
  expect(count("done2")==0&&count("done3")==0,"invalid RX never released or followed by terminal done0");
  if(o.rank==1)expect(count("done1")==0,"rank1 invalid input never publishes TX done0");
 } else {
  expect(count("done1")==1&&count("done2")==1&&count("done3")==1,"each role completes exactly once");
  if(o.rank==0)expect(at("fill")<at("done1")&&at("done1")<at("check")&&at("check")<at("done2")&&at("done2")<at("done3"),"rank0 produce validate release terminal ordering");
  else {expect(at("check")<at("d2d")&&at("d2d")<at("done2")&&at("done2")<at("done1")&&at("done1")<at("done3"),"rank1 validate D2D RX release TX publish terminal ordering");
   expect(count("d2d")==2,"all spans copied to independent TX");
   expect(tx_bytes[512]==rx_bytes[512]&&tx_bytes[4096+512+2999]==rx_bytes[4096+512+2999],"copy reaches both offset span boundaries");}
  for(size_t i=0;i<calls.size();i++)if(calls[i].rfind("done",0)==0)expect(i>0&&calls[i-1]=="sync","done0 follows actual stream event synchronization");
 }
 if(scenario.find("cutoff")==0) {expect(intervals==1,"driver emits one measured interval");expect(interval_pending==0,"custody_released interval occurs after both native session completions");}
 std::cout<<"case="<<scenario<<" failures="<<failures<<" intervals_before_native_end="<<interval_pending<<" calls=";
 for(const auto &s:calls)std::cout<<s<<",";std::cout<<"\n";return failures?1:0;
}
