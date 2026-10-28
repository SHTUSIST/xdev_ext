// SPDX-License-Identifier: GPL-2.0
// Real bilateral E6/E7 native TP driver. No fake device/backend or host payload copy.
#include "owner.h"
#include "echo.h"
#include "echo_gpu.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <time.h>
#include <cstring>
#include <cstdlib>
#include <memory>

static uint64_t now_ns() {
 timespec t{};if(clock_gettime(CLOCK_MONOTONIC,&t))throw std::runtime_error("clock_gettime");
 return uint64_t(t.tv_sec)*1000000000ULL+uint64_t(t.tv_nsec);
}
static uint64_t number(const char *s) {
 char *end=nullptr;errno=0;
 if(!s || !*s || *s=='-' || *s=='+')throw std::runtime_error("invalid unsigned argument");
 unsigned long long v=strtoull(s,&end,0);
 if(errno || *end)throw std::runtime_error("invalid unsigned argument");
 return uint64_t(v);
}
static unsigned small(const char *s) {
 uint64_t n=number(s);if(n>UINT_MAX)throw std::runtime_error("argument exceeds uint32");return unsigned(n);
}
struct barrier {
 int fd=-1;
 void open(unsigned rank,const char *address,unsigned port,uint64_t timeout) {
  sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(uint16_t(port));
  if(!port || port>65535 || inet_pton(AF_INET,address,&a.sin_addr)!=1)throw std::runtime_error("invalid control address/port");
  if(rank==0) {
   int listener=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
   if(listener<0)throw std::runtime_error("control socket failed");
   int on=1;setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on));
   if(bind(listener,reinterpret_cast<sockaddr*>(&a),sizeof(a)) || listen(listener,1))throw std::runtime_error("control bind/listen failed");
   pollfd p{listener,POLLIN,0};
   if(poll(&p,1,int(timeout/1000000))<=0)throw std::runtime_error("control accept timeout");
   fd=accept4(listener,nullptr,nullptr,SOCK_CLOEXEC);::close(listener);
  } else {
   uint64_t start=now_ns();
   do {fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    if(fd>=0 && !connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a)))break;
    if(fd>=0)::close(fd);
    fd=-1;
    timespec delay{0,100000000};nanosleep(&delay,nullptr);
   }while(now_ns()-start<timeout);
  }
  if(fd<0)throw std::runtime_error("control connect failed");
  timeval tv{time_t(timeout/1000000000),suseconds_t((timeout%1000000000)/1000)};
  setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
 }
 void exchange(const std::string &value) {
  size_t at=0;
  while(at<value.size()) {ssize_t n=send(fd,value.data()+at,value.size()-at,MSG_NOSIGNAL);
   if(n<=0)throw std::runtime_error("control send failed");
   at+=size_t(n);}
  std::string remote(value.size(),'\0');at=0;
  while(at<remote.size()) {ssize_t n=recv(fd,&remote[at],remote.size()-at,0);
   if(n<=0)throw std::runtime_error("control receive failed");
   at+=size_t(n);}
  if(remote!=value)throw std::runtime_error("bilateral run configuration/barrier mismatch");
 }
};
static std::string handshake(const tp_eval_options &o) {
 // Fixed-width text avoids differing host endianness/struct padding.
 char text[512];snprintf(text,sizeof(text),"%016llx:%016llx:%016llx:%016llx:%016llx:%08x:%08x:%08x:%08x:%08x:%016llx",
  (unsigned long long)o.communicator,(unsigned long long)o.epoch,(unsigned long long)o.first_sequence,
  (unsigned long long)o.iterations,(unsigned long long)o.elements,o.rows>UINT_MAX?UINT_MAX:unsigned(o.rows),
  o.mode,o.depth,o.dtype,o.operation,(unsigned long long)o.rows);
 return text;
}
int main(int argc,char **argv) {
 tp_eval_options o;const char *node=nullptr,*bpf=nullptr,*user_bpf=nullptr,*tp_ptx=nullptr,*oracle=nullptr,*address=nullptr;
 unsigned port=0;bool have_rank=false;
 tp_eval_owner owner;barrier control;CUgraph graph=nullptr;CUgraphExec exec=nullptr;
 std::vector<xdev_tp_work*> works;
 try {
  for(int i=1;i<argc;++i) {
   std::string key=argv[i];if(i+1>=argc)throw std::runtime_error("argument needs value");const char *v=argv[++i];
   if(key=="--rank"){o.rank=small(v);have_rank=true;}
   else if(key=="--mode") {if(!strcmp(v,"d1"))o.mode=1;else if(!strcmp(v,"d2"))o.mode=2;else throw std::runtime_error("mode must be d1/d2");}
   else if(key=="--depth")o.depth=small(v);
   else if(key=="--dtype") {if(!strcmp(v,"f16"))o.dtype=1;else if(!strcmp(v,"bf16"))o.dtype=2;else if(!strcmp(v,"f32"))o.dtype=3;else throw std::runtime_error("dtype");}
   else if(key=="--operation") {if(!strcmp(v,"sum"))o.operation=1;else if(!strcmp(v,"all-gather"))o.operation=3;else if(!strcmp(v,"echo"))o.operation=4;else throw std::runtime_error("operation must be sum/all-gather/echo");}
   else if(key=="--elements")o.elements=number(v);
   else if(key=="--rows")o.rows=number(v);
   else if(key=="--iterations")o.iterations=number(v);
   else if(key=="--first-sequence")o.first_sequence=number(v);
   else if(key=="--communicator")o.communicator=number(v);
   else if(key=="--epoch")o.epoch=number(v);
   else if(key=="--link")o.link=number(v);
   else if(key=="--device")o.device=small(v);
   else if(key=="--timeout-ns")o.timeout_ns=number(v);
   else if(key=="--nvidia-node")node=v;
   else if(key=="--bpf-object")bpf=v;
   else if(key=="--user-bpf-object")user_bpf=v;
   else if(key=="--tp-ptx")tp_ptx=v;
   else if(key=="--oracle-ptx")oracle=v;
   else if(key=="--control-address")address=v;
   else if(key=="--control-port")port=small(v);
   else throw std::runtime_error("unknown argument: "+key);
  }
  NATIVE(tp_eval_geometry(o));
  if(!have_rank || !o.link || !node || !bpf || !user_bpf || !tp_ptx || !oracle || !address || !port ||
     o.timeout_ns/1000000>INT_MAX || o.timeout_ns<1000000)throw std::runtime_error("missing or invalid runtime prerequisites");
  // This socket only coordinates barriers. Payload never enters it.
  control.open(o.rank,address,port,o.timeout_ns);control.exchange(handshake(o));
  owner.open(o,node,bpf,user_bpf,oracle,tp_ptx);works.resize(o.depth,nullptr);
  if(o.operation==4) {
   std::unique_ptr<tp_eval_echo> echo;
   std::unique_ptr<tp_eval_echo_gpu> echo_gpu;
   if(o.mode==2){echo_gpu.reset(new tp_eval_echo_gpu(owner,o));echo_gpu->capture();}
   else echo.reset(new tp_eval_echo(owner,o));
   for(uint64_t iteration=0;iteration<o.iterations;++iteration) {
    control.exchange(std::string("echo-barrier:")+std::to_string(iteration));
    uint64_t start=now_ns();bool valid=echo_gpu?echo_gpu->exchange(iteration):echo->exchange(iteration);uint64_t end=now_ns();
    printf("{\"record\":\"interval\",\"start\":%llu,\"end\":%llu,\"rank\":%u,\"clock\":1,\"kind\":\"%s\",\"completed\":true,\"custody_released\":true}\n",
      (unsigned long long)start,(unsigned long long)end,o.rank,o.rank==0?"rtt":"echo_reply");
    printf("{\"record\":\"validation\",\"sequence\":%llu,\"rank\":%u,\"direction\":\"rx\",\"payload_bytes\":%u,\"valid\":%s}\n",
      (unsigned long long)(o.first_sequence+iteration),o.rank,o.group_bytes,valid?"true":"false");fflush(stdout);
   }
   printf("{\"record\":\"metadata\",\"execution_kind\":\"echo\",\"native_mode\":%u,\"handoff_mode\":\"%s\",\"rank\":%u,\"clock\":1,\"completed\":%llu,\"communicator\":%llu,\"epoch\":%llu,\"group_bytes\":%u}\n",
     o.mode,o.mode==1?"cpu":"gpu",o.rank,(unsigned long long)o.iterations,(unsigned long long)o.communicator,(unsigned long long)o.epoch,o.group_bytes);fflush(stdout);
   if(echo_gpu)echo_gpu->close();else echo->close();
   owner.close(o.timeout_ns);::close(control.fd);return 0;
  }
  if(o.mode==2) {
   std::vector<xdev_tp_request> requests(o.depth);
   for(unsigned j=0;j<o.depth;++j) {
    requests[j]={owner.inputs[j],owner.outputs[j],o.rows,o.elements,o.operation,o.dtype,0,0};
   }
   CU(cuStreamBeginCapture(owner.stream,CU_STREAM_CAPTURE_MODE_THREAD_LOCAL));
   int submitted=xdev_tp_submit_batch(owner.comm,requests.data(),requests.size(),owner.stream,o.first_sequence,works.data());
   // Preserve every partial non-null work on failure; never retry accepted I/O.
   NATIVE(submitted);
   CU(cuStreamEndCapture(owner.stream,&graph));
   CU(cuGraphInstantiate(&exec,graph,0));
  }
  for(uint64_t iteration=0;iteration<o.iterations;++iteration) {
   owner.fill_inputs(o,iteration);
   control.exchange(std::string("barrier:")+std::to_string(iteration));
   uint64_t start=now_ns();
   if(o.mode==1) {
    if(o.operation==1)NATIVE(xdev_tp_allreduce_sum(owner.comm,owner.inputs[0],owner.outputs[0],o.elements,
       xdev_tp_dtype(o.dtype),owner.stream,o.first_sequence+iteration,&works[0]));
    else NATIVE(xdev_tp_logits_gather(owner.comm,owner.inputs[0],owner.outputs[0],o.rows,o.elements,
       xdev_tp_dtype(o.dtype),0,1,owner.stream,o.first_sequence+iteration,&works[0]));
   } else CU(cuGraphLaunch(exec,owner.stream));
   CU(cuStreamSynchronize(owner.stream));
   for(auto w:works)NATIVE(xdev_tp_work_wait(w,o.timeout_ns));
   uint64_t end=now_ns();
   printf("{\"record\":\"interval\",\"start\":%llu,\"end\":%llu,\"rank\":%u,\"clock\":1,\"kind\":\"%s\",\"completed\":true,\"custody_released\":true}\n",
    (unsigned long long)start,(unsigned long long)end,o.rank,o.depth>1?"batch":(o.operation==1?"allreduce":"all_gather"));
   for(unsigned j=0;j<o.depth;++j) {
    xdev_tp_work_stats s{};s.size=sizeof(s);NATIVE(xdev_tp_work_get_stats(works[j],&s));
    uint64_t sequence=o.first_sequence+iteration*o.depth+j;
    if(s.failed || s.error || s.retained || !s.completed || s.last_sequence!=sequence ||
       s.invocations!=(o.mode==2?iteration+1:1))throw std::runtime_error("actual per-replay key/count/custody mismatch");
    bool valid=owner.validate(o,j,iteration);
    printf("{\"record\":\"validation\",\"sequence\":%llu,\"rank\":%u,\"direction\":\"rx\",\"payload_bytes\":%llu,\"valid\":%s}\n",
      (unsigned long long)sequence,o.rank,(unsigned long long)o.payload_bytes,valid?"true":"false");
    fflush(stdout);
    if(!valid)throw std::runtime_error("independent GPU payload mismatch");
    if(o.mode==1){NATIVE(xdev_tp_work_destroy(works[j]));works[j]=nullptr;}
   }
  }
  xdev_tp_stats stats{};stats.size=sizeof(stats);NATIVE(xdev_tp_get_stats(owner.comm,&stats));
  if(stats.failed || stats.error || stats.retained || stats.fallback_calls || stats.logical_inflight ||
     stats.completed!=o.iterations*o.depth || stats.last_use_released!=stats.completed || stats.tx_done!=stats.completed ||
     stats.rx_delivered!=stats.completed)throw std::runtime_error("native final accounting incomplete");
  std::vector<xdev_tp_trace_record> traces(o.trace_capacity);size_t written=0;
  NATIVE(xdev_tp_trace_read(owner.comm,traces.data(),traces.size(),&written));
  printf("{\"record\":\"metadata\",\"native_mode\":%u,\"handoff_mode\":\"%s\",\"communicator\":%llu,\"epoch\":%llu,\"rank\":%u,\"clock\":%u,\"trace_dropped\":%llu,\"requested_depth\":%u,\"native_high_water\":%llu,\"group_bytes\":%u,\"frame_count\":%u,\"frame_size\":4096,\"wire_header_bytes\":64,\"completed\":%llu,\"gpu_invocations\":%llu,\"host_control_calls\":%llu}\n",
   o.mode,o.mode==1?"cpu":"gpu",(unsigned long long)o.communicator,(unsigned long long)o.epoch,o.rank,o.mode==1?1:2,
   (unsigned long long)stats.trace_dropped,o.depth,(unsigned long long)stats.logical_inflight_high_water,
   o.group_bytes,o.frame_count,(unsigned long long)stats.completed,(unsigned long long)stats.gpu_invocations,
   (unsigned long long)stats.host_control_calls);
  for(size_t i=0;i<written;++i) {const auto &t=traces[i];
   printf("{\"record\":\"event\",\"sequence\":%llu,\"timestamp\":%llu,\"kind\":%u,\"clock\":%u,\"rank\":%u,\"payload_bytes\":%llu,\"wire_bytes\":%llu,\"logical_inflight\":%llu,\"operation\":%u,\"error\":%d}\n",
    (unsigned long long)t.sequence,(unsigned long long)t.timestamp,t.kind,t.clock,t.rank,
    (unsigned long long)t.payload_bytes,(unsigned long long)t.wire_bytes,(unsigned long long)t.logical_inflight,t.operation,t.error);
  }
  fflush(stdout);
  // Graph/exec destruction removes future storage references before work free.
  if(exec){CU(cuGraphExecDestroy(exec));exec=nullptr;}
  if(graph){CU(cuGraphDestroy(graph));graph=nullptr;}
  for(auto w:works)if(w)NATIVE(xdev_tp_work_destroy(w));
  owner.close(o.timeout_ns);::close(control.fd);
  return 0;
 } catch(const std::exception &e) {
  fprintf(stderr,"TP_EVAL_ERROR %s\n",e.what());fflush(stdout);fflush(stderr);
  if(owner.started) {
   // Native accepted work or graph storage may remain live. Keep the process,
   // context, both authority allocations and endpoints for explicit recovery.
   fputs("TP_EVAL_RETAINED native_or_gpu_custody_unknown\n",stderr);fflush(stderr);
   for(;;)pause();
  }
  return 2;
 }
}
