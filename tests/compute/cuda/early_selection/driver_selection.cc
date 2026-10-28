// SPDX-License-Identifier: GPL-2.0
// Actual parser, owner forwarding prefix, handshake and bilateral preflight.
#include <atomic>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <thread>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include "peer_endpoint_owner.h"
#include EARLY_TP_OPTIONS
static unsigned failures;
static void check(bool ok,const char *why){if(!ok){++failures;std::cerr<<"DRIVER_ASSERT "<<why<<"\n";}}
static void native_check(int rc){if(rc)throw std::runtime_error(std::to_string(rc));}
#define NATIVE(call) native_check(call)
#include EARLY_TP_NUMBERS
#include EARLY_TP_HANDSHAKE
#include EARLY_TP_BARRIER
#include EARLY_TP_METADATA
// Frozen shape adaptation: old options have no request and behave as default0.
// New options use the declared field directly; no runtime success fallback.
template<class T>static auto request_value(const T &o,int)->decltype(o.early_cts){return o.early_cts;}
template<class T>static unsigned request_value(const T &,long){return 0;}
template<class T>static auto set_request(T &o,unsigned value,int)->decltype(o.early_cts=value,void()){o.early_cts=value;}
template<class T>static void set_request(T &,unsigned,long){}
static unsigned observed_flags,observed_mode,owner_calls;
static bool partial_open;
extern "C" int xdev_ext_cuda_peer_owner_open(const xdev_ext_cuda_peer_owner_opts *o,xdev_ext_cuda_peer_owner **p){
 ++owner_calls;observed_mode=o->mode;observed_flags=0;*p=reinterpret_cast<xdev_ext_cuda_peer_owner *>(1);return partial_open?-EIO:0;
}
extern "C" int xdev_ext_cuda_peer_owner_open_flags(const xdev_ext_cuda_peer_owner_opts *o,uint32_t flags,xdev_ext_cuda_peer_owner **p){
 ++owner_calls;observed_mode=o->mode;observed_flags=flags;*p=reinterpret_cast<xdev_ext_cuda_peer_owner *>(1);return partial_open?-EIO:0;
}
struct OwnerPrefix {
 xdev_ext_cuda_peer_owner *bootstrap=nullptr;bool started=false;
 void open(const tp_eval_options &o){const char *node="node",*bpf="bpf",*user_bpf="user";
#include EARLY_TP_OWNER_PREFIX
 }
};
static tp_eval_options parse(int argc,char **argv){
 tp_eval_options o;const char *node=nullptr,*bpf=nullptr,*user_bpf=nullptr,*tp_ptx=nullptr,*oracle=nullptr,*address=nullptr;
 unsigned port=0;bool have_rank=false;
 (void)node;(void)bpf;(void)user_bpf;(void)tp_ptx;(void)oracle;(void)address;(void)port;(void)have_rank;
#include EARLY_TP_PARSER
 return o;
}
static std::atomic<unsigned> bilateral_opens{0};
struct PeerOwner {void open(const tp_eval_options &o,const char*,const char*,const char*,const char*,const char*){
 check(o.mode==1 || o.mode==2,"serialized EARLY bit never changes actual native mode");++bilateral_opens;
}};
struct PairControl:actual_barrier {int supplied=-1;void open(unsigned,const char*,unsigned,uint64_t){fd=supplied;}};
static void peer(tp_eval_options o,int fd,bool &rejected){
 PairControl control;control.supplied=fd;PeerOwner owner;
 const char *address="unused",*node="node",*bpf="bpf",*user_bpf="user",*oracle="oracle",*tp_ptx="tp";
 unsigned port=1;
 try{
#include EARLY_TP_PREFLIGHT
 }catch(const std::exception&){rejected=true;}
}
int main(int argc,char **argv){
 assert(argc>=2);std::string kind=argv[1];
 if(kind=="parse"){
  unsigned expected=unsigned(std::stoul(argv[2]));bool accepted=false;tp_eval_options o;
  try{o=parse(argc-3,argv+3);accepted=true;}catch(const std::exception&){}
  check(accepted,"actual TP CLI accepts explicit EARLY selection");
  if(accepted){check(request_value(o,0)==expected,"actual TP parser retains requested selection");check(o.mode==1 || o.mode==2,"actual native mode remains1/2");}
 }else if(kind=="invalid"){
  bool rejected=false;try{(void)parse(argc-2,argv+2);}catch(const std::exception&){rejected=true;}
  check(rejected,"invalid selection rejected by actual parser/geometry before owner side effects");check(!owner_calls,"invalid input never opens owner");
 }else if(kind=="geometry"){
  tp_eval_options o;set_request(o,2,0);check(tp_eval_geometry(o)==-EINVAL,"actual geometry rejects early_cts above1");
 }else if(kind=="owner"){
  unsigned mode=unsigned(std::stoul(argv[2])),selected=unsigned(std::stoul(argv[3]));partial_open=std::stoul(argv[4])!=0;
  tp_eval_options o;o.mode=mode;set_request(o,selected,0);check(!tp_eval_geometry(o),"legal EARLY owner geometry");
  OwnerPrefix owner;bool rejected=false;try{owner.open(o);}catch(const std::exception&){rejected=true;}
  check(owner_calls==1 && observed_mode==mode,"actual owner prefix forwards mode once");
  check(observed_flags==(selected?2U:0U),"actual TP owner forwards EARLY to CUDA entrypoint");
  check(rejected==partial_open,"partial open status retained");check(owner.started&&owner.bootstrap,"actual partial bootstrap ownership remains inspectable");
 }else if(kind=="metadata"){
  tp_eval_options o;o.mode=unsigned(std::stoul(argv[2]));set_request(o,unsigned(std::stoul(argv[3])),0);
  actual_metadata(o,std::strcmp(argv[4],"echo")==0);return 0;
 }else{
  unsigned mode=unsigned(std::stoul(argv[2]));bool mixed=kind=="mixed";unsigned selected=kind=="ordinary"?0:1;
  tp_eval_options left;left.mode=mode;left.operation=4;left.communicator=7;left.epoch=9;left.first_sequence=23;left.iterations=2;left.elements=16;
  tp_eval_options right=left;right.rank=1;set_request(left,selected,0);set_request(right,mixed?0:selected,0);
  std::string expected="0000000000000007:0000000000000009:0000000000000017:0000000000000002:0000000000000010:00000001:";
  expected+=(selected?(mode==1?"80000001":"80000002"):(mode==1?"00000001":"00000002"));
  expected+=":00000001:00000003:00000004:0000000000000001";
  check(handshake(left)==expected,"actual handshake preserves ordinary bytes and encodes EARLY only in mode bit31");
  check(handshake(left).size()==handshake(right).size(),"mixed selection keeps fixed wire length");
  int fds[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,fds));bool rejected[2]={false,false};
  std::thread first(peer,left,fds[0],std::ref(rejected[0])),second(peer,right,fds[1],std::ref(rejected[1]));first.join();second.join();
  ::close(fds[0]);::close(fds[1]);
  check(rejected[0]==mixed&&rejected[1]==mixed,"both real handshake exchanges reject mixed EARLY selection");
  check(bilateral_opens==(mixed?0U:2U),"actual preflight refuses mixed selection before either owner opens");
 }
 std::cout<<"DRIVER_SELECTION case="<<kind<<" failures="<<failures<<"\n";return failures?1:0;
}
