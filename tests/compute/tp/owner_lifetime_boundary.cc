// SPDX-License-Identifier: GPL-2.0
// Actual complete owner TU. Only CUDA/OS/message/control call boundaries vary.
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cuda.h>
#include <linux/xdev_ext_peer.h>
static int owner_os_open(const char *,int,...);
static int owner_os_close(int);
static int owner_os_ioctl(int,unsigned long,...);
#define open owner_os_open
#define close owner_os_close
#define ioctl owner_os_ioctl
#include TP_OWNER_SOURCE
#undef open
#undef close
#undef ioctl
/* The real kernel registry lives in a C translation unit; C++ does not support
 * its unmodified C array-designated class table. No lookup is duplicated here. */
extern "C" int owner_registry_attach(unsigned,const void *);
extern "C" int owner_registry_detach(unsigned,const void *);
extern "C" bool owner_registry_has(unsigned);
struct xdev_ext_peer_endpoint {unsigned index;};
struct xdev_ext_cuda_user {unsigned index;};
static std::string fault;
static unsigned allocs,frees,registrations,closes,control_opens,control_closes,endpoint_creates,endpoint_closes,endpoint_stops;
static unsigned event_records,event_syncs,context_creates,context_destroys,stream_creates,stream_destroys;
static unsigned create_controls[2],allocation_fds[2],stop_before_free;
static CUdeviceptr registered_va[2];
static std::map<CUdeviceptr,size_t> live_allocations;
static std::map<int,bool> live_fds;
static struct xdev_ext_peer_endpoint endpoints[2]={{0},{1}};
static struct xdev_ext_cuda_user controls[3]={{0},{1},{2}};
static int owner_os_open(const char *,int,...){int fd=10+int(live_fds.size());live_fds[fd]=true;return fd;}
static int owner_os_close(int fd){assert(live_fds[fd]);live_fds[fd]=false;closes++;if(fault=="authority_close"&&fd==100){errno=EIO;return -1;}return 0;}
static int owner_os_ioctl(int fd,unsigned long op,...){
 assert(fd>=10&&op==XDEV_EXT_PEER_REGISTER);va_list ap;va_start(ap,op);auto *r=va_arg(ap,xdev_ext_peer_register *);va_end(ap);
 unsigned i=registrations++;registered_va[i]=r->gpu_va;
 if(fault=="register_second"&&i==1){errno=EIO;return -1;}
 r->generation=31+i;int result=100+int(i);live_fds[result]=true;return result;
}
CUresult cuInit(unsigned){return CUDA_SUCCESS;}
CUresult cuDeviceGet(CUdevice *d,int){*d=0;return CUDA_SUCCESS;}
CUresult cuCtxCreate(CUcontext *c,void *,unsigned,CUdevice){context_creates++;*c=reinterpret_cast<void *>(1);return CUDA_SUCCESS;}
CUresult cuCtxDestroy(CUcontext){context_destroys++;return CUDA_SUCCESS;}
CUresult cuCtxGetDevice(CUdevice *d){*d=0;return CUDA_SUCCESS;}
CUresult cuStreamCreate(CUstream *s,unsigned){stream_creates++;*s=reinterpret_cast<void *>(2);return CUDA_SUCCESS;}
CUresult cuStreamDestroy(CUstream){stream_destroys++;return CUDA_SUCCESS;}
CUresult cuCtxGetCurrent(CUcontext *c){*c=reinterpret_cast<void *>(1);return CUDA_SUCCESS;}
CUresult cuStreamGetCtx(CUstream,CUcontext *c){*c=reinterpret_cast<void *>(1);return CUDA_SUCCESS;}
CUresult cuStreamIsCapturing(CUstream,CUstreamCaptureStatus *s){*s=CU_STREAM_CAPTURE_STATUS_NONE;return CUDA_SUCCESS;}
CUresult cuMemAlloc(CUdeviceptr *p,size_t bytes){
 if(fault=="mem_second"&&allocs==1){allocs++;return CUDA_ERROR_UNKNOWN;}
 void *m=std::malloc(bytes);assert(m);*p=reinterpret_cast<uintptr_t>(m);live_allocations[*p]=bytes;allocs++;return CUDA_SUCCESS;
}
CUresult cuMemFree(CUdeviceptr p){assert(live_allocations.count(p));if(fault=="mem_free")return CUDA_ERROR_UNKNOWN;stop_before_free=endpoint_stops;frees++;std::free(reinterpret_cast<void *>(p));live_allocations.erase(p);return CUDA_SUCCESS;}
CUresult cuPointerSetAttribute(const void *,int,CUdeviceptr){return CUDA_SUCCESS;}
CUresult cuEventCreate(CUevent *e,unsigned){*e=reinterpret_cast<void *>(3);return CUDA_SUCCESS;}
CUresult cuEventRecord(CUevent,CUstream){event_records++;return fault=="event_record"?CUDA_ERROR_UNKNOWN:CUDA_SUCCESS;}
CUresult cuEventSynchronize(CUevent){event_syncs++;return fault=="event_sync"?CUDA_ERROR_UNKNOWN:CUDA_SUCCESS;}
CUresult cuEventDestroy(CUevent){return CUDA_SUCCESS;}
extern "C" int xdev_ext_link_discover(const char *,__u64 token,xdev_ext_link_snapshot *s){*s={};s->token=token;s->channels=1;s->up=1;return 0;}
static int user_ops_token,xdomain_ops_token;
extern "C" int xdev_ext_prog_attach(const xdev_ext_prog_opts *o,xdev_ext_prog **p){
 unsigned id=!std::strcmp(o->map_name,"user_plan_ops")?XDEV_EXT_MECH_CLASS_USER:XDEV_EXT_MECH_CLASS_XDOMAIN;
 const void *ops=id==XDEV_EXT_MECH_CLASS_USER?static_cast<void *>(&user_ops_token):static_cast<void *>(&xdomain_ops_token);
 int rc=owner_registry_attach(id,ops);
 if(!rc)*p=reinterpret_cast<xdev_ext_prog *>(const_cast<void *>(ops));return rc;
}
extern "C" int xdev_ext_prog_detach(xdev_ext_prog *p){
 unsigned id=p==reinterpret_cast<xdev_ext_prog *>(&user_ops_token)?XDEV_EXT_MECH_CLASS_USER:XDEV_EXT_MECH_CLASS_XDOMAIN;
 return owner_registry_detach(id,p);
}
extern "C" int xdev_ext_peer_endpoint_open(const xdev_ext_peer_endpoint_opts *o,xdev_ext_peer_endpoint **p){unsigned i=o->direction==XDEV_EXT_MECH_DIR_FROM_DEVICE;allocation_fds[i]=o->allocation_fd;*p=&endpoints[i];return 0;}
extern "C" int xdev_ext_peer_endpoint_create(xdev_ext_peer_endpoint *p){
 create_controls[p->index]=control_opens;endpoint_creates++;
 if(fault=="required_classes"){
  if(!owner_registry_has(XDEV_EXT_MECH_CLASS_USER)||!owner_registry_has(XDEV_EXT_MECH_CLASS_XDOMAIN))return -EOPNOTSUPP;
 }
 return 0;
}
extern "C" xdev_ext_user_stage *xdev_ext_peer_endpoint_user(xdev_ext_peer_endpoint *p,xdev_ext_peer_role role){return reinterpret_cast<xdev_ext_user_stage *>(uintptr_t(1+p->index*4+role));}
extern "C" int xdev_ext_peer_endpoint_start(xdev_ext_peer_endpoint *,const xdev_ext_start_frames_opts *){return 0;}
extern "C" int xdev_ext_peer_endpoint_stop(xdev_ext_peer_endpoint *){endpoint_stops++;return fault=="native_stop"?-EBUSY:0;}
extern "C" int xdev_ext_peer_endpoint_close(xdev_ext_peer_endpoint *){endpoint_closes++;return fault=="endpoint_close"?-EBUSY:0;}
extern "C" int xdev_ext_cuda_user_open(xdev_ext_user_stage *,CUcontext,CUdeviceptr,unsigned long long,unsigned,xdev_ext_cuda_user **p){*p=&controls[control_opens++];return 0;}
extern "C" int xdev_ext_cuda_user_close(xdev_ext_cuda_user *,CUstream){control_closes++;return fault=="control_close"?-EBUSY:0;}
static unsigned failures;
static void check(bool value,const char *why){if(!value){failures++;std::cerr<<"OWNER_ASSERT "<<why<<'\n';}}
int main(int argc,char **argv){
 assert(argc==3);fault=argv[1];setenv("XDEV_EXT_CUDA_PTX",argv[2],1);
 xdev_ext_cuda_peer_owner_opts opts{};opts.size=sizeof(opts);opts.version=1;opts.mode=2;opts.context_mode=XDEV_EXT_CUDA_PEER_BORROW_CURRENT;
 opts.context=reinterpret_cast<void *>(1);opts.stream=reinterpret_cast<void *>(2);opts.nvidia_node="mock-node";opts.bpf_object="mock-bpf";
 opts.link_token=7;opts.allocation_bytes=65536;opts.nr_batches=4;opts.first_sequence=23;opts.timeout_ns=1000000;opts.group_bytes=128;opts.depth=2;
 opts.user_bpf_object="mock-user-bpf";
 xdev_ext_cuda_peer_owner *owner=nullptr;int opened=xdev_ext_cuda_peer_owner_open(&opts,&owner);
 bool partial=fault=="mem_second"||fault=="register_second";
 check(partial?opened<0:opened==0,"owner open result follows allocation/registration boundary");
 check(owner!=nullptr,"partial and full ownership remain inspectable");
 if(!partial){
  check(allocs==2&&registrations==2&&allocation_fds[0]!=allocation_fds[1]&&registered_va[0]!=registered_va[1],"duplex endpoint uses two independent allocations and authority FDs");
  check(create_controls[0]==3&&create_controls[1]==3,"all three d2 controls attach before either session CREATE");
  check(!xdev_ext_cuda_peer_owner_start(owner),"actual owner START succeeds");
 }
 int closed=xdev_ext_cuda_peer_owner_close(&owner);
 bool unknown=fault!="success"&&fault!="required_classes"&&!partial;
 check(unknown?closed<0:closed==0,"close propagates unknown usage without declaring success");
 check(unknown?owner!=nullptr:owner==nullptr,"only successful close clears the owner handle");
 check(!context_creates&&!context_destroys&&!stream_creates&&!stream_destroys,"borrowed context and caller stream are never created or destroyed");
 if(unknown){check(!live_allocations.empty(),"unknown close retains remaining CUDA allocation ownership");
  if(fault!="mem_free")check(frees==0,"unknown use cannot free allocation payload");
 }else{check(live_allocations.empty(),"successful close releases every owned allocation");
  check(event_records&&event_syncs,"successful close requires actual event record and synchronization");
  if(!partial)check(stop_before_free==2&&endpoint_closes==2&&control_closes==3,"native stops/control close precede CUDA allocation free");
 }
 if(fault=="event_record"||fault=="event_sync")check(!endpoint_stops&&!control_closes&&!endpoint_closes&&!closes,"event failure retains all native resources");
 std::cout<<"OWNER_LIFETIME "<<fault<<" opened="<<opened<<" close="<<closed<<" live_allocations="<<live_allocations.size()<<" failures="<<failures<<'\n';
 return !!failures;
}
