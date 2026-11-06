// SPDX-License-Identifier: GPL-2.0
// Real production owner/endpoint/session/USER/CUDA USER control code.
// CUDA ABI answers are opaque control tokens from official headers. No GPU
// payload, launch, simulated completion, SDK runtime or native BPF runs here.
#include "peer_endpoint_owner.h"
#include "libxdev_ext_internal.h"
#include <linux/xdev_ext_peer.h>
#include <linux/bpf.h>
#include "uapi/linux/io_uring.h"
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>
#include <map>

extern "C" int declarations_c();
int declarations_cpp();
extern "C" int __real_close(int);
static unsigned checks,failures;
static std::string label;
static void eq(const char *what,long long got,long long want) {
 ++checks;if(got!=want){++failures;fprintf(stderr,"FAIL %s %s got=%lld want=%lld\n",label.c_str(),what,got,want);}
}
#define EQ(what,got,want) eq(what,(long long)(got),(long long)(want))
static void forbidden(const char *what){fprintf(stderr,"FORBIDDEN unexpected native boundary: %s\n",what);std::abort();}
struct Pin{int fd;std::string path;int closed=0;};
struct Allocation{CUdeviceptr base;size_t bytes;bool freed=false;};
static std::vector<Pin> pins;
static std::vector<Allocation> gpu_allocations;
static unsigned mask_value=0,need_classes=3,ordinary_calls,program_calls,lookups,attaches[2],detaches[2],create_calls,ctl_attached,ctl_detached;
static unsigned seen_program_fds[2];
static bool opaque_fd0_owned=false;
static int lookup_fail=-1,attach_fail=-1,create_fail=-1,create_errno=-EINVAL,stop_errno=0,event_failure=0,unregister_failure=0,ring_failure=-1,ring_setups=0;
static bool stats_released=false,force_fd0=false,bad_report=false;
static int expected_endpoint=-1;
static unsigned endpoint_flags=0,owner_mode=1;
static int resources_closed=0,mem_freed=0,events_destroyed=0,cuda_modules=0;
static CUcontext context=reinterpret_cast<CUcontext>(uintptr_t(0x1010));
static CUstream stream=reinterpret_cast<CUstream>(uintptr_t(0x2020));
static const char *paths[5]={"/sys/fs/bpf/test/tx-producer","/sys/fs/bpf/test/tx-xdomain","/sys/fs/bpf/test/tx-terminal","/sys/fs/bpf/test/rx-xdomain","/sys/fs/bpf/test/rx-consumer"};
static const unsigned needs[32]={3,3,3,3,3,3,3,3,3,3,1,1,3,3,1,1,3,3,3,3,3,2,3,2,3,3,1,1,3,2,1,0};
static std::vector<std::vector<int>> captured_selectors;
static std::map<int,bool> sessions_released,user_fds_closed;
static std::map<int,__u64> control_session_ids;
static int anon_fd(const char *name,size_t bytes=4096,bool cloexec=true){int fd=memfd_create(name,cloexec?MFD_CLOEXEC:0);if(fd<0||ftruncate(fd,bytes))forbidden("test memfd");if(fd==0)opaque_fd0_owned=true;return fd;}
static int get_pin(const char *path){
 unsigned at=lookups++;
 if(int(at)==lookup_fail){errno=EACCES;return -1;}
 if(!path||path[0]!='/')forbidden("invalid pin reached BPF_OBJ_GET");
 int fd=anon_fd("private-link-reference",4096,true);
 if(force_fd0&&pins.empty()){if(fd!=0){if(dup2(fd,0)!=0)forbidden("test fd0");__real_close(fd);}fd=0;if(fcntl(fd,F_SETFD,FD_CLOEXEC))forbidden("test fd0 CLOEXEC");}
 pins.push_back({fd,path,0});return fd;
}
extern "C" int bpf_obj_get(const char *pathname){return get_pin(pathname);}
extern "C" long __wrap_syscall(long number,...){
 va_list ap;va_start(ap,number);
 if(number==__NR_bpf){int cmd=va_arg(ap,int);auto *attr=va_arg(ap,union bpf_attr*);(void)va_arg(ap,unsigned int);va_end(ap);
  if(cmd!=BPF_OBJ_GET)forbidden("BPF operation other than OBJ_GET");
  return get_pin(reinterpret_cast<const char*>(uintptr_t(attr->pathname)));
 }
 va_end(ap);forbidden("unhooked syscall");return -1;
}
extern "C" int __wrap_open(const char *path,int,...){
 if(!strcmp(path,"/dev/nvidia-control-test"))return anon_fd("opaque-nvidia-file");
 if(!strcmp(path,"/dev/xdev_ext_peer"))return anon_fd("opaque-peer-file");
 forbidden("device/path open");return -1;
}
extern "C" int __wrap_close(int fd){
 for(auto &p:pins)if(p.fd==fd&&!p.closed){
  for(auto &entry:sessions_released)EQ("pin-close-after-session-release",entry.second,1);
  for(auto &entry:user_fds_closed)EQ("pin-close-after-USER-close",entry.second,1);
  EQ("pin-close-after-controller-close",ctl_detached,ctl_attached);
  ++p.closed;return __real_close(fd);
 }
 // Resource classification comes from the opaque control descriptors we
 // actually acquired. A valid owned metadata/controller FD0 is allowed;
 // PRIVATE cleanup must not close the process's untouched stdin FD0.
 if(fd==0&&!opaque_fd0_owned){EQ("PRIVATE-cleanup-must-not-close-unowned-stdio0",1,0);errno=EBADF;return -1;}
 if(fd==0)opaque_fd0_owned=false;
 if(user_fds_closed.count(fd))user_fds_closed[fd]=true;
 ++resources_closed;return __real_close(fd);
}
extern "C" int __wrap_ioctl(int,unsigned long request,...){
 va_list ap;va_start(ap,request);auto *arg=va_arg(ap,void*);va_end(ap);
 if(request!=XDEV_EXT_PEER_REGISTER)forbidden("owner ioctl");
 auto *r=static_cast<xdev_ext_peer_register*>(arg);r->generation=1;return anon_fd("opaque-allocation-authority");
}
static int sys_setup(unsigned,io_uring_params*){if(++ring_setups==ring_failure)return -EIO;return anon_fd("opaque-uring-control");}
static void compare_create(const xdev_ext_mech_create &c,const int *fds){
 unsigned endpoint=expected_endpoint>=0?unsigned(expected_endpoint):(create_calls-1)%2,base=endpoint?3:0,count=endpoint?2:3;
 EQ("active-stage-count",c.nr_stages,count);EQ("pool-authority-kind",c.pool_kind,XDEV_EXT_MECH_POOL_PEER);EQ("pool-fd-live",fcntl(c.pool_fd,F_GETFD)>=0,1);
 for(unsigned i=0;i<count;i++){
  unsigned slot=base+i;bool xd=slot==1||slot==3;
  EQ("stage-class",c.st[i].class_id,xd?11:10);
  EQ("stage-direction",c.st[i].direction,xd&&endpoint?2:1);
  EQ("stage-authority-live",fcntl(c.st[i].fd,F_GETFD)>=0,1);
  EQ("stage-flags",c.st[i].flags,xd?(endpoint_flags?2:0):(XDEV_EXT_USER_F_STRICT_ASYNC|XDEV_EXT_MECH_STAGE_F_POLL));
  if(fds){
   if(!(mask_value&(1U<<slot)))EQ("default-selector",fds[i],-1);
   else {
    bool matched=false;for(auto &p:pins)if(!p.closed&&p.fd==fds[i]&&p.path==paths[slot])matched=true;
    EQ("per-slot-owned-selector",matched,1);EQ("selected-FD-CLOEXEC",fcntl(fds[i],F_GETFD)&FD_CLOEXEC,FD_CLOEXEC);
   }
  }
 }
 if(fds){for(unsigned i=count;i<4;i++)EQ("inactive-selector",fds[i],-1);captured_selectors.emplace_back(fds,fds+count);seen_program_fds[endpoint]=count;}
}
static int sys_register(int ring,unsigned opcode,void *arg,unsigned){
 if(opcode!=IORING_REGISTER_XDEV_EXT_MECH)forbidden("uring registration opcode");
 auto *r=static_cast<io_uring_xdev_ext_mech*>(arg);
 if(r->op==XDEV_EXT_MECH_OP_USER_STAGE){
  auto *u=reinterpret_cast<xdev_ext_mech_user_stage*>(uintptr_t(r->arg));
  EQ("mode-external-controller",u->flags,owner_mode==2?XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL:0);
  u->off.hdr=0;u->off.ready=64;u->off.done=u->off.ready+u->entries*sizeof(xdev_ext_user_ready);
  u->off.slots=u->off.done+u->entries*sizeof(xdev_ext_user_done);u->off.mmap_size=u->off.slots+u->entries*sizeof(xdev_ext_user_slot);
  u->fd=anon_fd("user-control-metadata",u->off.mmap_size);user_fds_closed[u->fd]=false;return 0;
 }
 if(r->op==XDEV_EXT_MECH_OP_CREATE){
  ++ordinary_calls;++create_calls;auto *c=reinterpret_cast<xdev_ext_mech_create*>(uintptr_t(r->arg));compare_create(*c,nullptr);
  if(int(create_calls)==create_fail)return create_errno;
  c->session_id=100+create_calls;sessions_released[ring]=false;control_session_ids[ring]=c->session_id;return 0;
 }
 if(r->op==XDEV_EXT_MECH_OP_CREATE_PROGRAMS){
  ++program_calls;++create_calls;auto *p=reinterpret_cast<xdev_ext_mech_create_programs*>(uintptr_t(r->arg));compare_create(p->request.create,p->program_fds);
  auto &report=p->request.report;report.size=sizeof(report);report.version=XDEV_EXT_MECH_CREATE_REPORT_VERSION;report.failed_stage=UINT32_MAX;
  if(bad_report)report.version=999;
  if(int(create_calls)==create_fail){report.result=create_errno;report.phase=XDEV_EXT_MECH_CREATE_CLASS_LOOKUP;return 0;}
  report.session_id=100+create_calls;p->request.create.session_id=report.session_id;sessions_released[ring]=false;control_session_ids[ring]=report.session_id;return 0;
 }
 if(r->op==XDEV_EXT_MECH_OP_STOP){if(!stop_errno)sessions_released[ring]=true;return stop_errno;}
 if(r->op==XDEV_EXT_MECH_OP_STATS){if(stats_released)sessions_released[ring]=true;return stats_released?-ENOENT:0;}
 if(r->op==XDEV_EXT_MECH_OP_NOTIFY_ARM){
  // Actual session_start_frames arms one control notification before START.
  // This observes the bounded ABI request only: no event, completion or GPU
  // work is manufactured by returning successful control-plane delivery.
  EQ("NOTIFY_ARM-nonnull-request",r->arg!=0,1);
  if(!r->arg)return -EINVAL;
  const auto *arm=reinterpret_cast<const xdev_ext_mech_notify_arm*>(uintptr_t(r->arg));
  EQ("NOTIFY_ARM-existing-session",control_session_ids.count(ring),1);
  EQ("NOTIFY_ARM-session-id",arm->session_id,control_session_ids[ring]);
  EQ("NOTIFY_ARM-owner-batches-target",arm->batches_target,1);
  EQ("NOTIFY_ARM-no-published-target",arm->published_target,0);
  EQ("NOTIFY_ARM-zero-flags",arm->flags,0);
  EQ("NOTIFY_ARM-zero-reserved",arm->rsvd,0);
  return 0;
 }
 if(r->op==XDEV_EXT_MECH_OP_START)return 0;
 forbidden("unexpected mech operation");return -EINVAL;
}
static int sys_ioctl(int,unsigned long request,unsigned long){
 if(request==XDEV_EXT_USER_IOC_CTL_ATTACH){++ctl_attached;return 0;}
 if(request==XDEV_EXT_USER_IOC_CTL_DETACH){++ctl_detached;return 0;}
 forbidden("USER ioctl other than control attach/detach");return -EINVAL;
}
extern "C" int xdev_ext_link_discover(const char*,__u64 token,xdev_ext_link_snapshot *out){*out={};out->token=token;return 0;}
struct xdev_ext_prog{unsigned kind;};
extern "C" int xdev_ext_prog_attach(const xdev_ext_prog_opts *o,xdev_ext_prog **out){
 unsigned kind=!strcmp(o->map_name,"xdomain_peer_ops")?1:0;++attaches[kind];
 if(int(kind)==attach_fail)return -EBUSY;
 *out=new xdev_ext_prog{kind};return 0;
}
extern "C" int xdev_ext_prog_detach(xdev_ext_prog *p){++detaches[p->kind];delete p;return 0;}
// Network code is outside this PEER-only control cohort. These link boundaries
// abort if reached; they never synthesize a successful network operation.
#include "xdev_ext_xsk_shared.h"
extern "C" int xdev_ext_xsk_shared_preflight(const xdev_ext_xsk_shared*,xdev_ext_xsk_shared_error*){forbidden("network preflight");return -1;}
extern "C" int xdev_ext_xsk_shared_close(xdev_ext_xsk_shared*,xdev_ext_xsk_shared_error*){forbidden("network close");return -1;}
// A transmit-only zero-copy XSK session's XDP mode: a PEER session never owns
// a program, so ownership queries answer none and any XDP operation aborts.
extern "C" void xdev_ext_xsk_redirect_init(xdev_ext_xsk_redirect *r){*r=xdev_ext_xsk_redirect{};r->map_fd=r->prog_fd=-1;}
extern "C" bool xdev_ext_xsk_redirect_is_active(const xdev_ext_xsk_redirect *r){return r&&(r->attached||r->mapped);}
extern "C" int xdev_ext_xsk_redirect_zc_tx_xdp(xdev_ext_xsk_redirect*,int,int,uint32_t){forbidden("zero-copy TX XDP mode");return -1;}
extern "C" int xdev_ext_xsk_redirect_detach(xdev_ext_xsk_redirect*){forbidden("XDP detach");return -1;}

// All prototypes/types come from actual NVIDIA cuda.h. Only API control
// tokens and status codes are supplied; no PTX, payload or kernel executes.
extern "C" CUresult CUDAAPI cuInit(unsigned){return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuDeviceGet(CUdevice *d,int i){*d=i;return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuCtxCreate(CUcontext *c,CUctxCreateParams*,unsigned,CUdevice){*c=context;return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuCtxGetCurrent(CUcontext *c){*c=context;return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuCtxGetDevice(CUdevice *d){*d=0;return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuCtxGetId(CUcontext,unsigned long long *id){*id=11;return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuStreamGetId(CUstream,unsigned long long *id){*id=22;return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuStreamCreate(CUstream *s,unsigned){*s=stream;return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuStreamGetCtx(CUstream,CUcontext *c){*c=context;return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuStreamIsCapturing(CUstream,CUstreamCaptureStatus *status){*status=CU_STREAM_CAPTURE_STATUS_NONE;return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuMemAlloc(CUdeviceptr *p,size_t bytes){*p=UINT64_C(0x100000)+gpu_allocations.size()*UINT64_C(0x100000);gpu_allocations.push_back({*p,bytes,false});return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuMemFree(CUdeviceptr p){for(auto &a:gpu_allocations)if(a.base==p&&!a.freed){a.freed=true;++mem_freed;return CUDA_SUCCESS;}forbidden("unknown GPU allocation free");return CUDA_ERROR_INVALID_VALUE;}
extern "C" CUresult CUDAAPI cuPointerSetAttribute(const void*,CUpointer_attribute,CUdeviceptr){return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuPointerGetAttribute(void *out,CUpointer_attribute a,CUdeviceptr){
 if(a==CU_POINTER_ATTRIBUTE_CONTEXT)*static_cast<CUcontext*>(out)=context;
 else if(a==CU_POINTER_ATTRIBUTE_MEMORY_TYPE)*static_cast<CUmemorytype*>(out)=CU_MEMORYTYPE_DEVICE;
 else if(a==CU_POINTER_ATTRIBUTE_IS_MANAGED)*static_cast<unsigned*>(out)=0;
 else forbidden("unimplemented pointer attribute");
 return CUDA_SUCCESS;
}
extern "C" CUresult CUDAAPI cuMemGetAddressRange(CUdeviceptr *base,size_t *bytes,CUdeviceptr p){for(auto &a:gpu_allocations)if(p>=a.base&&p-a.base<a.bytes){*base=a.base;*bytes=a.bytes;return CUDA_SUCCESS;}return CUDA_ERROR_INVALID_VALUE;}
extern "C" CUresult CUDAAPI cuDeviceGetAttribute(int *v,CUdevice_attribute a,CUdevice){*v=a==CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_WRITES_ORDERING?CU_GPU_DIRECT_RDMA_WRITES_ORDERING_OWNER:1;return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuModuleLoad(CUmodule *m,const char*){*m=reinterpret_cast<CUmodule>(uintptr_t(0x3030+cuda_modules++));return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuModuleGetFunction(CUfunction *f,CUmodule,const char*){*f=reinterpret_cast<CUfunction>(uintptr_t(0x4040));return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuModuleUnload(CUmodule){return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuMemHostRegister(void*,size_t,unsigned){return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuMemHostUnregister(void*){return unregister_failure?CUDA_ERROR_UNKNOWN:CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuMemHostGetDevicePointer(CUdeviceptr *p,void*,unsigned){*p=UINT64_C(0x80000000);return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuEventCreate(CUevent *event,unsigned){*event=reinterpret_cast<CUevent>(uintptr_t(0x5050));return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuEventRecord(CUevent,CUstream){return event_failure==1?CUDA_ERROR_UNKNOWN:CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuEventSynchronize(CUevent){return event_failure==2?CUDA_ERROR_UNKNOWN:CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuEventDestroy(CUevent){++events_destroyed;return CUDA_SUCCESS;}
extern "C" CUresult CUDAAPI cuStreamDestroy(CUstream){forbidden("destroy borrowed stream");return CUDA_ERROR_INVALID_VALUE;}
extern "C" CUresult CUDAAPI cuCtxDestroy(CUcontext){forbidden("destroy borrowed context");return CUDA_ERROR_INVALID_VALUE;}
extern "C" CUresult CUDAAPI cuStreamSynchronize(CUstream){forbidden("no launched payload in control cohort");return CUDA_ERROR_INVALID_VALUE;}
extern "C" CUresult CUDAAPI cuLaunchKernel(CUfunction,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,CUstream,void**,void**){forbidden("GPU payload launch");return CUDA_ERROR_INVALID_VALUE;}

static xdev_ext_cuda_peer_owner_opts options(){xdev_ext_cuda_peer_owner_opts o{};o.size=sizeof(o);o.version=1;o.mode=owner_mode;o.context_mode=1;o.context=context;o.stream=stream;o.nvidia_node="/dev/nvidia-control-test";o.bpf_object="default-xdomain.bpf.o";o.user_bpf_object="default-user.bpf.o";o.link_token=7;o.allocation_bytes=65536;o.nr_batches=1;o.first_sequence=1;o.timeout_ns=1000000;o.group_bytes=4096;o.depth=1;return o;}
static int open_requested(const xdev_ext_cuda_peer_owner_opts *o,xdev_ext_cuda_peer_owner **out){
#ifdef CUDA_PRIVATE_NEW
 xdev_ext_cuda_peer_programs_opts p=XDEV_EXT_CUDA_PEER_PROGRAMS_OPTS_INIT;
 for(unsigned i=0;i<3;i++)p.tx_stage_pins[i]=mask_value&(1U<<i)?paths[i]:nullptr;
 for(unsigned i=0;i<2;i++)p.rx_stage_pins[i]=mask_value&(1U<<(i+3))?paths[i+3]:nullptr;
 return xdev_ext_cuda_peer_owner_open_programs(o,endpoint_flags,&p,out);
#else
 // Baseline adapter chooses the only actual owner entry. Ignoring requested
 // pins demonstrates old ordinary-CREATE bypass behavior, never algorithm
 // emulation or a missing-symbol failure.
 return xdev_ext_cuda_peer_owner_open_flags(o,endpoint_flags,out);
#endif
}
static void references_live(){for(auto &p:pins){EQ("pin-reference-retained",p.closed,0);EQ("retained-fd-live",fcntl(p.fd,F_GETFD)>=0,1);EQ("owned-FD-CLOEXEC",fcntl(p.fd,F_GETFD)&FD_CLOEXEC,FD_CLOEXEC);}EQ("backing-not-freed",mem_freed,0);}
static void route_expect(){
 EQ("global-USER-exact-once",attaches[0],need_classes&1?1:0);EQ("global-XD-exact-once",attaches[1],need_classes&2?1:0);
 EQ("per-explicit-slot-lookup",lookups,__builtin_popcount(mask_value));
 EQ("CREATE_PROGRAMS-count",program_calls,mask_value?2:0);EQ("ordinary-CREATE-count",ordinary_calls,mask_value?0:2);
 for(auto &p:pins){unsigned used=0;for(auto &v:captured_selectors)for(int fd:v)used+=fd==p.fd;EQ("each-owned-reference-selected-once",used,1);}
 if(force_fd0&&!pins.empty()){EQ("FD0-acquired",pins[0].fd,0);bool selected=false;for(auto &v:captured_selectors)for(int fd:v)if(fd==0)selected=true;EQ("FD0-selected",selected,1);}
}
static void finish_close(xdev_ext_cuda_peer_owner **o){unsigned before=lookups;EQ("close-success",xdev_ext_cuda_peer_owner_close(o),0);EQ("close-clears-owner",*o==nullptr,1);EQ("close-never-reopens-pins",lookups,before);for(auto &p:pins)EQ("owned-reference-closed-once",p.closed,1);}
static void endpoint_checks(){
 xdev_ext_peer_endpoint_opts opts{};opts.sz=sizeof(opts);opts.allocation_fd=anon_fd("endpoint-allocation");opts.control_fd=anon_fd("endpoint-control");opts.link_token=7;opts.direction=1;opts.depth=1;opts.group_bytes=4096;opts.deadline_ms=1;opts.layout={4096,0,4096,4096};
 xdev_ext_peer_endpoint *e=nullptr;EQ("endpoint-open",xdev_ext_peer_endpoint_open(&opts,&e),0);
#ifdef CUDA_PRIVATE_NEW
 int selected[3]={-1,-1,-1};xdev_ext_mech_create_report report;memset(&report,0xa5,sizeof(report));
 EQ("NULL-endpoint",xdev_ext_peer_endpoint_create_programs(nullptr,selected,3,&report),-EINVAL);xdev_ext_mech_create_report zero{};EQ("report-cleared-on-NULL",memcmp(&report,&zero,sizeof(report)),0);
 memset(&report,0xa5,sizeof(report));EQ("NULL-selectors",xdev_ext_peer_endpoint_create_programs(e,nullptr,3,&report),-EINVAL);EQ("NULL-selector-report-cleared",memcmp(&report,&zero,sizeof(report)),0);
 memset(&report,0xa5,sizeof(report));EQ("wrong-count",xdev_ext_peer_endpoint_create_programs(e,selected,2,&report),-EINVAL);EQ("wrong-count-report-cleared",memcmp(&report,&zero,sizeof(report)),0);
 memset(&report,0xa5,sizeof(report));selected[1]=-2;EQ("fd-below-default",xdev_ext_peer_endpoint_create_programs(e,selected,3,&report),-EINVAL);EQ("invalid-fd-report-cleared",memcmp(&report,&zero,sizeof(report)),0);
 selected[1]=-1;EQ("valid-all-default-explicit-transport",xdev_ext_peer_endpoint_create_programs(e,selected,3,&report),0);EQ("real-programs-transport",program_calls,1);EQ("no-ordinary-fallback",ordinary_calls,0);
#else
 EQ("legacy-endpoint-create",xdev_ext_peer_endpoint_create(e),0);EQ("legacy-ordinary-transport",ordinary_calls,1);
#endif
 EQ("endpoint-close",xdev_ext_peer_endpoint_close(e),0);
#ifdef CUDA_PRIVATE_NEW
 opts.direction=2;expected_endpoint=1;e=nullptr;EQ("RX-endpoint-open",xdev_ext_peer_endpoint_open(&opts,&e),0);
 int rx[2]={-1,-1};bad_report=true;
 EQ("NULL-report-still-validates-delivery",xdev_ext_peer_endpoint_create_programs(e,rx,2,nullptr),-EPROTO);
 bad_report=false;EQ("NULL-report-valid-create",xdev_ext_peer_endpoint_create_programs(e,rx,2,nullptr),0);
 EQ("RX-endpoint-close",xdev_ext_peer_endpoint_close(e),0);
#endif
 __real_close(opts.allocation_fd);__real_close(opts.control_fd);
}
#ifdef CUDA_PRIVATE_NEW
static void invalid_inputs(){
 auto o=options();xdev_ext_cuda_peer_programs_opts p=XDEV_EXT_CUDA_PEER_PROGRAMS_OPTS_INIT;xdev_ext_cuda_peer_owner *out=reinterpret_cast<xdev_ext_cuda_peer_owner*>(uintptr_t(1));
 auto invoke=[&](int want){unsigned acquired=lookups;out=reinterpret_cast<xdev_ext_cuda_peer_owner*>(uintptr_t(1));EQ("invalid-input-errno",xdev_ext_cuda_peer_owner_open_programs(&o,0,&p,&out),want);EQ("invalid-clears-output",out==nullptr,1);EQ("no-pin-acquisition",lookups,acquired);EQ("no-GPU-acquisition",gpu_allocations.size(),0);};
 p.size--;invoke(-EINVAL);p.size++;p.version=2;invoke(-EOPNOTSUPP);p.version=1;p.flags=1;invoke(-EOPNOTSUPP);p.flags=0;
 for(unsigned slot=0;slot<5;slot++){
  const char **path=slot<3?&p.tx_stage_pins[slot]:&p.rx_stage_pins[slot-3];
  *path="";invoke(-EINVAL);*path="relative/pin";invoke(-EINVAL);*path=nullptr;
 }
 o.bpf_object=nullptr;invoke(-EINVAL);o.bpf_object="default-xdomain.bpf.o";
 o.user_bpf_object=nullptr;invoke(-EINVAL);o.user_bpf_object="default-user.bpf.o";
 EQ("NULL-programs",xdev_ext_cuda_peer_owner_open_programs(&o,0,nullptr,&out),-EINVAL);EQ("NULL-programs-clear",out==nullptr,1);
 EQ("NULL-owner-options",xdev_ext_cuda_peer_owner_open_programs(nullptr,0,&p,&out),-EINVAL);EQ("NULL-out",xdev_ext_cuda_peer_owner_open_programs(&o,0,&p,nullptr),-EINVAL);
 EQ("EXTERNAL_CTL-not-caller-grant",xdev_ext_cuda_peer_owner_open_programs(&o,1,&p,&out),-EINVAL);EQ("unknown-endpoint-flags",xdev_ext_cuda_peer_owner_open_programs(&o,4,&p,&out),-EINVAL);
}
#endif
int main(int argc,char **argv){
 if(argc<2)return 2;
 label=argv[1];
 static xdev_ext_sys hook{sys_setup,sys_register,nullptr,sys_ioctl};xdev_ext__set_sys(&hook);
 EQ("C-declarations-linked",declarations_c(),0);EQ("C++17-declarations-linked",declarations_cpp(),0);
 if(label=="endpoint"){endpoint_checks();goto done;}
 if(label=="legacy-invalid"){
  auto o=options();xdev_ext_cuda_peer_owner *owner=reinterpret_cast<xdev_ext_cuda_peer_owner*>(uintptr_t(1));
  o.bpf_object=nullptr;EQ("legacy-still-requires-XD-object",xdev_ext_cuda_peer_owner_open(&o,&owner),-EINVAL);EQ("legacy-output-cleared",owner==nullptr,1);
  o.bpf_object="default-xdomain.bpf.o";o.user_bpf_object=nullptr;EQ("legacy-still-requires-USER-object",xdev_ext_cuda_peer_owner_open_flags(&o,0,&owner),-EINVAL);
  EQ("legacy-no-acquisition",gpu_allocations.size(),0);goto done;
 }
#ifdef CUDA_PRIVATE_NEW
 if(label=="invalid"){invalid_inputs();goto done;}
#endif
 mask_value=label=="legacy"?0:31;if(argc>2)mask_value=unsigned(std::strtoul(argv[2],nullptr,10));need_classes=needs[mask_value];
 if(label=="d2"||label=="controller-retained")owner_mode=2;
 if(label=="fd0")force_fd0=true;
 if(label=="early")endpoint_flags=XDEV_EXT_PEER_ENDPOINT_F_EARLY;
 if(label=="repeated"){paths[0]=paths[2]=paths[4]="/sys/fs/bpf/test/same-USER";paths[1]=paths[3]="/sys/fs/bpf/test/same-XDOMAIN";}
 if(label=="lookup-failure")lookup_fail=argc>3?std::atoi(argv[3]):2;
 if(label=="global-failure"){mask_value=0;need_classes=3;attach_fail=argc>2?std::atoi(argv[2]):0;}
 if(label=="RX-failure"){create_fail=2;create_errno=-ENOENT;}
 if(label=="TX-failure"){create_fail=1;create_errno=-EINVAL;}
 if(label=="endpoint-failure")ring_failure=argc>3?std::atoi(argv[3]):2;
 {auto o=options();xdev_ext_cuda_peer_owner *owner=nullptr;
#ifdef CUDA_PRIVATE_NEW
  if(!(need_classes&2))o.bpf_object=nullptr;
  if(!(need_classes&1))o.user_bpf_object=nullptr;
#endif
  int ret=open_requested(&o,&owner);
  if(lookup_fail>=0||attach_fail>=0||create_fail>=0||ring_failure>=0){
   EQ("original-open-error",ret,lookup_fail>=0?-EACCES:attach_fail>=0?-EBUSY:ring_failure>=0?-EIO:create_errno);EQ("partial-owner-exposed",owner!=nullptr,1);references_live();
   EQ("no-selection-fallback",ordinary_calls,mask_value?0:ordinary_calls);finish_close(&owner);goto done;
  }
  EQ("owner-open",ret,0);if(!owner)goto done;route_expect();references_live();
  if(label=="event-retained"){event_failure=argc>3?std::atoi(argv[3]):2;EQ("event-failure",xdev_ext_cuda_peer_owner_close(&owner),-EIO);EQ("owner-kept",owner!=nullptr,1);references_live();event_failure=0;}
  if(label=="controller-retained"){unregister_failure=1;EQ("controller-close-failure",xdev_ext_cuda_peer_owner_close(&owner),-EIO);EQ("owner-kept",owner!=nullptr,1);references_live();EQ("controller-reference-retained",ctl_detached,0);unregister_failure=0;}
  if(label=="cancel-released"){
   EQ("control-START",xdev_ext_cuda_peer_owner_start(owner),0);stop_errno=-ECANCELED;stats_released=true;
   EQ("final-cancellation-preserved",xdev_ext_cuda_peer_owner_close(&owner),-ECANCELED);EQ("owner-kept-after-error",owner!=nullptr,1);references_live();stop_errno=0;
  }
  if(label=="STOP-retained"||label=="cancel-retained"){
   stop_errno=label=="STOP-retained"?-EBUSY:-ECANCELED;EQ("native-close-not-released",xdev_ext_cuda_peer_owner_close(&owner),-EBUSY);EQ("owner-kept",owner!=nullptr,1);references_live();stats_released=true;stop_errno=0;
  }
  finish_close(&owner);
  EQ("all-controller-metadata-detached",ctl_detached,owner_mode==2?3:0);
 }
 done:printf("cuda_private_control scenario=%s mask=%u assertions=%u failures=%u\n",label.c_str(),mask_value,checks,failures);return failures?1:0;
}
