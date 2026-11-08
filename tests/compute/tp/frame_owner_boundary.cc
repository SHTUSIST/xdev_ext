// SPDX-License-Identifier: GPL-2.0
// Host-frame endpoint owner: the complete owner translation unit with the
// CUDA Driver, OS calls, programs and endpoints as recorded boundaries.
// Requirement (TP host-frame route, frame_endpoint_owner.h): two CUDA VMM
// windows exported as POSIX fds, each attached to its own CE device fd; the
// send endpoint uses window 0 (one group) and the receive endpoint window 1
// (receive_groups groups); each CE stage gets its own PRIVATE CE program
// instance and XDOMAIN keeps its class default; close releases endpoints
// before programs, CE fds and windows. No GPU, CE or XDOMAIN runs.
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cuda.h>
static int owner_os_open(const char *,int,...);
static int owner_os_close(int);
static int owner_os_ioctl(int,unsigned long,...);
#define open owner_os_open
#define close owner_os_close
#define ioctl owner_os_ioctl
#include TP_FRAME_OWNER_SOURCE
#undef open
#undef close
#undef ioctl

static unsigned checks,failures;
#define EQ(actual,expected) do{long long a_=(long long)(actual),e_=(long long)(expected);checks++;\
 if(a_!=e_){std::fprintf(stderr,"# line %d %s: got %lld expected %lld\n",__LINE__,#actual,a_,e_);failures++;}}while(0)

static std::vector<std::string> events;
static std::map<int,std::string> fds;
static int next_fd=40;
static std::string fail_at;
static void note(const std::string &s){events.push_back(s);}
static bool fault(const std::string &s){return fail_at==s;}
static int find(const std::string &s){for(size_t i=0;i<events.size();++i)if(events[i]==s)return int(i);return -1;}
static int count(const std::string &prefix){int n=0;for(auto &e:events)n+=e.rfind(prefix,0)==0;return n;}

static int owner_os_open(const char *path,int,...){int fd=next_fd++;fds[fd]=path;note(std::string("open:")+path);return fd;}
static int owner_os_close(int fd){if(!fds.count(fd))return errno=EBADF,-1;note("close:"+fds[fd]);fds.erase(fd);return 0;}
struct attach_seen {int fd,mem_fd;uint64_t va,size;};
static std::vector<attach_seen> attaches;
static int owner_os_ioctl(int fd,unsigned long request,...){
 va_list ap;va_start(ap,request);void *arg=va_arg(ap,void *);va_end(ap);
 if(request!=XDEV_EXT_NV_IOCTL_XFER_CMD)return errno=ENOTTY,-1;
 auto *x=static_cast<xdev_ext_nv_ioctl_xfer *>(arg);
 if(x->cmd!=XDEV_EXT_NV_ESC_CE_ATTACH_MEMORY || x->size!=sizeof(struct xdev_ext_nv_ce_attach_memory))return errno=EINVAL,-1;
 auto *a=reinterpret_cast<struct xdev_ext_nv_ce_attach_memory *>(uintptr_t(x->ptr));
 attaches.push_back({fd,a->mem_fd,a->gpu_va,a->size});note("attach:"+fds[fd]);
 a->status=0;return 0;
}
// ---- CUDA ---------------------------------------------------------------
static unsigned live_handles,live_reservations,live_maps;
static bool destroyed_stream;
static CUstream recorded_stream;
static CUdeviceptr next_va=0x7f0000000000ULL;
CUresult cuInit(unsigned){return CUDA_SUCCESS;}
CUresult cuDeviceGet(CUdevice *d,int o){*d=o;return CUDA_SUCCESS;}
CUresult cuCtxCreate(CUcontext *c,void *,unsigned,CUdevice){*c=reinterpret_cast<void *>(0x51);note("ctx-create");return CUDA_SUCCESS;}
CUresult cuCtxDestroy(CUcontext){note("ctx-destroy");return fault("ctx-destroy")?CUDA_ERROR_UNKNOWN:CUDA_SUCCESS;}
CUresult cuCtxGetCurrent(CUcontext *c){*c=reinterpret_cast<void *>(fault("wrong-context")?0x52:0x51);return CUDA_SUCCESS;}
CUresult cuCtxGetDevice(CUdevice *d){*d=0;return fault("device-query")?CUDA_ERROR_UNKNOWN:CUDA_SUCCESS;}
CUresult cuStreamCreate(CUstream *s,unsigned){note("stream-create");if(fault("stream-create"))return CUDA_ERROR_UNKNOWN;*s=reinterpret_cast<void *>(0x61);return CUDA_SUCCESS;}
CUresult cuStreamDestroy(CUstream){note("stream-destroy");destroyed_stream=true;return CUDA_SUCCESS;}
CUresult cuStreamGetCtx(CUstream,CUcontext *c){*c=reinterpret_cast<void *>(0x51);return fault("stream-getctx")?CUDA_ERROR_UNKNOWN:CUDA_SUCCESS;}
CUresult cuStreamIsCapturing(CUstream,CUstreamCaptureStatus *s){note("capture-query");*s=fault("capturing")?CU_STREAM_CAPTURE_STATUS_ACTIVE:CU_STREAM_CAPTURE_STATUS_NONE;return fault("capture-query")||destroyed_stream?CUDA_ERROR_UNKNOWN:CUDA_SUCCESS;}
CUresult cuEventCreate(CUevent *e,unsigned){if(fault("event-create"))return CUDA_ERROR_UNKNOWN;*e=reinterpret_cast<void *>(0x71);return CUDA_SUCCESS;}
CUresult cuEventRecord(CUevent,CUstream stream){note("event-record");recorded_stream=stream;return fault("event-record")?CUDA_ERROR_UNKNOWN:CUDA_SUCCESS;}
CUresult cuEventSynchronize(CUevent){note("event-sync");return fault("event-sync")?CUDA_ERROR_UNKNOWN:CUDA_SUCCESS;}
CUresult cuEventDestroy(CUevent){return CUDA_SUCCESS;}
static std::vector<CUmemAllocationProp> props;
CUresult cuMemGetAllocationGranularity(size_t *g,const CUmemAllocationProp *,CUmemAllocationGranularity_flags){*g=2u<<20;return CUDA_SUCCESS;}
CUresult cuMemCreate(CUmemGenericAllocationHandle *h,size_t size,const CUmemAllocationProp *p,unsigned long long){
 props.push_back(*p);note("mem-create:"+std::to_string(size));*h=0x1000+live_handles;++live_handles;return CUDA_SUCCESS;}
CUresult cuMemAddressReserve(CUdeviceptr *va,size_t size,size_t,CUdeviceptr,unsigned long long){*va=next_va;next_va+=size;++live_reservations;return CUDA_SUCCESS;}
CUresult cuMemMap(CUdeviceptr,size_t,size_t,CUmemGenericAllocationHandle,unsigned long long){++live_maps;return CUDA_SUCCESS;}
static std::vector<CUmemAccessDesc> access_seen;
CUresult cuMemSetAccess(CUdeviceptr,size_t,const CUmemAccessDesc *d,size_t n){if(n==1)access_seen.push_back(*d);return n==1?CUDA_SUCCESS:CUDA_ERROR_UNKNOWN;}
CUresult cuMemExportToShareableHandle(void *out,CUmemGenericAllocationHandle,CUmemAllocationHandleType type,unsigned long long){
 if(type!=CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR)return CUDA_ERROR_UNKNOWN;
 int fd=next_fd++;fds[fd]="export";*static_cast<int *>(out)=fd;note("export");return CUDA_SUCCESS;}
CUresult cuMemUnmap(CUdeviceptr,size_t){--live_maps;note("unmap");return CUDA_SUCCESS;}
CUresult cuMemAddressFree(CUdeviceptr,size_t){--live_reservations;return CUDA_SUCCESS;}
CUresult cuMemRelease(CUmemGenericAllocationHandle){--live_handles;note("release");return CUDA_SUCCESS;}
// ---- library boundaries ----------------------------------------------------
extern "C" int xdev_ext_link_discover(const char *,__u64 token,xdev_ext_link_snapshot *s){*s={};s->token=token;s->up=1;note("link");return 0;}
struct xdev_ext_prog {std::string map;int fd;};
extern "C" int xdev_ext_prog_attach(const xdev_ext_prog_opts *o,xdev_ext_prog **out){
 note(std::string("prog:")+o->map_name);
 *out=new xdev_ext_prog{o->map_name,next_fd++};return 0;}
extern "C" int xdev_ext_prog_link_fd(const xdev_ext_prog *p){return p->fd;}
extern "C" int xdev_ext_prog_detach(xdev_ext_prog *p){note("detach:"+p->map);delete p;return 0;}
struct xdev_ext_frame_endpoint {xdev_ext_frame_endpoint_opts o;int sel[2];};
static std::vector<xdev_ext_frame_endpoint_opts> endpoint_opts;
static std::vector<std::vector<int>> selectors;
extern "C" int xdev_ext_frame_endpoint_open(const xdev_ext_frame_endpoint_opts *o,xdev_ext_frame_endpoint **out){
 bool tx=o->direction==XDEV_EXT_MECH_DIR_TO_DEVICE;note(tx?"endpoint-open:tx":"endpoint-open:rx");
 if(fault(tx?"open-tx":"open-rx"))return -EIO;
 endpoint_opts.push_back(*o);*out=new xdev_ext_frame_endpoint{*o,{0,0}};return 0;}
extern "C" int xdev_ext_frame_endpoint_create_programs(xdev_ext_frame_endpoint *e,const int *f,__u32 n,xdev_ext_mech_create_report *){
 selectors.push_back(std::vector<int>(f,f+n));note(e->o.direction==XDEV_EXT_MECH_DIR_TO_DEVICE?"create:tx":"create:rx");return 0;}
extern "C" int xdev_ext_frame_endpoint_close(xdev_ext_frame_endpoint *e){
 note(e->o.direction==XDEV_EXT_MECH_DIR_TO_DEVICE?"endpoint-close:tx":"endpoint-close:rx");delete e;return 0;}

static void reset(){events.clear();fds.clear();attaches.clear();props.clear();access_seen.clear();endpoint_opts.clear();selectors.clear();
 fail_at.clear();live_handles=live_reservations=live_maps=0;destroyed_stream=false;recorded_stream=reinterpret_cast<void *>(1);}
static xdev_ext_cuda_frame_owner_opts options(){
 xdev_ext_cuda_frame_owner_opts o{};o.size=sizeof(o);o.version=XDEV_EXT_CUDA_FRAME_OWNER_VERSION;
 o.context_mode=2;o.device=0;o.nvidia_node="/dev/nvidia0";o.bpf_object="xdomain_rts_cts.bpf.o";
 o.ce_bpf_object="tp_ce_place.bpf.o";o.link_token=0xabc;o.timeout_ns=1000000000ULL;
 o.group_bytes=4160;o.receive_groups=2;o.endpoint_flags=XDEV_EXT_FRAME_ENDPOINT_F_EARLY;
 return o;
}

static void test_refuses_bad_options(){
 reset();xdev_ext_cuda_frame_owner *owner=reinterpret_cast<xdev_ext_cuda_frame_owner *>(1);
 auto o=options();o.group_bytes=0;EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EINVAL);EQ(owner==nullptr,1);
 o=options();o.group_bytes=4100;EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EINVAL);
 o=options();o.group_bytes=33*4096;EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EINVAL);
 o=options();o.receive_groups=0;EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EINVAL);
 o=options();o.ce_bpf_object=nullptr;EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EINVAL);
 o=options();o.bpf_object=nullptr;EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EINVAL);
 o=options();o.nvidia_node="";EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EINVAL);
 o=options();o.link_token=0;EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EINVAL);
 o=options();o.endpoint_flags=2;EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EOPNOTSUPP);
 o=options();o.size=8;EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EINVAL);
 EQ(events.size(),0);
}

static void test_open_view_close(){
 reset();xdev_ext_cuda_frame_owner *owner=nullptr;auto o=options();
 EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),0);
 EQ(owner!=nullptr,1);
 EQ(count("mem-create:"),2);EQ(find("mem-create:2097152")>=0,1);
 EQ(props.size(),2);
 for(auto &p:props){EQ(p.type,CU_MEM_ALLOCATION_TYPE_PINNED);EQ(p.requestedHandleTypes,CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR);
  EQ(p.location.type,CU_MEM_LOCATION_TYPE_DEVICE);EQ(p.location.id,0);}
 EQ(access_seen.size(),2);EQ(access_seen[0].flags,CU_MEM_ACCESS_FLAGS_PROT_READWRITE);
 EQ(count("open:/dev/nvidia0"),2);EQ(count("open:/dev/xdev_ext_peer"),1);
 EQ(attaches.size(),2);
 xdev_ext_cuda_frame_owner_view v{};v.size=sizeof(v);
 EQ(xdev_ext_cuda_frame_owner_get_view(owner,&v),0);
 EQ(v.group_bytes,4160);EQ(v.tx_bytes,4160);EQ(v.rx_bytes,2*4160);
 EQ(v.tx_va!=0 && v.rx_va!=0 && v.tx_va!=v.rx_va,1);
 EQ(v.context==reinterpret_cast<void *>(0x51),1);EQ(v.stream==reinterpret_cast<void *>(0x61),1);
 EQ(v.tx_frames!=nullptr && v.rx_frames!=nullptr && v.tx_frames!=v.rx_frames,1);
 // Each CE fd carries the export of its own window, mapped where the stage reads.
 EQ(attaches[0].fd!=attaches[1].fd,1);EQ(attaches[0].mem_fd!=attaches[1].mem_fd,1);
 EQ(attaches[0].size,2u<<20);
 EQ(endpoint_opts.size(),2);
 const auto &tx=endpoint_opts[0],&rx=endpoint_opts[1];
 EQ(tx.direction,XDEV_EXT_MECH_DIR_TO_DEVICE);EQ(rx.direction,XDEV_EXT_MECH_DIR_FROM_DEVICE);
 EQ(tx.depth,1);EQ(rx.depth,1);EQ(tx.group_bytes,4160);EQ(rx.group_bytes,4160);
 EQ(tx.link_token,0xabc);EQ(tx.flags,XDEV_EXT_FRAME_ENDPOINT_F_EARLY);EQ(rx.flags,XDEV_EXT_FRAME_ENDPOINT_F_EARLY);
 EQ(tx.window_va,v.tx_va);EQ(tx.window_bytes,4160);EQ(rx.window_va,v.rx_va);EQ(rx.window_bytes,2*4160);
 bool tx_first=attaches[0].va==v.tx_va;
 EQ(tx.ce_fd,tx_first?attaches[0].fd:attaches[1].fd);EQ(rx.ce_fd,tx_first?attaches[1].fd:attaches[0].fd);
 EQ(attaches[tx_first?0:1].va,v.tx_va);EQ(attaches[tx_first?1:0].va,v.rx_va);
 EQ(tx.control_fd==rx.control_fd && fds[tx.control_fd]=="/dev/xdev_ext_peer",1);
 // Programs: XDOMAIN class default once, one PRIVATE CE instance per CE stage.
 EQ(count("prog:xdomain_peer_ops"),1);EQ(count("prog:tp_ce_ops"),2);
 EQ(selectors.size(),2);
 EQ(selectors[0].size(),2);EQ(selectors[1].size(),2);
 EQ(selectors[0][1],-1);EQ(selectors[1][0],-1);
 EQ(selectors[0][0]>=0 && selectors[1][1]>=0 && selectors[0][0]!=selectors[1][1],1);
 EQ(find("attach:/dev/nvidia0")<find("create:tx"),1);EQ(find("link")>=0,1);
 // Close: last use, endpoints, programs, CE fds, windows, context.
 size_t opened=events.size();
 EQ(xdev_ext_cuda_frame_owner_close(&owner),0);
 EQ(owner==nullptr,1);
 auto after=[&](const std::string &s){for(size_t i=opened;i<events.size();++i)if(events[i]==s)return int(i);return -1;};
 EQ(after("event-sync")<after("endpoint-close:tx"),1);
 EQ(after("endpoint-close:rx")<after("detach:tp_ce_ops"),1);
 EQ(after("detach:tp_ce_ops")<after("close:/dev/nvidia0"),1);
 EQ(after("close:/dev/nvidia0")<after("unmap"),1);
 EQ(after("release")<after("ctx-destroy"),1);
 EQ(fds.size(),0);EQ(live_handles,0);EQ(live_reservations,0);EQ(live_maps,0);
}

static void test_partial_failure_is_owned(){
 reset();xdev_ext_cuda_frame_owner *owner=nullptr;auto o=options();
 fail_at="open-rx";
 EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EIO);
 EQ(owner!=nullptr,1);
 EQ(count("create:"),0);
 EQ(xdev_ext_cuda_frame_owner_close(&owner),0);
 EQ(owner==nullptr,1);
 EQ(count("endpoint-close:tx"),1);EQ(count("endpoint-close:rx"),0);
 EQ(fds.size(),0);EQ(live_handles,0);EQ(live_reservations,0);EQ(live_maps,0);
}

static xdev_ext_cuda_frame_owner_opts borrowed(CUstream stream=nullptr){
 auto o=options();o.context_mode=1;o.context=reinterpret_cast<void *>(0x51);o.stream=stream;return o;
}
static void test_borrowed_streams(){
 // CUDA's NULL/default stream is a valid borrowed stream, not absence of one.
 for(CUstream stream:{CUstream(nullptr),reinterpret_cast<void *>(0x61)}){
  reset();auto o=borrowed(stream);xdev_ext_cuda_frame_owner *owner=nullptr;
  EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),0);EQ(owner!=nullptr,1);
  EQ(xdev_ext_cuda_frame_owner_close(&owner),0);
  EQ(count("event-record"),1);EQ(count("event-sync"),1);
  EQ(find("event-sync")>=0 && find("event-sync")<find("endpoint-close:tx"),1);
  EQ(owner==nullptr,1);EQ(recorded_stream==stream,1);
  EQ(count("stream-destroy"),0);EQ(count("ctx-destroy"),0);
  EQ(fds.size(),0);EQ(live_maps,0);
 }
}
// A NULL stream may also return an implicit-capture Driver error; a failed
// capture query must retain the owner before inspecting its output status.
static void test_borrowed_close_refusals(){
 for(const char *failure:{"wrong-context","capturing","capture-query","event-create","event-record","event-sync"}){
  reset();auto o=borrowed();xdev_ext_cuda_frame_owner *owner=nullptr;
  EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),0);auto *same=owner;size_t open_fds=fds.size();
  fail_at=failure;
  int expected=fail_at=="wrong-context"?-EXDEV:fail_at=="capturing"?-EBUSY:-EIO;
  EQ(xdev_ext_cuda_frame_owner_close(&owner),expected);EQ(owner==same,1);
  EQ(count("endpoint-close:"),0);EQ(count("unmap"),0);EQ(live_maps,2);EQ(fds.size(),open_fds);
  fail_at.clear();EQ(xdev_ext_cuda_frame_owner_close(&owner),0);EQ(owner==nullptr,1);
  EQ(count("stream-destroy"),0);EQ(count("ctx-destroy"),0);EQ(live_maps,0);EQ(fds.size(),0);
 }
}
static void test_unbound_setup_cleanup(){
 for(const char *failure:{"stream-create","stream-getctx","device-query"}){
  reset();auto o=std::string(failure)=="stream-create"?options():borrowed();
  xdev_ext_cuda_frame_owner *owner=nullptr;fail_at=failure;
  EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),-EIO);EQ(owner!=nullptr,1);
  fail_at.clear();EQ(xdev_ext_cuda_frame_owner_close(&owner),0);EQ(owner==nullptr,1);
  EQ(count("capture-query"),0);EQ(count("event-record"),0);EQ(count("event-sync"),0);
  EQ(count("stream-destroy"),0);EQ(count("ctx-destroy"),std::string(failure)=="stream-create"?1:0);
  EQ(fds.size(),0);EQ(live_maps,0);
 }
}
static void test_owned_context_close_retry(){
 reset();auto o=options();xdev_ext_cuda_frame_owner *owner=nullptr;
 EQ(xdev_ext_cuda_frame_owner_open(&o,&owner),0);fail_at="ctx-destroy";
 EQ(xdev_ext_cuda_frame_owner_close(&owner),-EIO);EQ(owner!=nullptr,1);
 EQ(count("stream-destroy"),1);EQ(count("event-sync"),1);EQ(live_maps,0);
 fail_at.clear();EQ(xdev_ext_cuda_frame_owner_close(&owner),0);EQ(owner==nullptr,1);
 EQ(count("stream-destroy"),1);EQ(count("event-sync"),1);EQ(count("ctx-destroy"),2);
}

int main(){
 test_refuses_bad_options();
 test_open_view_close();
 test_partial_failure_is_owned();
 test_borrowed_streams();
 test_borrowed_close_refusals();
 test_unbound_setup_cleanup();
 test_owned_context_close_retry();
 std::printf("%s 1 - host-frame endpoint owner (%u checks, %u failures)\n",failures?"not ok":"ok",checks,failures);
 std::fflush(stdout);
 return failures!=0;
}
