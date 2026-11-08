// SPDX-License-Identifier: GPL-2.0
// Host-frame endpoint owner; contract in frame_endpoint_owner.h.
#include "frame_endpoint_owner.h"
#include "xdev_ext_nv_p2p_ioctl.h"
#include <cerrno>
#include <climits>
#include <new>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
namespace {
constexpr uint32_t frame_max_group=XDEV_EXT_MECH_MAX_FRAMES*XDEV_EXT_FRAME_SIZE;
int driver(CUresult rc) {return rc==CUDA_SUCCESS?0:-EIO;}
struct window {
 CUmemGenericAllocationHandle handle=0;
 CUdeviceptr va=0;
 size_t size=0;
 bool created=false,reserved=false,mapped=false;
 int exported=-1,ce=-1;
};
}
struct xdev_ext_cuda_frame_owner {
 xdev_ext_cuda_frame_owner_opts config{};
 CUcontext context=nullptr;
 CUstream stream=nullptr;
 CUevent last_use=nullptr;
 bool own_context=false,own_stream=false;
 int control=-1;
 window win[2]; // 0: send, 1: receive
 uint64_t window_bytes[2]{};
 xdev_ext_prog *xdomain=nullptr,*ce_program[2]{};
 xdev_ext_frame_endpoint *endpoint[2]{};
};
static int current(xdev_ext_cuda_frame_owner *o) {
 CUcontext c=nullptr;int rc=driver(cuCtxGetCurrent(&c));
 return rc?rc:c==o->context?0:-EXDEV;
}
/* A VMM allocation exported as a POSIX fd, mapped read-write for this GPU
 * and attached to its own CE device fd, as the CE stage requires. */
static int window_open(xdev_ext_cuda_frame_owner *o,window &w,uint64_t bytes) {
 CUmemAllocationProp prop{};
 prop.type=CU_MEM_ALLOCATION_TYPE_PINNED;
 prop.requestedHandleTypes=CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR;
 prop.location.type=CU_MEM_LOCATION_TYPE_DEVICE;prop.location.id=int(o->config.device);
 size_t granularity=0;int rc;
 if((rc=driver(cuMemGetAllocationGranularity(&granularity,&prop,CU_MEM_ALLOC_GRANULARITY_MINIMUM))))return rc;
 if(!granularity || bytes>SIZE_MAX-granularity)return -EINVAL;
 w.size=size_t((bytes+granularity-1)/granularity*granularity);
 if((rc=driver(cuMemCreate(&w.handle,w.size,&prop,0))))return rc;
 w.created=true;
 if((rc=driver(cuMemAddressReserve(&w.va,w.size,granularity,0,0))))return rc;
 w.reserved=true;
 if((rc=driver(cuMemMap(w.va,w.size,0,w.handle,0))))return rc;
 w.mapped=true;
 CUmemAccessDesc access{};
 access.location=prop.location;access.flags=CU_MEM_ACCESS_FLAGS_PROT_READWRITE;
 if((rc=driver(cuMemSetAccess(w.va,w.size,&access,1))))return rc;
 int exported=-1;
 if((rc=driver(cuMemExportToShareableHandle(&exported,w.handle,CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR,0))))return rc;
 w.exported=exported;
 w.ce=::open(o->config.nvidia_node,O_RDWR|O_CLOEXEC|O_NOFOLLOW);
 if(w.ce<0)return -errno;
 struct xdev_ext_nv_ce_attach_memory attach{};
 attach.mem_fd=w.exported;attach.gpu_va=w.va;attach.size=w.size;
 if(xdev_ext_nv_ce_attach_memory(w.ce,&attach))return errno?-errno:-EIO;
 return 0;
}
static int window_close(window &w) {
 int rc;
 if(w.ce>=0){int fd=w.ce;w.ce=-1;if(::close(fd))return -errno;}
 if(w.exported>=0){int fd=w.exported;w.exported=-1;if(::close(fd))return -errno;}
 if(w.mapped){if((rc=driver(cuMemUnmap(w.va,w.size))))return rc;w.mapped=false;}
 if(w.reserved){if((rc=driver(cuMemAddressFree(w.va,w.size))))return rc;w.reserved=false;w.va=0;}
 if(w.created){if((rc=driver(cuMemRelease(w.handle))))return rc;w.created=false;}
 return 0;
}
static int prepare(xdev_ext_cuda_frame_owner *o) {
 auto &c=o->config;int rc;
 xdev_ext_link_snapshot link{};
 if((rc=xdev_ext_link_discover("/sys/bus/thunderbolt/devices",c.link_token,&link)))return rc;
 if(c.context_mode==2) {
  CUdevice device;
  if((rc=driver(cuInit(0))) || (rc=driver(cuDeviceGet(&device,int(c.device)))))return rc;
  if((rc=driver(cuCtxCreate(&o->context,nullptr,0,device))))return rc;
  o->own_context=true;
  if((rc=driver(cuStreamCreate(&o->stream,CU_STREAM_NON_BLOCKING))))return rc;
  o->own_stream=true;
 } else {
  o->context=c.context;o->stream=c.stream;
  if((rc=current(o)))return rc;
  CUcontext stream_context=nullptr;
  if((rc=driver(cuStreamGetCtx(o->stream,&stream_context))))return rc;
  if(stream_context!=o->context)return -EXDEV;
  CUdevice actual,requested;
  if((rc=driver(cuCtxGetDevice(&actual))) || (rc=driver(cuDeviceGet(&requested,int(c.device)))))return rc;
  if(actual!=requested)return -EXDEV;
 }
 o->window_bytes[0]=c.group_bytes;
 o->window_bytes[1]=uint64_t(c.group_bytes)*c.receive_groups;
 for(unsigned i=0;i<2;++i)if((rc=window_open(o,o->win[i],o->window_bytes[i])))return rc;
 o->control=::open("/dev/xdev_ext_peer",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
 if(o->control<0)return -errno;
 xdev_ext_prog_opts p{};p.sz=sizeof(p);p.obj_path=c.bpf_object;p.map_name="xdomain_peer_ops";
 if((rc=xdev_ext_prog_attach(&p,&o->xdomain)))return rc;
 p.obj_path=c.ce_bpf_object;p.map_name="tp_ce_ops";
 for(auto &program:o->ce_program)if((rc=xdev_ext_prog_attach(&p,&program)))return rc;
 for(unsigned i=0;i<2;++i) {
  xdev_ext_frame_endpoint_opts e{};e.sz=sizeof(e);
  e.control_fd=o->control;e.ce_fd=o->win[i].ce;e.link_token=c.link_token;
  e.direction=i?XDEV_EXT_MECH_DIR_FROM_DEVICE:XDEV_EXT_MECH_DIR_TO_DEVICE;
  e.depth=1;e.group_bytes=c.group_bytes;e.flags=c.endpoint_flags;
  e.window_va=o->win[i].va;e.window_bytes=o->window_bytes[i];
  if((rc=xdev_ext_frame_endpoint_open(&e,&o->endpoint[i])))return rc;
 }
 /* Stage order: send [CE, XDOMAIN], receive [XDOMAIN, CE]. */
 for(unsigned i=0;i<2;++i) {
  int ce=xdev_ext_prog_link_fd(o->ce_program[i]);
  if(ce<0)return ce;
  int selectors[2]={i?-1:ce,i?ce:-1};
  if((rc=xdev_ext_frame_endpoint_create_programs(o->endpoint[i],selectors,2,nullptr)))return rc;
 }
 return 0;
}
extern "C" int xdev_ext_cuda_frame_owner_open(const xdev_ext_cuda_frame_owner_opts *c,
 xdev_ext_cuda_frame_owner **out) {
 if(out)*out=nullptr;
 if(!out || !c || c->size!=sizeof(*c) || c->version!=XDEV_EXT_CUDA_FRAME_OWNER_VERSION)return -EINVAL;
 if(c->endpoint_flags&~XDEV_EXT_FRAME_ENDPOINT_F_EARLY)return -EOPNOTSUPP;
 if(!c->nvidia_node || !*c->nvidia_node || !c->bpf_object || !*c->bpf_object ||
    !c->ce_bpf_object || !*c->ce_bpf_object || !c->link_token ||
    !c->group_bytes || c->group_bytes%64 || c->group_bytes>frame_max_group ||
    !c->receive_groups || c->receive_groups>UINT32_MAX/c->group_bytes ||
    c->timeout_ns<1000000 || c->timeout_ns/1000000>INT_MAX || c->device>INT_MAX ||
    (c->context_mode!=1 && c->context_mode!=2) ||
    (c->context_mode==1 && !c->context) || (c->context_mode==2 && (c->context || c->stream)))
  return -EINVAL;
 auto *o=new(std::nothrow) xdev_ext_cuda_frame_owner;
 if(!o)return -ENOMEM;
 o->config=*c;
 // Always expose partial ownership; no hidden destructor reclaims it.
 *out=o;
 return prepare(o);
}
extern "C" int xdev_ext_cuda_frame_owner_get_view(xdev_ext_cuda_frame_owner *o,
 xdev_ext_cuda_frame_owner_view *v) {
 if(!o || !v || v->size!=sizeof(*v) || !o->endpoint[0] || !o->endpoint[1])return -EINVAL;
 *v={sizeof(*v),o->context,o->stream,o->endpoint[0],o->endpoint[1],o->win[0].va,o->win[1].va,
     o->window_bytes[0],o->window_bytes[1],o->config.group_bytes};
 return 0;
}
extern "C" int xdev_ext_cuda_frame_owner_close(xdev_ext_cuda_frame_owner **pointer) {
 if(!pointer || !*pointer)return -EINVAL;
 auto *o=*pointer;int rc;
 if(o->context && o->stream) {
  if((rc=current(o)))return rc;
  CUstreamCaptureStatus capture;
  if((rc=driver(cuStreamIsCapturing(o->stream,&capture))))return rc;
  if(capture!=CU_STREAM_CAPTURE_STATUS_NONE)return -EBUSY;
  if(!o->last_use && (rc=driver(cuEventCreate(&o->last_use,CU_EVENT_DISABLE_TIMING))))return rc;
  if((rc=driver(cuEventRecord(o->last_use,o->stream))) || (rc=driver(cuEventSynchronize(o->last_use))))return rc;
 }
 // Endpoint close stops its session first: no batch can still use a window.
 for(auto &e:o->endpoint)if(e){if((rc=xdev_ext_frame_endpoint_close(e)))return rc;e=nullptr;}
 for(auto &program:o->ce_program)if(program){if((rc=xdev_ext_prog_detach(program)))return rc;program=nullptr;}
 if(o->xdomain){if((rc=xdev_ext_prog_detach(o->xdomain)))return rc;o->xdomain=nullptr;}
 if(o->control>=0){int fd=o->control;o->control=-1;if(::close(fd))return -errno;}
 for(auto &w:o->win)if((rc=window_close(w)))return rc;
 if(o->last_use){if((rc=driver(cuEventDestroy(o->last_use))))return rc;o->last_use=nullptr;}
 if(o->own_stream){if((rc=driver(cuStreamDestroy(o->stream))))return rc;o->own_stream=false;}
 if(o->own_context){if((rc=driver(cuCtxDestroy(o->context))))return rc;o->own_context=false;}
 delete o;*pointer=nullptr;return 0;
}
