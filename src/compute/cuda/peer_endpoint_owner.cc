// SPDX-License-Identifier: GPL-2.0
#include "peer_endpoint_owner.h"
#include <linux/xdev_ext_peer.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <new>
#include <vector>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
struct xdev_ext_cuda_peer_owner {
 xdev_ext_cuda_peer_owner_opts config{};
 uint32_t endpoint_flags=0;
 CUcontext context=nullptr;
 CUstream stream=nullptr;
 CUevent last_use=nullptr;
 bool own_context=false,own_stream=false,started=false;
 CUdeviceptr raw[2]{},va[2]{};
 int gpu=-1,control=-1,allocation[2]{-1,-1};
 xdev_ext_peer_endpoint *endpoint[2]{};
 xdev_ext_cuda_user *producer=nullptr,*terminal=nullptr,*consumer=nullptr;
 xdev_ext_prog *program=nullptr,*user_program=nullptr;
 std::vector<__u32> indices;
};
static int driver(CUresult rc) {return rc==CUDA_SUCCESS?0:-EIO;}
static int current(xdev_ext_cuda_peer_owner *o) {
 CUcontext c=nullptr;int rc=driver(cuCtxGetCurrent(&c));
 return rc?rc:c==o->context?0:-EXDEV;
}
static int prepare(xdev_ext_cuda_peer_owner *o) {
 auto &c=o->config;int rc;
 xdev_ext_link_snapshot link{};
 if((rc=xdev_ext_link_discover("/sys/bus/thunderbolt/devices",c.link_token,&link)))return rc;
 if(c.context_mode==XDEV_EXT_CUDA_PEER_CREATE_OWN) {
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
 CUstreamCaptureStatus capture;
 if((rc=driver(cuStreamIsCapturing(o->stream,&capture))))return rc;
 if(capture!=CU_STREAM_CAPTURE_STATUS_NONE)return -EOPNOTSUPP;
 o->gpu=::open(c.nvidia_node,O_RDWR|O_CLOEXEC|O_NOFOLLOW);
 if(o->gpu<0)return -errno;
 o->control=::open("/dev/xdev_ext_peer",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
 if(o->control<0)return -errno;
 for(unsigned i=0;i<2;++i) {
  if((rc=driver(cuMemAlloc(&o->raw[i],c.allocation_bytes+65536))))return rc;
  o->va[i]=(o->raw[i]+65535)&~CUdeviceptr(65535);
  unsigned sync=1;
  if((rc=driver(cuPointerSetAttribute(&sync,CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,o->va[i]))))return rc;
  xdev_ext_peer_register r{};r.gpu_fd=o->gpu;r.gpu_va=o->va[i];r.len=c.allocation_bytes;
  o->allocation[i]=ioctl(o->control,XDEV_EXT_PEER_REGISTER,&r);
  if(o->allocation[i]<0)return -errno;
  if(!r.generation)return -ESTALE;
 }
 xdev_ext_prog_opts p{};p.sz=sizeof(p);p.obj_path=c.bpf_object;p.map_name="xdomain_peer_ops";
 if((rc=xdev_ext_prog_attach(&p,&o->program)))return rc;
 p.obj_path=c.user_bpf_object;p.map_name="user_plan_ops";
 if((rc=xdev_ext_prog_attach(&p,&o->user_program)))return rc;
 for(unsigned i=0;i<2;++i) {
  xdev_ext_peer_endpoint_opts e{};e.sz=sizeof(e);e.allocation_fd=o->allocation[i];e.control_fd=o->control;
  e.link_token=c.link_token;e.direction=i?XDEV_EXT_MECH_DIR_FROM_DEVICE:XDEV_EXT_MECH_DIR_TO_DEVICE;
  e.depth=c.depth;e.group_bytes=c.group_bytes;e.deadline_ms=unsigned(c.timeout_ns/1000000);
  e.layout={4096,0,4096,c.group_bytes};e.flags=o->endpoint_flags|(c.mode==2?XDEV_EXT_PEER_ENDPOINT_F_EXTERNAL_CTL:0);
  if((rc=xdev_ext_peer_endpoint_open(&e,&o->endpoint[i])))return rc;
 }
 if(c.mode==2) {
  if((rc=xdev_ext_cuda_user_open(xdev_ext_peer_endpoint_user(o->endpoint[0],XDEV_EXT_PEER_PRODUCER),o->context,o->va[0],c.allocation_bytes,4096,&o->producer)))return rc;
  if((rc=xdev_ext_cuda_user_open(xdev_ext_peer_endpoint_user(o->endpoint[0],XDEV_EXT_PEER_TX_TERMINAL),o->context,o->va[0],c.allocation_bytes,4096,&o->terminal)))return rc;
  if((rc=xdev_ext_cuda_user_open(xdev_ext_peer_endpoint_user(o->endpoint[1],XDEV_EXT_PEER_RX_CONSUMER),o->context,o->va[1],c.allocation_bytes,4096,&o->consumer)))return rc;
 }
 for(auto e:o->endpoint)if((rc=xdev_ext_peer_endpoint_create(e)))return rc;
 unsigned frames=((c.group_bytes+4095)/4096)*c.depth;
 try {o->indices.resize(frames);}catch(const std::bad_alloc&){return -ENOMEM;}
 for(unsigned i=0;i<frames;++i)o->indices[i]=i;
 return 0;
}
extern "C" int xdev_ext_cuda_peer_owner_open(const xdev_ext_cuda_peer_owner_opts *c,xdev_ext_cuda_peer_owner **out) {
 return xdev_ext_cuda_peer_owner_open_flags(c,0,out);
}
extern "C" int xdev_ext_cuda_peer_owner_open_flags(const xdev_ext_cuda_peer_owner_opts *c,uint32_t endpoint_flags,xdev_ext_cuda_peer_owner **out) {
 if(out)*out=nullptr;
 if((endpoint_flags&~XDEV_EXT_PEER_ENDPOINT_F_EARLY) || !out || !c || c->size!=sizeof(*c) || c->version!=1 || (c->mode!=1 && c->mode!=2) ||
    !c->nvidia_node || !*c->nvidia_node || !c->bpf_object || !*c->bpf_object ||
    !c->user_bpf_object || !*c->user_bpf_object || !c->link_token ||
    !c->allocation_bytes || c->allocation_bytes%65536 || c->allocation_bytes>UINT64_MAX-65536 ||
    !c->group_bytes || c->group_bytes>32*4096 || c->group_bytes%64 ||
    !c->depth || c->depth>256 || (c->mode==1 && c->depth!=1) ||
    !c->nr_batches || !c->first_sequence || c->nr_batches>UINT64_MAX-c->first_sequence ||
    c->timeout_ns<1000000 || c->timeout_ns/1000000>INT_MAX || c->device>INT_MAX ||
    (c->context_mode!=1 && c->context_mode!=2) ||
    (c->context_mode==1 && !c->context) || (c->context_mode==2 && (c->context || c->stream)) ||
    uint64_t((c->group_bytes+4095)/4096)*c->depth*4096>c->allocation_bytes)return -EINVAL;
 if(c->mode==2) {
  const char *ptx=getenv("XDEV_EXT_CUDA_PTX");
  if(!ptx || !*ptx || access(ptx,R_OK))return -ENOENT;
 }
 auto *o=new(std::nothrow) xdev_ext_cuda_peer_owner;
 if(!o)return -ENOMEM;
 o->config=*c;o->endpoint_flags=endpoint_flags;
 // Always expose partial ownership; no hidden destructor may reclaim UNKNOWN.
 *out=o;
 return prepare(o);
}
extern "C" int xdev_ext_cuda_peer_owner_get_view(xdev_ext_cuda_peer_owner *o,xdev_ext_cuda_peer_owner_view *v) {
 if(!o || !v || v->size!=sizeof(*v) || !o->endpoint[0] || !o->endpoint[1])return -EINVAL;
 *v={sizeof(*v),o->context,o->stream,o->endpoint[0],o->endpoint[1],o->va[0],o->va[1],
     o->config.allocation_bytes,o->producer,o->terminal,o->consumer,4096};
 return 0;
}
extern "C" int xdev_ext_cuda_peer_owner_start(xdev_ext_cuda_peer_owner *o) {
 if(!o || o->started || o->indices.empty())return -EINVAL;
 int rc=current(o);if(rc)return rc;
 xdev_ext_start_frames_opts s{};s.sz=sizeof(s);s.nr_batches=o->config.nr_batches;
 s.first_seq=o->config.first_sequence;s.indices=o->indices.data();s.nr_indices=unsigned(o->indices.size());
 s.flags=XDEV_EXT_MECH_START_F_RECYCLE;
 o->started=true;
 for(auto e:o->endpoint)if((rc=xdev_ext_peer_endpoint_start(e,&s)))return rc;
 return 0;
}
extern "C" int xdev_ext_cuda_peer_owner_close(xdev_ext_cuda_peer_owner **pointer) {
 if(!pointer || !*pointer)return -EINVAL;
 auto *o=*pointer;int rc;
 if(o->context) {
  if((rc=current(o)))return rc;
  CUstreamCaptureStatus capture;
  if((rc=driver(cuStreamIsCapturing(o->stream,&capture))))return rc;
  if(capture!=CU_STREAM_CAPTURE_STATUS_NONE)return -EBUSY;
  if(!o->last_use && (rc=driver(cuEventCreate(&o->last_use,CU_EVENT_DISABLE_TIMING))))return rc;
  if((rc=driver(cuEventRecord(o->last_use,o->stream))) || (rc=driver(cuEventSynchronize(o->last_use))))return rc;
 }
 for(auto e:o->endpoint)if(e && o->started && (rc=xdev_ext_peer_endpoint_stop(e)))return rc;
 if(o->producer) {if((rc=xdev_ext_cuda_user_close(o->producer,o->stream)))return rc;o->producer=nullptr;}
 if(o->terminal) {if((rc=xdev_ext_cuda_user_close(o->terminal,o->stream)))return rc;o->terminal=nullptr;}
 if(o->consumer) {if((rc=xdev_ext_cuda_user_close(o->consumer,o->stream)))return rc;o->consumer=nullptr;}
 for(auto &e:o->endpoint)if(e){if((rc=xdev_ext_peer_endpoint_close(e)))return rc;e=nullptr;}
 if(o->program){if((rc=xdev_ext_prog_detach(o->program)))return rc;o->program=nullptr;}
 if(o->user_program){if((rc=xdev_ext_prog_detach(o->user_program)))return rc;o->user_program=nullptr;}
 for(unsigned i=0;i<2;++i) {
  if(o->allocation[i]>=0){int fd=o->allocation[i];o->allocation[i]=-1;if(::close(fd))return -errno;}
  if(o->raw[i]){if((rc=driver(cuMemFree(o->raw[i]))))return rc;o->raw[i]=o->va[i]=0;}
 }
 if(o->control>=0){int fd=o->control;o->control=-1;if(::close(fd))return -errno;}
 if(o->gpu>=0){int fd=o->gpu;o->gpu=-1;if(::close(fd))return -errno;}
 if(o->last_use){if((rc=driver(cuEventDestroy(o->last_use))))return rc;o->last_use=nullptr;}
 if(o->own_stream){if((rc=driver(cuStreamDestroy(o->stream))))return rc;o->own_stream=false;}
 if(o->own_context){if((rc=driver(cuCtxDestroy(o->context))))return rc;o->own_context=false;}
 delete o;*pointer=nullptr;return 0;
}
