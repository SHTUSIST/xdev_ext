// SPDX-License-Identifier: GPL-2.0
// TP host-frame route (GPU without GPUDirect RDMA), two ranks in one process.
// The production library and its CUDA kernels are included unchanged; the
// kernels run on the host. Only the CUDA Driver calls and the host-frame
// endpoint calls are controlled boundaries. The endpoint fake is a loopback:
// a send post copies the group from the sender's device window (where the
// copy engine would read it) to a wire, a receive wait copies it into the
// receiver's device window at the placement rule of
// libxdev_ext_frame_endpoint.h (where the copy engine would write it).
// Requirement under test (eval plan E2, TODO.59): with host frames selected,
// an all-reduce or all-gather exchanges its payload through the host-frame
// endpoints and produces the right tensor; peer USER endpoints are not used.
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include TP_LIBRARY_SOURCE
#define __device__
#define __global__
struct BoundaryDim {unsigned x=0,y=0,z=0;};
static thread_local BoundaryDim blockIdx,threadIdx,gridDim,blockDim;
#include TP_KERNEL_SOURCE

namespace fake {
std::mutex lock;
std::map<CUdeviceptr,size_t> allocations;
thread_local std::vector<std::string> *log=nullptr;
std::atomic<unsigned> peer_calls{0};
void note(const std::string &s){if(log)log->push_back(s);}
struct Function {std::string name;};
}
CUresult cuCtxGetCurrent(CUcontext *p){*p=reinterpret_cast<void *>(1);return CUDA_SUCCESS;}
CUresult cuStreamGetCtx(CUstream,CUcontext *p){*p=reinterpret_cast<void *>(1);return CUDA_SUCCESS;}
CUresult cuStreamIsCapturing(CUstream,CUstreamCaptureStatus *p){*p=CU_STREAM_CAPTURE_STATUS_NONE;return CUDA_SUCCESS;}
CUresult cuStreamQuery(CUstream){return CUDA_SUCCESS;}
CUresult cuStreamGetId(CUstream s,unsigned long long *p){*p=reinterpret_cast<uintptr_t>(s);return CUDA_SUCCESS;}
CUresult cuPointerGetAttribute(void *p,int attribute,CUdeviceptr){
 if(attribute==CU_POINTER_ATTRIBUTE_CONTEXT)*static_cast<CUcontext *>(p)=reinterpret_cast<void *>(1);
 else if(attribute==CU_POINTER_ATTRIBUTE_MEMORY_TYPE)*static_cast<CUmemorytype *>(p)=CU_MEMORYTYPE_DEVICE;
 else if(attribute==CU_POINTER_ATTRIBUTE_IS_MANAGED)*static_cast<unsigned *>(p)=0;
 else return CUDA_ERROR_UNKNOWN;
 return CUDA_SUCCESS;
}
CUresult cuMemGetAddressRange(CUdeviceptr *base,size_t *bytes,CUdeviceptr p){
 std::lock_guard<std::mutex> g(fake::lock);
 for(auto r:fake::allocations)if(p>=r.first && p-r.first<r.second){*base=r.first;*bytes=r.second;return CUDA_SUCCESS;}
 return CUDA_ERROR_UNKNOWN;
}
CUresult cuMemAlloc(CUdeviceptr *p,size_t n){
 void *m=std::calloc(1,n);if(!m)return CUDA_ERROR_UNKNOWN;
 std::lock_guard<std::mutex> g(fake::lock);*p=reinterpret_cast<uintptr_t>(m);fake::allocations[*p]=n;return CUDA_SUCCESS;
}
CUresult cuMemFree(CUdeviceptr p){
 std::lock_guard<std::mutex> g(fake::lock);fake::allocations.erase(p);std::free(reinterpret_cast<void *>(p));return CUDA_SUCCESS;
}
CUresult cuMemcpyHtoD(CUdeviceptr p,const void *s,size_t n){std::memcpy(reinterpret_cast<void *>(p),s,n);return CUDA_SUCCESS;}
CUresult cuMemcpyHtoDAsync(CUdeviceptr p,const void *s,size_t n,CUstream){return cuMemcpyHtoD(p,s,n);}
CUresult cuMemcpyDtoH(void *p,CUdeviceptr s,size_t n){std::memcpy(p,reinterpret_cast<void *>(s),n);return CUDA_SUCCESS;}
CUresult cuMemsetD8(CUdeviceptr p,unsigned char v,size_t n){std::memset(reinterpret_cast<void *>(p),v,n);return CUDA_SUCCESS;}
CUresult cuModuleLoad(CUmodule *m,const char *){*m=reinterpret_cast<void *>(1);return CUDA_SUCCESS;}
CUresult cuModuleGetFunction(CUfunction *f,CUmodule,const char *name){*f=new fake::Function{name};return CUDA_SUCCESS;}
CUresult cuModuleUnload(CUmodule){return CUDA_SUCCESS;}
CUresult cuEventCreate(CUevent *e,unsigned){*e=reinterpret_cast<void *>(1);return CUDA_SUCCESS;}
CUresult cuEventDestroy(CUevent){return CUDA_SUCCESS;}
CUresult cuEventQuery(CUevent){return CUDA_SUCCESS;}
CUresult cuEventRecord(CUevent,CUstream){return CUDA_SUCCESS;}
CUresult cuStreamGetCaptureInfo(CUstream,CUstreamCaptureStatus *s,cuuint64_t *,CUgraph *g,const CUgraphNode **,size_t *,const void **){*s=0;if(g)*g=nullptr;return CUDA_SUCCESS;}
CUresult cuUserObjectCreate(CUuserObject *,void *,void (*)(void *),unsigned,unsigned){return CUDA_ERROR_UNKNOWN;}
CUresult cuGraphRetainUserObject(CUgraph,CUuserObject,unsigned,unsigned){return CUDA_ERROR_UNKNOWN;}
CUresult cuUserObjectRelease(CUuserObject,unsigned){return CUDA_ERROR_UNKNOWN;}
CUresult cuLaunchKernel(CUfunction function,unsigned gx,unsigned,unsigned,unsigned bx,unsigned,unsigned,unsigned,CUstream,void **args,void **){
 using namespace xdev_tp_native;
 const auto &name=static_cast<fake::Function *>(function)->name;
 fake::note("kernel:"+name);
 auto *work=reinterpret_cast<DeviceWork *>(*static_cast<CUdeviceptr *>(args[0]));
 bool payload=name=="xdev_tp_pack_payload"||name=="xdev_tp_result_payload";
 auto *runtime=payload?nullptr:reinterpret_cast<Runtime *>(*static_cast<CUdeviceptr *>(args[1]));
 gridDim.x=gx;blockDim.x=bx;
 for(unsigned block=0;block<gx;block++)for(unsigned thread=0;thread<bx;thread++) {
  blockIdx.x=block;threadIdx.x=thread;
  if(name=="xdev_tp_pack_begin")xdev_tp_pack_begin(work,runtime,*static_cast<Shape *>(args[2]),
   *static_cast<uint64_t *>(args[3]),*static_cast<uint64_t *>(args[4]),*static_cast<uint32_t *>(args[5]),
   *static_cast<uint64_t *>(args[6]));
  else if(name=="xdev_tp_pack_payload")xdev_tp_pack_payload(work);
  else if(name=="xdev_tp_pack_commit")xdev_tp_pack_commit(work,runtime);
  else if(name=="xdev_tp_result_begin")xdev_tp_result_begin(work,runtime);
  else if(name=="xdev_tp_result_payload")xdev_tp_result_payload(work);
  else if(name=="xdev_tp_result_commit")xdev_tp_result_commit(work,runtime);
  else return CUDA_ERROR_UNKNOWN; // terminal/release are d2-only
 }
 return CUDA_SUCCESS;
}
// The peer USER route must stay unused on the host-frame route.
extern "C" int xdev_ext_peer_endpoint_next(xdev_ext_peer_endpoint *,int,xdev_ext_peer_message *){fake::peer_calls++;return -ENOSYS;}
extern "C" int xdev_ext_peer_endpoint_complete(xdev_ext_peer_endpoint *,const xdev_ext_peer_message *,int){fake::peer_calls++;return -ENOSYS;}
extern "C" int xdev_ext_user_batch_peer_span(const xdev_ext_user_batch *,__u32,__u64,__u64,__u32,xdev_ext_peer_span *){fake::peer_calls++;return -ENOSYS;}
extern "C" int xdev_ext_cuda_host_receive_visible(CUcontext){fake::peer_calls++;return -ENOSYS;}
extern "C" int xdev_ext_cuda_user_wait(xdev_ext_cuda_user *,CUstream,xdev_ext_cuda_message *){fake::peer_calls++;return -ENOSYS;}
extern "C" int xdev_ext_cuda_user_done(xdev_ext_cuda_user *,CUstream,xdev_ext_cuda_message *){fake::peer_calls++;return -ENOSYS;}
extern "C" int xdev_ext_cuda_receive_visible(xdev_ext_cuda_user *,CUstream){fake::peer_calls++;return -ENOSYS;}

// ---- loopback host-frame endpoints ---------------------------------------
struct Wire {
 std::mutex m;std::condition_variable cv;
 std::map<uint64_t,std::vector<unsigned char>> groups;
};
struct xdev_ext_frame_endpoint {
 unsigned direction;CUdeviceptr va;uint64_t window;uint32_t group;
 Wire *wire;uint64_t posted=0;int fail_wait=0;unsigned posts=0,waits=0;
};
extern "C" int tp_frame_placement(__u32,__u32,__u64,__u64,__u64 *,__u32 *);
extern "C" int xdev_ext_frame_endpoint_place(const xdev_ext_frame_endpoint *e,__u64 seq,__u64 *off,__u32 *bytes){
 if(!e || !seq || !off || !bytes)return -EINVAL;
 return tp_frame_placement(e->direction,e->group,e->window,seq,off,bytes);
}
extern "C" int xdev_ext_frame_endpoint_post(xdev_ext_frame_endpoint *e,__u64 seq){
 bool tx=e->direction==XDEV_EXT_MECH_DIR_TO_DEVICE;
 fake::note(std::string(tx?"post-tx:":"post-rx:")+std::to_string(seq));
 if(e->posted)return -EBUSY;
 e->posted=seq;e->posts++;
 if(tx) {
  __u64 off;__u32 bytes;xdev_ext_frame_endpoint_place(e,seq,&off,&bytes);
  const auto *p=reinterpret_cast<const unsigned char *>(e->va+off);
  std::lock_guard<std::mutex> g(e->wire->m);
  e->wire->groups[seq].assign(p,p+bytes);e->wire->cv.notify_all();
 }
 return 0;
}
extern "C" int xdev_ext_frame_endpoint_wait(xdev_ext_frame_endpoint *e,__u64 seq,int timeout_ms){
 bool tx=e->direction==XDEV_EXT_MECH_DIR_TO_DEVICE;
 fake::note(std::string(tx?"wait-tx:":"wait-rx:")+std::to_string(seq));
 e->waits++;
 if(e->posted!=seq)return -EINVAL;
 if(e->fail_wait)return e->fail_wait;
 if(!tx) {
  std::unique_lock<std::mutex> g(e->wire->m);
  if(!e->wire->cv.wait_for(g,std::chrono::milliseconds(timeout_ms>0?timeout_ms:5000),
     [&]{return e->wire->groups.count(seq)!=0;}))return -ETIMEDOUT;
  auto data=e->wire->groups[seq];e->wire->groups.erase(seq);g.unlock();
  __u64 off;__u32 bytes;xdev_ext_frame_endpoint_place(e,seq,&off,&bytes);
  if(data.size()!=bytes || off+bytes>e->window)return -EPROTO;
  std::memcpy(reinterpret_cast<void *>(e->va+off),data.data(),bytes);
 }
 e->posted=0;
 return 0;
}

// ---- test ----------------------------------------------------------------
static unsigned checks,failures;
#define EQ(actual,expected) do{long long a_=(long long)(actual),e_=(long long)(expected);checks++;\
 if(a_!=e_){std::fprintf(stderr,"# line %d %s: got %lld expected %lld\n",__LINE__,#actual,a_,e_);failures++;}}while(0)

static CUdeviceptr device(size_t n){CUdeviceptr p=0;cuMemAlloc(&p,n);return p;}
struct Rank {
 unsigned rank;CUstream stream;
 xdev_ext_frame_endpoint tx{},rx{};
 xdev_tp_comm *comm=nullptr;
 std::vector<std::string> events;
};
static uint32_t group_for(uint64_t payload){return uint32_t((payload+64+63)&~uint64_t(63));}
static xdev_tp_config config(Rank &r,uint64_t max_payload) {
 xdev_tp_config c{};c.size=sizeof(c);c.version=XDEV_TP_ABI_VERSION;c.rank=r.rank;c.world_size=2;
 c.mode=XDEV_TP_D1_EAGER;c.context=reinterpret_cast<void *>(1);
 c.tx_va=r.tx.va;c.rx_va=r.rx.va;c.tx_bytes=r.tx.window;c.rx_bytes=r.rx.window;c.frame_size=4096;
 c.logical_depth=1;c.max_payload_bytes=max_payload;c.first_sequence=1;c.communicator_id=7;c.epoch=9;
 c.timeout_ns=5000000000ULL;c.ptx_path="frames-boundary.ptx";
 c.flags=XDEV_TP_F_HOST_FRAMES;c.tx_frames=&r.tx;c.rx_frames=&r.rx;
 return c;
}
// Rank r sends on wires[r] and receives on wires[r^1]; rx window holds 2 groups.
static void setup(Rank *ranks,Wire *wires,uint64_t max_payload) {
 uint32_t group=group_for(max_payload);
 for(unsigned r=0;r<2;++r) {
  ranks[r].rank=r;ranks[r].stream=reinterpret_cast<void *>(uintptr_t(0x100+r));
  ranks[r].tx={XDEV_EXT_MECH_DIR_TO_DEVICE,device(group),group,group,&wires[r]};
  ranks[r].rx={XDEV_EXT_MECH_DIR_FROM_DEVICE,device(2ULL*group),2ULL*group,group,&wires[r^1]};
  auto c=config(ranks[r],max_payload);
  EQ(xdev_tp_create(&c,&ranks[r].comm),0);
 }
}

static void test_create_rules() {
 Wire wires[2];Rank r[2];
 uint32_t group=group_for(4096);
 r[0].rank=0;r[0].tx={XDEV_EXT_MECH_DIR_TO_DEVICE,device(group),group,group,&wires[0]};
 r[0].rx={XDEV_EXT_MECH_DIR_FROM_DEVICE,device(group),group,group,&wires[1]};
 xdev_tp_comm *comm=nullptr;
 auto c=config(r[0],4096);c.mode=XDEV_TP_D2_GPU;
 EQ(xdev_tp_create(&c,&comm),-EOPNOTSUPP);
 c=config(r[0],4096);c.tx_endpoint=reinterpret_cast<xdev_ext_peer_endpoint *>(&r[0].tx);
 EQ(xdev_tp_create(&c,&comm),-EINVAL);
 c=config(r[0],4096);c.rx_frames=nullptr;
 EQ(xdev_tp_create(&c,&comm),-EINVAL);
 c=config(r[0],4096);c.rx_frames=c.tx_frames;
 EQ(xdev_tp_create(&c,&comm),-EINVAL);
 c=config(r[0],4096);c.d2_rx_consumer=reinterpret_cast<xdev_ext_cuda_user *>(&r[0].rx);
 EQ(xdev_tp_create(&c,&comm),-EINVAL);
 c=config(r[0],4096);c.flags=XDEV_TP_F_HOST_FRAMES|2U;
 EQ(xdev_tp_create(&c,&comm),-EINVAL);
 // Host frames are explicit: without the flag the frame endpoints are not used.
 c=config(r[0],4096);c.flags=0;
 EQ(xdev_tp_create(&c,&comm),-EINVAL);
 EQ(comm==nullptr,1);
 EQ(fake::peer_calls.load(),0);
}

static void run_pair(Rank *ranks,const std::function<int(Rank &)> &call,int *rc) {
 std::thread t[2];
 for(unsigned r=0;r<2;++r)t[r]=std::thread([&,r]{fake::log=&ranks[r].events;rc[r]=call(ranks[r]);fake::log=nullptr;});
 for(auto &x:t)x.join();
}

static void test_allreduce() {
 Wire wires[2];Rank ranks[2];
 const uint64_t n=1000;
 setup(ranks,wires,n*4);
 CUdeviceptr in[2],out[2];
 std::vector<float> a(n),b(n);
 for(uint64_t i=0;i<n;++i){a[i]=0.5f*float(i)-3.0f;b[i]=float(i%17)+0.25f;}
 for(unsigned r=0;r<2;++r){in[r]=device(n*4);out[r]=device(n*4);cuMemcpyHtoD(in[r],r?b.data():a.data(),n*4);}
 for(uint64_t sequence=1;sequence<=2;++sequence) {
  xdev_tp_work *work[2]={};int rc[2]={1,1};
  for(auto &r:ranks)r.events.clear();
  run_pair(ranks,[&](Rank &r){return xdev_tp_allreduce_sum(r.comm,in[r.rank],out[r.rank],n,XDEV_TP_F32,r.stream,sequence,&work[r.rank]);},rc);
  for(unsigned r=0;r<2;++r) {
   EQ(rc[r],0);
   std::vector<float> got(n);cuMemcpyDtoH(got.data(),out[r],n*4);
   unsigned bad=0;for(uint64_t i=0;i<n;++i)bad+=got[i]!=a[i]+b[i];
   EQ(bad,0);
   EQ(xdev_tp_work_query(work[r]),0);
   std::string s=std::to_string(sequence);
   std::vector<std::string> want={"post-rx:"+s,"kernel:xdev_tp_pack_begin","kernel:xdev_tp_pack_payload",
    "kernel:xdev_tp_pack_commit","post-tx:"+s,"wait-rx:"+s,"kernel:xdev_tp_result_begin",
    "kernel:xdev_tp_result_payload","kernel:xdev_tp_result_commit","wait-tx:"+s};
   EQ(ranks[r].events==want,1);
   if(ranks[r].events!=want)for(auto &e:ranks[r].events)std::fprintf(stderr,"#  rank%u %s\n",r,e.c_str());
   EQ(xdev_tp_work_destroy(work[r]),0);
  }
 }
 for(unsigned r=0;r<2;++r) {
  xdev_tp_stats s{};s.size=sizeof(s);
  EQ(xdev_tp_get_stats(ranks[r].comm,&s),0);
  EQ(s.completed,2);EQ(s.failed,0);EQ(s.error,0);EQ(s.retained,0);
  EQ(s.tx_done,2);EQ(s.rx_delivered,2);EQ(s.last_use_released,2);
  EQ(s.payload_tx_bytes,2*n*4);EQ(s.payload_rx_bytes,2*n*4);
  EQ(s.wire_tx_bytes,2ULL*group_for(n*4));EQ(s.wire_rx_bytes,2ULL*group_for(n*4));
  EQ(s.host_control_calls,8);EQ(s.fallback_calls,0);
  EQ(ranks[r].tx.posts,2);EQ(ranks[r].rx.posts,2);
  EQ(xdev_tp_destroy(ranks[r].comm,1000000),0);
 }
 EQ(fake::peer_calls.load(),0);
}

static void test_all_gather_bf16() {
 Wire wires[2];Rank ranks[2];
 const uint64_t rows=2,width=3,n=rows*width;
 setup(ranks,wires,n*2);
 CUdeviceptr in[2],out[2];uint16_t local[2][n];
 for(unsigned r=0;r<2;++r){for(uint64_t i=0;i<n;++i)local[r][i]=uint16_t(0x3f80+16*r+i);
  in[r]=device(n*2);out[r]=device(2*n*2);cuMemcpyHtoD(in[r],local[r],n*2);}
 xdev_tp_work *work[2]={};int rc[2]={1,1};
 run_pair(ranks,[&](Rank &r){return xdev_tp_logits_gather(r.comm,in[r.rank],out[r.rank],rows,width,XDEV_TP_BF16,0,1,r.stream,1,&work[r.rank]);},rc);
 for(unsigned r=0;r<2;++r) {
  EQ(rc[r],0);
  uint16_t got[2*n];cuMemcpyDtoH(got,out[r],sizeof(got));
  unsigned bad=0;
  for(uint64_t row=0;row<rows;++row)for(uint64_t col=0;col<width;++col)for(unsigned src=0;src<2;++src)
   bad+=got[row*2*width+src*width+col]!=local[src][row*width+col];
  EQ(bad,0);
  EQ(xdev_tp_work_destroy(work[r]),0);
  EQ(xdev_tp_destroy(ranks[r].comm,1000000),0);
 }
}

// A payload larger than one host-frame group is refused before any post.
static void test_group_too_small() {
 Wire wires[2];Rank r{};
 uint32_t group=group_for(256);
 r.rank=0;r.stream=reinterpret_cast<void *>(0x100);
 r.tx={XDEV_EXT_MECH_DIR_TO_DEVICE,device(8192),8192,group,&wires[0]};
 r.rx={XDEV_EXT_MECH_DIR_FROM_DEVICE,device(8192),8192,group,&wires[1]};
 auto c=config(r,4096);
 EQ(xdev_tp_create(&c,&r.comm),0);
 CUdeviceptr in=device(4096),out=device(4096);xdev_tp_work *work=nullptr;
 fake::log=&r.events;
 EQ(xdev_tp_allreduce_sum(r.comm,in,out,1024,XDEV_TP_F32,r.stream,1,&work),-EMSGSIZE);
 fake::log=nullptr;
 EQ(work==nullptr,1);EQ(r.events.size(),0);
 xdev_tp_stats s{};s.size=sizeof(s);EQ(xdev_tp_get_stats(r.comm,&s),0);
 EQ(s.preflight_rejected,1);EQ(s.error,0);
 EQ(xdev_tp_destroy(r.comm,1000000),0);
}

// A failed receive after both posts is retained, never retried or replaced.
static void test_receive_failure_retained() {
 Wire wires[2];Rank r{};
 uint32_t group=group_for(16);
 r.rank=0;r.stream=reinterpret_cast<void *>(0x100);
 r.tx={XDEV_EXT_MECH_DIR_TO_DEVICE,device(group),group,group,&wires[0]};
 r.rx={XDEV_EXT_MECH_DIR_FROM_DEVICE,device(group),group,group,&wires[1]};
 r.rx.fail_wait=-EIO;
 auto c=config(r,16);
 EQ(xdev_tp_create(&c,&r.comm),0);
 CUdeviceptr in=device(16),out=device(16);xdev_tp_work *work=nullptr;
 fake::log=&r.events;
 EQ(xdev_tp_allreduce_sum(r.comm,in,out,4,XDEV_TP_F32,r.stream,1,&work),-EIO);
 fake::log=nullptr;
 EQ(work!=nullptr,1);
 EQ(r.tx.posts,1);EQ(r.rx.posts,1);
 xdev_tp_stats s{};s.size=sizeof(s);EQ(xdev_tp_get_stats(r.comm,&s),0);
 EQ(s.error,-EIO);EQ(s.retained,1);EQ(s.completed,0);
 xdev_tp_work *again=nullptr;
 EQ(xdev_tp_allreduce_sum(r.comm,in,out,4,XDEV_TP_F32,r.stream,2,&again),-EIO);
 EQ(again==nullptr,1);EQ(r.tx.posts,1);EQ(r.rx.posts,1);
 EQ(xdev_tp_work_query(work),-EIO);
}

int main() {
 test_create_rules();
 test_allreduce();
 test_all_gather_bf16();
 test_group_too_small();
 test_receive_failure_retained();
 std::printf("%s 1 - TP host-frame d1 route, two ranks (%u checks, %u failures)\n",
  failures?"not ok":"ok",checks,failures);
 std::fflush(stdout);
 return failures!=0;
}
