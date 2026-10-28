// SPDX-License-Identifier: GPL-2.0
// Actual complete owner TU, shared CUDA/OS/endpoint boundary dependencies.
// The generator adds flag observations only to the existing endpoint dependency.
static unsigned observed_flags[2],observed_direction[2],observed_endpoints;
#include EARLY_OWNER_BOUNDARY
extern "C" int owner_registry_attach(unsigned,const void *) { return 0; }
extern "C" int owner_registry_detach(unsigned,const void *) { return 0; }
extern "C" bool owner_registry_has(unsigned) { return true; }

// Frozen transition adapter: legacy executes actual old open and cannot select
// EARLY; after the declared new interface exists, call it directly, no fallback.
static int requested_open(const xdev_ext_cuda_peer_owner_opts *opts,
                          unsigned endpoint_flags,xdev_ext_cuda_peer_owner **owner) {
#if EARLY_SELECTION_NEW_API
 return xdev_ext_cuda_peer_owner_open_flags(opts,endpoint_flags,owner);
#else
 (void)endpoint_flags;
 return xdev_ext_cuda_peer_owner_open(opts,owner);
#endif
}
struct LegacyOpts {
 size_t size;
 uint32_t version,mode,context_mode,device;
 CUcontext context;CUstream stream;
 const char *nvidia_node,*bpf_object;
 uint64_t link_token,allocation_bytes,nr_batches,first_sequence,timeout_ns;
 uint32_t group_bytes,depth;
 const char *user_bpf_object;
};
int main(int argc,char **argv) {
 assert(argc==6);fault=argv[1];unsigned mode=unsigned(std::stoul(argv[2]));
 unsigned selection=unsigned(std::stoul(argv[3]));bool old_abi=std::strcmp(argv[4],"old")==0;
 setenv("XDEV_EXT_CUDA_PTX",argv[5],1);
 xdev_ext_cuda_peer_owner_opts opts{};opts.size=sizeof(opts);opts.version=1;opts.mode=mode;
 opts.context_mode=XDEV_EXT_CUDA_PEER_BORROW_CURRENT;opts.context=reinterpret_cast<void *>(1);opts.stream=reinterpret_cast<void *>(2);
 opts.nvidia_node="boundary-node";opts.bpf_object="boundary-bpf";opts.user_bpf_object="boundary-user-bpf";
 opts.link_token=7;opts.allocation_bytes=65536;opts.nr_batches=4;opts.first_sequence=23;
 opts.timeout_ns=1000000000;opts.group_bytes=128;opts.depth=mode==1?1:2;
 check(sizeof(opts)==sizeof(LegacyOpts),"existing version1 options ABI size remains unchanged");
 check(offsetof(xdev_ext_cuda_peer_owner_opts,user_bpf_object)==offsetof(LegacyOpts,user_bpf_object),"existing version1 trailing option offset unchanged");
 auto *owner=reinterpret_cast<xdev_ext_cuda_peer_owner *>(uintptr_t(0x1234));
 int opened=old_abi?xdev_ext_cuda_peer_owner_open(&opts,&owner):requested_open(&opts,selection,&owner);
 if(selection & ~2U) {
  check(opened==-EINVAL,"unknown/EXTERNAL_CTL input bits rejected");
  check(owner==nullptr,"invalid selection clears supplied output");
  check(!allocs&&!registrations&&live_fds.empty()&&!endpoint_creates&&!observed_endpoints&&!control_opens,
        "invalid selection rejected before CUDA, OS, endpoint or control resources");
  if(owner && owner!=reinterpret_cast<xdev_ext_cuda_peer_owner *>(uintptr_t(0x1234)))xdev_ext_cuda_peer_owner_close(&owner);
 } else {
  bool partial=fault=="mem_second"||fault=="register_second";
  check(partial?opened<0:opened==0,"selected open preserves original partial failure status");
  check(owner!=nullptr,"selected open exposes actual partial/full ownership");
  if(!partial) {
   const unsigned expected=(mode==2?1U:0U)|(old_abi?0U:selection);
   check(observed_endpoints==2,"selected owner prepares both endpoints");
   check(observed_flags[0]==expected&&observed_flags[1]==expected,"both real endpoint preparations receive requested EARLY plus mode-derived EXTERNAL_CTL");
   check(observed_direction[0]==XDEV_EXT_MECH_DIR_TO_DEVICE&&observed_direction[1]==XDEV_EXT_MECH_DIR_FROM_DEVICE,"real duplex endpoint directions retained");
   check(allocs==2&&registrations==2&&registered_va[0]!=registered_va[1]&&allocation_fds[0]!=allocation_fds[1],"selected owner retains two independent authorities");
   check(control_opens==(mode==2?3U:0U),"EXTERNAL_CTL and CUDA controls derive only from actual mode");
   check(!xdev_ext_cuda_peer_owner_start(owner),"selected owner still starts through actual existing API");
  }
  int closed=xdev_ext_cuda_peer_owner_close(&owner);
  bool unknown=fault=="event_sync";
  check(unknown?closed<0:closed==0,"selected owner retains original UNKNOWN close behavior");
  check(unknown?owner!=nullptr:owner==nullptr,"only successful selected close clears owner");
  check(unknown?!live_allocations.empty():live_allocations.empty(),"selected owner preserves allocation lifetime on partial/UNKNOWN paths");
  if(unknown)check(!frees&&!endpoint_stops&&!control_closes&&!endpoint_closes&&!closes,"failed last-use proof retains every underlying resource");
  check(!context_creates&&!context_destroys&&!stream_creates&&!stream_destroys,"selection never takes ownership of borrowed CUDA context/stream");
 }
 std::cout<<"EARLY_SELECTION mode="<<mode<<" requested="<<selection<<" old_abi="<<old_abi<<" endpoint_flags="<<observed_flags[0]<<","<<observed_flags[1]<<" opened="<<opened<<" failures="<<failures<<"\n";
 for(auto &entry:live_allocations)std::free(reinterpret_cast<void *>(entry.first));
 return failures?1:0;
}
