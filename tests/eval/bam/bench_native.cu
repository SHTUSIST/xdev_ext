// Minimal serial native BaM queue adapter, derived from official nvm_parallel_queue.h
// and page_cache.h, NOT read_data(): no enqueue_second/bookkeeping command.
#include <cuda_runtime.h>
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include "nvm_ctrl.h"
#include "nvm_aq.h"
#include "nvm_admin.h"
#include "nvm_dma.h"
#include "nvm_error.h"
#include "nvm_cmd.h"
#include "nvm_parallel_queue.h"
#include "native_core.h"

struct MissingCapability : std::runtime_error { using std::runtime_error::runtime_error; };
struct Result { uint64_t logical, raw; unsigned error, status; };
struct Pair { nvm_queue_t sq, cq; };
// One command outstanding. PRP is always a controller-page aligned device page;
// tail command NLB is its exact LBA length, never a rounded cache page.
__global__ void native_io(Pair* pair, const uint64_t* prps, uint64_t n,
    uint64_t start_lba, uint64_t bytes, uint32_t page, uint32_t lba,
    uint32_t nsid, uint8_t opcode, Result* result) {
    if (blockIdx.x || threadIdx.x) return;
    for (uint64_t i=0;i<n;++i) {
        nvm_cmd_t cmd = {};
        uint16_t cid=get_cid(&pair->sq);
        uint64_t chunk=bytes-i*page; if(chunk>page) chunk=page;
        nvm_cmd_header(&cmd,cid,opcode,nsid);
        nvm_cmd_data_ptr(&cmd,prps[i],0);
        nvm_cmd_rw_blks(&cmd,start_lba+i*(page/lba),chunk/lba);
        uint16_t sqpos=sq_enqueue(&pair->sq,&cmd);
        ++result->raw;
        uint32_t absolute=0,head=0;
        uint32_t pos=cq_poll(&pair->cq,cid,&absolute,&head);
        volatile nvm_cpl_t* cpl=((volatile nvm_cpl_t*)pair->cq.vaddr)+pos;
        uint32_t dw3=cpl->dword[3],dw2=cpl->dword[2];
        // NVMe status occupies DW3[31:17]; bit 16 is phase, not an error.
        uint16_t status=dw3>>16;
        uint8_t submitted=((volatile nvm_cmd_t*)pair->sq.vaddr)[sqpos].dword[0]&255;
        bool phase=(status&1)==((~(absolute>>pair->cq.qs_log2))&1);
        // Normalize the expected phase for the shared host/device checker.
        unsigned bad=bam::completion(cid,dw3&65535,submitted,opcode,
                                   dw2>>16,pair->sq.no,(status&0xfffe)|unsigned(phase));
        if(bad==1 || (dw2&65535)!=((sqpos+1)&pair->sq.qs_minus_1)) { result->error=3; return; }
        cq_dequeue(&pair->cq,pos,&pair->sq,absolute,head);
        put_cid(&pair->sq,cid);
        if(bad){result->error=bad;result->status=status>>1;return;}
        ++result->logical;
    }
}

static bool uncertain=false;
[[noreturn]] static void quarantine(const char* why) {
    // Returning/exiting after an uncertain GPU submission can revoke DMA memory.
    // Keep process, controller, queues, PRPs and buffers alive. No timeout/replay.
    std::fprintf(stderr,"{\"backend\":\"bam-native\",\"state\":\"unknown\",\"reclaim\":false,\"resubmit\":false,\"reason\":\"%s\"}\n",why);
    std::fflush(stderr);
    for(;;) pause();
}
static void ck(cudaError_t e) { if(e!=cudaSuccess) {
    if(uncertain) quarantine(cudaGetErrorString(e));
    throw std::runtime_error(cudaGetErrorString(e));
} }
static void nv(int e) { if(!nvm_ok(e)) throw std::runtime_error(nvm_strerror(e)); }
template<class F> static void admin_call(F f) {
    uncertain=true;int e=f();
    if(!nvm_ok(e))quarantine("admin command failure: completion/drain not proven");
    uncertain=false;
}
static uint64_t number(const char* s) {
    if(!*s || *s=='-') throw std::runtime_error("invalid numeric argument");
    char* end=nullptr;errno=0;auto n=std::strtoull(s,&end,10);
    if(errno || *end) throw std::runtime_error("invalid numeric argument");return n;
}
static std::vector<unsigned char> image(const char* path,size_t n) {
    std::ifstream f(path,std::ios::binary); if(!f) throw std::runtime_error("image open failed");
    std::vector<unsigned char> v(n);f.read((char*)v.data(),n);
    if(size_t(f.gcount())!=n || f.peek()!=EOF) throw std::runtime_error("image length mismatch");return v;
}
struct Mapping { nvm_dma_t* dma=nullptr; void* original=nullptr; void* address=nullptr; size_t size=0; };
struct Session {
    int fd=-1; nvm_ctrl_t* ctrl=nullptr; nvm_aq_ref aq=nullptr;
    nvm_dma_t* admin=nullptr; void* admin_buffer=nullptr; Pair pair={}; Pair* gpu_pair=nullptr;
    Result* gpu_result=nullptr; uint64_t* gpu_prps=nullptr;
    nvm_ns_info ns={}; nvm_ctrl_info info={};
    bool cq_created=false,sq_created=false,registered=false,cleanup_started=false;
    std::vector<Mapping> maps; std::vector<void*> allocations;
    uint64_t raw=0,logical=0,host_seed_bytes=0,host_oracle_bytes=0;
    // libnvm unmap/free APIs return void; their internal release errors cannot be
    // certified by this adapter. Queue deletion and all CUDA frees are checked.
    void close() {
        if(cleanup_started)throw std::runtime_error("cleanup already attempted; no replay");
        cleanup_started=true;
        if(uncertain) quarantine("cleanup while ownership unknown");
        if(sq_created){admin_call([&]{return nvm_admin_sq_delete(aq,&pair.sq,&pair.cq);});sq_created=false;}
        if(cq_created){admin_call([&]{return nvm_admin_cq_delete(aq,&pair.cq);});cq_created=false;}
        for(auto &m:maps){nvm_dma_unmap(m.dma);ck(cudaFree(m.original));}maps.clear();
        for(auto p:allocations)ck(cudaFree(p));allocations.clear();
        if(registered){ck(cudaHostUnregister((void*)ctrl->mm_ptr));registered=false;}
        if(aq){nvm_aq_destroy(aq);aq=nullptr;}
        if(admin){nvm_dma_unmap(admin);admin=nullptr;}
        if(admin_buffer){free(admin_buffer);admin_buffer=nullptr;}
        if(ctrl){nvm_ctrl_free(ctrl);ctrl=nullptr;}
        if(fd>=0){if(::close(fd))throw std::runtime_error("controller fd close failed");fd=-1;}
    }
    template<class T> T* alloc(size_t n) {
        T* p=nullptr;ck(cudaMalloc((void**)&p,n*sizeof(T)));allocations.push_back(p);
        ck(cudaMemset(p,0,n*sizeof(T)));return p;
    }
    Mapping map(size_t n) {
        Mapping m;m.size=(n+65535)&~size_t(65535);
        ck(cudaMalloc(&m.original,m.size+65536));
        m.address=(void*)((uintptr_t(m.original)+65535)&~uintptr_t(65535));
        int e=nvm_dma_map_device(&m.dma,ctrl,m.address,m.size);
        if(!nvm_ok(e)){ck(cudaFree(m.original));throw MissingCapability("native P2P DMA mapping unavailable");}
        maps.push_back(m);ck(cudaMemset(m.address,0,m.size));return m;
    }
    void setup(const char* path,uint32_t nsid,uint64_t expected_capacity,uint32_t lba,uint32_t page) {
        fd=open(path,O_RDWR|O_CLOEXEC);if(fd<0)throw MissingCapability("controller open unavailable");
        if(!nvm_ok(nvm_ctrl_init(&ctrl,fd)))throw MissingCapability("libnvm controller mapping unavailable");
        if(posix_memalign(&admin_buffer,ctrl->page_size,ctrl->page_size*3))
            throw std::runtime_error("admin allocation failed");
        std::memset(admin_buffer,0,ctrl->page_size*3);
        nv(nvm_dma_map_host(&admin,ctrl,admin_buffer,ctrl->page_size*3));
        admin_call([&]{return nvm_aq_create(&aq,ctrl,admin);});
        admin_call([&]{return nvm_admin_ctrl_info(aq,&info,NVM_DMA_OFFSET(admin,2),admin->ioaddrs[2]);});
        admin_call([&]{return nvm_admin_ns_info(aq,&ns,nsid,NVM_DMA_OFFSET(admin,2),admin->ioaddrs[2]);});
        if(ns.ns_id!=nsid || ns.size!=expected_capacity || ns.capacity<expected_capacity ||
           ns.lba_data_size!=lba || ns.metadata_size || ctrl->page_size!=page)
            throw std::runtime_error("namespace geometry differs from qualification");
        if(cudaHostRegister((void*)ctrl->mm_ptr,NVM_CTRL_MEM_MINSIZE,cudaHostRegisterIoMemory)!=cudaSuccess)
            throw MissingCapability("GPU MMIO registration unavailable");
        registered=true;
        uint16_t cqs=1,sqs=1;admin_call([&]{return nvm_admin_request_num_queues(aq,&sqs,&cqs);});
        if(!sqs||!cqs||ctrl->max_qs<2)throw std::runtime_error("no native queue capacity");
        auto sqm=map(65536),cqm=map(65536);
        admin_call([&]{return nvm_admin_cq_create(aq,&pair.cq,1,cqm.dma,0,2,false);});cq_created=true;
        admin_call([&]{return nvm_admin_sq_create(aq,&pair.sq,&pair.cq,1,sqm.dma,0,2,false);});sq_created=true;
        for(auto q:{&pair.sq,&pair.cq}) {
            void* db=nullptr;ck(cudaHostGetDevicePointer(&db,(void*)q->db,0));q->db=(volatile uint32_t*)db;
            q->qs_minus_1=q->qs-1;q->qs_log2=1;
        }
        pair.sq.tickets=alloc<padded_struct>(2);pair.sq.tail_mark=alloc<padded_struct>(2);
        pair.sq.cid=alloc<padded_struct>(65536);
        pair.cq.head_mark=alloc<padded_struct>(2);pair.cq.pos_locks=alloc<padded_struct>(2);
        gpu_pair=alloc<Pair>(1);ck(cudaMemcpy(gpu_pair,&pair,sizeof(pair),cudaMemcpyHostToDevice));
        gpu_result=alloc<Result>(1);
    }
    void io(Mapping& m,uint64_t bytes,uint64_t start,uint32_t page,uint32_t lba,uint8_t opcode) {
        uint64_t n=(bytes+page-1)/page;
        std::vector<uint64_t> prps(n);
        for(uint64_t i=0;i<n;++i) {
            uint64_t off=65536+i*page,idx=off/m.dma->page_size;
            if(idx>=m.dma->n_ioaddrs)throw std::runtime_error("PRP map out of range");
            prps[i]=m.dma->ioaddrs[idx]+off%m.dma->page_size;
            if(prps[i]%page)throw std::runtime_error("unaligned PRP");
        }
        gpu_prps=alloc<uint64_t>(n);ck(cudaMemcpy(gpu_prps,prps.data(),n*8,cudaMemcpyHostToDevice));
        ck(cudaMemset(gpu_result,0,sizeof(Result)));
        uncertain=true;
        native_io<<<1,1>>>(gpu_pair,gpu_prps,n,start,bytes,page,lba,ns.ns_id,opcode,gpu_result);
        ck(cudaGetLastError());ck(cudaDeviceSynchronize());
        Result result={};ck(cudaMemcpy(&result,gpu_result,sizeof(result),cudaMemcpyDeviceToHost));
        // A normally returned serial kernel has no command outstanding, including
        // terminal status errors. Driver/launch/sync/copy failures stay UNKNOWN.
        if(result.error==3)quarantine("CQE identity/SQ head mismatch");
        uncertain=false;raw+=result.raw;logical+=result.logical;
        if(result.error || result.raw!=n || result.logical!=n)
            throw std::runtime_error("native CQE failure or short completion");
    }
    void upload(Mapping& m,const std::vector<unsigned char>& v) {
        ck(cudaMemset(m.address,0xa5,m.size));
        ck(cudaMemcpy((char*)m.address+65536,v.data(),v.size(),cudaMemcpyHostToDevice));host_seed_bytes+=v.size();
    }
    void verify(Mapping& m,const std::vector<unsigned char>& expected) {
        std::vector<unsigned char> actual(m.size);
        ck(cudaMemcpy(actual.data(),m.address,m.size,cudaMemcpyDeviceToHost));host_oracle_bytes+=m.size;
        if(!bam::verify(expected.data(),expected.size(),actual.data()+65536,expected.size(),
            actual.data()+65536-32,32,actual.data()+65536+expected.size(),32))
            throw std::runtime_error("full image or DMA guard mismatch");
        for(size_t i=0;i<65536;++i)if(actual[i]!=0xa5)throw std::runtime_error("prefix redzone modified");
        for(size_t i=65536+expected.size();i<m.size;++i)
            if(actual[i]!=0xa5)throw std::runtime_error("suffix/untouched buffer tail modified");
    }
};
int main(int argc,char** argv) {
    // Only run_native.py emits authorization after validating the receipt.
    if(argc!=15 || std::string(argv[1])!="--authorized-native-v1") {
        std::fprintf(stderr,"qualification runner required\n");return 4;
    }
    Session* s=new Session;bool changed=false;Mapping data;std::vector<unsigned char> original;
    uint64_t bytes=0,start=0;uint32_t page=0,lba=0;
    try {
        uint64_t nsid=number(argv[3]),capacity=number(argv[4]);lba=number(argv[5]);page=number(argv[6]);
        start=number(argv[7]);uint64_t blocks=number(argv[8]);bytes=number(argv[9]);
        bool write=std::string(argv[12])=="write";
        if(!nsid||nsid>0xfffffffe||!lba||!page||page>65536||page%lba||
           (page&(page-1))||(lba&(lba-1))||!blocks||blocks>64*1024*1024/lba||
           start>capacity||blocks>capacity-start||!bytes||bytes%lba||bytes>blocks*lba||
           (std::string(argv[12])!="read"&&!write))throw std::runtime_error("invalid geometry/direction");
        size_t region=blocks*lba;original=image(argv[13],region);
        auto expected=original;
        if(write){auto seed=image(argv[14],bytes);std::copy(seed.begin(),seed.end(),expected.begin());}
        int count=0;if(cudaGetDeviceCount(&count)!=cudaSuccess){std::fprintf(stderr,"NOT_RUN: CUDA driver/device unavailable\n");delete s;return 4;}int selected=-1;
        for(int i=0;i<count;++i){cudaDeviceProp p;ck(cudaGetDeviceProperties(&p,i));
            char uuid[41];std::snprintf(uuid,sizeof(uuid),"GPU-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            (unsigned char)p.uuid.bytes[0],(unsigned char)p.uuid.bytes[1],(unsigned char)p.uuid.bytes[2],(unsigned char)p.uuid.bytes[3],
            (unsigned char)p.uuid.bytes[4],(unsigned char)p.uuid.bytes[5],(unsigned char)p.uuid.bytes[6],(unsigned char)p.uuid.bytes[7],
            (unsigned char)p.uuid.bytes[8],(unsigned char)p.uuid.bytes[9],(unsigned char)p.uuid.bytes[10],(unsigned char)p.uuid.bytes[11],
            (unsigned char)p.uuid.bytes[12],(unsigned char)p.uuid.bytes[13],(unsigned char)p.uuid.bytes[14],(unsigned char)p.uuid.bytes[15]);
            if(std::string(argv[10])==uuid && p.major>=7 && uint64_t(p.major*10+p.minor)==number(argv[11]))selected=i;
        }
        if(selected<0){std::fprintf(stderr,"NOT_RUN: qualified GPU absent\n");delete s;return 4;}
        ck(cudaSetDevice(selected));
        // SIGINT/SIGTERM must not unwind accepted native I/O. SIGKILL and system
        // reset remain external physical hazards and cannot be handled in process.
        std::signal(SIGINT,SIG_IGN);std::signal(SIGTERM,SIG_IGN);std::signal(SIGHUP,SIG_IGN);
        s->setup(argv[2],nsid,capacity,lba,page);
        if(start>s->ns.size || blocks>s->ns.size-start)throw std::runtime_error("actual namespace bound");
        data=s->map(region+131072);
        s->upload(data,std::vector<unsigned char>(region,0xa5));
        s->io(data,region,start,page,lba,NVM_IO_READ);s->verify(data,original);
        uint64_t baseline=s->raw,workload=0;
        if(write) {
            s->upload(data,expected);changed=true;
            s->io(data,bytes,start,page,lba,NVM_IO_WRITE);workload=s->raw-baseline;
            s->upload(data,std::vector<unsigned char>(region,0xa5));
            s->io(data,region,start,page,lba,NVM_IO_READ);s->verify(data,expected);
            s->upload(data,original);s->io(data,bytes,start,page,lba,NVM_IO_WRITE);
            s->upload(data,std::vector<unsigned char>(region,0xa5));
            s->io(data,region,start,page,lba,NVM_IO_READ);s->verify(data,original);changed=false;
        } else {
            s->upload(data,std::vector<unsigned char>(region,0xa5));
            s->io(data,bytes,start,page,lba,NVM_IO_READ);workload=s->raw-baseline;
            s->verify(data,std::vector<unsigned char>(original.begin(),original.begin()+bytes));
        }
        s->close();
        std::printf("{\"backend\":\"bam-native\",\"mode\":\"correctness\",\"state\":\"success\",\"full_image_verified\":true,\"original_restored\":true,\"logical_operations\":%llu,\"raw_native_commands\":%llu,\"verification_and_restoration_commands\":%llu,\"host_seed_bytes\":%llu,\"host_oracle_bytes\":%llu}\n",
          (unsigned long long)workload,(unsigned long long)s->raw,(unsigned long long)(s->raw-workload),(unsigned long long)s->host_seed_bytes,(unsigned long long)s->host_oracle_bytes);
        delete s;return 0;
    } catch(const std::exception& e) {
        if(uncertain)quarantine(e.what());
        std::fprintf(stderr,"{\"backend\":\"bam-native\",\"state\":\"error\",\"original_restore_required\":%s}\n",changed?"true":"false");
        std::fprintf(stderr,"%s\n",e.what());
        try{s->close();}catch(const std::exception& cleanup){std::fprintf(stderr,"cleanup: %s\n",cleanup.what());}
        int code=dynamic_cast<const MissingCapability*>(&e)?4:1;
        delete s;return code;
    }
}
