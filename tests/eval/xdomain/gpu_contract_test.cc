// SPDX-License-Identifier: GPL-2.0
// Only metadata and bounded summaries exist in this recording boundary. No payload.
#include <cuda.h>
#include "gpu_adapter.h"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <type_traits>
#include <vector>

static_assert(CU_GPU_DIRECT_RDMA_WRITES_ORDERING_NONE == 0);
static_assert(CU_GPU_DIRECT_RDMA_WRITES_ORDERING_OWNER == 100);
static_assert(CU_GPU_DIRECT_RDMA_WRITES_ORDERING_ALL_DEVICES == 200);
static_assert(CU_FLUSH_GPU_DIRECT_RDMA_WRITES_TO_OWNER == 100);
static_assert(CU_FLUSH_GPU_DIRECT_RDMA_WRITES_OPTION_HOST == 1);

namespace {
// Append-only diagnostic fault controls. Defaults preserve the original 51 cases.
thread_local const char *diagnostic_failure_name = nullptr;
thread_local CUresult diagnostic_failure_result = CUDA_SUCCESS;
thread_local int diagnostic_open_errno = 0;
std::mutex sync_mutex;
std::condition_variable sync_cv;
bool block_sync=false, sync_entered=false, release_sync=false;
constexpr CUdeviceptr BASE = 0x100000003ULL;
constexpr uint64_t BYTES = 65536;
constexpr uint64_t COOKIE = 0x725a551234ULL;
CUcontext ctx = reinterpret_cast<CUcontext>(0x1230);
CUstream stream = reinterpret_cast<CUstream>(0x2340);
CUmodule module = reinterpret_cast<CUmodule>(0x3450);
CUfunction fill_fn = reinterpret_cast<CUfunction>(0x4560);
CUfunction verify_fn = reinterpret_cast<CUfunction>(0x5670);
struct State {
    std::vector<std::string> calls;
    std::map<CUdeviceptr, std::vector<unsigned char>> metadata;
    std::vector<tb_verify_extent> expected_extents;
    int devices = 1, rdma = 1, ordering = CU_GPU_DIRECT_RDMA_WRITES_ORDERING_OWNER;
    int flush_options = CU_FLUSH_GPU_DIRECT_RDMA_WRITES_OPTION_HOST;
    int managed = 0, memory_type = CU_MEMORYTYPE_DEVICE, ordinal = 0;
    bool wrong_bdf = false, wrong_context = false, sync_set = false;
    bool sync_query_zero = false, node_bad = false, sentinel_seen = false;
    bool hold_in_sync = false, verify_launched = false;
    bool proc_missing = false, proc_wrong_minor = false, proc_ambiguous = false, proc_nondigit = false;
    size_t proc_offset = 0;
    CUdeviceptr result_device = 0;
    uint64_t launched_bytes = 0, launched_cookie = 0;
    size_t verify_sync_count = 0;
    CUdeviceptr next = BASE, payload_base = 0;
    size_t payload_alloc = 0;
    uint64_t requested_cookie = COOKIE;
    std::string fail, summary_mode;
    tb_guard *guard = nullptr;
} s;
void check(bool value, const char *why) { if (!value) throw std::runtime_error(why); }
CUresult call(const char *name) {
    s.calls.emplace_back(name);
    if (diagnostic_failure_name && std::string(name) == diagnostic_failure_name)
        return diagnostic_failure_result;
    return s.fail == name ? CUDA_ERROR_UNKNOWN : CUDA_SUCCESS;
}
size_t count(const char *name) { return std::count(s.calls.begin(), s.calls.end(), name); }
size_t at(const char *name) {
    auto it = std::find(s.calls.begin(), s.calls.end(), name);
    check(it != s.calls.end(), name);
    return static_cast<size_t>(it - s.calls.begin());
}
size_t last_at(const char *name) {
    auto it=std::find(s.calls.rbegin(),s.calls.rend(),name);
    check(it!=s.calls.rend(),name);return s.calls.size()-1-static_cast<size_t>(it-s.calls.rbegin());
}
size_t destructive() {
    return count("cuMemFree") + count("cuStreamDestroy") + count("cuCtxDestroy") + count("close");
}
struct Fixture {
    tb_guard *g = nullptr;
    tb_gpu *gpu = nullptr;
    tb_gpu_request req{"0000:65:00.0", "/dev/nvidia0", "recording-only.ptx", BYTES};
    Fixture() { block_sync=false;sync_entered=false;release_sync=false;s = State{}; check(tb_guard_new(TB_BACKING_GPU, &g) == 0, "guard_new"); s.guard = g; }
    int open() { return tb_gpu_open(&gpu, g, &req); }
    void ready() {
        check(open() == TB_GPU_OK, "open success");
        check(tb_gpu_fill(gpu, 0x0123456789abcdefULL, false) == TB_GPU_OK, "fill success");
    }
    void stopped(bool pair = true) {
        uint64_t ticket = 0;
        check(tb_guard_begin(g, TB_OP_CREATE, &ticket) == 0, "CREATE after synchronized fill");
        check(tb_guard_end(g, ticket, TB_PHASE_SESSION_CREATED, false, true) == 0, "CREATE end");
        check(tb_guard_begin(g, TB_OP_STOP, &ticket) == 0, "STOP begin");
        check(tb_guard_end(g, ticket, TB_PHASE_DRAINED_SAFE, true, true) == 0, "STOP end");
        if (pair) check(tb_guard_pair_stopped(g) == 0, "pair stop proof");
    }
    tb_verify_result verify(uint64_t cookie = COOKIE) {
        tb_verify_extent e{0, 4096, BYTES, 0x0123456789abcdefULL, TB_EXPECT_PAYLOAD, 0};
        tb_verify_result r{};
        s.requested_cookie = cookie;
        check(tb_gpu_verify(gpu, &e, 1, cookie, &r) == TB_GPU_OK, "verify success");
        return r;
    }
};
void held(tb_guard *g) {
    struct tb_guard_snapshot snap{}; tb_guard_snapshot(g, &snap);
    check(snap.held && !snap.gpu_safe && snap.cleanup_permissions == TB_CLEANUP_NONE, "sticky unsafe HELD");
}
void reject_summary(const char *mode) {
    Fixture f; f.ready(); f.stopped();
    check(tb_gpu_receive_visible(f.gpu) == TB_GPU_OK, "visible");
    s.summary_mode = mode;
    tb_verify_extent e{0, 0, BYTES, 1, TB_EXPECT_PAYLOAD, 0}; tb_verify_result r{};
    check(tb_gpu_verify(f.gpu, &e, 1, COOKIE, &r) != TB_GPU_OK, "malformed summary accepted");
}
void run_case(const std::string &name) {
    if (name == "missing-driver") { Fixture f; s.fail="cuInit"; check(f.open()==TB_GPU_UNAVAILABLE,"missing driver unavailable"); check(!count("cuMemAlloc"),"resource acquired"); }
    else if (name == "missing-device") { Fixture f; s.devices=0; check(f.open()!=TB_GPU_OK,"missing GPU accepted"); check(!count("cuMemAlloc"),"resource acquired"); }
    else if (name == "rdma-unsupported") { Fixture f; s.rdma=0; check(f.open()==TB_GPU_UNSUPPORTED,"RDMA unsupported"); }
    else if (name == "wrong-bdf") { Fixture f; s.wrong_bdf=true; check(f.open()!=TB_GPU_OK,"BDF mismatch accepted"); }
    else if (name == "wrong-node") { Fixture f; s.node_bad=true; check(f.open()!=TB_GPU_OK,"wrong node accepted"); }
    else if (name == "proc-node-missing" || name == "proc-node-minor-mismatch" || name == "proc-node-ambiguous" || name == "proc-node-nondecimal") { Fixture f; s.proc_missing=name=="proc-node-missing"; s.proc_wrong_minor=name=="proc-node-minor-mismatch"; s.proc_ambiguous=name=="proc-node-ambiguous"; s.proc_nondigit=name=="proc-node-nondecimal"; check(f.open()!=TB_GPU_OK,"unproved node identity accepted"); }
    else if (name == "wrong-context") { Fixture f; s.wrong_context=true; check(f.open()!=TB_GPU_OK,"foreign context accepted"); }
    else if (name == "wrong-device") { Fixture f; s.ordinal=9; check(f.open()!=TB_GPU_OK,"foreign device accepted"); }
    else if (name == "managed-refusal") { Fixture f; s.managed=1; check(f.open()!=TB_GPU_OK,"managed memory accepted"); }
    else if (name == "host-memory-refusal") { Fixture f; s.memory_type=CU_MEMORYTYPE_HOST; check(f.open()!=TB_GPU_OK,"host memory accepted"); }
    else if (name == "sync-memops-set-failure") { Fixture f; s.fail="cuPointerSetAttribute"; check(f.open()!=TB_GPU_OK,"set error ignored"); }
    else if (name == "sync-memops-query-zero") { Fixture f; s.sync_query_zero=true; check(f.open()!=TB_GPU_OK,"SYNC_MEMOPS not confirmed"); }
    else if (name == "sync-memops-query-failure") { Fixture f; s.fail="sync-query"; check(f.open()!=TB_GPU_OK,"query error ignored"); }
    else if (name == "attributes-all-checked") { Fixture f; check(f.open()==TB_GPU_OK,"open"); check(count("rdma-supported") && count("rdma-ordering") && count("rdma-flush-options"),"missing attribute"); check(s.sync_set && count("sync-query"),"SYNC_MEMOPS set/query required"); }
    else if (name == "attribute-query-failure") { for (const char *a : {"rdma-supported", "rdma-ordering", "rdma-flush-options"}) { Fixture f; s.fail=a; check(f.open()!=TB_GPU_OK,"attribute failure ignored"); } }
    else if (name == "ordering-owner" || name == "ordering-all" || name == "ordering-none-host") {
        Fixture f; s.ordering=name=="ordering-all" ? CU_GPU_DIRECT_RDMA_WRITES_ORDERING_ALL_DEVICES : name=="ordering-owner" ? CU_GPU_DIRECT_RDMA_WRITES_ORDERING_OWNER : CU_GPU_DIRECT_RDMA_WRITES_ORDERING_NONE;
        f.ready(); struct tb_gpu_registration reg{}; check(tb_gpu_registration(f.gpu,&reg)==TB_GPU_OK,"registration");
        check(reg.visibility==static_cast<uint32_t>(name=="ordering-none-host" ? TB_GPU_HOST_FLUSH_OWNER : TB_GPU_NATIVE_OWNER),"route");
        f.stopped(); check(tb_gpu_receive_visible(f.gpu)==TB_GPU_OK,"visible");
        check(count("cuFlushGPUDirectRDMAWrites")==static_cast<size_t>(name=="ordering-none-host"),"flush route");
    }
    else if (name == "ordering-none-no-host") { Fixture f; s.ordering=CU_GPU_DIRECT_RDMA_WRITES_ORDERING_NONE; s.flush_options=CU_FLUSH_GPU_DIRECT_RDMA_WRITES_OPTION_MEMOPS; check(f.open()==TB_GPU_UNSUPPORTED,"HOST bit absent"); }
    else if (name == "ordering-unknown") { Fixture f; s.ordering=1; check(f.open()!=TB_GPU_OK,"unofficial ordering accepted"); }
    else if (name == "flush-failure-held") { Fixture f; s.ordering=0; f.ready(); f.stopped(); s.fail="cuFlushGPUDirectRDMAWrites"; check(tb_gpu_receive_visible(f.gpu)!=TB_GPU_OK,"flush failure ignored"); held(f.g); size_t n=destructive(); check(tb_gpu_close(f.gpu)!=TB_GPU_OK,"held close"); check(destructive()==n,"held cleanup"); }
    else if (name == "no-create-before-fill") { Fixture f; check(f.open()==TB_GPU_OK,"open"); uint64_t t; check(tb_guard_begin(f.g,TB_OP_CREATE,&t)!=0,"CREATE without FILL proof"); }
    else if (name == "fill-launch-sync-proof") { Fixture f; f.ready(); check(at("fill-launch")<last_at("cuStreamSynchronize"),"launch/sync order"); struct tb_guard_snapshot snap{}; tb_guard_snapshot(f.g,&snap); check(snap.gpu_safe && snap.phase==TB_PHASE_GPU_READY,"ready proof"); }
    else if (name == "receiver-guard-launch") { Fixture f; check(f.open()==TB_GPU_OK,"open"); check(tb_gpu_fill(f.gpu,1,true)==TB_GPU_OK,"guard fill"); check(count("fill-launch")==1 && at("fill-launch")<last_at("cuStreamSynchronize"),"guard launch/sync"); }
    else if (name == "launch-failure-held" || name == "sync-failure-held" || name == "late-sync-held") {
        Fixture f; check(f.open()==TB_GPU_OK,"open"); s.fail=name=="launch-failure-held" ? "fill-launch" : name=="sync-failure-held" ? "cuStreamSynchronize" : ""; s.hold_in_sync=name=="late-sync-held";
        check(tb_gpu_fill(f.gpu,1,false)!=TB_GPU_OK,"unknown work accepted"); held(f.g); uint64_t t; check(tb_guard_begin(f.g,TB_OP_CREATE,&t)!=0,"late success CREATE"); check(tb_guard_begin(f.g,TB_OP_START,&t)!=0,"late success START"); size_t n=destructive(); check(tb_gpu_close(f.gpu)!=TB_GPU_OK,"held close"); check(destructive()==n,"unknown work freed");
    }
    else if (name == "blocked-sync-watchdog-held") {
        Fixture f;check(f.open()==TB_GPU_OK,"open");block_sync=true;int result=TB_GPU_OK;
        std::thread owner([&] {result=tb_gpu_fill(f.gpu,1,false);});
        bool entered=false;
        {std::unique_lock<std::mutex> lock(sync_mutex);entered=sync_cv.wait_for(lock,std::chrono::seconds(2),[] {return sync_entered;});}
        if(entered) tb_guard_hold(f.g,TB_HOLD_DEADLINE);
        {std::lock_guard<std::mutex> lock(sync_mutex);release_sync=true;}sync_cv.notify_all();owner.join();
        check(entered,"owner never entered blocking synchronization");check(result!=TB_GPU_OK,"late blocked sync success accepted");held(f.g);
        size_t n=destructive();check(tb_gpu_close(f.gpu)!=TB_GPU_OK,"watchdog held close");check(destructive()==n,"watchdog held cleanup");
        uint64_t ticket;check(tb_guard_begin(f.g,TB_OP_CREATE,&ticket)!=0 && tb_guard_begin(f.g,TB_OP_START,&ticket)!=0,"late sync permitted CREATE/START");
    }
    else if (name == "verify-launch-failure-held" || name == "verify-sync-failure-held" || name == "verify-late-sync-held") {
        Fixture f; f.ready(); f.stopped(); check(tb_gpu_receive_visible(f.gpu)==TB_GPU_OK,"visible");
        s.fail=name=="verify-launch-failure-held"?"verify-launch":name=="verify-sync-failure-held"?"cuStreamSynchronize":"";
        s.hold_in_sync=name=="verify-late-sync-held";
        tb_verify_extent e{0,0,BYTES,1,TB_EXPECT_PAYLOAD,0};tb_verify_result r{};
        check(tb_gpu_verify(f.gpu,&e,1,COOKIE,&r)!=TB_GPU_OK,"unknown verify accepted");
        held(f.g);check(!count("summary-copy"),"unsafe summary copy");
        size_t n=destructive();check(tb_gpu_close(f.gpu)!=TB_GPU_OK,"held verify close");check(destructive()==n,"unsafe verify cleanup");
    }
    else if (name == "verify-zero-cookie") {
        Fixture f;f.ready();f.stopped();check(tb_gpu_receive_visible(f.gpu)==TB_GPU_OK,"visible");
        tb_verify_extent e{0,0,BYTES,1,TB_EXPECT_PAYLOAD,0};tb_verify_result r{};
        size_t n=count("verify-launch");check(tb_gpu_verify(f.gpu,&e,1,0,&r)!=TB_GPU_OK,"zero request cookie");check(count("verify-launch")==n,"zero cookie launched");
    }
    else if (name == "alignment-rounded-original-base") { Fixture f; f.req.registered_bytes=BYTES+1; check(f.open()==TB_GPU_OK,"open"); struct tb_gpu_registration r{}; check(tb_gpu_registration(f.gpu,&r)==TB_GPU_OK,"reg"); check(r.registered_address%TB_GPU_ALIGN==0 && r.registered_bytes==2*BYTES,"alignment/rounding"); check(r.registered_address>=BASE && r.registered_address+r.registered_bytes<=BASE+s.payload_alloc,"allocation extent"); check(tb_gpu_close(f.gpu)==TB_GPU_OK,"pristine cleanup"); check(count("free-original")==1 && !count("free-interior"),"original base free"); }
    else if (name == "length-zero-overflow-limit") { for(uint64_t n : {UINT64_C(0), UINT64_MAX, static_cast<uint64_t>(TB_MAX_ALLOCATION+1)}) { Fixture f; f.req.registered_bytes=n; check(f.open()!=TB_GPU_OK,"bad size accepted"); check(!count("cuMemAlloc"),"invalid size allocated"); } }
    else if (name == "address-overflow") { Fixture f; s.next=UINT64_MAX-100; check(f.open()!=TB_GPU_OK,"address wrap accepted"); }
    else if (name == "active-access-refused") { Fixture f; f.ready(); uint64_t t; check(tb_guard_begin(f.g,TB_OP_CREATE,&t)==0,"create"); check(tb_guard_end(f.g,t,TB_PHASE_SESSION_CREATED,false,true)==0,"created"); size_t before=s.calls.size(); tb_verify_extent e{0,0,BYTES,1,TB_EXPECT_PAYLOAD,0}; tb_verify_result r{}; check(tb_gpu_fill(f.gpu,1,false)!=TB_GPU_OK,"active fill"); check(tb_gpu_receive_visible(f.gpu)!=TB_GPU_OK,"active visible"); check(tb_gpu_verify(f.gpu,&e,1,COOKIE,&r)!=TB_GPU_OK,"active verify"); check(tb_gpu_close(f.gpu)!=TB_GPU_OK,"active close"); check(s.calls.size()==before,"active CUDA side effect"); }
    else if (name == "pair-proof-required") { Fixture f; f.ready(); f.stopped(false); size_t n=s.calls.size(); check(tb_gpu_receive_visible(f.gpu)!=TB_GPU_OK,"one STOP visibility"); check(tb_gpu_close(f.gpu)!=TB_GPU_OK,"one STOP cleanup"); check(s.calls.size()==n,"one STOP CUDA side effect"); }
    else if (name == "visibility-proof-required") { Fixture f; f.ready(); f.stopped(); tb_verify_extent e{0,0,BYTES,1,TB_EXPECT_PAYLOAD,0}; tb_verify_result r{}; size_t n=s.calls.size(); check(tb_gpu_verify(f.gpu,&e,1,COOKIE,&r)!=TB_GPU_OK,"verify without visible"); check(s.calls.size()==n,"unproved verify launched"); }
    else if (name == "summary-sentinel-success") { Fixture f; f.ready(); f.stopped(); check(tb_gpu_receive_visible(f.gpu)==TB_GPU_OK,"visible"); auto r=f.verify(); check(s.sentinel_seen,"failing sentinel missing"); check(r.bytes==BYTES && r.mismatches==0 && r.first_bad==UINT64_MAX && r.launch_cookie==COOKIE,"summary"); check(at("verify-launch")<at("summary-copy"),"summary before launch"); check(count("payload-copy")==0,"CPU payload read"); }
    else if (name.rfind("summary-",0)==0) reject_summary(name.substr(8).c_str());
    else if (name == "metadata-extents-preserved") {
        Fixture f;f.ready();f.stopped();check(tb_gpu_receive_visible(f.gpu)==TB_GPU_OK,"visible");
        s.expected_extents={{0,0,4096,1,TB_EXPECT_GUARD,0},{4096,32768,12288,9,TB_EXPECT_PAYLOAD,0},{16384,0,BYTES-16384,1,TB_EXPECT_GUARD,0}};
        tb_verify_result r{};check(tb_gpu_verify(f.gpu,s.expected_extents.data(),s.expected_extents.size(),COOKIE,&r)==TB_GPU_OK,"mixed extents verify");
    }
    else if (name == "bad-extents-refused") { Fixture f; f.ready(); f.stopped(); check(tb_gpu_receive_visible(f.gpu)==TB_GPU_OK,"visible"); for (tb_verify_extent e : {tb_verify_extent{1,0,BYTES-1,1,TB_EXPECT_PAYLOAD,0}, tb_verify_extent{0,0,BYTES-1,1,TB_EXPECT_GUARD,0}, tb_verify_extent{0,UINT64_MAX,BYTES,1,TB_EXPECT_PAYLOAD,0}, tb_verify_extent{0,0,BYTES,1,99,0}}) { tb_verify_result r{}; size_t n=count("verify-launch"); check(tb_gpu_verify(f.gpu,&e,1,COOKIE,&r)!=TB_GPU_OK,"bad extent accepted"); check(count("verify-launch")==n,"bad extent launched"); } }
    else if (name == "held-all-operations-refused") { Fixture f; f.ready(); tb_guard_hold(f.g,TB_HOLD_SIGNAL); size_t n=s.calls.size(); tb_verify_extent e{0,0,BYTES,1,1,0}; tb_verify_result r{}; check(tb_gpu_fill(f.gpu,1,false)!=TB_GPU_OK && tb_gpu_receive_visible(f.gpu)!=TB_GPU_OK && tb_gpu_verify(f.gpu,&e,1,COOKIE,&r)!=TB_GPU_OK && tb_gpu_close(f.gpu)!=TB_GPU_OK,"held operation"); check(s.calls.size()==n,"held CUDA side effect"); check(tb_guard_delete(f.g)!=0,"held guard deleted"); }
    else throw std::runtime_error("unknown test");
}
const char *cases[] = {
 "missing-driver","missing-device","rdma-unsupported","wrong-bdf","wrong-node","proc-node-missing","proc-node-minor-mismatch","proc-node-ambiguous","proc-node-nondecimal","wrong-context","wrong-device","managed-refusal","host-memory-refusal",
 "sync-memops-set-failure","sync-memops-query-zero","sync-memops-query-failure","attributes-all-checked","attribute-query-failure",
 "ordering-owner","ordering-all","ordering-none-host","ordering-none-no-host","ordering-unknown","flush-failure-held","no-create-before-fill",
 "fill-launch-sync-proof","receiver-guard-launch","launch-failure-held","sync-failure-held","late-sync-held","blocked-sync-watchdog-held","verify-launch-failure-held","verify-sync-failure-held","verify-late-sync-held","verify-zero-cookie","alignment-rounded-original-base","length-zero-overflow-limit","address-overflow",
 "active-access-refused","pair-proof-required","visibility-proof-required","summary-sentinel-success","summary-sentinel","summary-zero-bytes","summary-partial-bytes","summary-cookie","summary-first-bad","summary-mismatch","metadata-extents-preserved","bad-extents-refused","held-all-operations-refused"
};

// Independent SPEC regression cases; run_case and cases above stay frozen.
tb_gpu_diagnostic diagnostic_snapshot() {
    tb_gpu_diagnostic result{};
    result.size = sizeof(result);
    result.version = TB_GPU_DIAGNOSTIC_VERSION;
    check(tb_gpu_last_diagnostic(&result) == TB_GPU_OK, "diagnostic getter");
    check(result.size == sizeof(result) && result.version == TB_GPU_DIAGNOSTIC_VERSION,
          "diagnostic schema changed");
    check(std::memchr(result.operation, 0, sizeof(result.operation)) != nullptr,
          "diagnostic operation not terminated");
    return result;
}
void require_cuda_diagnostic(CUresult result, const char *operation) {
    const auto d = diagnostic_snapshot();
    check((d.flags & TB_GPU_DIAG_CUDA) != 0, "original CUDA result missing");
    check(d.cuda_result == static_cast<int32_t>(result), "CUDA error numeric value changed");
    check(std::string(d.operation) == operation, "CUDA operation name changed");
}
void seed_diagnostic_failure() {
    tb_guard *g = nullptr;
    check(tb_guard_new(TB_BACKING_GPU, &g) == 0, "seed diagnostic guard");
    tb_gpu *gpu = nullptr;
    const tb_gpu_request request{"0000:65:00.0", "/dev/nvidia0", "recording-only.ptx", BYTES};
    s.fail = "cuInit";
    check(tb_gpu_open(&gpu, g, &request) != TB_GPU_OK, "seed diagnostic failure");
    s.fail.clear();
    require_cuda_diagnostic(CUDA_ERROR_NOT_INITIALIZED, "cuInit");
}
void require_clean_diagnostic() {
    const auto d = diagnostic_snapshot();
    check(d.flags == 0 && d.cuda_result == 0 && d.system_errno == 0 &&
          d.guard_error == 0 && d.operation[0] == 0, "operation retained stale diagnostic");
}
void diagnostic_case(const std::string &name) {
    diagnostic_failure_name = nullptr;
    diagnostic_failure_result = CUDA_SUCCESS;
    diagnostic_open_errno = 0;
    if (name == "diagnostic-cuda-error-values-and-operation") {
        for (const auto error : {CUDA_ERROR_INVALID_CONTEXT, CUDA_ERROR_LAUNCH_FAILED}) {
            Fixture f;
            check(f.open() == TB_GPU_OK, "diagnostic setup open");
            diagnostic_failure_name = "cuStreamSynchronize";
            diagnostic_failure_result = error;
            check(tb_gpu_fill(f.gpu, 1, false) == TB_GPU_HELD, "sync error must retain resources");
            require_cuda_diagnostic(error, "cuStreamSynchronize");
            diagnostic_failure_name = nullptr;
        }
    } else if (name == "diagnostic-cuda-error-before-object") {
        Fixture f;
        diagnostic_failure_name = "cuDeviceGetByPCIBusId";
        diagnostic_failure_result = CUDA_ERROR_INVALID_CONTEXT;
        check(f.open() != TB_GPU_OK, "device query error accepted");
        require_cuda_diagnostic(CUDA_ERROR_INVALID_CONTEXT, "cuDeviceGetByPCIBusId");
        diagnostic_failure_name = nullptr;
    } else if (name == "diagnostic-system-errno") {
        for (const int error : {EACCES, ENOENT}) {
            Fixture f;
            diagnostic_open_errno = error;
            check(f.open() != TB_GPU_OK, "failed setup open accepted");
            const auto d = diagnostic_snapshot();
            check((d.flags & TB_GPU_DIAG_SYSTEM) != 0 && d.system_errno == error,
                  "original setup errno missing");
            check((d.flags & TB_GPU_DIAG_CUDA) == 0 && d.cuda_result == 0,
                  "system failure fabricated CUDA error");
            check(std::string(d.operation).find("open") != std::string::npos,
                  "system operation missing");
            diagnostic_open_errno = 0;
        }
    } else if (name == "diagnostic-guard-denied-before-object") {
        Fixture f;
        tb_guard_hold(f.g, TB_HOLD_CANCEL);
        const auto before = s.calls.size();
        check(f.open() == TB_GPU_HELD, "pre-object HELD admission");
        const auto d = diagnostic_snapshot();
        check(d.flags == TB_GPU_DIAG_GUARD && d.guard_error == -EPERM,
              "actual guard denial missing");
        check(d.cuda_result == 0 && d.system_errno == 0 && s.calls.size() == before,
              "guard denial fabricated CUDA/system activity");
    } else if (name == "diagnostic-held-getter-no-side-effects") {
        Fixture f;
        f.ready();
        diagnostic_failure_name = "cuStreamSynchronize";
        diagnostic_failure_result = CUDA_ERROR_INVALID_CONTEXT;
        // A fresh fill is permitted before any CREATE and supplies unknown work.
        check(tb_gpu_fill(f.gpu, 1, false) == TB_GPU_HELD, "second fill HELD");
        const auto before = s.calls.size();
        struct tb_guard_snapshot a{}, b{};
        tb_guard_snapshot(f.g, &a);
        const auto first = diagnostic_snapshot();
        const auto second = diagnostic_snapshot();
        tb_guard_snapshot(f.g, &b);
        check(std::memcmp(&first, &second, sizeof(first)) == 0,
              "getter mutated diagnostic snapshot");
        check(a.held && b.held && a.hold_reasons == b.hold_reasons &&
              a.operation_ticket == b.operation_ticket &&
              a.cleanup_permissions == b.cleanup_permissions && s.calls.size() == before,
              "HELD getter changed authority or invoked CUDA");
        diagnostic_failure_name = nullptr;
    } else if (name == "diagnostic-owner-thread-isolation") {
        Fixture f;
        diagnostic_failure_name = "cuDeviceGetByPCIBusId";
        diagnostic_failure_result = CUDA_ERROR_INVALID_CONTEXT;
        check(f.open() != TB_GPU_OK, "main owner query failure");
        const auto owner = diagnostic_snapshot();
        bool child_clean = false, child_guard_only = false;
        std::exception_ptr child_error;
        std::thread child([&] {
            try {
                const auto fresh = diagnostic_snapshot();
                child_clean = fresh.flags == 0 && fresh.cuda_result == 0 &&
                              fresh.system_errno == 0 && fresh.guard_error == 0;
                tb_guard *g = nullptr;
                check(tb_guard_new(TB_BACKING_GPU, &g) == 0, "child guard");
                tb_guard_hold(g, TB_HOLD_CANCEL);
                tb_gpu *gpu = nullptr;
                check(tb_gpu_open(&gpu, g, &f.req) == TB_GPU_HELD, "child held open");
                const auto own = diagnostic_snapshot();
                child_guard_only = own.flags == TB_GPU_DIAG_GUARD &&
                                   own.guard_error == -EPERM && own.cuda_result == 0;
            } catch (...) { child_error = std::current_exception(); }
        });
        child.join();
        if (child_error) std::rethrow_exception(child_error);
        const auto after = diagnostic_snapshot();
        check(child_clean && child_guard_only, "new owner inherited another owner diagnostic");
        check(std::memcmp(&owner, &after, sizeof(owner)) == 0,
              "child owner changed parent diagnostic");
        diagnostic_failure_name = nullptr;
    } else if (name == "diagnostic-success-resets-failure") {
        Fixture failed;
        diagnostic_failure_name = "cuDeviceGetByPCIBusId";
        diagnostic_failure_result = CUDA_ERROR_INVALID_CONTEXT;
        check(failed.open() != TB_GPU_OK, "setup failure");
        require_cuda_diagnostic(CUDA_ERROR_INVALID_CONTEXT, "cuDeviceGetByPCIBusId");
        diagnostic_failure_name = nullptr;
        Fixture success;
        check(success.open() == TB_GPU_OK, "subsequent success");
        const auto d = diagnostic_snapshot();
        check(d.flags == 0 && d.cuda_result == 0 && d.system_errno == 0 &&
              d.guard_error == 0 && d.operation[0] == 0, "success retained stale error");
    } else if (name == "diagnostic-each-operation-entry-reset") {
        Fixture f;
        check(f.open() == TB_GPU_OK, "entry reset setup");
        seed_diagnostic_failure();
        // Registration is a pure getter and must preserve the last call snapshot.
        const auto prior = diagnostic_snapshot();
        struct tb_gpu_registration registration{};
        const auto calls_before = s.calls.size();
        check(tb_gpu_registration(f.gpu, &registration) == TB_GPU_OK, "registration getter");
        const auto after_registration = diagnostic_snapshot();
        check(std::memcmp(&prior, &after_registration, sizeof(prior)) == 0 &&
              s.calls.size() == calls_before, "registration getter reset or queried diagnostic");
        check(tb_gpu_fill(f.gpu, 1, false) == TB_GPU_OK, "successful FILL");
        require_clean_diagnostic();
        f.stopped();
        seed_diagnostic_failure();
        check(tb_gpu_receive_visible(f.gpu) == TB_GPU_OK, "successful VISIBLE");
        require_clean_diagnostic();
        seed_diagnostic_failure();
        f.verify();
        require_clean_diagnostic();
        seed_diagnostic_failure();
        check(tb_gpu_close(f.gpu) == TB_GPU_OK, "successful CLOSE");
        require_clean_diagnostic();
    } else if (name == "diagnostic-active-guard-denial") {
        Fixture f;
        f.ready();
        uint64_t ticket = 0;
        check(tb_guard_begin(f.g, TB_OP_CREATE, &ticket) == 0, "CREATE admission");
        check(tb_guard_end(f.g, ticket, TB_PHASE_SESSION_CREATED, false, true) == 0,
              "CREATE commit");
        const auto before = s.calls.size();
        check(tb_gpu_fill(f.gpu, 1, false) != TB_GPU_OK, "active fill accepted");
        const auto d = diagnostic_snapshot();
        check(d.flags == TB_GPU_DIAG_GUARD && d.guard_error == -EPERM &&
              d.cuda_result == 0 && d.system_errno == 0 && s.calls.size() == before,
              "active guard rejection lost original result or fabricated CUDA");
    } else if (name == "diagnostic-invalid-caller-schema") {
        Fixture f;
        tb_guard_hold(f.g, TB_HOLD_CANCEL);
        check(f.open() == TB_GPU_HELD, "held setup");
        const auto original = diagnostic_snapshot();
        const auto calls_before = s.calls.size();
        for (const uint32_t size : {UINT32_C(0), static_cast<uint32_t>(sizeof(tb_gpu_diagnostic)-1)}) {
            tb_gpu_diagnostic bad{};
            bad.size = size; bad.version = TB_GPU_DIAGNOSTIC_VERSION;
            check(tb_gpu_last_diagnostic(&bad) != TB_GPU_OK, "invalid size accepted");
        }
        tb_gpu_diagnostic bad{};
        bad.size = sizeof(bad); bad.version = TB_GPU_DIAGNOSTIC_VERSION + 1;
        check(tb_gpu_last_diagnostic(&bad) != TB_GPU_OK, "invalid version accepted");
        check(tb_gpu_last_diagnostic(nullptr) != TB_GPU_OK, "null getter accepted");
        const auto after = diagnostic_snapshot();
        check(std::memcmp(&original, &after, sizeof(original)) == 0 &&
              s.calls.size() == calls_before, "invalid getter changed owner diagnostic");
    } else throw std::runtime_error("unknown diagnostic test");
    diagnostic_failure_name = nullptr;
    diagnostic_open_errno = 0;
}
const char *diagnostic_cases[] = {
    "diagnostic-cuda-error-values-and-operation", "diagnostic-cuda-error-before-object",
    "diagnostic-system-errno", "diagnostic-guard-denied-before-object",
    "diagnostic-held-getter-no-side-effects", "diagnostic-owner-thread-isolation",
    "diagnostic-success-resets-failure", "diagnostic-each-operation-entry-reset",
    "diagnostic-active-guard-denial", "diagnostic-invalid-caller-schema"
};
} // namespace

// Definitions are checked by the compiler against NVIDIA's actual cuda.h.
extern "C" {
CUresult CUDAAPI cuInit(unsigned int) { auto r=call("cuInit"); return r==CUDA_SUCCESS?r:CUDA_ERROR_NOT_INITIALIZED; }
CUresult CUDAAPI cuDriverGetVersion(int *v) { *v=CUDA_VERSION; return call("cuDriverGetVersion"); }
CUresult CUDAAPI cuDeviceGetCount(int *v) { *v=s.devices; return call("cuDeviceGetCount"); }
CUresult CUDAAPI cuDeviceGet(CUdevice *v,int n) { *v=n; auto r=call("cuDeviceGet"); return s.devices==0?CUDA_ERROR_NO_DEVICE:r; }
CUresult CUDAAPI cuDeviceGetByPCIBusId(CUdevice *v,const char *) { *v=0; auto r=call("cuDeviceGetByPCIBusId"); return s.devices==0?CUDA_ERROR_NO_DEVICE:r; }
CUresult CUDAAPI cuDeviceGetPCIBusId(char *p,int n,CUdevice) { std::snprintf(p,n,"%s",s.wrong_bdf?"0000:66:00.0":"0000:65:00.0"); return call("cuDeviceGetPCIBusId"); }
CUresult CUDAAPI cuDeviceGetAttribute(int *v,CUdevice_attribute attr,CUdevice) {
 const char *name="cuDeviceGetAttribute"; *v=0;
 switch(attr) {
 case CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_SUPPORTED:*v=s.rdma;name="rdma-supported";break;
 case CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_WRITES_ORDERING:*v=s.ordering;name="rdma-ordering";break;
 case CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_FLUSH_WRITES_OPTIONS:*v=s.flush_options;name="rdma-flush-options";break;
 case CU_DEVICE_ATTRIBUTE_PCI_BUS_ID:*v=0x65;break;
 case CU_DEVICE_ATTRIBUTE_PCI_DEVICE_ID:case CU_DEVICE_ATTRIBUTE_PCI_DOMAIN_ID:break;
 default:break;
 }
 return call(name);
}
#if CUDA_VERSION >= 13000
CUresult CUDAAPI cuCtxCreate(CUcontext *p,CUctxCreateParams *,unsigned int,CUdevice) { *p=ctx;return call("cuCtxCreate"); }
#else
CUresult CUDAAPI cuCtxCreate(CUcontext *p,unsigned int,CUdevice) { *p=ctx;return call("cuCtxCreate"); }
#endif
CUresult CUDAAPI cuCtxSetCurrent(CUcontext) { return call("cuCtxSetCurrent"); }
CUresult CUDAAPI cuCtxGetCurrent(CUcontext *p) { *p=ctx;return call("cuCtxGetCurrent"); }
CUresult CUDAAPI cuCtxGetDevice(CUdevice *d) { *d=0;return call("cuCtxGetDevice"); }
CUresult CUDAAPI cuCtxDestroy(CUcontext) { return call("cuCtxDestroy"); }
CUresult CUDAAPI cuStreamCreate(CUstream *p,unsigned int) { *p=stream; return call("cuStreamCreate"); }
CUresult CUDAAPI cuStreamSynchronize(CUstream p) { check(p==stream,"wrong stream sync"); if(s.hold_in_sync) tb_guard_hold(s.guard,TB_HOLD_DEADLINE); if(block_sync) {std::unique_lock<std::mutex> lock(sync_mutex);sync_entered=true;sync_cv.notify_all();sync_cv.wait(lock,[] {return release_sync;});} return call("cuStreamSynchronize"); }
CUresult CUDAAPI cuStreamDestroy(CUstream) { return call("cuStreamDestroy"); }
CUresult CUDAAPI cuMemAlloc(CUdeviceptr *p,size_t n) { auto r=call("cuMemAlloc"); *p=s.next; s.next+=0x1000000; if(!s.payload_base) {s.payload_base=*p;s.payload_alloc=n;} else {check(n<=65536,"metadata allocation unbounded");s.metadata[*p].resize(n);} return r; }
CUresult CUDAAPI cuMemFree(CUdeviceptr p) { s.calls.emplace_back(p==s.payload_base?"free-original":s.metadata.count(p)?"free-metadata":"free-interior"); return call("cuMemFree"); }
CUresult CUDAAPI cuPointerSetAttribute(const void *v,CUpointer_attribute a,CUdeviceptr) { check(a==CU_POINTER_ATTRIBUTE_SYNC_MEMOPS && *static_cast<const unsigned int *>(v)==1,"wrong sync set"); s.sync_set=true; return call("cuPointerSetAttribute"); }
CUresult CUDAAPI cuPointerGetAttribute(void *p,CUpointer_attribute a,CUdeviceptr) {
 const char *name="cuPointerGetAttribute";
 switch(a) {
 case CU_POINTER_ATTRIBUTE_CONTEXT:*static_cast<CUcontext *>(p)=s.wrong_context?reinterpret_cast<CUcontext>(0x999):ctx;break;
 case CU_POINTER_ATTRIBUTE_MEMORY_TYPE:*static_cast<unsigned int *>(p)=s.memory_type;break;
 case CU_POINTER_ATTRIBUTE_IS_MANAGED:*static_cast<unsigned int *>(p)=s.managed;break;
 case CU_POINTER_ATTRIBUTE_DEVICE_ORDINAL:*static_cast<int *>(p)=s.ordinal;break;
 case CU_POINTER_ATTRIBUTE_SYNC_MEMOPS:*static_cast<unsigned int *>(p)=s.sync_set&&!s.sync_query_zero;name="sync-query";break;
 default:return CUDA_ERROR_INVALID_VALUE;
 }
 return call(name);
}
CUresult CUDAAPI cuModuleLoad(CUmodule *p,const char *) { *p=module; return call("cuModuleLoad"); }
CUresult CUDAAPI cuModuleGetFunction(CUfunction *p,CUmodule,const char *name) { check(std::string(name)=="tb_pattern_fill" || std::string(name)=="tb_pattern_verify","unfrozen PTX entry"); *p=std::string(name)=="tb_pattern_verify"?verify_fn:fill_fn; return call("cuModuleGetFunction"); }
CUresult CUDAAPI cuModuleUnload(CUmodule) { return call("cuModuleUnload"); }
CUresult CUDAAPI cuMemcpyHtoD(CUdeviceptr p,const void *v,size_t n) {
 check(s.metadata.count(p) && n<=s.metadata[p].size(),"HtoD payload/unknown buffer");
 std::memcpy(s.metadata[p].data(),v,n);
 if(n==sizeof(tb_verify_result)) { tb_verify_result r{};std::memcpy(&r,v,n);s.sentinel_seen=r.bytes==0 && r.mismatches==UINT64_MAX && r.first_bad==0 && r.launch_cookie==0; }
 return call("cuMemcpyHtoD");
}
CUresult CUDAAPI cuMemcpyDtoH(void *p,CUdeviceptr src,size_t n) {
 if(n!=sizeof(tb_verify_result) || !s.metadata.count(src)) { s.calls.emplace_back("payload-copy"); return CUDA_ERROR_INVALID_VALUE; }
 check(s.verify_launched && src==s.result_device,"summary copy without actual result launch");
 check(count("cuStreamSynchronize")>s.verify_sync_count,"summary copy before successful verify sync");
 tb_verify_result r{s.launched_bytes,0,UINT64_MAX,s.launched_cookie};
 if(s.summary_mode=="sentinel") r={0,UINT64_MAX,0,0};
 if(s.summary_mode=="zero-bytes") r.bytes=0;
 if(s.summary_mode=="partial-bytes") r.bytes=BYTES-1;
 if(s.summary_mode=="cookie") r.launch_cookie^=1;
 if(s.summary_mode=="first-bad") r.first_bad=0;
 if(s.summary_mode=="mismatch") r.mismatches=1;
 std::memcpy(p,&r,n); return call("summary-copy");
}
CUresult CUDAAPI cuLaunchKernel(CUfunction f,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,CUstream st,void **params,void **) {
 check(st==stream && params,"wrong launch stream/params");
 const auto address=*static_cast<uint64_t *>(params[0]);
 const auto bytes=*static_cast<uint64_t *>(params[1]);
 check(address==(BASE+TB_GPU_ALIGN-1)/TB_GPU_ALIGN*TB_GPU_ALIGN && bytes==BYTES,"launch address/registered length");
 if(f==verify_fn) {
   s.verify_launched=true; s.launched_bytes=bytes; s.launched_cookie=*static_cast<uint64_t *>(params[4]);
   s.result_device=*static_cast<uint64_t *>(params[5]); s.verify_sync_count=count("cuStreamSynchronize");
   check(s.metadata.count(s.result_device),"result allocation absent");
   const auto ext=*static_cast<uint64_t *>(params[2]);const auto nr=*static_cast<uint32_t *>(params[3]);
   check(nr && s.metadata.count(ext) && s.metadata[ext].size()>=nr*sizeof(tb_verify_extent),"extent kernel args");
   if(!s.expected_extents.empty()) {check(nr==s.expected_extents.size(),"extent count changed");check(std::memcmp(s.metadata[ext].data(),s.expected_extents.data(),nr*sizeof(tb_verify_extent))==0,"extent metadata changed");}
   tb_verify_result sentinel{};std::memcpy(&sentinel,s.metadata[s.result_device].data(),sizeof(sentinel));
   check(sentinel.bytes==0 && sentinel.mismatches==UINT64_MAX && sentinel.first_bad==0 && sentinel.launch_cookie==0,"result sentinel not uploaded before launch");
 } else {
   const auto seed=*static_cast<uint64_t *>(params[2]);const auto guard=*static_cast<uint32_t *>(params[3]);
   check((seed==UINT64_C(0x0123456789abcdef) && guard==0) || (seed==1 && guard<=1),"fill seed/receiver flag");
 }
 return call(f==verify_fn?"verify-launch":"fill-launch");
}
CUresult CUDAAPI cuFlushGPUDirectRDMAWrites(CUflushGPUDirectRDMAWritesTarget t,CUflushGPUDirectRDMAWritesScope scope) { check(t==CU_FLUSH_GPU_DIRECT_RDMA_WRITES_TARGET_CURRENT_CTX && scope==CU_FLUSH_GPU_DIRECT_RDMA_WRITES_TO_OWNER,"flush target/scope"); return call("cuFlushGPUDirectRDMAWrites"); }
CUresult CUDAAPI cuGetErrorName(CUresult,const char **p) { *p="recorded-error";return CUDA_SUCCESS; }
CUresult CUDAAPI cuGetErrorString(CUresult,const char **p) { *p="recorded-error";return CUDA_SUCCESS; }
int __wrap_open(const char *path,int,...) {
 if(std::string(path)=="/proc/driver/nvidia/gpus/0000:65:00.0/information") {call("proc-open");if(s.proc_missing) {errno=ENOENT;return -1;}return 901;}
 check(std::string(path)=="/dev/nvidia0","unexpected open");call("open");if(diagnostic_open_errno) {errno=diagnostic_open_errno;return -1;}return 900;
}
int __wrap_fstat(int fd,struct stat *st) { check(fd==900,"wrong fstat");std::memset(st,0,sizeof(*st));st->st_mode=(s.node_bad?S_IFREG:S_IFCHR)|0600;st->st_rdev=makedev(239,0);call("fstat");return 0; }
ssize_t __wrap_read(int fd,void *buf,size_t len) {
 check(fd==901,"unexpected read");
 std::string text="Model: Recording NVIDIA fixture\nBus Location: 0000:65:00.0\nDevice Minor: \t "+(s.proc_nondigit?"oops":std::to_string(s.proc_wrong_minor?9:0))+"\n";
 if(s.proc_ambiguous) text+="Device Minor: 1\n";
 size_t n=std::min(len,text.size()-s.proc_offset);std::memcpy(buf,text.data()+s.proc_offset,n);s.proc_offset+=n;call("proc-read");return static_cast<ssize_t>(n);
}
int __wrap_close(int fd) { check(fd==900 || fd==901,"wrong close");call(fd==901?"proc-close":"close");return 0; }
}
int main(int argc,char **argv) {
 if(argc==2 && std::string(argv[1])=="--list") { for(auto c:cases) std::puts(c);for(auto c:diagnostic_cases) std::puts(c); return 0; }
 int failed=0; size_t number=0;
 for(auto name:cases) { if(argc==2 && name!=std::string(argv[1])) continue; ++number; try {run_case(name);std::printf("ok %zu - %s\n",number,name);} catch(const std::exception &e) {++failed;std::printf("not ok %zu - %s: %s\n",number,name,e.what()); for(const auto &c:s.calls) std::printf("# %s\n",c.c_str());} }
 for(auto name:diagnostic_cases) { if(argc==2 && name!=std::string(argv[1])) continue; ++number; try {diagnostic_case(name);std::printf("ok %zu - %s\n",number,name);} catch(const std::exception &e) {++failed;std::printf("not ok %zu - %s: %s\n",number,name,e.what());} }
 std::printf("1..%zu\n",number);return number ? (failed?1:0) : 2;
}
