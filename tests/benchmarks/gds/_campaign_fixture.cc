/* SPDX-License-Identifier: GPL-2.0-only
 * Dependency-boundary observer for the actual benchmark translation unit.
 * This is a host control-flow test, never a CUDA/storage device or timing model.
 * Official SDK declarations supply every ABI type; no SDK is distributed here.
 */
#include <cuda_runtime_api.h>
#include <cufile.h>
#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <string>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace observer {
static FILE *trace;
static uint64_t operations, read_operations, write_operations, read_bytes, write_bytes;
static uint64_t tick;
static size_t allocated;
static std::map<void *, size_t> allocations;
static std::vector<unsigned char> input_bytes;
static const char *fault;
static size_t configured_chunk;
static void event(const char *name, size_t bytes = 0, uint64_t offset = 0)
{
    if (trace) {
        std::fprintf(trace, "%s %llu %zu %llu\n", name,
                     static_cast<unsigned long long>(operations), bytes,
                     static_cast<unsigned long long>(offset));
        std::fflush(trace);
    }
}
static bool is_fault(const char *name) { return fault && !std::strcmp(fault, name); }
static CUfileError_t success() { CUfileError_t e{}; e.err = CU_FILE_SUCCESS; return e; }
static size_t capacity()
{
    const char *value = std::getenv("GDS_FIXTURE_CAPACITY");
    return value ? std::strtoull(value, nullptr, 10) : 256U * 1024 * 1024;
}
static int ordinary(CUfileHandle_t handle)
{
    int descriptor = int(reinterpret_cast<intptr_t>(handle)) - 1;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/self/fd/%d", descriptor);
    return ::open(path, O_RDWR | O_CLOEXEC);
}
static void damage(void *base, size_t bytes, off_t offset)
{
    auto *p = static_cast<unsigned char *>(base);
    if (operations == 1) {
        if (is_fault("payload-first")) p[offset + bytes - 1] ^= 1;
        if (is_fault("prefix-first")) p[offset - 1] ^= 1;
        if (is_fault("tail-first")) p[offset + bytes] ^= 1;
        if (is_fault("prefix-edge-first")) p[offset - 4096] ^= 1;
        if (is_fault("suffix-edge-first")) p[offset + configured_chunk + 4096 - 1] ^= 1;
    }
    if (operations == 2 && is_fault("unused-tail-partial")) p[offset + bytes] ^= 1;
    if (operations == 3 && is_fault("payload-early-trial")) p[offset + bytes - 1] ^= 1;
}
}

/* Calls below are controlled SDK dependencies. They do not claim physical
 * allocation, DMA, direct-path qualification, completion or elapsed time. */
cudaError_t cudaGetDeviceCount(int *count) { *count = 1; return cudaSuccess; }
cudaError_t cudaSetDevice(int) { return cudaSuccess; }
const char *cudaGetErrorString(cudaError_t) { return "controlled dependency error"; }
cudaError_t cudaMemGetInfo(size_t *available, size_t *total)
{
    *total = observer::capacity(); *available = *total - observer::allocated;
    observer::event("capacity", *available); return cudaSuccess;
}
cudaError_t cudaMalloc(void **pointer, size_t bytes)
{
    observer::event("allocate", bytes);
    if (bytes > observer::capacity() - observer::allocated) return cudaErrorMemoryAllocation;
    *pointer = std::malloc(bytes);
    if (!*pointer) return cudaErrorMemoryAllocation;
    observer::allocations[*pointer] = bytes; observer::allocated += bytes;
    return cudaSuccess;
}
cudaError_t cudaFree(void *pointer)
{
    observer::event("free");
    auto entry = observer::allocations.find(pointer);
    if (entry == observer::allocations.end()) return cudaErrorInvalidValue;
    observer::allocated -= entry->second;
    observer::allocations.erase(entry); std::free(pointer); return cudaSuccess;
}
cudaError_t cudaMemset(void *pointer, int value, size_t bytes)
{
    observer::event("initialize", bytes); std::memset(pointer, value, bytes); return cudaSuccess;
}
cudaError_t cudaMemcpy(void *destination, const void *source, size_t bytes, cudaMemcpyKind kind)
{
    const char *event = kind == cudaMemcpyDeviceToHost ? "readback" :
                        kind == cudaMemcpyDeviceToDevice ? "capture" : "seed";
    observer::event(event, bytes, uint64_t(reinterpret_cast<uintptr_t>(source)));
    std::memcpy(destination, source, bytes); return cudaSuccess;
}
cudaError_t cudaDeviceSynchronize()
{
    observer::event("complete"); return cudaSuccess;
}
CUfileError_t cuFileSetParameterBool(CUFileBoolConfigParameter_t, bool value)
{
    observer::event(value ? "compat-enabled" : "compat-disabled"); return observer::success();
}
CUfileError_t cuFileDriverOpen() { observer::event("driver-open"); return observer::success(); }
CUfileError_t cuFileDriverClose() { observer::event("driver-close"); return observer::success(); }
CUfileError_t cuFileDriverGetProperties(CUfileDrvProps_t *properties)
{
    *properties = {}; return observer::success();
}
CUfileError_t cuFileSetStatsLevel(int level)
{
    observer::event("stats-level", size_t(level)); return observer::success();
}
CUfileError_t cuFileStatsReset() { return observer::success(); }
CUfileError_t cuFileStatsStart() { observer::event("stats-start"); return observer::success(); }
CUfileError_t cuFileStatsStop() { observer::event("stats-stop"); return observer::success(); }
CUfileError_t cuFileHandleRegister(CUfileHandle_t *handle, CUfileDescr_t *description)
{
    int fd = description->handle.fd;
    observer::event((fcntl(fd, F_GETFL) & O_DIRECT) ? "direct-handle" : "buffered-handle");
    *handle = reinterpret_cast<CUfileHandle_t>(intptr_t(fd + 1)); return observer::success();
}
void cuFileHandleDeregister(CUfileHandle_t) { observer::event("handle-release"); }
CUfileError_t cuFileBufRegister(const void *, size_t bytes, int)
{
    observer::event("register", bytes); return observer::success();
}
CUfileError_t cuFileBufDeregister(const void *)
{
    observer::event("deregister"); return observer::success();
}
ssize_t cuFileRead(CUfileHandle_t handle, void *base, size_t bytes, off_t file_offset, off_t buffer_offset)
{
    ++observer::operations; ++observer::read_operations; observer::read_bytes += bytes;
    observer::event("read", bytes, uint64_t(file_offset));
    int fd = observer::ordinary(handle);
    ssize_t result = ::pread(fd, static_cast<char *>(base) + buffer_offset, bytes, file_offset);
    if (result > 0) {
        const auto *input = static_cast<unsigned char *>(base) + buffer_offset;
        observer::input_bytes.insert(observer::input_bytes.end(), input, input + result);
    }
    ::close(fd); observer::damage(base, bytes, buffer_offset);
    return observer::is_fault("short") ? ssize_t(bytes - 1) : result;
}
ssize_t cuFileWrite(CUfileHandle_t handle, const void *base, size_t bytes, off_t file_offset, off_t buffer_offset)
{
    ++observer::operations; ++observer::write_operations; observer::write_bytes += bytes;
    observer::event("write", bytes, uint64_t(file_offset));
    const auto *input = static_cast<const unsigned char *>(base) + buffer_offset;
    observer::input_bytes.insert(observer::input_bytes.end(), input, input + bytes);
    int fd = observer::ordinary(handle);
    ssize_t result = ::pwrite(fd, static_cast<const char *>(base) + buffer_offset, bytes, file_offset);
    if (observer::operations == 1 && observer::is_fault("file-first")) {
        unsigned char byte;
        if (::pread(fd, &byte, 1, file_offset + off_t(bytes) - 1) == 1) {
            byte ^= 1; (void)::pwrite(fd, &byte, 1, file_offset + off_t(bytes) - 1);
        }
    }
    ::close(fd); observer::damage(const_cast<void *>(base), bytes, buffer_offset);
    return observer::is_fault("short") ? ssize_t(bytes - 1) : result;
}
CUfileError_t cuFileGetStatsL3(CUfileStatsLevel3_t *statistics)
{
    *statistics = {}; statistics->num_gpus = 1;
    auto &s = statistics->per_gpu_stats[0];
    s.n_total_reads = s.n_nvfs_reads = observer::read_operations;
    s.n_total_writes = s.n_nvfs_writes = observer::write_operations;
    s.read_bytes = observer::read_bytes; s.writes_bytes = observer::write_bytes;
    if (observer::is_fault("posix")) s.n_posix_reads = 1;
    if (observer::is_fault("native-count")) {
        if (observer::write_operations) ++s.n_nvfs_writes;
        else ++s.n_nvfs_reads;
    }
    if (observer::is_fault("native-bytes")) {
        if (observer::write_operations) ++s.writes_bytes;
        else ++s.read_bytes;
    }
    if (observer::is_fault("dynamic-routing")) s.n_dr_reads = 1;
    observer::event("stats-retrieve"); return observer::success();
}

static int fixture_clock_gettime(clockid_t, timespec *time)
{
    ++observer::tick; time->tv_sec = time_t(observer::tick); time->tv_nsec = 0;
    observer::event("clock"); return 0;
}
static int fixture_fsync(int fd)
{
    observer::event("fsync"); return ::fsync(fd);
}
static ssize_t fixture_pread(int fd, void *destination, size_t bytes, off_t offset)
{
    observer::event("file-readback", bytes, uint64_t(offset));
    return ::pread(fd, destination, bytes, offset);
}

/* Observe the existing success publication at the libc boundary, so moving
 * JSON before final validation cannot pass by merely emitting phase markers. */
extern "C" int __wrap_printf(const char *format, ...)
{
    observer::event("publish");
    va_list arguments;
    va_start(arguments, format);
    int result = std::vfprintf(stdout, format, arguments);
    va_end(arguments);
    return result;
}

#define clock_gettime fixture_clock_gettime
#define fsync fixture_fsync
#define pread fixture_pread
#define GDS_CAMPAIGN_EVENT(name) observer::event(name)
#define main gds_actual_main
#include GDS_BENCH_SOURCE
#undef main
#undef clock_gettime
#undef fsync
#undef pread

int main(int argc, char **argv)
{
    observer::trace = std::fopen(std::getenv("GDS_FIXTURE_TRACE"), "w");
    if (!observer::trace) return 90;
    observer::fault = std::getenv("GDS_FIXTURE_FAULT");
    observer::configured_chunk = argc > 3 ? std::strtoull(argv[3], nullptr, 10) : 0;
    int result = gds_actual_main(argc, argv);
    /* Fixture-only raw source capture is compared by Python after the complete
     * actual function returns. No per-I/O comparison, SHA or digest is used. */
    if (const char *path = std::getenv("GDS_FIXTURE_INPUT")) {
        FILE *input = std::fopen(path, "wb");
        if (!input) return 91;
        if (std::fwrite(observer::input_bytes.data(), 1, observer::input_bytes.size(), input) !=
            observer::input_bytes.size()) return 92;
        if (std::fclose(input)) return 93;
    }
    observer::event("returned", size_t(result)); std::fclose(observer::trace);
    return result;
}
