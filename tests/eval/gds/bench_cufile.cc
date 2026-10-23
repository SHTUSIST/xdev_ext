/* SPDX-License-Identifier: GPL-2.0-only
 * Ported cuFile read/write workload from chainio_p2p_bench.cu.
 * Uses official SDK types; native path requires process L3 operation evidence.
 * Non-cuFile network/UVM workloads are outside this executable.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cuda_runtime_api.h>
#include <cufile.h>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <new>
#include <string>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <vector>

static constexpr size_t guard = 4096;

/* Optional final-phase observer for host contract tests; no-op otherwise. */
#ifndef GDS_CAMPAIGN_EVENT
#define GDS_CAMPAIGN_EVENT(name) ((void)0)
#endif

static uint64_t now_ns()
{
    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return uint64_t(ts.tv_sec) * 1000000000ULL + uint64_t(ts.tv_nsec);
}

static unsigned char pattern(uint64_t index, uint64_t iteration)
{
    return static_cast<unsigned char>((index * 37 + index / 251 + iteration * 53) % 256);
}

static bool cuda_ok(cudaError_t error, const char *operation)
{
    if (error == cudaSuccess) return true;
    std::fprintf(stderr, "CUDA %s failed: %s\n", operation, cudaGetErrorString(error));
    return false;
}

static bool file_ok(CUfileError_t error, const char *operation)
{
    if (error.err == CU_FILE_SUCCESS) return true;
    std::fprintf(stderr, "cuFile %s failed: %d\n", operation, int(error.err));
    return false;
}

/* Keep the original source's complete buffered I/O helpers, including EINTR. */
static ssize_t pread_all(int fd, void *buf, size_t n, off_t off)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = ::pread(fd, static_cast<char *>(buf) + done, n - done, off + done);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return -1; }
        done += static_cast<size_t>(r);
    }
    return static_cast<ssize_t>(done);
}

static ssize_t pwrite_all(int fd, const void *buf, size_t n, off_t off)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = ::pwrite(fd, static_cast<const char *>(buf) + done, n - done, off + done);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return -1; }
        done += static_cast<size_t>(r);
    }
    return static_cast<ssize_t>(done);
}

struct Resources {
    int dir = -1, ordinary = -1, direct = -1;
    void *gpu = nullptr;
    CUfileHandle_t file = nullptr;
    bool created = false, driver = false, registered = false, collecting = false;
    bool close()
    {
        bool okay = true;
        if (collecting) { if (!file_ok(cuFileStatsStop(), "stats stop")) okay = false; collecting = false; }
        if (registered) { if (!file_ok(cuFileBufDeregister(gpu), "buffer deregister")) okay = false; registered = false; }
        if (file) { cuFileHandleDeregister(file); file = nullptr; }
        if (gpu) { if (!cuda_ok(cudaFree(gpu), "free")) okay = false; gpu = nullptr; }
        if (driver) { if (!file_ok(cuFileDriverClose(), "driver close")) okay = false; driver = false; }
        if (direct >= 0) { if (::close(direct)) okay = false; direct = -1; }
        if (ordinary >= 0) { if (::close(ordinary)) okay = false; ordinary = -1; }
        if (created) { if (unlinkat(dir, "payload.bin", 0)) okay = false; created = false; }
        if (dir >= 0) { if (::close(dir)) okay = false; dir = -1; }
        if (!okay) std::fprintf(stderr, "resource cleanup failed\n");
        return okay;
    }
    ~Resources() { close(); }
};

static int unsupported(const char *reason)
{
    std::fprintf(stderr, "SKIP: %s\n", reason);
    return 4;
}

static bool number(const char *text, uint64_t maximum, uint64_t &value)
{
    value = 0;
    if (!*text) return false;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9') return false;
        unsigned digit = unsigned(*text - '0');
        if (value > (maximum - digit) / 10) return false;
        value = value * 10 + digit;
    }
    return value > 0 && value <= maximum;
}

static int finish(Resources &resources, int result)
{
    return resources.close() ? result : 1;
}

#ifdef GDS_PER_CHUNK_ORACLE
/* Previous schema1 correctness loop, compiled out by default: one reusable
 * chunk buffer whose full GPU readback/comparison (and checkpoint file reread)
 * runs after every chunk or trial, so later reuse overwrites earlier raw output
 * and the campaign cannot be judged once at its end. */
static int execute(Resources &res, const char *workload, uint64_t bytes, size_t chunk,
                   uint64_t iterations, const char *directory)
{
    bool checkpoint = !std::strcmp(workload, "checkpoint");
    int device_count = 0;
    if (cudaGetDeviceCount(&device_count) != cudaSuccess || device_count < 1)
        return unsupported("no CUDA hardware device available");
    if (!cuda_ok(cudaSetDevice(0), "select device")) return 1;
    /* Disable compatibility explicitly for this process, then verify properties.
     * Properties alone are not proof: successful native counters are mandatory.
     */
    if (!file_ok(cuFileSetParameterBool(CUFILE_PARAM_PROPERTIES_ALLOW_COMPAT_MODE, false), "disable compat") ||
        !file_ok(cuFileSetParameterBool(CUFILE_PARAM_FORCE_COMPAT_MODE, false), "disable forced compat"))
        return unsupported("native-only cuFile configuration unsupported");
    if (!file_ok(cuFileDriverOpen(), "driver open")) return unsupported("native cuFile driver unavailable");
    res.driver = true;
    CUfileDrvProps_t properties{};
    if (!file_ok(cuFileDriverGetProperties(&properties), "properties") ||
        (properties.nvfs.dcontrolflags & (1U << CU_FILE_ALLOW_COMPAT_MODE)))
        return unsupported("cannot verify compatibility is disabled");
    if (!file_ok(cuFileSetStatsLevel(3), "stats level"))
        return unsupported("cuFile process L3 statistics unavailable");

    res.dir = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (res.dir < 0) { std::perror("temporary directory"); return 1; }
    res.ordinary = openat(res.dir, "payload.bin", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (res.ordinary < 0) { std::perror("exclusive temporary file"); return 1; }
    res.created = true;
    struct stat ordinary_stat{};
    if (fstat(res.ordinary, &ordinary_stat) || !S_ISREG(ordinary_stat.st_mode) ||
        ftruncate(res.ordinary, static_cast<off_t>(bytes))) {
        std::perror("regular temporary file"); return 1;
    }
    res.direct = openat(res.dir, "payload.bin", O_RDWR | O_DIRECT | O_CLOEXEC | O_NOFOLLOW);
    if (res.direct < 0) return unsupported("selected filesystem does not support O_DIRECT");
    struct stat direct_stat{};
    if (fstat(res.direct, &direct_stat) || !S_ISREG(direct_stat.st_mode) ||
        ordinary_stat.st_dev != direct_stat.st_dev || ordinary_stat.st_ino != direct_stat.st_ino)
        return 1;
    CUfileDescr_t description{};
    description.type = CU_FILE_HANDLE_TYPE_OPAQUE_FD;
    description.handle.fd = res.direct;
    if (!file_ok(cuFileHandleRegister(&res.file, &description), "file register"))
        return unsupported("filesystem/native cuFile handle unsupported");
    if (!cuda_ok(cudaMalloc(&res.gpu, chunk + 2 * guard), "allocate")) return 1;
    if (!file_ok(cuFileBufRegister(res.gpu, chunk + 2 * guard, 0), "buffer register"))
        return unsupported("native GPU buffer registration unsupported");
    res.registered = true;
    std::vector<unsigned char> expected(chunk + 2 * guard, 0xa5);
    std::vector<unsigned char> observed(chunk + 2 * guard);
    if (!file_ok(cuFileStatsReset(), "stats reset") || !file_ok(cuFileStatsStart(), "stats start"))
        return unsupported("cannot isolate process native path counters");
    res.collecting = true;
    uint64_t io_ns = 0, verified = 0, io_bytes = 0, operations = 0;
    for (uint64_t iteration = 0; iteration < iterations; ++iteration) {
        if (!checkpoint) {
            for (uint64_t offset = 0; offset < bytes; offset += chunk) {
                size_t part = size_t(std::min<uint64_t>(chunk, bytes - offset));
                for (size_t j = 0; j < part; ++j) expected[guard + j] = pattern(offset + j, iteration);
                if (pwrite_all(res.ordinary, expected.data() + guard, part, off_t(offset)) != ssize_t(part)) {
                    std::perror("dense seed write"); return 1;
                }
            }
            if (fsync(res.ordinary)) { std::perror("seed fsync"); return 1; }
        }
        for (uint64_t offset = 0; offset < bytes; offset += chunk) {
            size_t part = size_t(std::min<uint64_t>(chunk, bytes - offset));
            std::fill(expected.begin(), expected.end(), 0xa5);
            for (size_t j = 0; j < part; ++j) expected[guard + j] = pattern(offset + j, iteration);
            // Initialization and full oracle are deliberately outside io_ns.
            if (!cuda_ok(cudaMemset(res.gpu, 0xa5, chunk + 2 * guard), "guard initialize")) return 1;
            if (checkpoint && !cuda_ok(cudaMemcpy(static_cast<char *>(res.gpu) + guard,
                expected.data() + guard, part, cudaMemcpyHostToDevice), "checkpoint seed")) return 1;
            if (!cuda_ok(cudaDeviceSynchronize(), "seed synchronize")) return 1;
            uint64_t start = now_ns();
            ssize_t count = checkpoint ? cuFileWrite(res.file, res.gpu, part, off_t(offset), guard)
                                       : cuFileRead(res.file, res.gpu, part, off_t(offset), guard);
            if (count != ssize_t(part)) {
                std::fprintf(stderr, "cuFile exact I/O failed: got %zd expected %zu\n", count, part); return 1;
            }
            if (!cuda_ok(cudaDeviceSynchronize(), "I/O completion")) return 1;
            uint64_t end = now_ns();
            if (!start || end <= start) { std::fprintf(stderr, "clock failure\n"); return 1; }
            io_ns += end - start;
            if (!cuda_ok(cudaMemcpy(observed.data(), res.gpu, observed.size(), cudaMemcpyDeviceToHost), "complete oracle readback") ||
                !cuda_ok(cudaDeviceSynchronize(), "oracle synchronize")) return 1;
            if (observed != expected) { std::fprintf(stderr, "payload or GPU guard mismatch\n"); return 1; }
            ++operations;
            io_bytes += part;
            if (!checkpoint) verified += part;
        }
        if (checkpoint) {
            uint64_t start = now_ns();
            if (fsync(res.direct)) { std::perror("checkpoint fsync"); return 1; }
            uint64_t end = now_ns();
            if (!start || end <= start) return 1;
            io_ns += end - start;
            struct stat saved{};
            if (fstat(res.ordinary, &saved) || saved.st_size != off_t(bytes)) return 1;
            for (uint64_t offset = 0; offset < bytes; offset += chunk) {
                size_t part = size_t(std::min<uint64_t>(chunk, bytes - offset));
                if (pread_all(res.ordinary, observed.data(), part, off_t(offset)) != ssize_t(part)) {
                    std::perror("checkpoint complete file oracle"); return 1;
                }
                for (size_t j = 0; j < part; ++j)
                    if (observed[j] != pattern(offset + j, iteration)) {
                        std::fprintf(stderr, "checkpoint file payload mismatch\n"); return 1;
                    }
                verified += part;
            }
        }
    }
    if (!file_ok(cuFileStatsStop(), "stats stop")) return unsupported("native path statistics unavailable");
    res.collecting = false;
    CUfileStatsLevel3_t statistics{};
    if (!file_ok(cuFileGetStatsL3(&statistics), "stats retrieve") ||
        !statistics.num_gpus || statistics.num_gpus > 16)
        return unsupported("native path cannot be established from process counters");
    uint64_t native = 0, posix = 0, total = 0, transferred = 0, invalid = 0;
    for (uint32_t i = 0; i < statistics.num_gpus; ++i) {
        const auto &s = statistics.per_gpu_stats[i];
        native += checkpoint ? s.n_p2p_writes + s.n_nvfs_writes : s.n_p2p_reads + s.n_nvfs_reads;
        posix += s.n_posix_reads + s.n_posix_writes;
        total += checkpoint ? s.n_total_writes : s.n_total_reads;
        transferred += checkpoint ? s.writes_bytes : s.read_bytes;
        invalid += s.n_unaligned_reads + s.n_unaligned_writes + s.n_sparse_regions + s.n_inline_regions +
                   s.n_reads_err + s.n_writes_err + s.n_dr_reads + s.n_dr_writes;
        // No cuFile I/O in the opposite direction was requested.
        invalid += checkpoint ? s.n_total_reads : s.n_total_writes;
    }
    if (native != operations || total != operations || posix || invalid || transferred != io_bytes)
        return unsupported("observed cuFile path includes fallback or lacks exact native accounting");
    if (io_bytes != bytes * iterations || verified != io_bytes || !io_ns) return 1;
    if (!res.close()) return 1;
    std::printf("{\"schema_version\":1,\"mode\":\"cufile-direct\",\"workload\":\"%s\","
        "\"bytes\":%llu,\"chunk\":%zu,\"iterations\":%llu,\"io_bytes\":%llu,"
        "\"verified_bytes\":%llu,\"operations\":%llu,\"native_operations\":%llu,"
        "\"posix_operations\":0,\"guards_ok\":true,\"status\":\"pass\","
        "\"execution\":\"physical-cuda-cufile\",\"path_evidence\":\"cufile-l3-native-counters\","
        "\"compat_allowed\":false,\"io_ns\":%llu}\n", workload,
        (unsigned long long)bytes, chunk, (unsigned long long)iterations,
        (unsigned long long)io_bytes, (unsigned long long)verified,
        (unsigned long long)operations, (unsigned long long)native, (unsigned long long)io_ns);
    return 0;
}

#else
/* Strict campaign, schema2 / gds-campaign-v1.  Each operation owns one guarded
 * slot [4096 prefix | chunk | 4096 suffix] of a single allocation registered
 * once before the campaign, so every trial's raw output, unused chunk tail and
 * guards survive until one final readback; no device-to-device history copy
 * is needed.  Checkpoint trial t writes its own file region at t*bytes, so a
 * later clean trial cannot overwrite an earlier trial's stored result.  Only
 * exact I/O results and native path accounting are checked during the
 * campaign; every content comparison happens once, after it. */
static int execute(Resources &res, const char *workload, uint64_t bytes, size_t chunk,
                   uint64_t iterations, const char *directory)
{
    bool checkpoint = !std::strcmp(workload, "checkpoint");
    const uint64_t chunks = (bytes + chunk - 1) / chunk, wanted = chunks * iterations;
    const size_t slot = chunk + 2 * guard;
    if (wanted > SIZE_MAX / slot) return unsupported("campaign history exceeds the address space");
    const size_t history = size_t(wanted) * slot;
    const uint64_t file_bytes = checkpoint ? bytes * iterations : bytes;
    int device_count = 0;
    if (cudaGetDeviceCount(&device_count) != cudaSuccess || device_count < 1)
        return unsupported("no CUDA hardware device available");
    if (!cuda_ok(cudaSetDevice(0), "select device")) return 1;
    /* Disable compatibility explicitly for this process, then verify properties.
     * Properties alone are not proof: successful native counters are mandatory.
     */
    if (!file_ok(cuFileSetParameterBool(CUFILE_PARAM_PROPERTIES_ALLOW_COMPAT_MODE, false), "disable compat") ||
        !file_ok(cuFileSetParameterBool(CUFILE_PARAM_FORCE_COMPAT_MODE, false), "disable forced compat"))
        return unsupported("native-only cuFile configuration unsupported");
    if (!file_ok(cuFileDriverOpen(), "driver open")) return unsupported("native cuFile driver unavailable");
    res.driver = true;
    CUfileDrvProps_t properties{};
    if (!file_ok(cuFileDriverGetProperties(&properties), "properties") ||
        (properties.nvfs.dcontrolflags & (1U << CU_FILE_ALLOW_COMPAT_MODE)))
        return unsupported("cannot verify compatibility is disabled");
    if (!file_ok(cuFileSetStatsLevel(3), "stats level"))
        return unsupported("cuFile process L3 statistics unavailable");

    res.dir = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (res.dir < 0) { std::perror("temporary directory"); return 1; }
    res.ordinary = openat(res.dir, "payload.bin", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (res.ordinary < 0) { std::perror("exclusive temporary file"); return 1; }
    res.created = true;
    struct stat ordinary_stat{};
    if (fstat(res.ordinary, &ordinary_stat) || !S_ISREG(ordinary_stat.st_mode) ||
        ftruncate(res.ordinary, static_cast<off_t>(file_bytes))) {
        std::perror("regular temporary file"); return 1;
    }
    res.direct = openat(res.dir, "payload.bin", O_RDWR | O_DIRECT | O_CLOEXEC | O_NOFOLLOW);
    if (res.direct < 0) return unsupported("selected filesystem does not support O_DIRECT");
    struct stat direct_stat{};
    if (fstat(res.direct, &direct_stat) || !S_ISREG(direct_stat.st_mode) ||
        ordinary_stat.st_dev != direct_stat.st_dev || ordinary_stat.st_ino != direct_stat.st_ino)
        return 1;
    CUfileDescr_t description{};
    description.type = CU_FILE_HANDLE_TYPE_OPAQUE_FD;
    description.handle.fd = res.direct;
    if (!file_ok(cuFileHandleRegister(&res.file, &description), "file register"))
        return unsupported("filesystem/native cuFile handle unsupported");
    /* Admit the complete raw history before any allocation or I/O; never shrink
     * it or validate early to fit. */
    size_t available = 0, total = 0;
    if (!cuda_ok(cudaMemGetInfo(&available, &total), "memory information")) return 1;
    if (history > available) return unsupported("device memory cannot hold the complete campaign history");
    /* Host images for the one final oracle are reserved before the campaign too. */
    std::vector<unsigned char> expected(history, 0xa5), observed(history), seed(chunk);
    std::vector<unsigned char> stored(checkpoint ? size_t(file_bytes) : 0);
    for (uint64_t iteration = 0; iteration < iterations; ++iteration)
        for (uint64_t offset = 0; offset < bytes; offset += chunk) {
            size_t part = size_t(std::min<uint64_t>(chunk, bytes - offset));
            size_t base = size_t(iteration * chunks + offset / chunk) * slot + guard;
            for (size_t j = 0; j < part; ++j) expected[base + j] = pattern(offset + j, iteration);
        }
    if (!cuda_ok(cudaMalloc(&res.gpu, history), "allocate")) return 1;
    if (!file_ok(cuFileBufRegister(res.gpu, history, 0), "buffer register"))
        return unsupported("native GPU buffer registration unsupported");
    res.registered = true;
    // Initialization is outside io_ns: guards everywhere, checkpoint state seeded once.
    if (checkpoint ? !cuda_ok(cudaMemcpy(res.gpu, expected.data(), history, cudaMemcpyHostToDevice), "checkpoint seed")
                   : !cuda_ok(cudaMemset(res.gpu, 0xa5, history), "guard initialize")) return 1;
    if (!cuda_ok(cudaDeviceSynchronize(), "seed synchronize")) return 1;
    if (!file_ok(cuFileStatsReset(), "stats reset") || !file_ok(cuFileStatsStart(), "stats start"))
        return unsupported("cannot isolate process native path counters");
    res.collecting = true;
    uint64_t io_ns = 0, io_bytes = 0, operations = 0;
    for (uint64_t iteration = 0; iteration < iterations; ++iteration) {
        if (!checkpoint) {
            for (uint64_t offset = 0; offset < bytes; offset += chunk) {
                size_t part = size_t(std::min<uint64_t>(chunk, bytes - offset));
                for (size_t j = 0; j < part; ++j) seed[j] = pattern(offset + j, iteration);
                if (pwrite_all(res.ordinary, seed.data(), part, off_t(offset)) != ssize_t(part)) {
                    std::perror("dense seed write"); return 1;
                }
            }
            if (fsync(res.ordinary)) { std::perror("seed fsync"); return 1; }
        }
        const uint64_t region = checkpoint ? iteration * bytes : 0;
        for (uint64_t offset = 0; offset < bytes; offset += chunk) {
            size_t part = size_t(std::min<uint64_t>(chunk, bytes - offset));
            off_t buffer = off_t(size_t(iteration * chunks + offset / chunk) * slot + guard);
            uint64_t start = now_ns();
            ssize_t count = checkpoint ? cuFileWrite(res.file, res.gpu, part, off_t(region + offset), buffer)
                                       : cuFileRead(res.file, res.gpu, part, off_t(region + offset), buffer);
            if (count != ssize_t(part)) {
                std::fprintf(stderr, "cuFile exact I/O failed: got %zd expected %zu\n", count, part); return 1;
            }
            if (!cuda_ok(cudaDeviceSynchronize(), "I/O completion")) return 1;
            uint64_t end = now_ns();
            if (!start || end <= start) { std::fprintf(stderr, "clock failure\n"); return 1; }
            io_ns += end - start;
            ++operations;
            io_bytes += part;
        }
        if (checkpoint) {
            uint64_t start = now_ns();
            if (fsync(res.direct)) { std::perror("checkpoint fsync"); return 1; }
            uint64_t end = now_ns();
            if (!start || end <= start) return 1;
            io_ns += end - start;
        }
    }
    if (!file_ok(cuFileStatsStop(), "stats stop")) return unsupported("native path statistics unavailable");
    res.collecting = false;
    CUfileStatsLevel3_t statistics{};
    if (!file_ok(cuFileGetStatsL3(&statistics), "stats retrieve") ||
        !statistics.num_gpus || statistics.num_gpus > 16)
        return unsupported("native path cannot be established from process counters");
    uint64_t native = 0, posix = 0, all = 0, transferred = 0, invalid = 0;
    for (uint32_t i = 0; i < statistics.num_gpus; ++i) {
        const auto &s = statistics.per_gpu_stats[i];
        native += checkpoint ? s.n_p2p_writes + s.n_nvfs_writes : s.n_p2p_reads + s.n_nvfs_reads;
        posix += s.n_posix_reads + s.n_posix_writes;
        all += checkpoint ? s.n_total_writes : s.n_total_reads;
        transferred += checkpoint ? s.writes_bytes : s.read_bytes;
        invalid += s.n_unaligned_reads + s.n_unaligned_writes + s.n_sparse_regions + s.n_inline_regions +
                   s.n_reads_err + s.n_writes_err + s.n_dr_reads + s.n_dr_writes;
        // No cuFile I/O in the opposite direction was requested.
        invalid += checkpoint ? s.n_total_reads : s.n_total_writes;
    }
    if (native != operations || all != operations || posix || invalid || transferred != io_bytes)
        return unsupported("observed cuFile path includes fallback or lacks exact native accounting");
    if (operations != wanted || io_bytes != bytes * iterations || !io_ns) return 1;
    GDS_CAMPAIGN_EVENT("campaign-end");

    /* The one final oracle: complete device history, then complete stored file. */
    GDS_CAMPAIGN_EVENT("oracle-begin");
    if (!cuda_ok(cudaMemcpy(observed.data(), res.gpu, history, cudaMemcpyDeviceToHost), "complete history readback") ||
        !cuda_ok(cudaDeviceSynchronize(), "oracle synchronize")) return 1;
    bool device_ok = observed == expected, file_ok_bytes = true;
    if (checkpoint) {
        struct stat saved{};
        if (fstat(res.ordinary, &saved) || saved.st_size != off_t(file_bytes) ||
            pread_all(res.ordinary, stored.data(), stored.size(), 0) != ssize_t(stored.size())) {
            std::perror("checkpoint complete file oracle"); return 1;
        }
        for (uint64_t iteration = 0; iteration < iterations && file_ok_bytes; ++iteration)
            for (uint64_t index = 0; index < bytes; ++index)
                if (stored[size_t(iteration * bytes + index)] != pattern(index, iteration)) { file_ok_bytes = false; break; }
    }
    GDS_CAMPAIGN_EVENT("oracle-end");
    if (!device_ok) { std::fprintf(stderr, "payload, unused chunk tail or GPU guard mismatch in campaign history\n"); return 1; }
    if (!file_ok_bytes) { std::fprintf(stderr, "checkpoint file payload mismatch in campaign history\n"); return 1; }

    GDS_CAMPAIGN_EVENT("manifest");
    if (!res.close()) return 1;
    std::printf("{\"schema_version\":2,\"measurement_policy\":\"gds-campaign-v1\",\"mode\":\"cufile-direct\",\"workload\":\"%s\","
        "\"bytes\":%llu,\"chunk\":%zu,\"iterations\":%llu,\"io_bytes\":%llu,"
        "\"verified_bytes\":%llu,\"operations\":%llu,\"native_operations\":%llu,"
        "\"posix_operations\":0,\"guards_ok\":true,\"status\":\"pass\","
        "\"execution\":\"physical-cuda-cufile\",\"path_evidence\":\"cufile-l3-native-counters\","
        "\"compat_allowed\":false,\"io_ns\":%llu,\"input_id\":\"deterministic-pattern-v1\","
        "\"source_window\":[0,%llu],\"output_residency\":\"%s\",\"queue_depth\":1,\"direct_io\":true,"
        "\"buffer_registration\":\"once-reused\",\"registration_count\":1,\"campaign_complete\":true,"
        "\"validation_phase\":\"post-campaign\",\"full_byte_compare\":true,\"history_operations\":%llu,"
        "\"history_bytes\":%llu,\"manifest_count\":1,\"capture_in_timing\":true}\n", workload,
        (unsigned long long)bytes, chunk, (unsigned long long)iterations,
        (unsigned long long)io_bytes, (unsigned long long)io_bytes,
        (unsigned long long)operations, (unsigned long long)native, (unsigned long long)io_ns,
        (unsigned long long)bytes, checkpoint ? "file" : "vram",
        (unsigned long long)operations, (unsigned long long)history);
    return 0;
}
#endif

int main(int argc, char **argv)
{
    uint64_t bytes, chunk, iterations;
    if (argc != 6 || (std::strcmp(argv[1], "llm-load") && std::strcmp(argv[1], "checkpoint")) ||
        !number(argv[2], 1024ULL * 1024 * 1024, bytes) ||
        !number(argv[3], 16ULL * 1024 * 1024, chunk) || !number(argv[4], 1000, iterations) ||
        bytes % 4096 || chunk % 4096 || chunk > bytes) return 2;
    Resources resources;
    int result = 1;
    try { result = execute(resources, argv[1], bytes, size_t(chunk), iterations, argv[5]); }
    catch (const std::bad_alloc &) { std::fprintf(stderr, "allocation failed\n"); }
    return finish(resources, result);
}
