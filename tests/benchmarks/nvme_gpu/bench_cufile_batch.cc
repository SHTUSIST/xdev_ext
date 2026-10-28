/* SPDX-License-Identifier: GPL-2.0-only
 * bench_cufile_batch - the cuFile batch and stream-async arms of the
 * NVMe<->GPU comparison (GPUDirect Storage, native path only).
 *
 *   --api batch  cuFileBatchIOSetUp/Submit/GetStatus on two batch handles:
 *                each handle carries a wave of ceil(qd/2) I/Os and is
 *                resubmitted when its whole wave completed, so up to qd
 *                I/Os are in flight and one wave refills while the other
 *                runs.  A wave never exceeds the driver's max_batch_io_size.
 *   --api async  cuFileReadAsync/cuFileWriteAsync on qd registered CUDA
 *                streams, one I/O per stream at a time, completion by a
 *                CUDA event after each I/O.
 *
 * The synchronous cuFileRead/Write arm stays in ../gds/bench_cufile.cc; this
 * file shares its native-path evidence policy: compatibility mode disabled
 * and verified in the driver properties, and process level-3 statistics
 * whose successful NVFS/P2P operations and bytes exactly equal the
 * campaign, with no POSIX, unaligned, sparse, inline, dynamic-routing or
 * failed operation.  Anything else exits 4 without a result.
 *
 * Same geometry, schedule, payload, seeding and oracle as bench_uring_cuda.cc
 * (nvme_gpu_core.h): the whole device window (load) or file window (save) is
 * read back once after each pass, outside the timed region.  The device
 * buffer is one cudaMalloc registered once with cuFileBufRegister.
 *
 * --destination slot-ring (default) is the session arm's device layout: qd
 * device slots, schedule position i at slot i mod qd; a load rewrites a slot
 * only after the I/O that last wrote it completed.  window places block b at
 * device offset b*size and is not paired with the session.
 *
 * --completion-wait block (default) sleeps when nothing progressed:
 * cuFileBatchIOGetStatus with min_nr equal to the oldest wave's outstanding
 * I/Os and the campaign deadline as timeout, or cudaEventSynchronize on the
 * oldest stream's cudaEventBlockingSync event.  Whether libcufile itself
 * sleeps or spins inside GetStatus is the library's choice and is not
 * verified here.  poll spins with a zero timeout and cudaEventQuery; its CPU
 * fields are no CPU-cost data.
 * Exit: 0 verified, 1 failure, 2 usage, 4 unavailable capability.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../common/cpu_timer.h"
static struct cpu_timer endpoint_timer;
static void endpoint_timer_cleanup() { cpu_timer_destroy(&endpoint_timer); }
#include <cuda_runtime_api.h>
#include <cufile.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <new>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#include "nvme_gpu_core.h"

namespace {

constexpr uint64_t kCheckChunk = 64ULL << 20;

enum Api { API_BATCH, API_ASYNC };

uint64_t now_ns()
{
    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return uint64_t(ts.tv_sec) * 1000000000ULL + uint64_t(ts.tv_nsec);
}

uint64_t cpu_us()
{
    rusage ru{};
    if (getrusage(RUSAGE_SELF, &ru)) return 0;
    return xg_cpu_us(ru.ru_utime.tv_sec, ru.ru_utime.tv_usec, ru.ru_stime.tv_sec,
                     ru.ru_stime.tv_usec);
}

bool cuda_ok(cudaError_t e, const char *what)
{
    if (e == cudaSuccess) return true;
    std::fprintf(stderr, "CUDA %s failed: %s\n", what, cudaGetErrorString(e));
    return false;
}

bool file_ok(CUfileError_t e, const char *what)
{
    if (e.err == CU_FILE_SUCCESS) return true;
    std::fprintf(stderr, "cuFile %s failed: %d\n", what, int(e.err));
    return false;
}

int skip(const char *why)
{
    std::fprintf(stderr, "SKIP: %s\n", why);
    return XG_EXIT_UNAVAILABLE;
}

struct Options {
    uint32_t direction = XG_LOAD;
    Api api = API_BATCH;
    bool ring = true, block = true;   /* --destination slot-ring, --completion-wait block */
    const char *file = nullptr;
    uint64_t file_offset = 0, timeout_ms = 60000;
    xg_geometry g{};
};

void usage(FILE *f)
{
    std::fprintf(f,
        "usage: bench_cufile_batch --api batch|async --direction load|save --file PATH\n"
        "         [--file-offset N] --size N --qd N --window-bytes N [--passes N]\n"
        "         [--pattern seq|rand] [--seed N] [--timeout-ms N]\n"
        "         [--destination slot-ring|window] [--completion-wait block|poll]\n");
}

int parse(int argc, char **argv, Options &o)
{
    enum { O_API = 1, O_DIR, O_FILE, O_FOFF, O_SIZE, O_QD, O_WIN, O_PASS, O_PAT, O_SEED,
           O_TMO, O_DEST, O_WAIT, O_HELP };
    static const option opts[] = {
        {"api", required_argument, nullptr, O_API},
        {"direction", required_argument, nullptr, O_DIR},
        {"file", required_argument, nullptr, O_FILE},
        {"file-offset", required_argument, nullptr, O_FOFF},
        {"size", required_argument, nullptr, O_SIZE},
        {"qd", required_argument, nullptr, O_QD},
        {"window-bytes", required_argument, nullptr, O_WIN},
        {"passes", required_argument, nullptr, O_PASS},
        {"pattern", required_argument, nullptr, O_PAT},
        {"seed", required_argument, nullptr, O_SEED},
        {"timeout-ms", required_argument, nullptr, O_TMO},
        {"destination", required_argument, nullptr, O_DEST},
        {"completion-wait", required_argument, nullptr, O_WAIT},
        {"help", no_argument, nullptr, O_HELP},
        {nullptr, 0, nullptr, 0},
    };
    bool have_dir = false, have_api = false;
    uint64_t seed = 1;
    int c, bad = 0;

    o.g.passes = 1;
    opterr = 0;
    while ((c = getopt_long(argc, argv, "", opts, nullptr)) != -1) {
        switch (c) {
        case O_API:
            have_api = true;
            if (!std::strcmp(optarg, "batch")) o.api = API_BATCH;
            else if (!std::strcmp(optarg, "async")) o.api = API_ASYNC;
            else bad = 1;
            break;
        case O_DIR: bad |= xg_parse_direction(optarg, &o.direction); have_dir = true; break;
        case O_FILE: o.file = optarg; break;
        case O_FOFF: bad |= xg_parse_u64(optarg, UINT64_MAX >> 2, &o.file_offset); break;
        case O_SIZE: bad |= xg_parse_u64(optarg, XG_MAX_SIZE, &o.g.size); break;
        case O_QD: bad |= xg_parse_u64(optarg, XG_MAX_QD, &o.g.qd); break;
        case O_WIN: bad |= xg_parse_u64(optarg, XG_MAX_WINDOW, &o.g.window); break;
        case O_PASS: bad |= xg_parse_u64(optarg, XG_MAX_PASSES, &o.g.passes); break;
        case O_PAT: bad |= xg_parse_pattern(optarg, &o.g.pattern); break;
        case O_SEED: bad |= xg_parse_u64(optarg, UINT32_MAX, &seed); break;
        case O_TMO: bad |= xg_parse_u64(optarg, 3600000, &o.timeout_ms); break;
        case O_DEST:
            if (!std::strcmp(optarg, "slot-ring")) o.ring = true;
            else if (!std::strcmp(optarg, "window")) o.ring = false;
            else bad = 1;
            break;
        case O_WAIT:
            if (!std::strcmp(optarg, "block")) o.block = true;
            else if (!std::strcmp(optarg, "poll")) o.block = false;
            else bad = 1;
            break;
        case O_HELP: usage(stdout); std::exit(0);
        default: bad = 1; break;
        }
    }
    o.g.seed = uint32_t(seed);
    if (bad || optind != argc || !have_dir || !have_api || !o.file || !o.timeout_ms ||
        o.file_offset % 4096 || xg_geometry_check(&o.g))
        return XG_EXIT_USAGE;
    return XG_EXIT_PASS;
}

int direct_io(int fd, bool write, void *buf, uint64_t len, uint64_t off)
{
    uint64_t done = 0;
    while (done < len) {
        ssize_t k = write ? ::pwrite(fd, static_cast<char *>(buf) + done, len - done, off_t(off + done))
                          : ::pread(fd, static_cast<char *>(buf) + done, len - done, off_t(off + done));
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return k < 0 ? -errno : -EIO;
        done += uint64_t(k);
    }
    return 0;
}

/* Per-stream state of the async API; the SDK reads these at execution. */
struct AsyncSlot {
    cudaStream_t stream = nullptr;
    cudaEvent_t done = nullptr;
    bool registered = false, busy = false;
    uint64_t pos = 0, started = 0;
    size_t size = 0;
    off_t file_offset = 0, buf_offset = 0;
    ssize_t bytes = 0;
};

struct Wave {
    CUfileBatchHandle_t handle = nullptr;
    std::vector<CUfileIOParams_t> params;
    std::vector<CUfileIOEvents_t> events;
    unsigned outstanding = 0;
    uint64_t submitted = 0;
};

struct Run {
    Options o;
    int fd = -1;
    void *dev = nullptr;
    uint64_t dev_bytes = 0;
    std::vector<char> dev_busy;    /* slot-ring load: an I/O writes the slot */
    CUfileHandle_t fh = nullptr;
    bool driver = false, buf_registered = false, collecting = false;
    std::vector<AsyncSlot> slots;
    std::vector<Wave> waves;
    unsigned char *check = nullptr;
    uint64_t check_bytes = 0;
    unsigned batch_cap = 0;

    bool close()
    {
        bool ok = true;
        if (!slots.empty() || !waves.empty())
            if (!cuda_ok(cudaDeviceSynchronize(), "final drain")) ok = false;
        for (auto &w : waves)
            if (w.handle) cuFileBatchIODestroy(w.handle);
        waves.clear();
        for (auto &s : slots) {
            if (s.registered && !file_ok(cuFileStreamDeregister(s.stream), "stream deregister")) ok = false;
            if (s.done && !cuda_ok(cudaEventDestroy(s.done), "event destroy")) ok = false;
            if (s.stream && !cuda_ok(cudaStreamDestroy(s.stream), "stream destroy")) ok = false;
        }
        slots.clear();
        if (collecting) { if (!file_ok(cuFileStatsStop(), "stats stop")) ok = false; collecting = false; }
        if (buf_registered) { if (!file_ok(cuFileBufDeregister(dev), "buffer deregister")) ok = false; buf_registered = false; }
        if (fh) { cuFileHandleDeregister(fh); fh = nullptr; }
        if (dev && !cuda_ok(cudaFree(dev), "free")) ok = false;
        dev = nullptr;
        if (driver) { if (!file_ok(cuFileDriverClose(), "driver close")) ok = false; driver = false; }
        std::free(check);
        check = nullptr;
        if (fd >= 0 && ::close(fd)) ok = false;
        fd = -1;
        return ok;
    }
    ~Run() { close(); }
};

bool load(const Run &r) { return r.o.direction == XG_LOAD; }

uint64_t remaining_timespec(uint64_t deadline, timespec &ts)
{
    uint64_t now = now_ns(), left = now < deadline ? deadline - now : 0;
    ts.tv_sec = time_t(left / 1000000000ULL);
    ts.tv_nsec = long(left % 1000000000ULL);
    return left;
}

/* Device offset of schedule position @pos holding @block. */
off_t device_offset(const Run &r, uint64_t pos, uint64_t block)
{
    return off_t((r.o.ring ? xg_ring_slot(&r.o.g, pos) : block) * r.o.g.size);
}

/*
 * Fill wave @w with the next schedule positions and submit it.  A slot-ring
 * load stops at a position whose device slot an earlier I/O still writes.
 */
int submit_wave(Run &r, Wave &w, uint64_t p, uint64_t &next, uint64_t n, unsigned width)
{
    const bool gate = load(r) && r.o.ring;
    unsigned k = 0;
    for (; k < width && next < n; k++, next++) {
        if (gate && r.dev_busy[xg_ring_slot(&r.o.g, next)]) break;
        uint64_t block = xg_block(&r.o.g, p, next);
        CUfileIOParams_t &io = w.params[k];
        std::memset(&io, 0, sizeof(io));
        io.mode = CUFILE_BATCH;
        io.fh = r.fh;
        io.opcode = load(r) ? CUFILE_READ : CUFILE_WRITE;
        io.cookie = reinterpret_cast<void *>(uintptr_t(next + 1));
        io.u.batch.devPtr_base = r.dev;
        io.u.batch.devPtr_offset = device_offset(r, next, block);
        io.u.batch.file_offset = off_t(r.o.file_offset + block * r.o.g.size);
        io.u.batch.size = size_t(r.o.g.size);
        if (gate) r.dev_busy[xg_ring_slot(&r.o.g, next)] = 1;
    }
    if (!k) return 0;
    if (!file_ok(cuFileBatchIOSubmit(w.handle, k, w.params.data(), 0), "batch submit")) return -EIO;
    w.outstanding = k;
    w.submitted = now_ns();
    return 0;
}

/*
 * Completions of wave @w: poll (no minimum, zero timeout) or, with @block,
 * sleep until the whole wave completed or @deadline.  Returns the number
 * retired or -errno.
 */
int reap_wave(Run &r, Wave &w, bool block, uint64_t deadline)
{
    timespec ts{0, 0};
    if (block && !remaining_timespec(deadline, ts)) return -ETIMEDOUT;
    unsigned got = w.outstanding;
    if (!file_ok(cuFileBatchIOGetStatus(w.handle, block ? w.outstanding : 0, &got,
                                        w.events.data(), &ts), "batch status"))
        return -EIO;
    if (got > w.outstanding) return -EPROTO;
    for (unsigned e = 0; e < got; e++) {
        uint64_t pos = uintptr_t(w.events[e].cookie) - 1;
        if (w.events[e].status != CUFILE_COMPLETE || w.events[e].ret != size_t(r.o.g.size)) {
            std::fprintf(stderr, "batch I/O status %d ret %zu\n",
                         int(w.events[e].status), w.events[e].ret);
            return -EIO;
        }
        if (load(r) && r.o.ring) r.dev_busy[xg_ring_slot(&r.o.g, pos)] = 0;
    }
    w.outstanding -= got;
    return int(got);
}

int pass_batch(Run &r, uint64_t p, uint64_t &io_ns)
{
    const uint64_t n = xg_blocks(&r.o.g);
    const unsigned width = unsigned(r.waves[0].params.size());
    uint64_t next = 0, retired = 0;
    uint64_t t0 = now_ns(), deadline = t0 + r.o.timeout_ms * 1000000ULL;

    while (retired < n) {
        bool progress = false;
        Wave *oldest = nullptr;
        for (auto &w : r.waves) {
            if (w.outstanding) {
                int got = reap_wave(r, w, false, deadline);
                if (got < 0) return got;
                retired += unsigned(got);
                progress |= got > 0;
            }
            /* A wave is resubmitted once its whole previous wave completed. */
            if (!w.outstanding && next < n) {
                if (submit_wave(r, w, p, next, n, width)) return -EIO;
                progress |= w.outstanding > 0;
            }
            if (w.outstanding && (!oldest || w.submitted < oldest->submitted)) oldest = &w;
        }
        if (!progress && r.o.block) {
            if (!oldest) return -EPROTO;
            int got = reap_wave(r, *oldest, true, deadline);
            if (got < 0) return got;
            retired += unsigned(got);
        }
        if (now_ns() >= deadline) return -ETIMEDOUT;
    }
    uint64_t t1 = now_ns();
    if (!t0 || t1 <= t0) return -EIO;
    cpu_timer_store(&endpoint_timer, "io_ns", endpoint_timer.count, t0, t1);
    io_ns = t1 - t0;
    return 0;
}

bool submit_async(Run &r, AsyncSlot &s, uint64_t p, uint64_t pos)
{
    uint64_t block = xg_block(&r.o.g, p, pos);
    s.pos = pos;
    s.size = size_t(r.o.g.size);
    s.file_offset = off_t(r.o.file_offset + block * r.o.g.size);
    s.buf_offset = device_offset(r, pos, block);
    s.bytes = -1;
    CUfileError_t e = load(r) ?
        cuFileReadAsync(r.fh, r.dev, &s.size, &s.file_offset, &s.buf_offset, &s.bytes, s.stream) :
        cuFileWriteAsync(r.fh, r.dev, &s.size, &s.file_offset, &s.buf_offset, &s.bytes, s.stream);
    if (!file_ok(e, "async submit") || !cuda_ok(cudaEventRecord(s.done, s.stream), "event record"))
        return false;
    if (load(r) && r.o.ring) r.dev_busy[xg_ring_slot(&r.o.g, pos)] = 1;
    s.busy = true;
    s.started = now_ns();
    return true;
}

int pass_async(Run &r, uint64_t p, uint64_t &io_ns)
{
    const uint64_t n = xg_blocks(&r.o.g);
    const bool gate = load(r) && r.o.ring;
    uint64_t next = 0, retired = 0;
    uint64_t t0 = now_ns(), deadline = t0 + r.o.timeout_ms * 1000000ULL;

    while (retired < n) {
        bool progress = false;
        AsyncSlot *oldest = nullptr;
        for (auto &s : r.slots) {
            if (s.busy) {
                cudaError_t e = cudaEventQuery(s.done);
                if (e == cudaErrorNotReady) {
                    if (!oldest || s.started < oldest->started) oldest = &s;
                    continue;
                }
                if (!cuda_ok(e, "event query")) return -EIO;
                if (s.bytes != ssize_t(r.o.g.size)) {
                    std::fprintf(stderr, "async I/O returned %zd\n", s.bytes);
                    return -EIO;
                }
                if (gate) r.dev_busy[xg_ring_slot(&r.o.g, s.pos)] = 0;
                s.busy = false;
                retired++;
                progress = true;
            }
            /* A free stream takes the next position unless its device slot is still written. */
            if (next < n && !(gate && r.dev_busy[xg_ring_slot(&r.o.g, next)])) {
                if (!submit_async(r, s, p, next++)) return -EIO;
                progress = true;
            }
        }
        if (!progress && r.o.block) {
            if (!oldest) return -EPROTO;
            if (!cuda_ok(cudaEventSynchronize(oldest->done), "event wait")) return -EIO;
        }
        if (now_ns() >= deadline) return -ETIMEDOUT;
    }
    uint64_t t1 = now_ns();
    if (!t0 || t1 <= t0) return -EIO;
    cpu_timer_store(&endpoint_timer, "io_ns", endpoint_timer.count, t0, t1);
    io_ns = t1 - t0;
    return 0;
}

/* Outside timing: device buffer (slot s holds block s on the ring) or file window. */
int fill_window(Run &r, bool device, uint32_t seed)
{
    const uint64_t limit = device ? r.dev_bytes : r.o.g.window;
    for (uint64_t off = 0; off < limit; off += r.check_bytes) {
        uint64_t n = limit - off < r.check_bytes ? limit - off : r.check_bytes;
        xg_fill(r.check, off, n, seed);
        int ret = device ?
            (cuda_ok(cudaMemcpy(static_cast<char *>(r.dev) + off, r.check, n, cudaMemcpyHostToDevice),
                     "window seed") ? 0 : -EIO) :
            direct_io(r.fd, true, r.check, n, r.o.file_offset + off);
        if (ret) return ret;
    }
    if (device) return cuda_ok(cudaDeviceSynchronize(), "seed sync") ? 0 : -EIO;
    return fsync(r.fd) ? -errno : 0;
}

/* Outside timing: one complete readback of pass @p's destination and compare. */
int verify_window(Run &r, uint64_t p)
{
    const xg_geometry &g = r.o.g;
    if (r.o.ring && !load(r)) {
        /* slot-ring save: the block of position i holds slot (i mod qd)'s image. */
        for (uint64_t i = 0; i < xg_blocks(&g); i++) {
            uint64_t b = xg_block(&g, p, i);
            int ret = direct_io(r.fd, false, r.check, g.size, r.o.file_offset + b * g.size);
            if (ret) return ret;
            if (xg_compare(r.check, xg_ring_save_source(&g, i) * g.size, g.size, g.seed) >= 0) {
                std::fprintf(stderr, "file block %llu is not slot %llu's image\n",
                             (unsigned long long)b, (unsigned long long)xg_ring_slot(&g, i));
                return -EBADMSG;
            }
        }
        return 0;
    }
    const uint64_t limit = load(r) ? r.dev_bytes : g.window;
    for (uint64_t off = 0; off < limit; off += r.check_bytes) {
        uint64_t n = limit - off < r.check_bytes ? limit - off : r.check_bytes;
        int ret = load(r) ?
            (cuda_ok(cudaMemcpy(r.check, static_cast<char *>(r.dev) + off, n, cudaMemcpyDeviceToHost),
                     "window readback") ? 0 : -EIO) :
            direct_io(r.fd, false, r.check, n, r.o.file_offset + off);
        if (ret) return ret;
        if (r.o.ring) {
            /* slot-ring load: slot d holds the block of the last position sent to it. */
            for (uint64_t k = 0; k < n; k += g.size) {
                uint64_t d = (off + k) / g.size, want = xg_ring_load_block(&g, p, d);
                if (xg_compare(r.check + k, want * g.size, g.size, g.seed) >= 0) {
                    std::fprintf(stderr, "device slot %llu does not hold block %llu\n",
                                 (unsigned long long)d, (unsigned long long)want);
                    return -EBADMSG;
                }
            }
            continue;
        }
        int64_t bad = xg_compare(r.check, off, n, g.seed);
        if (bad >= 0) {
            std::fprintf(stderr, "%s window mismatch at byte %llu\n", load(r) ? "device" : "file",
                         (unsigned long long)(off + uint64_t(bad)));
            return -EBADMSG;
        }
    }
    return 0;
}

/* Native-path evidence of the whole campaign (all passes). */
int native_evidence(Run &r, uint64_t operations, uint64_t bytes)
{
    if (!file_ok(cuFileStatsStop(), "stats stop")) return skip("native path statistics unavailable");
    r.collecting = false;
    CUfileStatsLevel3_t st{};
    if (!file_ok(cuFileGetStatsL3(&st), "stats retrieve") || !st.num_gpus || st.num_gpus > 16)
        return skip("native path cannot be established from process counters");
    uint64_t native = 0, posix = 0, total = 0, moved = 0, invalid = 0;
    bool write = !load(r);
    for (uint32_t i = 0; i < st.num_gpus; ++i) {
        const auto &s = st.per_gpu_stats[i];
        native += write ? s.n_p2p_writes + s.n_nvfs_writes : s.n_p2p_reads + s.n_nvfs_reads;
        posix += s.n_posix_reads + s.n_posix_writes;
        total += write ? s.n_total_writes : s.n_total_reads;
        moved += write ? s.writes_bytes : s.read_bytes;
        invalid += s.n_unaligned_reads + s.n_unaligned_writes + s.n_sparse_regions + s.n_inline_regions +
                   s.n_reads_err + s.n_writes_err + s.n_dr_reads + s.n_dr_writes;
        invalid += write ? s.n_total_reads : s.n_total_writes;
    }
    if (native != operations || total != operations || posix || invalid || moved != bytes)
        return skip("observed cuFile path includes fallback or lacks exact native accounting");
    return XG_EXIT_PASS;
}

int execute(Run &r)
{
    const Options &o = r.o;
    int count = 0;
    if (cudaGetDeviceCount(&count) != cudaSuccess || count < 1)
        return skip("no CUDA device available");
    if (!cuda_ok(cudaSetDevice(0), "select device")) return XG_EXIT_FAIL;
    if (!file_ok(cuFileSetParameterBool(CUFILE_PARAM_PROPERTIES_ALLOW_COMPAT_MODE, false), "disable compat") ||
        !file_ok(cuFileSetParameterBool(CUFILE_PARAM_FORCE_COMPAT_MODE, false), "disable forced compat"))
        return skip("native-only cuFile configuration unsupported");
    if (!file_ok(cuFileDriverOpen(), "driver open")) return skip("native cuFile driver unavailable");
    r.driver = true;
    CUfileDrvProps_t props{};
    if (!file_ok(cuFileDriverGetProperties(&props), "properties") ||
        (props.nvfs.dcontrolflags & (1U << CU_FILE_ALLOW_COMPAT_MODE)))
        return skip("cannot verify compatibility is disabled");
    if (o.api == API_BATCH) {
        r.batch_cap = props.max_batch_io_size;
        if (!r.batch_cap) return skip("driver reports no batch I/O capacity");
    }
    if (!file_ok(cuFileSetStatsLevel(3), "stats level")) return skip("cuFile process L3 statistics unavailable");

    r.fd = ::open(o.file, O_RDWR | O_DIRECT | O_CLOEXEC);
    struct stat st{};
    if (r.fd < 0) return skip("file does not open with O_DIRECT");
    if (fstat(r.fd, &st) || !S_ISREG(st.st_mode) ||
        uint64_t(st.st_size) < o.file_offset + o.g.window)
        return XG_EXIT_USAGE;
    CUfileDescr_t descr{};
    descr.type = CU_FILE_HANDLE_TYPE_OPAQUE_FD;
    descr.handle.fd = r.fd;
    if (!file_ok(cuFileHandleRegister(&r.fh, &descr), "file register"))
        return skip("filesystem/native cuFile handle unsupported");
    r.dev_bytes = o.ring ? xg_ring_bytes(&o.g) : o.g.window;
    if (o.ring) r.dev_busy.assign(o.g.qd, 0);
    if (!cuda_ok(cudaMalloc(&r.dev, r.dev_bytes), "device buffer")) return XG_EXIT_FAIL;
    if (!file_ok(cuFileBufRegister(r.dev, r.dev_bytes, 0), "buffer register"))
        return skip("native GPU buffer registration of the window unsupported");
    r.buf_registered = true;
    r.check_bytes = o.g.window < kCheckChunk ? o.g.window : kCheckChunk / o.g.size * o.g.size;
    if (posix_memalign(reinterpret_cast<void **>(&r.check), 4096, r.check_bytes)) return XG_EXIT_FAIL;

    if (o.api == API_BATCH) {
        unsigned handles = o.g.qd >= 2 ? 2 : 1;
        unsigned width = unsigned((o.g.qd + handles - 1) / handles);
        if (width > r.batch_cap) return skip("qd/2 exceeds the driver's max_batch_io_size");
        r.waves.resize(handles);
        for (auto &w : r.waves) {
            w.params.resize(width);
            w.events.resize(width);
            if (!file_ok(cuFileBatchIOSetUp(&w.handle, width), "batch setup"))
                return skip("cuFile batch API unavailable");
        }
    } else {
        r.slots.resize(o.g.qd);
        for (auto &s : r.slots) {
            if (!cuda_ok(cudaStreamCreateWithFlags(&s.stream, cudaStreamNonBlocking), "stream") ||
                !cuda_ok(cudaEventCreateWithFlags(&s.done, cudaEventDisableTiming |
                                                  (o.block ? cudaEventBlockingSync : 0)), "event"))
                return XG_EXIT_FAIL;
            if (!file_ok(cuFileStreamRegister(s.stream, 0), "stream register"))
                return skip("cuFile stream async API unavailable");
            s.registered = true;
        }
    }

    if (fill_window(r, !load(r), o.g.seed)) return XG_EXIT_FAIL;
    if (!file_ok(cuFileStatsReset(), "stats reset") || !file_ok(cuFileStatsStart(), "stats start"))
        return skip("cannot isolate process native path counters");
    r.collecting = true;
    uint64_t io_ns = 0, cpu = 0, busy = 0, verified = 0;
    for (uint64_t p = 0; p < o.g.passes; p++) {
        uint64_t span = 0;
        if (fill_window(r, load(r), ~o.g.seed)) return XG_EXIT_FAIL;
        uint64_t c0 = cpu_us(), b0 = xg_host_busy_us();
        int ret = o.api == API_BATCH ? pass_batch(r, p, span) : pass_async(r, p, span);
        cpu += cpu_us() - c0;
        busy += xg_host_busy_us() - b0;
        if (ret) {
            std::fprintf(stderr, "pass %llu: %s\n", (unsigned long long)p, std::strerror(-ret));
            return XG_EXIT_FAIL;
        }
        if (!cuda_ok(cudaDeviceSynchronize(), "drain") || verify_window(r, p)) return XG_EXIT_FAIL;
        io_ns += span;
        verified += o.ring && load(r) ? r.dev_bytes : o.g.window;
    }
    const uint64_t ops = xg_blocks(&o.g) * o.g.passes, bytes = o.g.window * o.g.passes;
    int ret = native_evidence(r, ops, bytes);
    if (ret) return ret;
    if (!r.close()) return XG_EXIT_FAIL;
    std::printf("{\"schema_version\":1,\"arm\":\"%s\",\"direction\":\"%s\","
        "\"route\":\"%s\",\"execution\":\"physical-cuda-cufile\",\"performance_claim\":\"physical\","
        "\"path_evidence\":\"cufile-l3-native-counters\",\"compat_allowed\":false,"
        "\"destination\":\"%s\",\"completion_wait\":\"%s\","
        "\"size\":%llu,\"qd\":%llu,\"pattern\":\"%s\",\"window_bytes\":%llu,\"passes\":%llu,"
        "\"operations\":%llu,\"native_operations\":%llu,\"io_bytes\":%llu,\"verified_bytes\":%llu,"
        "\"oracle\":\"%s\",\"io_ns\":%llu,\"cpu_us\":%llu,\"host_busy_us\":%llu,"
        "\"status\":\"pass\"}\n",
        o.api == API_BATCH ? "gds-batch" : "gds-async",
        load(r) ? "load" : "save",
        load(r) ? "nvme>gpu-direct" : "gpu-direct>nvme",
        o.ring ? "slot-ring" : "window", o.block ? "block" : "poll",
        (unsigned long long)o.g.size, (unsigned long long)o.g.qd,
        o.g.pattern == XG_SEQ ? "seq" : "rand", (unsigned long long)o.g.window,
        (unsigned long long)o.g.passes, (unsigned long long)ops, (unsigned long long)ops,
        (unsigned long long)bytes, (unsigned long long)verified,
        load(r) ? (o.ring ? "device-slot-ring-readback" : "device-window-readback")
                : (o.ring ? "file-window-slot-images" : "file-window-readback"),
        (unsigned long long)io_ns, (unsigned long long)cpu, (unsigned long long)busy);
    return std::fflush(stdout) ? XG_EXIT_FAIL : XG_EXIT_PASS;
}

} // namespace

int main(int argc, char **argv)
{
    Run r;
    int ret = parse(argc, argv, r.o);
    if (ret) {
        usage(stderr);
        return ret;
    }
    int cpu_error = cpu_timer_init(&endpoint_timer, "CLOCK_MONOTONIC", r.o.g.passes);
    if (cpu_error)
        std::fprintf(stderr, "XDEV_EXT_CPU_TIMER_REFUSED phase=init code=%d\n", cpu_error);
    atexit(endpoint_timer_cleanup);
    try {
        ret = execute(r);
    } catch (const std::bad_alloc &) {
        std::fprintf(stderr, "allocation failed\n");
        ret = XG_EXIT_FAIL;
    }
    if (!r.close() && ret == XG_EXIT_PASS) ret = XG_EXIT_FAIL;
    if (ret == XG_EXIT_PASS) {
        cpu_error = cpu_timer_publish(&endpoint_timer);
        if (cpu_error)
            std::fprintf(stderr, "XDEV_EXT_CPU_TIMER_REFUSED phase=publish code=%d\n", cpu_error);
    }
    return ret;
}
