/* SPDX-License-Identifier: GPL-2.0-only
 * bench_uring_cuda - the strong staged arm of the NVMe<->GPU comparison.
 *
 *   load: io_uring O_DIRECT READ_FIXED into cudaHostRegister'ed staging
 *         slots, then cudaMemcpyAsync H2D on CUDA streams
 *   save: cudaMemcpyAsync D2H into the slots, then O_DIRECT WRITE_FIXED
 *
 * Once per run: the staging slots are allocated, registered with CUDA and
 * with io_uring (fixed buffers), the file is registered (fixed file) and the
 * device buffer is allocated.  2*qd slots give double buffering: up to qd
 * NVMe commands are in flight while the other slots copy.  Every in-flight
 * copy has its own completion event; slot reuse waits for that event.
 *
 * --destination slot-ring (default) uses the session arm's device layout: a
 * ring of qd device slots, schedule position i in slot i mod qd.  A load
 * rewrites a device slot only after its previous copy completed, so at most
 * qd blocks are in flight, the bound the session's depth sets.  window
 * places block b at device offset b*size over the whole window; it is not
 * paired with the session.
 *
 * --completion-wait block (default) sleeps when nothing progressed: on the
 * oldest outstanding operation, an NVMe command through
 * io_uring_wait_cqe_timeout or a copy through cudaEventSynchronize on a
 * cudaEventBlockingSync event.  poll spins on io_uring_peek_cqe and
 * cudaEventQuery; its cpu_us and host_busy_us approach the wall time by
 * construction and are no CPU-cost data.
 *
 * Timed region (per pass): from the first submission to the last
 * completion.  Seeding the file or the device window and the oracle are
 * outside it: after each pass the whole device window (load) or the whole
 * file window (save) is read back once and compared against the
 * position-encoding payload of nvme_gpu_core.h (slot-ring: the block each
 * slot must hold, or the slot image each block must hold).  No per-I/O
 * checksum.
 *
 * nvme_stage_ns and copy_stage_ns sum the host-observed submit-to-reap time
 * of each NVMe command and each copy; they overlap and are a breakdown, not
 * a partition of io_ns.  Exit: 0 verified, 1 failure, 2 usage, 4 unavailable
 * device/driver/filesystem capability (stdout empty unless 0).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../common/cpu_timer.h"
static struct cpu_timer endpoint_timer;
static void endpoint_timer_cleanup() { cpu_timer_destroy(&endpoint_timer); }
#include <cuda_runtime_api.h>
#include <liburing.h>

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

constexpr uint64_t kAlign = 2ULL << 20;
constexpr uint64_t kCheckChunk = 64ULL << 20;   /* bounded oracle buffer */

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

int skip(const char *why)
{
    std::fprintf(stderr, "SKIP: %s\n", why);
    return XG_EXIT_UNAVAILABLE;
}

struct Options {
    uint32_t direction = XG_LOAD;
    bool ring = true, block = true;   /* --destination slot-ring, --completion-wait block */
    const char *file = nullptr;
    uint64_t file_offset = 0, streams = 2, timeout_ms = 60000;
    xg_geometry g{};
};

void usage(FILE *f)
{
    std::fprintf(f,
        "usage: bench_uring_cuda --direction load|save --file PATH [--file-offset N]\n"
        "         --size N --qd N --window-bytes N [--passes N] [--pattern seq|rand]\n"
        "         [--seed N] [--streams N] [--timeout-ms N]\n"
        "         [--destination slot-ring|window] [--completion-wait block|poll]\n");
}

int parse(int argc, char **argv, Options &o)
{
    enum { O_DIR = 1, O_FILE, O_FOFF, O_SIZE, O_QD, O_WIN, O_PASS, O_PAT, O_SEED,
           O_STREAMS, O_TMO, O_DEST, O_WAIT, O_HELP };
    static const option opts[] = {
        {"direction", required_argument, nullptr, O_DIR},
        {"file", required_argument, nullptr, O_FILE},
        {"file-offset", required_argument, nullptr, O_FOFF},
        {"size", required_argument, nullptr, O_SIZE},
        {"qd", required_argument, nullptr, O_QD},
        {"window-bytes", required_argument, nullptr, O_WIN},
        {"passes", required_argument, nullptr, O_PASS},
        {"pattern", required_argument, nullptr, O_PAT},
        {"seed", required_argument, nullptr, O_SEED},
        {"streams", required_argument, nullptr, O_STREAMS},
        {"timeout-ms", required_argument, nullptr, O_TMO},
        {"destination", required_argument, nullptr, O_DEST},
        {"completion-wait", required_argument, nullptr, O_WAIT},
        {"help", no_argument, nullptr, O_HELP},
        {nullptr, 0, nullptr, 0},
    };
    bool have_dir = false;
    uint64_t seed = 1;
    int c, bad = 0;

    o.g.passes = 1;
    opterr = 0;
    while ((c = getopt_long(argc, argv, "", opts, nullptr)) != -1) {
        switch (c) {
        case O_DIR: bad |= xg_parse_direction(optarg, &o.direction); have_dir = true; break;
        case O_FILE: o.file = optarg; break;
        case O_FOFF: bad |= xg_parse_u64(optarg, UINT64_MAX >> 2, &o.file_offset); break;
        case O_SIZE: bad |= xg_parse_u64(optarg, XG_MAX_SIZE, &o.g.size); break;
        case O_QD: bad |= xg_parse_u64(optarg, XG_MAX_QD, &o.g.qd); break;
        case O_WIN: bad |= xg_parse_u64(optarg, XG_MAX_WINDOW, &o.g.window); break;
        case O_PASS: bad |= xg_parse_u64(optarg, XG_MAX_PASSES, &o.g.passes); break;
        case O_PAT: bad |= xg_parse_pattern(optarg, &o.g.pattern); break;
        case O_SEED: bad |= xg_parse_u64(optarg, UINT32_MAX, &seed); break;
        case O_STREAMS: bad |= xg_parse_u64(optarg, XG_MAX_STREAMS, &o.streams); break;
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
    if (bad || optind != argc || !have_dir || !o.file || !o.streams || !o.timeout_ms ||
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

struct Slot {
    unsigned char *host = nullptr;
    cudaEvent_t done = nullptr;
    uint64_t pos = 0, block = 0, started = 0;   /* schedule position, its block */
    /* save adds READY: the D2H copy finished, the write waits for a queue slot. */
    enum State { FREE, NVME, COPY, READY } state = FREE;
};

struct Run {
    Options o;
    int fd = -1;
    io_uring ring{};
    bool ring_ok = false, files_ok = false, bufs_ok = false;
    unsigned char *host = nullptr;     /* 2*qd slots, one allocation */
    bool host_registered = false;
    void *dev = nullptr;               /* the device slot ring or window */
    uint64_t dev_bytes = 0;
    std::vector<char> dev_busy;        /* slot-ring load: a copy targets the slot */
    std::vector<cudaStream_t> streams;
    std::vector<Slot> slots;
    unsigned char *check = nullptr;    /* oracle buffer of check_bytes */
    uint64_t check_bytes = 0;
    uint64_t nvme_ns = 0, copy_ns = 0;

    bool close()
    {
        bool ok = true;
        for (auto &s : slots)
            if (s.done && !cuda_ok(cudaEventDestroy(s.done), "event destroy")) ok = false;
        slots.clear();
        for (auto s : streams)
            if (!cuda_ok(cudaStreamDestroy(s), "stream destroy")) ok = false;
        streams.clear();
        if (bufs_ok && io_uring_unregister_buffers(&ring)) ok = false;
        if (files_ok && io_uring_unregister_files(&ring)) ok = false;
        if (ring_ok) io_uring_queue_exit(&ring);
        bufs_ok = files_ok = ring_ok = false;
        /* No copy may still read or write the slots when they are unregistered. */
        if (host_registered && !cuda_ok(cudaDeviceSynchronize(), "final drain")) ok = false;
        if (host_registered && !cuda_ok(cudaHostUnregister(host), "host unregister")) ok = false;
        host_registered = false;
        std::free(host);
        host = nullptr;
        if (dev && !cuda_ok(cudaFree(dev), "free")) ok = false;
        dev = nullptr;
        std::free(check);
        check = nullptr;
        if (fd >= 0 && ::close(fd)) ok = false;
        fd = -1;
        return ok;
    }
    ~Run() { close(); }
};

/* Hand slot @i's NVMe command to the ring (READ_FIXED or WRITE_FIXED). */
int submit_nvme(Run &r, unsigned i)
{
    io_uring_sqe *sqe = io_uring_get_sqe(&r.ring);
    Slot &s = r.slots[i];
    if (!sqe) return -EBUSY;
    uint64_t off = r.o.file_offset + s.block * r.o.g.size;
    if (r.o.direction == XG_LOAD)
        io_uring_prep_read_fixed(sqe, 0, s.host, unsigned(r.o.g.size), off, int(i));
    else
        io_uring_prep_write_fixed(sqe, 0, s.host, unsigned(r.o.g.size), off, int(i));
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, reinterpret_cast<void *>(uintptr_t(i)));
    s.state = Slot::NVME;
    s.started = now_ns();
    return 0;
}

bool start_copy(Run &r, unsigned i)
{
    Slot &s = r.slots[i];
    cudaStream_t st = r.streams[i % r.streams.size()];
    uint64_t off = r.o.ring ? xg_ring_slot(&r.o.g, s.pos) * r.o.g.size : s.block * r.o.g.size;
    char *d = static_cast<char *>(r.dev) + off;
    cudaError_t e = r.o.direction == XG_LOAD ?
        cudaMemcpyAsync(d, s.host, r.o.g.size, cudaMemcpyHostToDevice, st) :
        cudaMemcpyAsync(s.host, d, r.o.g.size, cudaMemcpyDeviceToHost, st);
    if (!cuda_ok(e, "memcpy async") || !cuda_ok(cudaEventRecord(s.done, st), "event record"))
        return false;
    s.state = Slot::COPY;
    s.started = now_ns();
    return true;
}

/*
 * Block mode: nothing progressed, so sleep until the oldest outstanding
 * operation completes (an NVMe command or a copy).  0 or -errno.
 */
int wait_oldest(Run &r, uint64_t deadline)
{
    const Slot *oldest = nullptr;
    for (const auto &s : r.slots)
        if ((s.state == Slot::NVME || s.state == Slot::COPY) &&
            (!oldest || s.started < oldest->started))
            oldest = &s;
    if (!oldest) return -EPROTO;
    if (oldest->state == Slot::COPY)
        return cuda_ok(cudaEventSynchronize(oldest->done), "event wait") ? 0 : -EIO;
    uint64_t now = now_ns();
    if (now >= deadline) return -ETIMEDOUT;
    __kernel_timespec ts{};
    ts.tv_sec = (long long)((deadline - now) / 1000000000ULL);
    ts.tv_nsec = (long long)((deadline - now) % 1000000000ULL);
    io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe_timeout(&r.ring, &cqe, &ts);
    if (ret == -EINTR) return 0;
    return ret == -ETIME ? -ETIMEDOUT : ret;
}

/*
 * One pass over the window.  load: FREE -> NVME (read) -> COPY (H2D) -> FREE;
 * save: FREE -> COPY (D2H) -> READY -> NVME (write) -> FREE.  At most qd NVMe
 * commands are in flight; returns 0 or -errno with *@io_ns the timed span.
 */
int pass(Run &r, uint64_t p, uint64_t &io_ns)
{
    const uint64_t n = xg_blocks(&r.o.g), qd = r.o.g.qd;
    uint64_t next = 0, retired = 0, nvme_inflight = 0;
    bool load = r.o.direction == XG_LOAD, gate = load && r.o.ring;
    uint64_t t0 = now_ns(), deadline = t0 + r.o.timeout_ms * 1000000ULL;

    while (retired < n) {
        unsigned pending_sqes = 0;
        bool progress = false;
        /* Start work on free slots while the schedule and the NVMe queue allow. */
        for (unsigned i = 0; i < r.slots.size() && next < n; i++) {
            Slot &s = r.slots[i];
            if (s.state != Slot::FREE) continue;
            if (load && nvme_inflight >= qd) break;
            /* slot-ring load: a device slot is rewritten only after its last copy. */
            if (gate && r.dev_busy[xg_ring_slot(&r.o.g, next)]) break;
            s.pos = next++;
            s.block = xg_block(&r.o.g, p, s.pos);
            if (gate) r.dev_busy[xg_ring_slot(&r.o.g, s.pos)] = 1;
            progress = true;
            if (load) {
                if (submit_nvme(r, i)) return -EBUSY;
                nvme_inflight++;
                pending_sqes++;
            } else if (!start_copy(r, i)) {
                return -EIO;
            }
        }
        /* Copies whose event fired move on; save writes wait for queue room. */
        for (unsigned i = 0; i < r.slots.size(); i++) {
            Slot &s = r.slots[i];
            if (s.state == Slot::COPY) {
                cudaError_t e = cudaEventQuery(s.done);
                if (e == cudaErrorNotReady) continue;
                if (!cuda_ok(e, "event query")) return -EIO;
                r.copy_ns += now_ns() - s.started;
                progress = true;
                if (load) {
                    if (gate) r.dev_busy[xg_ring_slot(&r.o.g, s.pos)] = 0;
                    s.state = Slot::FREE;
                    retired++;
                    continue;
                }
                s.state = Slot::READY;
            }
            if (s.state == Slot::READY && nvme_inflight < qd) {
                if (submit_nvme(r, i)) return -EBUSY;
                nvme_inflight++;
                pending_sqes++;
                progress = true;
            }
        }
        if (pending_sqes) {
            int ret = io_uring_submit(&r.ring);
            if (ret < 0) return ret;
        }
        /* Reap every available NVMe completion. */
        io_uring_cqe *cqe;
        while (io_uring_peek_cqe(&r.ring, &cqe) == 0) {
            uint64_t i = uintptr_t(io_uring_cqe_get_data(cqe));
            int res = cqe->res;
            io_uring_cqe_seen(&r.ring, cqe);
            if (i >= r.slots.size() || r.slots[i].state != Slot::NVME) return -EPROTO;
            if (res != int(r.o.g.size)) {
                std::fprintf(stderr, "NVMe I/O of block %llu returned %d\n",
                             (unsigned long long)r.slots[i].block, res);
                return res < 0 ? res : -EIO;
            }
            nvme_inflight--;
            progress = true;
            r.nvme_ns += now_ns() - r.slots[i].started;
            if (load) {
                if (!start_copy(r, unsigned(i))) return -EIO;
            } else {
                r.slots[i].state = Slot::FREE;
                retired++;
            }
        }
        if (!progress && r.o.block && retired < n) {
            int ret = wait_oldest(r, deadline);
            if (ret) return ret;
        }
        if (now_ns() >= deadline) return -ETIMEDOUT;
    }
    uint64_t t1 = now_ns();
    if (!t0 || t1 <= t0) return -EIO;
    cpu_timer_store(&endpoint_timer, "io_ns", endpoint_timer.count, t0, t1);
    io_ns = t1 - t0;
    return 0;
}

/* Window bytes [off, off + n) of the device, from or into r.check. */
bool device_copy(Run &r, bool to_device, uint64_t off, uint64_t n)
{
    char *d = static_cast<char *>(r.dev) + off;
    cudaError_t e = to_device ? cudaMemcpy(d, r.check, n, cudaMemcpyHostToDevice)
                              : cudaMemcpy(r.check, d, n, cudaMemcpyDeviceToHost);
    return cuda_ok(e, to_device ? "window seed" : "window readback");
}

/*
 * Outside timing: the device buffer (or the file window) gets @seed's
 * payload.  On the slot ring, slot s therefore holds block s.
 */
int fill_window(Run &r, bool device, uint32_t seed)
{
    const uint64_t limit = device ? r.dev_bytes : r.o.g.window;
    for (uint64_t off = 0; off < limit; off += r.check_bytes) {
        uint64_t n = limit - off < r.check_bytes ? limit - off : r.check_bytes;
        xg_fill(r.check, off, n, seed);
        int ret = device ? (device_copy(r, true, off, n) ? 0 : -EIO)
                         : direct_io(r.fd, true, r.check, n, r.o.file_offset + off);
        if (ret) return ret;
    }
    if (device) return cuda_ok(cudaDeviceSynchronize(), "seed sync") ? 0 : -EIO;
    return fsync(r.fd) ? -errno : 0;
}

/* Outside timing: one complete readback of pass @p's destination and compare. */
int verify_window(Run &r, uint64_t p)
{
    const xg_geometry &g = r.o.g;
    const bool device = r.o.direction == XG_LOAD;
    if (r.o.ring && !device) {
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
    const uint64_t limit = device ? r.dev_bytes : g.window;
    for (uint64_t off = 0; off < limit; off += r.check_bytes) {
        uint64_t n = limit - off < r.check_bytes ? limit - off : r.check_bytes;
        int ret = device ? (device_copy(r, false, off, n) ? 0 : -EIO)
                         : direct_io(r.fd, false, r.check, n, r.o.file_offset + off);
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
            std::fprintf(stderr, "%s window mismatch at byte %llu\n", device ? "device" : "file",
                         (unsigned long long)(off + uint64_t(bad)));
            return -EBADMSG;
        }
    }
    return 0;
}

int execute(Run &r)
{
    const Options &o = r.o;
    int count = 0;
    if (cudaGetDeviceCount(&count) != cudaSuccess || count < 1)
        return skip("no CUDA device available");
    if (!cuda_ok(cudaSetDevice(0), "select device")) return XG_EXIT_FAIL;

    r.fd = ::open(o.file, O_RDWR | O_DIRECT | O_CLOEXEC);
    struct stat st{};
    if (r.fd < 0) return skip("file does not open with O_DIRECT");
    if (fstat(r.fd, &st) || !(S_ISREG(st.st_mode) || S_ISBLK(st.st_mode))) return XG_EXIT_USAGE;
    if (S_ISREG(st.st_mode) && uint64_t(st.st_size) < o.file_offset + o.g.window)
        return XG_EXIT_USAGE;

    int ret = io_uring_queue_init(unsigned(2 * o.g.qd), &r.ring, 0);
    if (ret) return skip("io_uring unavailable");
    r.ring_ok = true;
    if (io_uring_register_files(&r.ring, &r.fd, 1)) return skip("io_uring fixed files unavailable");
    r.files_ok = true;

    const uint64_t nslots = 2 * o.g.qd, bytes = nslots * o.g.size;
    if (posix_memalign(reinterpret_cast<void **>(&r.host), kAlign, bytes)) return XG_EXIT_FAIL;
    if (!cuda_ok(cudaHostRegister(r.host, bytes, cudaHostRegisterDefault), "host register"))
        return skip("cudaHostRegister of the staging slots failed");
    r.host_registered = true;
    std::vector<iovec> iov(nslots);
    r.slots.resize(nslots);
    for (uint64_t i = 0; i < nslots; i++) {
        r.slots[i].host = r.host + i * o.g.size;
        iov[i] = iovec{r.slots[i].host, size_t(o.g.size)};
        unsigned flags = cudaEventDisableTiming | (o.block ? cudaEventBlockingSync : 0);
        if (!cuda_ok(cudaEventCreateWithFlags(&r.slots[i].done, flags), "event"))
            return XG_EXIT_FAIL;
    }
    if (io_uring_register_buffers(&r.ring, iov.data(), unsigned(nslots)))
        return skip("io_uring fixed buffers unavailable");
    r.bufs_ok = true;
    for (uint64_t i = 0; i < o.streams; i++) {
        cudaStream_t s;
        if (!cuda_ok(cudaStreamCreateWithFlags(&s, cudaStreamNonBlocking), "stream")) return XG_EXIT_FAIL;
        r.streams.push_back(s);
    }
    r.dev_bytes = o.ring ? xg_ring_bytes(&o.g) : o.g.window;
    if (o.ring) r.dev_busy.assign(o.g.qd, 0);
    if (!cuda_ok(cudaMalloc(&r.dev, r.dev_bytes), "device buffer")) return XG_EXIT_FAIL;
    /* A multiple of size no larger than kCheckChunk (size <= 4 MiB). */
    r.check_bytes = o.g.window < kCheckChunk ? o.g.window : kCheckChunk / o.g.size * o.g.size;
    if (posix_memalign(reinterpret_cast<void **>(&r.check), 4096, r.check_bytes))
        return XG_EXIT_FAIL;
    /* The source holds the payload once; every pass reads the same bytes. */
    if (fill_window(r, o.direction == XG_SAVE, o.g.seed)) return XG_EXIT_FAIL;

    uint64_t io_ns = 0, cpu = 0, busy = 0, verified = 0;
    for (uint64_t p = 0; p < o.g.passes; p++) {
        uint64_t span = 0;
        /* The destination starts every pass as the complemented-seed sentinel. */
        if (fill_window(r, o.direction == XG_LOAD, ~o.g.seed)) return XG_EXIT_FAIL;
        uint64_t c0 = cpu_us(), b0 = xg_host_busy_us();
        ret = pass(r, p, span);
        cpu += cpu_us() - c0;
        busy += xg_host_busy_us() - b0;
        if (ret) {
            std::fprintf(stderr, "pass %llu: %s\n", (unsigned long long)p, std::strerror(-ret));
            return XG_EXIT_FAIL;
        }
        if (!cuda_ok(cudaDeviceSynchronize(), "drain") || verify_window(r, p)) return XG_EXIT_FAIL;
        io_ns += span;
        verified += o.ring && o.direction == XG_LOAD ? r.dev_bytes : o.g.window;
    }
    const uint64_t nvme_ns = r.nvme_ns, copy_ns = r.copy_ns;
    if (!r.close()) return XG_EXIT_FAIL;
    std::printf("{\"schema_version\":1,\"arm\":\"uring-cuda\",\"direction\":\"%s\","
        "\"route\":\"%s\",\"execution\":\"physical-cuda\",\"performance_claim\":\"physical\","
        "\"destination\":\"%s\",\"completion_wait\":\"%s\","
        "\"size\":%llu,\"qd\":%llu,\"pattern\":\"%s\",\"window_bytes\":%llu,\"passes\":%llu,"
        "\"streams\":%llu,\"staging_slots\":%llu,\"operations\":%llu,\"io_bytes\":%llu,"
        "\"verified_bytes\":%llu,\"oracle\":\"%s\",\"io_ns\":%llu,\"cpu_us\":%llu,"
        "\"host_busy_us\":%llu,\"nvme_stage_ns\":%llu,\"copy_stage_ns\":%llu,\"status\":\"pass\"}\n",
        o.direction == XG_LOAD ? "load" : "save",
        o.direction == XG_LOAD ? "nvme-read-fixed>registered-host>cuda-h2d-async"
                               : "cuda-d2h-async>registered-host>nvme-write-fixed",
        o.ring ? "slot-ring" : "window", o.block ? "block" : "poll",
        (unsigned long long)o.g.size, (unsigned long long)o.g.qd,
        o.g.pattern == XG_SEQ ? "seq" : "rand", (unsigned long long)o.g.window,
        (unsigned long long)o.g.passes, (unsigned long long)o.streams,
        (unsigned long long)nslots, (unsigned long long)(xg_blocks(&o.g) * o.g.passes),
        (unsigned long long)(o.g.window * o.g.passes), (unsigned long long)verified,
        o.direction == XG_LOAD ? (o.ring ? "device-slot-ring-readback" : "device-window-readback")
                               : (o.ring ? "file-window-slot-images" : "file-window-readback"),
        (unsigned long long)io_ns, (unsigned long long)cpu, (unsigned long long)busy,
        (unsigned long long)nvme_ns,
        (unsigned long long)copy_ns);
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
