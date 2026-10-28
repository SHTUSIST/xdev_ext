/* SPDX-License-Identifier: GPL-2.0-only
 * udp_pinned_cuda - the pinned-socket baseline of the GPU<->NIC comparison.
 *
 * An ordinary UDP socket whose datagrams land in, or leave from, CUDA pinned
 * host buffers (cudaHostAlloc, allocated once); copies run on --streams CUDA
 * streams and complete by events.  The kernel socket copies each payload
 * between its skb and the pinned buffer; the GPU copy engine moves it
 * between the pinned buffer and the device slot.
 *
 *   ingest  recvmmsg scatters each datagram into [its 40-byte header
 *           buffer, its payload at the segment's offset in the pinned group
 *           buffer of slot g mod depth]; NXP parse, protocol CRC and strict
 *           segment order; one cudaMemcpyAsync H2D of the whole group into
 *           device slot g mod depth.
 *   egress  one cudaMemcpyAsync D2H of slot g mod depth into its pinned
 *           group buffer; after the event, NXP headers and CRC, sendmmsg
 *           gathers [header, payload at its offset] per datagram.
 *
 * So each group costs one copy call in each direction (copies_per_group 1).
 * --completion-wait block (default) sleeps in poll() for datagrams and in
 * cudaEventSynchronize on cudaEventBlockingSync events for copies; poll
 * spins with MSG_DONTWAIT and cudaEventQuery, so its CPU fields are no
 * CPU-cost data.
 *
 * Same NXP wire, group plan, slot placement, seeding and oracle as the
 * session arm (gpu_nic_core.h); the peer is nxp_peer.  Ingest is timed from
 * READY (stderr) to the last group's event; egress from the first copy to
 * the last sendmmsg.  After ingest the device slots are read back once.
 * Exit: 0 verified, 1 failure, 2 usage, 4 unavailable capability.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cuda_runtime_api.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <net/if.h>
#include <new>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#include "gpu_nic_core.h"

namespace {

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

struct Options {
    bool ingest = false, block = true;   /* --completion-wait block */
    const char *ifname = nullptr;
    uint64_t size = 0, messages = 0, depth = 0, window_groups = 0, wire = 0, streams = 2,
             seed = 1, timeout_ms = 60000;
    sockaddr_in local{}, remote{};
};

void usage(FILE *f)
{
    std::fprintf(f,
        "usage: udp_pinned_cuda --direction ingest|egress --ifname IF --size N --messages N\n"
        "         --depth N [--window-groups N] --wire-session N --local-ip A --local-port P\n"
        "         --peer-ip A --peer-port P [--streams N] [--seed N] [--timeout-ms N]\n"
        "         [--completion-wait block|poll]\n");
}

int parse(int argc, char **argv, Options &o)
{
    enum { O_DIR = 1, O_IF, O_SIZE, O_MSG, O_DEPTH, O_WIN, O_WIRE, O_LIP, O_LPORT, O_PIP,
           O_PPORT, O_STREAMS, O_SEED, O_TMO, O_WAIT, O_HELP };
    static const option opts[] = {
        {"direction", required_argument, nullptr, O_DIR},
        {"ifname", required_argument, nullptr, O_IF},
        {"size", required_argument, nullptr, O_SIZE},
        {"messages", required_argument, nullptr, O_MSG},
        {"depth", required_argument, nullptr, O_DEPTH},
        {"window-groups", required_argument, nullptr, O_WIN},
        {"wire-session", required_argument, nullptr, O_WIRE},
        {"local-ip", required_argument, nullptr, O_LIP},
        {"local-port", required_argument, nullptr, O_LPORT},
        {"peer-ip", required_argument, nullptr, O_PIP},
        {"peer-port", required_argument, nullptr, O_PPORT},
        {"streams", required_argument, nullptr, O_STREAMS},
        {"seed", required_argument, nullptr, O_SEED},
        {"timeout-ms", required_argument, nullptr, O_TMO},
        {"completion-wait", required_argument, nullptr, O_WAIT},
        {"help", no_argument, nullptr, O_HELP},
        {nullptr, 0, nullptr, 0},
    };
    unsigned have = 0;
    bool have_dir = false;
    int c, bad = 0;

    o.local.sin_family = o.remote.sin_family = AF_INET;
    opterr = 0;
    while ((c = getopt_long(argc, argv, "", opts, nullptr)) != -1) {
        switch (c) {
        case O_DIR:
            have_dir = true;
            if (!std::strcmp(optarg, "ingest")) o.ingest = true;
            else if (std::strcmp(optarg, "egress")) bad = 1;
            break;
        case O_IF: o.ifname = optarg; break;
        case O_SIZE: bad |= xg_parse_u64(optarg, GN_MAX_SIZE, &o.size); break;
        case O_MSG: bad |= xg_parse_u64(optarg, GN_MAX_MESSAGES, &o.messages); break;
        case O_DEPTH: bad |= xg_parse_u64(optarg, GN_MAX_DEPTH, &o.depth); break;
        case O_WIN: bad |= xg_parse_u64(optarg, GN_MAX_MESSAGES, &o.window_groups); break;
        case O_WIRE: bad |= xg_parse_u64(optarg, UINT64_MAX, &o.wire); break;
        case O_LIP: bad |= gn_parse_ip(optarg, &o.local.sin_addr.s_addr); have |= 1; break;
        case O_LPORT: bad |= gn_parse_port(optarg, &o.local.sin_port); have |= 2; break;
        case O_PIP: bad |= gn_parse_ip(optarg, &o.remote.sin_addr.s_addr); have |= 4; break;
        case O_PPORT: bad |= gn_parse_port(optarg, &o.remote.sin_port); have |= 8; break;
        case O_STREAMS: bad |= xg_parse_u64(optarg, XG_MAX_STREAMS, &o.streams); break;
        case O_SEED: bad |= xg_parse_u64(optarg, UINT32_MAX, &o.seed); break;
        case O_TMO: bad |= xg_parse_u64(optarg, 3600000, &o.timeout_ms); break;
        case O_WAIT:
            if (!std::strcmp(optarg, "block")) o.block = true;
            else if (!std::strcmp(optarg, "poll")) o.block = false;
            else bad = 1;
            break;
        case O_HELP: usage(stdout); std::exit(0);
        default: bad = 1; break;
        }
    }
    if (!o.window_groups) o.window_groups = o.depth;
    if (bad || optind != argc || !have_dir || !o.ifname || !o.size || !o.messages || !o.depth ||
        !o.wire || have != 15 || !o.streams || !o.timeout_ms ||
        (!o.ingest && o.window_groups != o.depth))
        return XG_EXIT_USAGE;
    return XG_EXIT_PASS;
}

struct Slot {
    cudaEvent_t done = nullptr;
    bool busy = false, copied = false;   /* copied: the group's copy was issued */
    uint64_t group = 0;
};

struct Run {
    Options o;
    gn_plan p{};
    int fd = -1;
    unsigned char *pinned = nullptr;   /* depth group buffers, then the header buffers */
    unsigned char *headers = nullptr;  /* depth * frames NXP headers of kHeader bytes */
    uint64_t copy_calls = 0;
    void *dev = nullptr;
    std::vector<cudaStream_t> streams;
    std::vector<Slot> slots;

    bool close()
    {
        bool ok = true;
        if (!slots.empty() && !cuda_ok(cudaDeviceSynchronize(), "final drain")) ok = false;
        for (auto &s : slots)
            if (s.done && !cuda_ok(cudaEventDestroy(s.done), "event destroy")) ok = false;
        slots.clear();
        for (auto s : streams)
            if (!cuda_ok(cudaStreamDestroy(s), "stream destroy")) ok = false;
        streams.clear();
        if (pinned && !cuda_ok(cudaFreeHost(pinned), "free pinned")) ok = false;
        pinned = nullptr;
        if (dev && !cuda_ok(cudaFree(dev), "free")) ok = false;
        dev = nullptr;
        if (fd >= 0 && ::close(fd)) ok = false;
        fd = -1;
        return ok;
    }
    ~Run() { close(); }
};

constexpr size_t kHeader = 64;          /* one 40-byte NXP header, cache-line spaced */

unsigned char *group_buffer(Run &r, uint64_t slot)
{
    return r.pinned + slot * r.p.l.group_bytes;
}

unsigned char *header(Run &r, uint64_t slot, uint32_t i)
{
    return r.headers + (slot * r.p.frames + i) * kHeader;
}

cudaStream_t stream_of(Run &r, uint64_t slot) { return r.streams[slot % r.streams.size()]; }

/* Block mode: sleep until @fd is readable or @deadline. */
void wait_readable(int fd, uint64_t deadline)
{
    uint64_t now = now_ns();
    if (now >= deadline) return;
    pollfd pfd{fd, POLLIN, 0};
    uint64_t ms = (deadline - now) / 1000000ULL + 1;
    (void)poll(&pfd, 1, ms > 1000 ? 1000 : int(ms));
}

/* A finished copy frees its slot; @block waits for it.  -1, 0 pending, 1 done. */
int slot_finish(Slot &s, bool block)
{
    if (!s.busy || !s.copied) return 0;
    cudaError_t e = block ? cudaEventSynchronize(s.done) : cudaEventQuery(s.done);
    if (e == cudaErrorNotReady) return 0;
    if (!cuda_ok(e, "group event")) return -1;
    s.busy = s.copied = false;
    return 1;
}

int ingest(Run &r, uint64_t &io_ns)
{
    const gn_plan &p = r.p;
    uint64_t g = 0, completed = 0, t0 = now_ns(), t1 = 0;
    uint64_t deadline = t0 + r.o.timeout_ms * 1000000ULL;
    uint32_t i = 0;
    mmsghdr msg[64];
    iovec iov[2 * 64];

    std::fprintf(stderr, "XDEV_EVAL_READY direction=ingest arm=udp-pinned-cuda groups=%llu group_bytes=%u\n",
                 (unsigned long long)p.groups, p.l.group_bytes);
    while (completed < p.groups) {
        for (auto &s : r.slots) {
            int done = slot_finish(s, false);
            if (done < 0) return -EIO;
            if (done && ++completed == p.groups) t1 = now_ns();
        }
        if (now_ns() >= deadline) {
            std::fprintf(stderr, "timeout after %llu of %llu groups\n",
                         (unsigned long long)completed, (unsigned long long)p.groups);
            return -ETIMEDOUT;
        }
        if (g == p.groups) {
            /* Everything arrived; block mode sleeps on the oldest pending copy. */
            Slot *oldest = nullptr;
            for (auto &s : r.slots)
                if (s.busy && s.copied && (!oldest || s.group < oldest->group)) oldest = &s;
            if (r.o.block && oldest) {
                int done = slot_finish(*oldest, true);
                if (done < 0) return -EIO;
                if (done && ++completed == p.groups) t1 = now_ns();
            }
            continue;
        }
        const uint64_t slot = g % p.depth;
        Slot &s = r.slots[slot];
        if (!i) {
            /* The slot's buffer and device bytes are free once its copy finished. */
            if (s.busy) {
                int done = slot_finish(s, true);
                if (done <= 0) return -EIO;
                if (++completed == p.groups) t1 = now_ns();
            }
            s.group = g;
            s.busy = true;
        }
        /* Receive at most the rest of this group: header buffer, payload in place. */
        unsigned want = p.frames - i < 64 ? p.frames - i : 64;
        for (unsigned k = 0; k < want; k++) {
            uint32_t off, len;
            gn_segment(&p, i + k, &off, &len);
            iov[2 * k] = iovec{header(r, slot, i + k), XDEV_EXT_MP_NXP_LEN};
            iov[2 * k + 1] = iovec{group_buffer(r, slot) + off, len};
            std::memset(&msg[k], 0, sizeof(msg[k]));
            msg[k].msg_hdr.msg_iov = &iov[2 * k];
            msg[k].msg_hdr.msg_iovlen = 2;
        }
        int n = recvmmsg(r.fd, msg, want, MSG_DONTWAIT, nullptr);
        if (n < 0 && errno == EAGAIN) {
            if (r.o.block) wait_readable(r.fd, deadline);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -errno;
        for (int k = 0; k < n; k++, i++) {
            unsigned char *nxp = header(r, slot, i);
            const unsigned char *payload = static_cast<const unsigned char *>(iov[2 * k + 1].iov_base);
            xdev_ext_mp_segment seg;
            /* A longer datagram than this segment's is truncated: never accepted. */
            if ((msg[k].msg_hdr.msg_flags & MSG_TRUNC) ||
                gn_nxp_parse(nxp, msg[k].msg_len, &p, r.o.wire, &seg) ||
                seg.generation != g + 1 || seg.index != i ||
                gn_nxp_crc(nxp, payload, seg.payload_len) !=
                    xdev_ext_mp_get_be32(nxp + XDEV_EXT_MP_NXP_CSUM_OFF)) {
                std::fprintf(stderr, "segment %u of group %llu missing, reordered or corrupt\n",
                             i, (unsigned long long)g);
                return -EBADMSG;
            }
        }
        if (i == p.frames) {
            char *dst = static_cast<char *>(r.dev) + slot * p.l.group_bytes;
            if (!cuda_ok(cudaMemcpyAsync(dst, group_buffer(r, slot), p.l.group_bytes,
                                         cudaMemcpyHostToDevice, stream_of(r, slot)), "group H2D") ||
                !cuda_ok(cudaEventRecord(s.done, stream_of(r, slot)), "event record"))
                return -EIO;
            r.copy_calls++;
            s.copied = true;
            i = 0;
            g++;
        }
    }
    if (!t1 || t1 <= t0) return -EIO;
    io_ns = t1 - t0;
    return 0;
}

int egress(Run &r, uint64_t &io_ns)
{
    const gn_plan &p = r.p;
    uint64_t next = 0, sent = 0, t0 = now_ns(), deadline = t0 + r.o.timeout_ms * 1000000ULL;
    std::vector<uint64_t> fifo;
    std::vector<mmsghdr> msg(p.frames);
    std::vector<iovec> iov(2 * p.frames);

    while (sent < p.groups) {
        while (next < p.groups && fifo.size() < p.depth) {
            uint64_t slot = next % p.depth;
            Slot &s = r.slots[slot];
            if (s.busy) break;
            if (!cuda_ok(cudaMemcpyAsync(group_buffer(r, slot),
                                         static_cast<const char *>(r.dev) + slot * p.l.group_bytes,
                                         p.l.group_bytes, cudaMemcpyDeviceToHost, stream_of(r, slot)),
                         "group D2H") ||
                !cuda_ok(cudaEventRecord(s.done, stream_of(r, slot)), "event record"))
                return -EIO;
            r.copy_calls++;
            s.busy = true;
            s.group = next;
            fifo.push_back(next++);
        }
        if (fifo.empty()) continue;
        uint64_t slot = fifo.front() % p.depth;
        Slot &s = r.slots[slot];
        cudaError_t e = r.o.block ? cudaEventSynchronize(s.done) : cudaEventQuery(s.done);
        if (e == cudaErrorNotReady) {
            if (now_ns() >= deadline) return -ETIMEDOUT;
            continue;
        }
        if (!cuda_ok(e, "group event")) return -EIO;
        for (uint32_t i = 0; i < p.frames; i++) {
            uint32_t off, len;
            gn_segment(&p, i, &off, &len);
            unsigned char *nxp = header(r, slot, i);
            const unsigned char *payload = group_buffer(r, slot) + off;
            if (gn_nxp_header(nxp, &p, r.o.wire, s.group, i)) return -EINVAL;
            xdev_ext_mp_put_be32(nxp + XDEV_EXT_MP_NXP_CSUM_OFF, gn_nxp_crc(nxp, payload, len));
            iov[2 * i] = iovec{nxp, XDEV_EXT_MP_NXP_LEN};
            iov[2 * i + 1] = iovec{const_cast<unsigned char *>(payload), len};
            std::memset(&msg[i], 0, sizeof(msg[i]));
            msg[i].msg_hdr.msg_iov = &iov[2 * i];
            msg[i].msg_hdr.msg_iovlen = 2;
        }
        for (uint32_t done = 0; done < p.frames;) {
            int k = sendmmsg(r.fd, msg.data() + done, p.frames - done, 0);
            if (k < 0 && (errno == EINTR || errno == ENOBUFS || errno == EAGAIN)) continue;
            if (k <= 0) return k < 0 ? -errno : -EIO;
            done += uint32_t(k);
        }
        /* sendmmsg copied the payloads into skbs: the buffers are free. */
        s.busy = false;
        fifo.erase(fifo.begin());
        sent++;
        if (now_ns() >= deadline) return -ETIMEDOUT;
    }
    uint64_t t1 = now_ns();
    if (!t0 || t1 <= t0) return -EIO;
    io_ns = t1 - t0;
    return 0;
}

int execute(Run &r)
{
    Options &o = r.o;
    ifreq ifr{};
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return XG_EXIT_UNAVAILABLE;
    std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", o.ifname);
    int mtu_ok = ioctl(fd, SIOCGIFMTU, &ifr);
    ::close(fd);
    if (mtu_ok) {
        std::fprintf(stderr, "SKIP: %s: no MTU\n", o.ifname);
        return XG_EXIT_UNAVAILABLE;
    }
    if (gn_plan_init(&r.p, o.size, o.messages, uint32_t(ifr.ifr_mtu), uint32_t(o.depth),
                     o.window_groups))
        return XG_EXIT_USAGE;
    int count = 0;
    if (cudaGetDeviceCount(&count) != cudaSuccess || count < 1) {
        std::fprintf(stderr, "SKIP: no CUDA device available\n");
        return XG_EXIT_UNAVAILABLE;
    }
    if (!cuda_ok(cudaSetDevice(0), "select device")) return XG_EXIT_FAIL;
    r.fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int one = 1, rcvbuf = 64 << 20;
    if (r.fd < 0 || setsockopt(r.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
        bind(r.fd, reinterpret_cast<sockaddr *>(&o.local), sizeof(o.local)) ||
        connect(r.fd, reinterpret_cast<sockaddr *>(&o.remote), sizeof(o.remote))) {
        std::fprintf(stderr, "SKIP: UDP endpoint: %s\n", std::strerror(errno));
        return XG_EXIT_UNAVAILABLE;
    }
    /* A larger receive queue only; failure leaves the system default. */
    (void)setsockopt(r.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    const uint64_t window = uint64_t(r.p.depth) * r.p.l.group_bytes;
    /* One allocation: the group buffers, then the header buffers. */
    if (!cuda_ok(cudaHostAlloc(reinterpret_cast<void **>(&r.pinned),
                               window + uint64_t(r.p.depth) * r.p.frames * kHeader,
                               cudaHostAllocDefault),
                 "pinned buffers") ||
        !cuda_ok(cudaMalloc(&r.dev, window), "device slots"))
        return XG_EXIT_FAIL;
    r.headers = r.pinned + window;
    for (uint64_t i = 0; i < o.streams; i++) {
        cudaStream_t s;
        if (!cuda_ok(cudaStreamCreateWithFlags(&s, cudaStreamNonBlocking), "stream")) return XG_EXIT_FAIL;
        r.streams.push_back(s);
    }
    r.slots.resize(r.p.depth);
    for (auto &s : r.slots)
        if (!cuda_ok(cudaEventCreateWithFlags(&s.done, cudaEventDisableTiming |
                                              (o.block ? cudaEventBlockingSync : 0)), "event"))
            return XG_EXIT_FAIL;
    std::vector<unsigned char> host(window);
    for (uint64_t s = 0; s < r.p.depth; s++)
        xg_fill(host.data() + s * r.p.l.group_bytes, s * r.p.l.group_bytes, r.p.l.group_bytes,
                o.ingest ? ~uint32_t(o.seed) : uint32_t(o.seed));
    if (!cuda_ok(cudaMemcpy(r.dev, host.data(), window, cudaMemcpyHostToDevice), "seed"))
        return XG_EXIT_FAIL;
    uint64_t io_ns = 0, c0 = cpu_us(), b0 = xg_host_busy_us();
    int err = o.ingest ? ingest(r, io_ns) : egress(r, io_ns);
    uint64_t cpu = cpu_us() - c0, busy = xg_host_busy_us() - b0;
    if (err) {
        std::fprintf(stderr, "campaign failed: %s\n", std::strerror(-err));
        return XG_EXIT_FAIL;
    }
    uint64_t used = 0;
    if (o.ingest) {
        std::vector<unsigned char> seen(r.p.window_groups);
        if (!cuda_ok(cudaDeviceSynchronize(), "drain") ||
            !cuda_ok(cudaMemcpy(host.data(), r.dev, window, cudaMemcpyDeviceToHost), "readback"))
            return XG_EXIT_FAIL;
        err = gn_check_slots(host.data(), &r.p, uint32_t(o.seed), seen.data(), &used);
        if (err) {
            std::fprintf(stderr, "slot oracle failed: %s\n", std::strerror(-err));
            return XG_EXIT_FAIL;
        }
    }
    const uint64_t copy_calls = r.copy_calls;
    if (!r.close()) return XG_EXIT_FAIL;
    std::printf("{\"schema_version\":1,\"arm\":\"udp-pinned-cuda\",\"direction\":\"%s\",\"route\":\"%s\","
        "\"execution\":\"physical-cuda\",\"performance_claim\":\"physical\",\"size\":%llu,"
        "\"messages\":%llu,\"group_bytes\":%u,\"groups\":%llu,\"depth\":%u,\"mtu\":%u,"
        "\"streams\":%llu,\"io_bytes\":%llu,\"slots_used\":%llu,\"oracle\":\"%s\",\"io_ns\":%llu,"
        "\"cpu_us\":%llu,\"host_busy_us\":%llu,\"completion_wait\":\"%s\",\"seg_len\":%u,"
        "\"frames\":%u,\"copies_per_group\":%u,\"copy_calls\":%llu,\"fallback_groups\":0,"
        "\"status\":\"pass\"}\n",
        o.ingest ? "ingest" : "egress",
        o.ingest ? "udp-recvmmsg>pinned-host>cuda-h2d-async" : "cuda-d2h-async>pinned-host>udp-sendmmsg",
        (unsigned long long)r.p.size, (unsigned long long)r.p.messages, r.p.l.group_bytes,
        (unsigned long long)r.p.groups, r.p.depth, r.p.mtu, (unsigned long long)o.streams,
        (unsigned long long)(r.p.groups * r.p.l.group_bytes), (unsigned long long)used,
        o.ingest ? "device-slot-group-images" : "peer-receipt-required",
        (unsigned long long)io_ns, (unsigned long long)cpu, (unsigned long long)busy,
        o.block ? "block" : "poll", r.p.l.seg_len, r.p.frames, 1u,
        (unsigned long long)copy_calls);
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
    try {
        ret = execute(r);
    } catch (const std::bad_alloc &) {
        std::fprintf(stderr, "allocation failed\n");
        ret = XG_EXIT_FAIL;
    }
    if (!r.close() && ret == XG_EXIT_PASS) ret = XG_EXIT_FAIL;
    return ret;
}
