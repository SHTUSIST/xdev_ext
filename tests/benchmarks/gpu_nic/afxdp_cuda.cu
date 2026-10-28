/* SPDX-License-Identifier: GPL-2.0-only
 * afxdp_cuda - the strong AF_XDP baseline of the GPU<->NIC comparison.
 *
 * One AF_XDP socket with its own UMEM, registered with cudaHostRegister once,
 * so the GPU copy engine reads and writes the UMEM chunks directly; copies
 * run on --streams CUDA streams and complete by events.  No CPU payload copy.
 *
 *   ingest  RX ring -> the session's own NXP parse, CRC and group order
 *           (xdev_ext_mech_prog.h: xdev_ext_mp_rx_parse, xdev_ext_mp_rx_order)
 *           -> once the group is complete, H2D into device slot g mod depth:
 *           one cudaMemcpy2DAsync (pitch frame_size) of the full segments
 *           plus one copy of the short last segment when the payloads sit
 *           at one pitch in consecutive chunks, otherwise one
 *           cudaMemcpyAsync per segment (fallback_groups counts those)
 *           -> chunks back to the fill ring after the group's event.
 *   egress  slot s owns UMEM chunks [s*frames, (s+1)*frames): one
 *           cudaMemcpy2DAsync D2H of slot g mod depth into their payload
 *           areas plus the tail copy -> after the event, NXP headers and CRC
 *           (xdev_ext_mp_tx_encode) -> TX ring -> the slot is reused once
 *           all its frames completed.
 *
 * Copy calls per group (copies_per_group): gn_group_copy(), 1 or 2.
 * --completion-wait block (default) sleeps when nothing progressed: in
 * cudaEventSynchronize on cudaEventBlockingSync events, in poll() for RX
 * data, and, since AF_XDP has no TX-completion wakeup (xsk_poll reports only
 * RX data and TX ring room), in a kTxNapUs nap between completion-ring
 * checks.  poll spins; its CPU fields are no CPU-cost data.
 *
 * Same wire, layout, group plan, slot placement, seeding and oracle as the
 * session arm (gpu_nic_core.h), so ingest faces the same nxp_peer sender and
 * egress the same nxp_peer receiver.  Ingest is timed from READY (stderr) to
 * the last group's event; egress from the first copy to the last TX
 * completion.  After ingest the device slots are read back once and checked.
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
#include <linux/if_link.h>
#include <new>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <time.h>
#include <vector>

#include "../../../kernel/tools/include/xdev_ext_xsk_redirect.h"
#include "xsk_port.h"

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
    bool ingest = false, copy_mode = false, block = true;   /* --completion-wait block */
    const char *ifname = nullptr;
    uint64_t queue = 0, size = 0, messages = 0, depth = 0, window_groups = 0, wire = 0,
             streams = 2, seed = 1, timeout_ms = 60000;
    xdev_ext_mech_peer peer{};
};

void usage(FILE *f)
{
    std::fprintf(f,
        "usage: afxdp_cuda --direction ingest|egress --ifname IF [--queue N] [--copy-mode]\n"
        "         --size N --messages N --depth N [--window-groups N] --wire-session N\n"
        "         --local-ip A --peer-ip A --local-port P --peer-port P --peer-mac M\n"
        "         [--local-mac M] [--streams N] [--seed N] [--timeout-ms N]\n"
        "         [--completion-wait block|poll]\n");
}

int if_query(const char *ifname, unsigned long req, ifreq *ifr)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -errno;
    std::memset(ifr, 0, sizeof(*ifr));
    std::snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%s", ifname);
    int ret = ioctl(fd, req, ifr) ? -errno : 0;
    ::close(fd);
    return ret;
}

int parse(int argc, char **argv, Options &o)
{
    enum { O_DIR = 1, O_IF, O_QUEUE, O_COPY, O_SIZE, O_MSG, O_DEPTH, O_WIN, O_WIRE, O_LIP,
           O_PIP, O_LPORT, O_PPORT, O_PMAC, O_LMAC, O_STREAMS, O_SEED, O_TMO, O_WAIT, O_HELP };
    static const option opts[] = {
        {"direction", required_argument, nullptr, O_DIR},
        {"ifname", required_argument, nullptr, O_IF},
        {"queue", required_argument, nullptr, O_QUEUE},
        {"copy-mode", no_argument, nullptr, O_COPY},
        {"size", required_argument, nullptr, O_SIZE},
        {"messages", required_argument, nullptr, O_MSG},
        {"depth", required_argument, nullptr, O_DEPTH},
        {"window-groups", required_argument, nullptr, O_WIN},
        {"wire-session", required_argument, nullptr, O_WIRE},
        {"local-ip", required_argument, nullptr, O_LIP},
        {"peer-ip", required_argument, nullptr, O_PIP},
        {"local-port", required_argument, nullptr, O_LPORT},
        {"peer-port", required_argument, nullptr, O_PPORT},
        {"peer-mac", required_argument, nullptr, O_PMAC},
        {"local-mac", required_argument, nullptr, O_LMAC},
        {"streams", required_argument, nullptr, O_STREAMS},
        {"seed", required_argument, nullptr, O_SEED},
        {"timeout-ms", required_argument, nullptr, O_TMO},
        {"completion-wait", required_argument, nullptr, O_WAIT},
        {"help", no_argument, nullptr, O_HELP},
        {nullptr, 0, nullptr, 0},
    };
    unsigned have = 0;
    bool have_dir = false, have_lmac = false;
    int c, bad = 0;

    opterr = 0;
    while ((c = getopt_long(argc, argv, "", opts, nullptr)) != -1) {
        switch (c) {
        case O_DIR:
            have_dir = true;
            if (!std::strcmp(optarg, "ingest")) o.ingest = true;
            else if (std::strcmp(optarg, "egress")) bad = 1;
            break;
        case O_IF: o.ifname = optarg; break;
        case O_QUEUE: bad |= xg_parse_u64(optarg, 4095, &o.queue); break;
        case O_COPY: o.copy_mode = true; break;
        case O_SIZE: bad |= xg_parse_u64(optarg, GN_MAX_SIZE, &o.size); break;
        case O_MSG: bad |= xg_parse_u64(optarg, GN_MAX_MESSAGES, &o.messages); break;
        case O_DEPTH: bad |= xg_parse_u64(optarg, GN_MAX_DEPTH, &o.depth); break;
        case O_WIN: bad |= xg_parse_u64(optarg, GN_MAX_MESSAGES, &o.window_groups); break;
        case O_WIRE: bad |= xg_parse_u64(optarg, UINT64_MAX, &o.wire); break;
        case O_LIP: bad |= gn_parse_ip(optarg, &o.peer.local_ip); have |= 1; break;
        case O_PIP: bad |= gn_parse_ip(optarg, &o.peer.peer_ip); have |= 2; break;
        case O_LPORT: bad |= gn_parse_port(optarg, &o.peer.local_port); have |= 4; break;
        case O_PPORT: bad |= gn_parse_port(optarg, &o.peer.peer_port); have |= 8; break;
        case O_PMAC: bad |= xdev_ext_mech_ctl_parse_mac(optarg, o.peer.peer_mac); have |= 16; break;
        case O_LMAC: bad |= xdev_ext_mech_ctl_parse_mac(optarg, o.peer.local_mac); have_lmac = true; break;
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
        !o.wire || have != 31 || !o.streams || !o.timeout_ms ||
        (!o.ingest && o.window_groups != o.depth))
        return XG_EXIT_USAGE;
    if (!have_lmac) {
        ifreq ifr;
        if (if_query(o.ifname, SIOCGIFHWADDR, &ifr)) {
            std::fprintf(stderr, "SKIP: %s has no hardware address\n", o.ifname);
            return XG_EXIT_UNAVAILABLE;
        }
        std::memcpy(o.peer.local_mac, ifr.ifr_hwaddr.sa_data, 6);
    }
    return XG_EXIT_PASS;
}

struct Slot {
    cudaEvent_t done = nullptr;
    bool busy = false;              /* copies of a group pending */
    uint64_t group = 0;
    std::vector<uint64_t> chunks;   /* UMEM chunk addresses the group uses */
    std::vector<uint64_t> payload;  /* ingest: UMEM address of each segment's payload */
    uint32_t tx_outstanding = 0;    /* egress: frames on the TX ring not yet completed */
};

struct Run {
    Options o;
    gn_plan p{};
    xp_sock x{};
    xdev_ext_xsk_redirect redirect = XDEV_EXT_XSK_REDIRECT_INIT;
    bool registered = false;
    void *dev = nullptr;
    std::vector<cudaStream_t> streams;
    std::vector<Slot> slots;
    uint64_t copy_calls = 0, fallback_groups = 0;

    Run() { x.fd = -1; }
    bool close()
    {
        bool ok = true;
        if (xdev_ext_xsk_redirect_is_active(&redirect)) xdev_ext_xsk_redirect_detach(&redirect);
        if (!slots.empty() && !cuda_ok(cudaDeviceSynchronize(), "final drain")) ok = false;
        for (auto &s : slots)
            if (s.done && !cuda_ok(cudaEventDestroy(s.done), "event destroy")) ok = false;
        slots.clear();
        for (auto s : streams)
            if (!cuda_ok(cudaStreamDestroy(s), "stream destroy")) ok = false;
        streams.clear();
        if (registered && !cuda_ok(cudaHostUnregister(x.umem), "UMEM unregister")) ok = false;
        registered = false;
        if (dev && !cuda_ok(cudaFree(dev), "free")) ok = false;
        dev = nullptr;
        xp_close(&x);
        return ok;
    }
    ~Run() { close(); }
};

cudaStream_t stream_of(Run &r, uint64_t slot) { return r.streams[slot % r.streams.size()]; }

constexpr long kTxNapUs = 50;   /* block mode: pause between TX completion-ring checks */

/*
 * One group between device slot memory @dev and host memory where segment i
 * starts at @host + i*@pitch: gn_group_copy()'s 2D copy of the full
 * segments and its tail copy.  The copy calls issued, or -1.
 */
int copy_group(const gn_plan &p, char *dev, unsigned char *host, size_t pitch, bool to_device,
               cudaStream_t st)
{
    struct gn_group_copy c = gn_group_copy(&p);
    cudaMemcpyKind kind = to_device ? cudaMemcpyHostToDevice : cudaMemcpyDeviceToHost;
    if (c.rows) {
        cudaError_t e = to_device ?
            cudaMemcpy2DAsync(dev, c.width, host, pitch, c.width, c.rows, kind, st) :
            cudaMemcpy2DAsync(host, pitch, dev, c.width, c.width, c.rows, kind, st);
        if (!cuda_ok(e, "group 2D copy")) return -1;
    }
    if (c.tail) {
        char *d = dev + size_t(c.rows) * c.width;
        unsigned char *h = host + size_t(c.rows) * pitch;
        cudaError_t e = to_device ? cudaMemcpyAsync(d, h, c.tail, kind, st)
                                  : cudaMemcpyAsync(h, d, c.tail, kind, st);
        if (!cuda_ok(e, "group tail copy")) return -1;
    }
    return int(c.calls);
}

/*
 * Ingest: a slot's group is finished once all its segments were issued and
 * its event fired; its chunks go back to the fill ring.  @block waits.
 * Returns -1 on a CUDA error, 1 when finished, 0 when still pending.
 */
int ingest_finish(Slot &s, uint32_t frames, bool block, std::vector<uint64_t> &recycle)
{
    if (!s.busy || s.chunks.size() != frames) return 0;
    cudaError_t e = block ? cudaEventSynchronize(s.done) : cudaEventQuery(s.done);
    if (e == cudaErrorNotReady) return 0;
    if (!cuda_ok(e, "group event")) return -1;
    s.busy = false;
    recycle.insert(recycle.end(), s.chunks.begin(), s.chunks.end());
    s.chunks.clear();
    s.payload.clear();
    return 1;
}

/* A complete group lands in its device slot: one 2D copy, or per segment. */
int ingest_copy(Run &r, Slot &s, uint64_t slot)
{
    const gn_plan &p = r.p;
    char *dst = static_cast<char *>(r.dev) + slot * p.l.group_bytes;
    cudaStream_t st = stream_of(r, slot);
    if (gn_chunks_strided(s.payload.data(), p.frames, r.x.frame_size)) {
        int calls = copy_group(p, dst, r.x.umem + s.payload[0], r.x.frame_size, true, st);
        if (calls < 0) return -EIO;
        r.copy_calls += unsigned(calls);
    } else {
        /* The NIC filled chunks out of pitch: one copy per segment. */
        for (uint32_t i = 0; i < p.frames; i++) {
            uint32_t off, len;
            gn_segment(&p, i, &off, &len);
            if (!cuda_ok(cudaMemcpyAsync(dst + off, r.x.umem + s.payload[i], len,
                                         cudaMemcpyHostToDevice, st), "segment H2D"))
                return -EIO;
        }
        r.copy_calls += p.frames;
        r.fallback_groups++;
    }
    return cuda_ok(cudaEventRecord(s.done, st), "event record") ? 0 : -EIO;
}

/* Block mode: sleep until the xsk has RX data or @deadline (at most 1 s). */
void wait_rx(Run &r, uint64_t deadline)
{
    uint64_t now = now_ns();
    if (now >= deadline) return;
    pollfd pfd{r.x.fd, POLLIN, 0};
    uint64_t ms = (deadline - now) / 1000000ULL + 1;
    (void)poll(&pfd, 1, ms > 1000 ? 1000 : int(ms));
}

int ingest(Run &r, uint64_t &io_ns)
{
    const gn_plan &p = r.p;
    xdev_ext_mp_rx_cfg cfg{};
    cfg.session_id = r.o.wire;
    cfg.mtu = p.mtu;
    cfg.frame_size = r.x.frame_size;
    cfg.hdr_room = p.l.hdr_room;
    cfg.seg_len = p.l.seg_len;
    cfg.group_bytes = p.l.group_bytes;
    struct xdev_ext_mp_rx_order order{};
    xdev_ext_mp_rx_order_session(&order, 1);
    std::vector<uint64_t> recycle;
    uint64_t completed = 0, issued_groups = 0;
    uint64_t t0 = now_ns(), deadline = t0 + r.o.timeout_ms * 1000000ULL, t1 = 0;

    std::fprintf(stderr, "XDEV_EVAL_READY direction=ingest arm=afxdp-cuda groups=%llu group_bytes=%u xsk=%s\n",
                 (unsigned long long)p.groups, p.l.group_bytes, r.x.zero_copy ? "zc" : "copy");
    while (completed < p.groups) {
        bool progress = false;
        uint32_t cons = *r.x.rx.consumer;
        uint32_t prod = __atomic_load_n(r.x.rx.producer, __ATOMIC_ACQUIRE);
        for (; cons != prod; cons++) {
            const xdp_desc *d = &static_cast<xdp_desc *>(r.x.rx.descs)[cons & r.x.rx.mask];
            uint64_t chunk = d->addr & ~uint64_t(r.x.frame_size - 1);
            uint32_t data_off = uint32_t(d->addr - chunk);
            const unsigned char *pkt = r.x.umem + d->addr;
            xdev_ext_mp_segment seg;
            progress = true;
            if (xdev_ext_mp_rx_parse(pkt, data_off, d->len, &r.o.peer, &cfg, &seg) !=
                XDEV_EXT_MP_RX_SEGMENT) {
                recycle.push_back(chunk);
                continue;
            }
            const unsigned char *payload = r.x.umem + chunk + seg.payload_off;
            if (gn_nxp_crc(pkt + XDEV_EXT_MP_NXP_OFF, payload, seg.payload_len) !=
                    xdev_ext_mp_get_be32(pkt + XDEV_EXT_MP_NXP_OFF + XDEV_EXT_MP_NXP_CSUM_OFF) ||
                xdev_ext_mp_rx_order(&order, &seg, now_ns()) != XDEV_EXT_MP_HOLD) {
                std::fprintf(stderr, "NXP segment failed CRC or group order (generation %u)\n",
                             seg.generation);
                return -EBADMSG;
            }
            uint64_t g = uint64_t(seg.generation) - 1, slot = g % p.depth;
            Slot &s = r.slots[slot];
            if (!seg.index) {
                /* The slot's previous group must finish before this one lands. */
                int done = ingest_finish(s, p.frames, true, recycle);
                if (done < 0) return -EIO;
                if (done && ++completed == p.groups) t1 = now_ns();
                if (s.busy) return -EPROTO;
                s.group = g;
                s.busy = true;
            }
            s.chunks.push_back(chunk);
            s.payload.push_back(chunk + seg.payload_off);
            if (seg.index + 1u == seg.count) {
                if (ingest_copy(r, s, slot)) return -EIO;
                issued_groups++;
            }
        }
        __atomic_store_n(r.x.rx.consumer, cons, __ATOMIC_RELEASE);
        /* Finished groups give their chunks back. */
        for (auto &s : r.slots) {
            int done = ingest_finish(s, p.frames, false, recycle);
            if (done < 0) return -EIO;
            if (done) progress = true;
            if (done && ++completed == p.groups) t1 = now_ns();
        }
        if (!recycle.empty()) {
            uint32_t n = xp_fq_push(&r.x.fq, recycle.data(), uint32_t(recycle.size()));
            recycle.erase(recycle.begin(), recycle.begin() + n);
        }
        if (now_ns() >= deadline) {
            std::fprintf(stderr, "timeout after %llu of %llu groups (%llu issued)\n",
                         (unsigned long long)completed, (unsigned long long)p.groups,
                         (unsigned long long)issued_groups);
            return -ETIMEDOUT;
        }
        if (!progress && r.o.block && completed < p.groups) {
            /* A received group's copy frees chunks for the fill ring: wait on it first. */
            Slot *oldest = nullptr;
            for (auto &s : r.slots)
                if (s.busy && s.chunks.size() == p.frames && (!oldest || s.group < oldest->group))
                    oldest = &s;
            if (oldest) {
                int done = ingest_finish(*oldest, p.frames, true, recycle);
                if (done < 0) return -EIO;
                if (done && ++completed == p.groups) t1 = now_ns();
            } else {
                wait_rx(r, deadline);
            }
        }
    }
    if (!t1 || t1 <= t0) return -EIO;
    io_ns = t1 - t0;
    return 0;
}

/* Reap TX completions: each returns a frame of the slot that owns its chunk. */
bool tx_reap(Run &r, uint64_t &completed_frames)
{
    uint32_t cons = *r.x.cq.consumer;
    uint32_t prod = __atomic_load_n(r.x.cq.producer, __ATOMIC_ACQUIRE);
    bool any = cons != prod;
    for (; cons != prod; cons++) {
        uint64_t addr = static_cast<uint64_t *>(r.x.cq.descs)[cons & r.x.cq.mask];
        uint64_t slot = addr / r.x.frame_size / r.p.frames;
        if (slot < r.slots.size() && r.slots[slot].tx_outstanding)
            r.slots[slot].tx_outstanding--;
        completed_frames++;
    }
    __atomic_store_n(r.x.cq.consumer, cons, __ATOMIC_RELEASE);
    return any;
}

int egress(Run &r, uint64_t &io_ns)
{
    const gn_plan &p = r.p;
    const uint64_t total_frames = p.groups * p.frames;
    uint64_t next = 0, sent_groups = 0, completed_frames = 0;
    std::vector<uint64_t> fifo;  /* groups whose copies are queued, in generation order */
    uint64_t t0 = now_ns(), deadline = t0 + r.o.timeout_ms * 1000000ULL;

    while (completed_frames < total_frames) {
        bool progress = tx_reap(r, completed_frames);
        /* Queue the copy of the next group once its slot's frames all completed. */
        while (next < p.groups && fifo.size() < p.depth) {
            const uint64_t slot = next % p.depth;
            Slot &s = r.slots[slot];
            if (s.busy || s.tx_outstanding) break;
            s.group = next;
            s.busy = true;
            const uint64_t base = slot * p.frames * r.x.frame_size;
            int calls = copy_group(p, static_cast<char *>(r.dev) + slot * p.l.group_bytes,
                                   r.x.umem + base + p.l.hdr_room, r.x.frame_size, false,
                                   stream_of(r, slot));
            if (calls < 0) return -EIO;
            r.copy_calls += unsigned(calls);
            if (!cuda_ok(cudaEventRecord(s.done, stream_of(r, slot)), "event record")) return -EIO;
            fifo.push_back(next++);
            progress = true;
        }
        /* Transmit, strictly in generation order, groups whose copies finished. */
        while (!fifo.empty()) {
            const uint64_t slot = fifo.front() % p.depth;
            Slot &s = r.slots[slot];
            cudaError_t e = cudaEventQuery(s.done);
            if (e == cudaErrorNotReady) break;
            if (!cuda_ok(e, "event query")) return -EIO;
            uint32_t prod = *r.x.tx.producer;
            uint32_t cons = __atomic_load_n(r.x.tx.consumer, __ATOMIC_ACQUIRE);
            if (r.x.tx.mask + 1 - (prod - cons) < p.frames) break;
            const uint64_t base = slot * p.frames * r.x.frame_size;
            for (uint32_t i = 0; i < p.frames; i++) {
                uint32_t off, len;
                gn_segment(&p, i, &off, &len);
                const uint64_t chunk = base + uint64_t(i) * r.x.frame_size;
                unsigned char *pkt = r.x.umem + chunk + p.l.hdr_room - XDEV_EXT_MP_PKT_HDR_LEN;
                xdev_ext_mp_tx_seg seg{};
                seg.session_id = r.o.wire;
                seg.generation = uint32_t(s.group + 1);
                seg.total_len = p.l.group_bytes;
                seg.relative_offset = off;
                seg.payload_len = len;
                seg.index = uint16_t(i);
                seg.count = uint16_t(p.frames);
                if (xdev_ext_mp_tx_encode(pkt, &r.o.peer, &seg)) return -EINVAL;
                xdev_ext_mp_put_be16(pkt + XDEV_EXT_MP_ETH_LEN + 10,
                                xdev_ext_mp_ip_csum(pkt + XDEV_EXT_MP_ETH_LEN));
                xdev_ext_mp_put_be32(pkt + XDEV_EXT_MP_NXP_OFF + XDEV_EXT_MP_NXP_CSUM_OFF,
                                gn_nxp_crc(pkt + XDEV_EXT_MP_NXP_OFF, pkt + XDEV_EXT_MP_PKT_HDR_LEN, len));
                xdp_desc *d = &static_cast<xdp_desc *>(r.x.tx.descs)[(prod + i) & r.x.tx.mask];
                xdev_ext_mp_tx_desc(d, chunk, p.l.hdr_room, len);
            }
            __atomic_store_n(r.x.tx.producer, prod + p.frames, __ATOMIC_RELEASE);
            if (sendto(r.x.fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0) < 0 &&
                errno != EAGAIN && errno != EBUSY && errno != ENOBUFS)
                return -errno;
            /* The slot is reused once its frames come back on the completion ring. */
            s.tx_outstanding = p.frames;
            s.busy = false;
            fifo.erase(fifo.begin());
            sent_groups++;
            progress = true;
        }
        /* Unconsumed TX descriptors need a kick (copy mode drives TX from sendto). */
        const bool unconsumed = *r.x.tx.producer != __atomic_load_n(r.x.tx.consumer, __ATOMIC_ACQUIRE);
        if ((unconsumed || (fifo.empty() && next == p.groups)) &&
            sendto(r.x.fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0) < 0 &&
            errno != EAGAIN && errno != EBUSY && errno != ENOBUFS)
            return -errno;
        if (now_ns() >= deadline) {
            std::fprintf(stderr, "timeout: %llu groups sent, %llu of %llu frames completed\n",
                         (unsigned long long)sent_groups, (unsigned long long)completed_frames,
                         (unsigned long long)total_frames);
            return -ETIMEDOUT;
        }
        if (!progress && r.o.block && completed_frames < total_frames) {
            cudaError_t e = fifo.empty() ? cudaSuccess :
                            cudaEventQuery(r.slots[fifo.front() % p.depth].done);
            if (e == cudaErrorNotReady) {
                /* The oldest queued copy gates the next transmission. */
                if (!cuda_ok(cudaEventSynchronize(r.slots[fifo.front() % p.depth].done), "event wait"))
                    return -EIO;
            } else if (cuda_ok(e, "event query")) {
                /* TX ring room or completions are pending, and they have no wakeup. */
                timespec nap{0, kTxNapUs * 1000};
                nanosleep(&nap, nullptr);
            } else {
                return -EIO;
            }
        }
    }
    uint64_t t1 = now_ns();
    if (!t0 || t1 <= t0) return -EIO;
    io_ns = t1 - t0;
    return 0;
}

int execute(Run &r)
{
    Options &o = r.o;
    ifreq ifr;
    int err = if_query(o.ifname, SIOCGIFMTU, &ifr);
    if (err) {
        std::fprintf(stderr, "SKIP: %s: %s\n", o.ifname, std::strerror(-err));
        return XG_EXIT_UNAVAILABLE;
    }
    if (gn_plan_init(&r.p, o.size, o.messages, uint32_t(ifr.ifr_mtu), uint32_t(o.depth),
                     o.window_groups))
        return XG_EXIT_USAGE;
    /* Egress slots own fixed chunk ranges; ingest holds at most as many chunks. */
    if (uint64_t(r.p.depth) * r.p.frames > 2048) return XG_EXIT_USAGE;
    uint32_t headroom = 0;
    if (o.ingest && xdev_ext_mech_ctl_rx_headroom(&r.p.l, &headroom)) return XG_EXIT_USAGE;
    int count = 0;
    if (cudaGetDeviceCount(&count) != cudaSuccess || count < 1) {
        std::fprintf(stderr, "SKIP: no CUDA device available\n");
        return XG_EXIT_UNAVAILABLE;
    }
    if (!cuda_ok(cudaSetDevice(0), "select device")) return XG_EXIT_FAIL;
    err = xp_open(&r.x, o.ifname, uint32_t(o.queue), 4096, headroom, o.ingest, !o.ingest,
                  o.copy_mode);
    if (err) {
        std::fprintf(stderr, "SKIP: AF_XDP socket on %s: %s\n", o.ifname, std::strerror(-err));
        return XG_EXIT_UNAVAILABLE;
    }
    if (!cuda_ok(cudaHostRegister(r.x.umem, r.x.umem_size, cudaHostRegisterDefault), "UMEM register")) {
        std::fprintf(stderr, "SKIP: cudaHostRegister of the UMEM failed\n");
        return XG_EXIT_UNAVAILABLE;
    }
    r.registered = true;
    const uint64_t window = uint64_t(r.p.depth) * r.p.l.group_bytes;
    if (!cuda_ok(cudaMalloc(&r.dev, window), "device slots")) return XG_EXIT_FAIL;
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
    /* ingest: sentinel slots; egress: slot s holds block s.  Outside timing. */
    for (uint64_t s = 0; s < r.p.depth; s++)
        xg_fill(host.data() + s * r.p.l.group_bytes, s * r.p.l.group_bytes, r.p.l.group_bytes,
                o.ingest ? ~uint32_t(o.seed) : uint32_t(o.seed));
    if (!cuda_ok(cudaMemcpy(r.dev, host.data(), window, cudaMemcpyHostToDevice), "seed"))
        return XG_EXIT_FAIL;
    if (o.ingest) {
        if (xp_fq_fill(&r.x, 0, XP_RING_SIZE)) return XG_EXIT_FAIL;
        xdev_ext_xsk_flow_filter filter{};
        filter.flags = XDEV_EXT_XSK_FILTER_F_ALL;
        filter.src_ipv4 = ntohl(o.peer.peer_ip);
        filter.dst_ipv4 = ntohl(o.peer.local_ip);
        filter.payload_magic = XDEV_EXT_MP_NXP_MAGIC;
        filter.src_port = ntohs(o.peer.peer_port);
        filter.dst_port = ntohs(o.peer.local_port);
        err = xdev_ext_xsk_redirect_attach(&r.redirect, &filter, int(if_nametoindex(o.ifname)),
                                      uint32_t(o.queue), r.x.fd,
                                      o.copy_mode ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE);
        if (err) {
            std::fprintf(stderr, "SKIP: XDP redirect: %s\n", std::strerror(-err));
            return XG_EXIT_UNAVAILABLE;
        }
    } else if (uint64_t(r.p.depth) * r.p.frames > r.x.nr_frames) {
        return XG_EXIT_USAGE;
    }
    uint64_t io_ns = 0, c0 = cpu_us(), b0 = xg_host_busy_us();
    err = o.ingest ? ingest(r, io_ns) : egress(r, io_ns);
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
    const bool zc = r.x.zero_copy;
    const uint64_t copy_calls = r.copy_calls, fallback = r.fallback_groups;
    const struct gn_group_copy plan = gn_group_copy(&r.p);
    if (!r.close()) return XG_EXIT_FAIL;
    std::printf("{\"schema_version\":1,\"arm\":\"afxdp-cuda\",\"direction\":\"%s\",\"route\":\"%s\","
        "\"execution\":\"physical-cuda\",\"performance_claim\":\"physical\",\"size\":%llu,"
        "\"messages\":%llu,\"group_bytes\":%u,\"groups\":%llu,\"depth\":%u,\"mtu\":%u,\"xsk\":\"%s\","
        "\"streams\":%llu,\"io_bytes\":%llu,\"slots_used\":%llu,\"oracle\":\"%s\",\"io_ns\":%llu,"
        "\"cpu_us\":%llu,\"host_busy_us\":%llu,\"completion_wait\":\"%s\",\"seg_len\":%u,"
        "\"frames\":%u,\"copies_per_group\":%u,\"copy_calls\":%llu,\"fallback_groups\":%llu,"
        "\"status\":\"pass\"}\n",
        o.ingest ? "ingest" : "egress",
        o.ingest ? "afxdp-rx>registered-umem>cuda-h2d-async" : "cuda-d2h-async>registered-umem>afxdp-tx",
        (unsigned long long)r.p.size, (unsigned long long)r.p.messages, r.p.l.group_bytes,
        (unsigned long long)r.p.groups, r.p.depth, r.p.mtu, zc ? "zc" : "copy",
        (unsigned long long)o.streams, (unsigned long long)(r.p.groups * r.p.l.group_bytes),
        (unsigned long long)used, o.ingest ? "device-slot-group-images" : "peer-receipt-required",
        (unsigned long long)io_ns, (unsigned long long)cpu, (unsigned long long)busy,
        o.block ? "block" : "poll", r.p.l.seg_len, r.p.frames, plan.calls,
        (unsigned long long)copy_calls, (unsigned long long)fallback);
    return std::fflush(stdout) ? XG_EXIT_FAIL : XG_EXIT_PASS;
}

} // namespace

int main(int argc, char **argv)
{
    Run r;
    int ret = parse(argc, argv, r.o);
    if (ret) {
        if (ret == XG_EXIT_USAGE) usage(stderr);
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
