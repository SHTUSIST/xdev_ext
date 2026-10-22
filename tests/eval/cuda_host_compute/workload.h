// Correctness-only orchestration shared by the scalar fixture and CUDA adapter.
#ifndef CUDA_HOST_COMPUTE_WORKLOAD_H
#define CUDA_HOST_COMPUTE_WORKLOAD_H
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace host_compute {
constexpr uint64_t xor_constant = UINT64_C(0xdeadbeefcafebabe);
constexpr uint64_t round_constant = UINT64_C(0x9e3779b97f4a7c15);
constexpr size_t guard_size = 64;
struct Failure {
    int code;
    std::string reason;
};
struct Config {
    size_t bytes = 4096, frames = 3, rounds = 3;
    std::string shape = "all", inject = "none";
    size_t fault_round = 0;
    std::string fault_route = "staged", fault_shape = "batch";
    size_t payload() const { return bytes * frames; }
    bool fault(const std::string &kind, const std::string &route,
               const std::string &selected_shape, size_t round) const {
        return inject == kind && route == fault_route &&
               selected_shape == fault_shape && round == fault_round;
    }
};
inline size_t decimal(const char *text) {
    if (!*text) throw Failure{2, "invalid numeric argument"};
    size_t n = 0;
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9' || n > (SIZE_MAX - (*p - '0')) / 10)
            throw Failure{2, "invalid numeric argument"};
        n = n * 10 + static_cast<unsigned>(*p - '0');
    }
    return n;
}
inline Config binary_config(int argc, char **argv) {
    if (argc != 9) throw Failure{2, "use run.py for the public CLI"};
    Config c;
    c.bytes = decimal(argv[1]); c.frames = decimal(argv[2]);
    c.rounds = decimal(argv[3]); c.shape = argv[4]; c.inject = argv[5];
    c.fault_round = decimal(argv[6]); c.fault_route = argv[7]; c.fault_shape = argv[8];
    if (!c.bytes || c.bytes % 8 || !c.frames || c.frames > 4096 ||
        !c.rounds || c.rounds > 1000 || c.bytes > 67108864 / c.frames ||
        (c.shape != "all" && c.shape != "per-frame" && c.shape != "batch" &&
         c.shape != "single-launch"))
        throw Failure{2, "invalid workload dimensions or shape"};
    return c;
}
inline uint64_t input_word(size_t i, size_t round) {
    return (static_cast<uint64_t>(i) * UINT64_C(1315423911)) ^
           (static_cast<uint64_t>(round) * round_constant);
}
inline void reset(uint8_t *base, size_t bytes, size_t round) {
    std::memset(base, 0xa5, guard_size);
    for (size_t i = 0; i < bytes / 8; ++i) {
        uint64_t word = input_word(i, round);
        std::memcpy(base + guard_size + i * 8, &word, 8);
    }
    std::memset(base + guard_size + bytes, 0x5a, guard_size);
}
inline void verify(const uint8_t *base, size_t bytes, size_t round) {
    for (size_t i = 0; i < guard_size; ++i)
        if (base[i] != 0xa5 || base[guard_size + bytes + i] != 0x5a)
            throw Failure{1, "guard corruption"};
    for (size_t i = 0; i < bytes / 8; ++i) {
        uint64_t expected = input_word(i, round) ^ xor_constant;
        // Recompute independently; compare every byte including the final word.
        if (std::memcmp(base + guard_size + i * 8, &expected, 8))
            throw Failure{1, "payload corruption"};
    }
}
struct Setup { size_t host_allocations = 0, host_registrations = 0, device_allocations = 0; };
struct Cleanup { size_t host_frees = 0, host_unregistrations = 0, device_frees = 0; };
struct Case {
    std::string route, shape;
    size_t rounds_verified = 0, payload_bytes_verified = 0, guard_bytes_verified = 0;
    size_t kernel_launches = 0, kernel_syncs = 0, h2d_bytes = 0, d2h_bytes = 0;
    size_t guard_h2d_bytes = 0, guard_d2h_bytes = 0, copy_syncs = 0;
};
inline std::string quoted(const std::string &s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c >= 32 && c < 127) out += c;
        else out += '?';
    }
    return out + '"';
}
inline void print_record(const Config &c, const char *mode, const char *backend,
                         const char *semantics, int code, const std::string &reason,
                         const Setup &setup, const Cleanup &cleanup,
                         const std::vector<Case> &cases, bool same_pointer) {
    const char *status = code == 0 ? "ok" : code == 3 ? "unknown" : code == 4 ? "unavailable" : "error";
    std::cout << "{\"schema\":\"cuda-host-compute-v1\",\"mode\":" << quoted(mode)
              << ",\"backend\":" << quoted(backend) << ",\"status\":" << quoted(status)
              << ",\"scope\":\"correctness-only\",\"resource_semantics\":" << quoted(semantics)
              << ",\"performance_measured\":false,\"bytes_per_frame\":" << c.bytes
              << ",\"frames\":" << c.frames << ",\"rounds\":" << c.rounds
              << ",\"mapped_pointer_equals_host\":"
              << (setup.device_allocations ? (same_pointer ? "true" : "false") : "null")
              << ",\"setup\":{\"host_allocations\":" << setup.host_allocations
              << ",\"host_registrations\":" << setup.host_registrations
              << ",\"device_allocations\":" << setup.device_allocations
              << "},\"steady\":{\"host_allocations\":0,\"host_registrations\":0,\"device_allocations\":0}"
              << ",\"cleanup\":{\"host_frees\":" << cleanup.host_frees
              << ",\"host_unregistrations\":" << cleanup.host_unregistrations
              << ",\"device_frees\":" << cleanup.device_frees << "},\"cases\":[";
    if (code == 0) for (size_t i = 0; i < cases.size(); ++i) {
        const Case &x = cases[i];
        if (i) std::cout << ',';
        std::cout << "{\"route\":" << quoted(x.route) << ",\"shape\":" << quoted(x.shape)
                  << ",\"rounds_verified\":" << x.rounds_verified
                  << ",\"payload_bytes_verified\":" << x.payload_bytes_verified
                  << ",\"guard_bytes_verified\":" << x.guard_bytes_verified
                  << ",\"kernel_launches\":" << x.kernel_launches
                  << ",\"kernel_syncs\":" << x.kernel_syncs
                  << ",\"h2d_bytes\":" << x.h2d_bytes << ",\"d2h_bytes\":" << x.d2h_bytes
                  << ",\"guard_h2d_bytes\":" << x.guard_h2d_bytes
                  << ",\"guard_d2h_bytes\":" << x.guard_d2h_bytes
                  << ",\"copy_syncs\":" << x.copy_syncs << '}';
    }
    std::cout << ']';
    if (code) std::cout << ",\"reason\":" << quoted(reason);
    std::cout << "}\n";
}

template<class Backend>
int execute(Backend &b, const Config &c, const char *mode,
            const char *backend, const char *semantics) {
    Setup setup; Cleanup cleanup;
    uint8_t *host[2] = {nullptr, nullptr}, *mapped = nullptr, *device = nullptr;
    bool registered[2] = {false, false};
    bool same_pointer = false;
    int code = 0; std::string reason;
    std::vector<Case> cases;
    const size_t payload = c.payload(), span = payload + 2 * guard_size;
    // Raw allocations intentionally have no freeing destructor: UNKNOWN retains
    // all potentially referenced memory until the worker process terminates.
    try {
        b.discover();
        for (size_t i = 0; i < 2; ++i) {
            host[i] = b.host_allocate(span); ++setup.host_allocations;
            b.host_register(host[i], span); registered[i] = true; ++setup.host_registrations;
        }
        mapped = b.mapped_pointer(host[0]); same_pointer = mapped == host[0];
        device = b.device_allocate(span); ++setup.device_allocations;
        for (const std::string route : {"mapped-host", "staged"}) {
            for (const std::string shape : {"per-frame", "batch", "single-launch"}) {
                if (c.shape != "all" && c.shape != shape) continue;
                Case x; x.route = route; x.shape = shape;
                for (size_t r = 0; r < c.rounds; ++r) {
                    uint8_t *h = host[route == "mapped-host" ? 0 : 1];
                    reset(h, payload, r);
                    if (route == "staged") {
                        if (c.fault("copy-error", route, shape, r)) throw Failure{1, "injected preacceptance copy failure"};
                        b.to_device(device, h, span);
                        x.h2d_bytes += payload; x.guard_h2d_bytes += 128; ++x.copy_syncs;
                    }
                    uint8_t *target = (route == "mapped-host" ? mapped : device) + guard_size;
                    size_t launches = shape == "single-launch" ? 1 : c.frames;
                    for (size_t frame = 0; frame < launches; ++frame) {
                        if (!frame && c.fault("launch-error", route, shape, r))
                            throw Failure{1, "injected preacceptance launch failure"};
                        size_t words = (shape == "single-launch" ? payload : c.bytes) / 8;
                        size_t offset = shape == "single-launch" ? 0 : frame * c.bytes;
                        b.launch(reinterpret_cast<uint64_t *>(target + offset), words); ++x.kernel_launches;
                        if (shape == "per-frame" || frame + 1 == launches) {
                            if (c.fault("sync-unknown", route, shape, r))
                                throw Failure{3, "injected completion UNKNOWN; resources retained"};
                            b.fence(); ++x.kernel_syncs;
                        }
                    }
                    if (route == "staged") {
                        b.to_host(h, device, span);
                        x.d2h_bytes += payload; x.guard_d2h_bytes += 128; ++x.copy_syncs;
                    }
                    if (c.fault("payload-last", route, shape, r)) h[guard_size + payload - 1] ^= 1;
                    if (c.fault("prefix", route, shape, r)) h[guard_size - 1] ^= 1;
                    if (c.fault("suffix", route, shape, r)) h[guard_size + payload] ^= 1;
                    verify(h, payload, r);
                    ++x.rounds_verified; x.payload_bytes_verified += payload; x.guard_bytes_verified += 128;
                }
                cases.push_back(x);
            }
        }
    } catch (const Failure &e) { code = e.code; reason = e.reason; }
      catch (const std::exception &) { code = 1; reason = "host bookkeeping failure"; }
    if (code != 3) {
        try { b.drain(); }
        catch (const Failure &e) { code = 3; reason = e.reason; }
    }
    if (code != 3) {
        try {
            if (c.inject == "cleanup-error" && code == 0)
                throw Failure{1, "injected cleanup failure; remaining resources retained"};
            if (device) { b.device_free(device); ++cleanup.device_frees; device = nullptr; }
            for (size_t i = 0; i < 2; ++i) {
                if (registered[i]) { b.host_unregister(host[i]); ++cleanup.host_unregistrations; registered[i] = false; }
                if (host[i]) { b.host_free(host[i]); ++cleanup.host_frees; host[i] = nullptr; }
            }
        } catch (const Failure &e) { code = 1; reason = e.reason; }
    }
    print_record(c, mode, backend, semantics, code, reason, setup, cleanup, cases, same_pointer);
    return code;
}
inline uint8_t *aligned_host(size_t span) {
    void *p = nullptr;
    if (posix_memalign(&p, 4096, (span + 4095) & ~size_t(4095)))
        throw Failure{1, "host allocation failed"};
    return static_cast<uint8_t *>(p);
}
} // namespace host_compute
#endif
