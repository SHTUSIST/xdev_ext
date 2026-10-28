// Offline scalar adapter: no CUDA registration, device or DMA is exercised.
#include "workload.h"
using namespace host_compute;
class ScalarBackend {
public:
    void discover() {}
    uint8_t *host_allocate(size_t n) { return aligned_host(n); }
    void host_register(uint8_t *, size_t) {} // simulated registration
    uint8_t *mapped_pointer(uint8_t *p) { return p; }
    uint8_t *device_allocate(size_t n) { return aligned_host(n); }
    void to_device(uint8_t *d, const uint8_t *h, size_t n) { std::memcpy(d, h, n); }
    void to_host(uint8_t *h, const uint8_t *d, size_t n) { std::memcpy(h, d, n); }
    void launch(uint64_t *p, size_t words) {
        for (size_t i = 0; i < words; ++i) p[i] ^= xor_constant;
    }
    void fence() {} // simulated known completion
    void drain() {}
    void device_free(uint8_t *p) { std::free(p); }
    void host_unregister(uint8_t *) {} // simulated unregistration
    void host_free(uint8_t *p) { std::free(p); }
};
int main(int argc, char **argv) {
    try {
        Config c = binary_config(argc, argv); ScalarBackend b;
        return execute(b, c, "host-fixture", "host-scalar-fixture", "simulated");
    } catch (const Failure &) { return 2; }
}
