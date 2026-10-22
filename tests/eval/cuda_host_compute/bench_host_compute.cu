// Adapted from cumem_viability_test.cu (original SHA256 in README).
// The original XOR kernel and per-frame, batch, single-launch shapes are retained.
// Correctness-only; official CUDA runtime/compiler required, no fallback backend.
#include <cuda_runtime.h>
#include "workload.h"
using namespace host_compute;

// Original uint64 XOR computation; each selected word is touched exactly once.
__global__ void xor_kernel(uint64_t *p, size_t n, uint64_t c)
{
    size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < n) p[i] ^= c;
}

class CudaBackend {
    bool pending = false;
    static void check(cudaError_t error, const char *operation, int code = 1) {
        if (error != cudaSuccess)
            throw Failure{code, std::string(operation) + " failed (CUDA error " +
                                std::to_string(static_cast<int>(error)) + ")"};
    }
public:
    void discover() {
        int devices = 0;
        cudaError_t e = cudaGetDeviceCount(&devices);
        if (e == cudaErrorNoDevice || e == cudaErrorInsufficientDriver ||
            e == cudaErrorInitializationError || e == cudaErrorSystemDriverMismatch)
            throw Failure{4, "CUDA driver or GPU unavailable before submission"};
        check(e, "device discovery");
        if (devices < 1) throw Failure{4, "CUDA GPU unavailable before submission"};
        check(cudaSetDeviceFlags(cudaDeviceMapHost), "mapped-host device flags");
        check(cudaSetDevice(0), "device selection");
        int can_map = 0, can_register = 0;
        check(cudaDeviceGetAttribute(&can_map, cudaDevAttrCanMapHostMemory, 0), "mapped-host capability", 4);
        check(cudaDeviceGetAttribute(&can_register, cudaDevAttrHostRegisterSupported, 0), "registration capability", 4);
        if (!can_map || !can_register)
            throw Failure{4, "required mapped-host registration capability unavailable"};
    }
    uint8_t *host_allocate(size_t span) { return aligned_host(span); }
    void host_register(uint8_t *p, size_t span) {
        // Page-aligned independent ranges; both routes register exactly once.
        cudaError_t e = cudaHostRegister(p, (span + 4095) & ~size_t(4095), cudaHostRegisterMapped);
        if (e == cudaErrorNotSupported)
            throw Failure{4, "host registration unsupported before submission"};
        check(e, "host registration");
    }
    uint8_t *mapped_pointer(uint8_t *p) {
        void *device = nullptr;
        check(cudaHostGetDevicePointer(&device, p, 0), "registered-host mapping", 4);
        return static_cast<uint8_t *>(device);
    }
    uint8_t *device_allocate(size_t span) {
        void *p = nullptr;
        check(cudaMalloc(&p, span), "device allocation");
        return static_cast<uint8_t *>(p);
    }
    void to_device(uint8_t *d, const uint8_t *h, size_t span) {
        // Guards travel with payload; separate counters expose their extra bytes.
        pending = true;
        check(cudaMemcpy(d, h, span, cudaMemcpyHostToDevice), "H2D copy");
        // A synchronous H2D copy may still have device work pending on return.
        // Keep conservative ownership until the subsequent checked kernel fence.
    }
    void to_host(uint8_t *h, const uint8_t *d, size_t span) {
        pending = true;
        check(cudaMemcpy(h, d, span, cudaMemcpyDeviceToHost), "D2H copy");
        // D2H synchronous completion makes the host bytes available to the oracle.
        pending = false;
    }
    void launch(uint64_t *p, size_t words) {
        pending = true; // preserve ownership even if launch status is uncertain
        xor_kernel<<<static_cast<unsigned>((words + 255) / 256), 256>>>(p, words, xor_constant);
        check(cudaGetLastError(), "kernel launch");
    }
    void fence() {
        check(cudaDeviceSynchronize(), "kernel completion UNKNOWN; resources retained", 3);
        pending = false;
    }
    void drain() {
        if (pending) {
            check(cudaDeviceSynchronize(), "drain completion UNKNOWN; resources retained", 3);
            pending = false;
        }
    }
    void device_free(uint8_t *p) { check(cudaFree(p), "device cleanup"); }
    void host_unregister(uint8_t *p) { check(cudaHostUnregister(p), "host unregister"); }
    void host_free(uint8_t *p) { std::free(p); }
};
int main(int argc, char **argv) {
    try {
        Config c = binary_config(argc, argv);
        if (c.inject != "none") return 2;
        CudaBackend b;
        return execute(b, c, "cuda-correctness", "cuda-runtime", "cuda-runtime");
    } catch (const Failure &) { return 2; }
}
