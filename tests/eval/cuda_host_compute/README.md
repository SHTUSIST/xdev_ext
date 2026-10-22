# Registered-host GPU compute correctness

This workload adapts the original `cumem_viability_test.cu`, preserving its uint64
XOR kernel and three launch shapes. Original source SHA256:
`903b082bc860b1d745964071df1df20563f14cd6b69a7ef9ef8920bf40762aaf`.
The former experiment is retired; this directory owns the maintained source.
Machine-specific prose, timing output and inherited hardware results were removed.

Both routes reuse independent host allocations registered once during setup.
`mapped-host` uses the device pointer returned by the CUDA mapping API.
`staged` reuses one device allocation for H2D, the same XOR kernel and D2H.
Pointer equality is reported as an attribute, never assumed.

Each route supports `per-frame` (one checked kernel fence per frame), `batch`
(frame launches followed by one fence), and `single-launch` (whole payload and
one fence). Each round independently regenerates identical input for both routes
and checks every output byte plus complete 64-byte prefix and suffix guards.
There are no allocations or registrations during steady rounds.

The staged device allocation also has guards. H2D/D2H transfer the guarded span
in one copy per direction: the payload counters are `h2d_bytes`/`d2h_bytes`, and
the additional bytes are `guard_h2d_bytes`/`guard_d2h_bytes`. **Actual transferred
bytes in each direction are payload plus guard counters.** `copy_syncs` counts
synchronous copy API calls separately from explicit `kernel_syncs`. An H2D API
return is not treated as proof of final device completion; the following kernel
fence also establishes completion of that stream's work. Guard transfer is
correctness instrumentation, not a claim about unavoidable baseline cost.

This version is correctness-only and emits no performance measurements. GPU
mapped-host accesses are distinct from NIC/NVMe DMA and native peer transfers.
It does not establish a speed advantage or certify a provider lifecycle.

## Commands

The scalar fixture needs Python 3 and a C++17 compiler. It uses the same
orchestration, independent oracle and lifecycle decisions with simulated resource
calls. Its success is not CUDA compilation, pinned memory, real DMA or GPU proof.

```sh
python3 run.py --mode host-fixture --bytes 24 --frames 3 --rounds 3
python3 test_contract.py
python3 run.py --mode host-fixture --inject payload-last --fault-round 2
python3 run.py --mode host-fixture --inject sync-unknown --fault-round 2
```

`CXX` selects the scalar compiler; `NVCC` selects the official CUDA compiler.
An explicit missing compiler never falls back. Use a CUDA Toolkit matching the
intended supported GPU, with runtime libraries discoverable by its normal loader.
Build-only performs no driver discovery or device execution:

```sh
python3 build.py --arch sm_80 --output build/bench_host_compute
# Only on an authorized physical GPU with the required mapped-host capability:
python3 run.py --mode cuda-correctness --shape all
```

`CUDA_ARCH` defaults to `sm_80` and must match the intended supported GPU when
executing. The equivalent compile command is:

```sh
nvcc -std=c++17 -O2 -arch=sm_80 --cudart=shared -o build/bench_host_compute bench_host_compute.cu
```

`run.py` compiles into an owned temporary directory beside the source and removes
it after worker termination. It uses argument arrays without a shell. Defaults
are 4096 bytes/frame, 3 frames and 3 rounds. Decimal arguments must be positive;
bytes/frame must be a multiple of 8, frames<=4096, rounds<=1000, and total payload
<=64 MiB. Duplicate/unknown options, signs, fractions and trailing arguments fail
before setup. `--help` is dependency-free.

Host-only injection selects payload/guard corruption, preacceptance launch/copy
failure, UNKNOWN completion or cleanup failure. `--fault-route`, `--fault-shape`
and `--fault-round` select the case. Fault injection is rejected in CUDA mode.

## Result and ownership contract

Valid invocations emit one final `cuda-host-compute-v1` JSON record. Operation
counts are simulated for `host-scalar-fixture` and actual adapter operations for
`cuda-runtime`. Only after all cases and cleanup succeed are `cases` emitted.
Error/UNKNOWN/unavailable records have no successful cases. Exit codes:

- 0: all data/guards, operations and cleanup verified;
- 1: known error, corruption, compiler failure or cleanup failure;
- 2: CLI misuse;
- 3: completion UNKNOWN, with referenced resources retained until termination;
- 4: compiler, driver, GPU or required mapping capability unavailable before work.

CUDA calls and launch status are checked. Known errors drain accepted work before
cleanup; a failed completion/drain fence retains ownership. UNKNOWN does not
retry work, unregister/free any potentially referenced resource, or reset the
device. Cleanup failure stops further cleanup and is not retried blindly.
Driver/device discovery, compilation, scalar correctness and real GPU execution
are separate validation stages. The portable tests run only the scalar fixture
and forced missing-compiler paths; actual CUDA correctness requires later
authorized physical-device execution. No VM performance run is part of this test.

The CUDA APIs and compilation model are documented by NVIDIA:
[Runtime memory APIs](https://docs.nvidia.com/cuda/cuda-runtime-api/cuda_runtime_api/group__CUDART__MEMORY.html),
[NVCC](https://docs.nvidia.com/cuda/cuda-compiler-driver-nvcc/index.html).
