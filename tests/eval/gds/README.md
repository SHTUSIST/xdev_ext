# cuFile storage/GPU comparison

This workload moves a regular file into CUDA device memory (`llm-load`) or
writes synthetic device state to a regular file (`checkpoint`). It calls the
real synchronous cuFile APIs. It is a storage/GPU microbenchmark, without a
model inference engine or application-consistent checkpoint protocol.

The cuFile read/write branches and complete buffered I/O helpers were moved
and adapted from `chainio_p2p_bench.cu`, original SHA256
`2235b9846387b2ab8ec7d42fdcca567243b357045f08cd40ef30b0b78cd5d831`.
The port replaces the old handwritten cuFile ABI, ambiguous native/compat
labels, unchecked I/O results and CSV output with official SDK types,
full data verification, native path evidence and a strict result record.
Non-cuFile NIC, mapped-host and UVM workloads are outside this port.

## Build and run

Use a C++17 compiler and official CUDA/cuFile development headers/libraries
that expose the cuFile level3 statistics APIs. The SDK root must contain
`include/{cuda.h,cuda_runtime_api.h,cufile.h}` and its matching CRT headers;
libraries may be under `lib`, `lib64` or `targets/x86_64-linux/lib`.
Only the benchmark executable is built; no kernel modules or system settings
are changed. The compiler defaults to `c++`; `CXX` may name another executable.

```sh
python3 tests/eval/gds/run.py --mode cufile-direct --workload llm-load \
  --bytes 16777216 --chunk 1048576 --iterations 3 --directory EXISTING_DIR \
  --cuda-root /usr/local/cuda --build-only

# Run only on a real GPU/storage host, on the intended mounted filesystem.
python3 tests/eval/gds/run.py --mode cufile-direct --workload checkpoint \
  --bytes 16777216 --chunk 1048576 --iterations 3 --directory EXISTING_DIR \
  --cuda-root /usr/local/cuda

python3 tests/eval/gds/test_gds.py -v
```

The test suite never runs the hardware workload on a host exposing an NVIDIA
device. `GDS_CUDA_ROOT` selects an official SDK for its build-only check.
The executable lives in `build/`. No CUDA/cuFile dependency is bundled here.

`--directory` must already exist. Every execution creates a private0700
temporary directory with an exclusive0600 regular file and removes it on exit.
It accepts no raw device, input or output filename. File I/O is `O_DIRECT`;
unsupported direct I/O is refused without reopening buffered. Numeric values
are ASCII decimal integers: bytes1..1GiB and chunk1..16MiB must be multiples
of4096 with chunk<=bytes, iterations1..1000. A final partial chunk is allowed
when its size is still4096-aligned.

Exit0 means a fully verified hardware run, or a successful build-only command.
Build-only prints its artifact path to stderr and no result JSON. Exit2 rejects
configuration. Exit4 reports missing dependencies/device/filesystem or
unavailable native path evidence with `SKIP` on stderr; stdout is empty.
Exit1 reports execution, exact I/O, corruption or cleanup failure. A run that
times out emits no success result. Do not use VM timings as performance data.

## Path and correctness evidence

Only `cufile-direct` is accepted. Compatibility is explicitly disabled and
driver properties are checked. A cuFile function call, device pointer,
driver-open success or `nvidia-fs` presence alone does not establish direct I/O.
This workload also requires isolated process level3 counters: successful
NVFS/P2PDMA counts and bytes must exactly match all requested I/O, with zero
POSIX, unaligned, sparse, inline, dynamic-routing or erroneous operations.
Absent or inconsistent counters produce exit4 with no timing/success record.
This strict subset may reject a working native configuration whose library
internally splits or routes requests. No fallback is relabelled direct.
The official [cuFile API reference](https://docs.nvidia.com/gpudirect-storage/api-reference-guide/)
documents the statistics and driver properties; the
[troubleshooting guide](https://docs.nvidia.com/gpudirect-storage/troubleshooting-guide/)
describes POSIX path counters.

One registered CUDA chunk allocation is reused throughout the run. For each
chunk, all4096 prefix guard bytes and the entire unused tail plus4096 suffix
guard bytes are checked. Every payload byte uses the deterministic pattern
`(absolute_file_index*37 + absolute_file_index/251 + iteration*53) % 256`,
where `/` is integer division and iteration starts at zero. Every load receives
full GPU readback validation. Every checkpoint receives full GPU readback and
complete file reread after `fsync`. Exact short I/O fails the run. All resource
cleanup must succeed before the executable emits its single JSON record.

`io_ns` includes synchronous cuFile calls, CUDA completion and checkpoint
`fsync`; it excludes seed preparation and full validation. Its counts and
`verified_bytes` cover every requested iteration. Successful JSON is checked
again by the runner before it is relayed. This implementation does not prove
power-loss durability or application checkpoint consistency.

## Comparison scope

The existing [`bench_cuda_staging.c`](../bench_cuda_staging.c) supplies the
pageable and reused pinned host-memory load/checkpoint workload. It already
adapts the legacy `bench_llm_load.c` and `bench_gpu_checkpoint.c` shapes; no
duplicate host-staging implementation is introduced here. Select the same
bytes, chunk schedule, input pattern, completion and validation scope when
comparing paths. That workload uses buffered file I/O; this cuFile workload
requires direct I/O, so storage cache semantics must be accounted for before
making a performance comparison. No performance advantage is asserted here.

cuFile native storage↔VRAM bypasses host staging. The xdev_ext main path shares
pinned host pages across separately mapped devices and still performs
host↔VRAM DMA. They are different data paths; cuFile success does not establish
xdev_ext session ownership, descriptor completion or shared-page lifecycle.
