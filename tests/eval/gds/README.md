# cuFile storage/GPU comparison

[Performance evaluation policy](../PERFORMANCE_POLICY.md)

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

### Strict campaign (`gds-campaign-v1`, schema2)

Every cuFile operation of the whole campaign owns one guarded slot of a single
CUDA allocation that is registered once before the first operation and reused
for the run: a4096-byte prefix guard, the chunk area and a4096-byte suffix guard.
History capacity (`operations*(chunk+8192)` bytes of device memory plus the host
images for the final comparison) is admitted before any allocation or I/O;
insufficient capacity exits4 with no result. Nothing is shrunk or validated
early to fit. `llm-load` reseeds the same regular-file window for every
iteration (outside `io_ns`) and reads each chunk into its own slot. `checkpoint`
seeds all device state once (outside `io_ns`) and writes iteration `t` to its own
file region at offset `t*bytes`, so a later clean iteration cannot overwrite an
earlier iteration's stored bytes.

During the campaign only exact I/O results and the native-path accounting are
checked; an exact short I/O fails immediately. After the last operation, its
completion and the checkpoint `fsync`, the benchmark reads the complete slot
history back once and compares every payload byte, every unused chunk-tail byte
and every guard byte; `checkpoint` also rereads the complete file once and
compares every stored byte of every iteration. Every payload byte uses the
deterministic pattern `(absolute_file_index*37 + absolute_file_index/251 +
iteration*53) % 256`, where `/` is integer division, the index is relative to the
logical window and iteration starts at zero. An early damaged byte therefore
fails the run even when later operations are clean. Only after this comparison
does it release every resource, serialize one real JSON manifest on stderr,
and print its single schema2 JSON result on stdout. The manifest carries the
input formula and iteration/window identity, complete memory geometry, observed
history FNV-1a-64 fingerprint, and full device/file byte-comparison results.
FNV-1a is a non-cryptographic evidence fingerprint, not a replacement for the
complete byte comparison. `run.py` independently reconstructs that fingerprint
and validates the manifest before relaying stdout. Save stderr with stdout to
retain this manifest; the temporary data directory is still removed.

The stderr contract is one LF-terminated JSON object line, with optional JSON
whitespace (space, Tab or CR) around the object. Blank lines and ordinary SDK
text diagnostics, including `[WARN]` messages, may surround it. Every line
whose first non-JSON-whitespace character is `{` is reserved for evidence;
malformed or unterminated objects are errors, never ignored diagnostics.
Additional objects, duplicate keys, non-finite numbers and complete non-object
JSON lines (including arrays, strings, numbers, booleans and null) are refused.
Standalone `NaN`/`Infinity` lines are also refused. No success record is relayed
until this stderr contract and the exact requested manifest both pass.

`io_ns` includes the synchronous cuFile calls, CUDA completion and checkpoint
`fsync`; it excludes seeding, the history readback and the comparison. Slots are
preallocated, so there is no history copy inside or outside the timer. The record
carries the fairness evidence `input_id`, `source_window`, `output_residency`,
`queue_depth=1`, `direct_io`, `buffer_registration=once-reused`,
`registration_count=1`, `campaign_complete`, `validation_phase=post-campaign`,
`full_byte_compare`, `history_operations`, `history_bytes`, `manifest_count=1`
and `capture_in_timing`. `run.py` relays only an exact schema2 record for the
requested campaign; `run.py:checked_comparison(left, right)` admits a pair of
schema2 records (for example `linux-pinned` and `cufile-direct`) only when input,
window, residency, depth, direct I/O and once-reused registration are identical
and both were validated once after their complete campaign. Schema1 records are
correctness-only and are refused for comparison. This implementation does not
prove power-loss durability or application checkpoint consistency.

The previous schema1 loop, which reused one chunk buffer and compared GPU
contents (and reread the checkpoint file) after every chunk or iteration, remains
in `bench_cufile.cc` under `#ifdef GDS_PER_CHUNK_ORACLE` and is not built by default.

`test_campaign_timing.py` executes the actual benchmark body with the official
SDK headers and controlled host dependencies (ordinary memory and disposable
regular files) to check the order of operations, history retention and refusal
paths: `GDS_CUDA_ROOT=/official/sdk python3 -B tests/eval/gds/test_campaign_timing.py -v`.
`test_campaign_result.py` checks the runner relay. Neither runs a device, measures
time or establishes any path, DMA or performance property.
`test_manifest_evidence.py` also exercises actual runner admission with the
actual-body output, including whitespace-prefixed contradictory/duplicate and
malformed records, non-object JSON, and accepted SDK diagnostics; it runs in
`make check` with the same official SDK and compiler selection.

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
