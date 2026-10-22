# Evaluation workloads

This directory ports selected workload ideas from the earlier
`bench_nvme_pipeline_compare.c`, `bench_nvme_pipeline_cost.c`,
`bench_llm_load.c`, and `bench_gpu_checkpoint.c` into bounded, independently
verifiable programs. It contains source and reproducible commands, without
historical measurements or machine-specific configurations.

These are comparison baselines. The file-to-TCP program uses a userspace buffer
and ordinary sockets; the CUDA program uses buffered file I/O and synchronous
CUDA copies, with either pageable or CUDA-allocated pinned host memory. Neither
program measures the current xdev_ext session, common page pool, kernel CE
provider, native NIC queue, or device-local P2P path. Current implementation
correctness and concurrent session tests live in
[`xdev_ext_preload` selftests](../../kernel/tools/testing/selftests/xdev_ext_preload/).
[Application call-shape checks](apps/README.md) separately distinguish custom
operations from compatible libc fallback.

The optional [cuFile storage/GPU comparison](gds/README.md) ports the original
cuFile load/checkpoint source. It requires a real CUDA device, an official SDK
and exact per-process native-path counters; missing capabilities return exit4
without a result or timing. Its direct storage↔VRAM route differs from xdev_ext's
shared pinned host pages. Build and capability-contract checks can run without
certifying physical DMA; performance comparisons require actual devices and
matching I/O, cache and completion semantics.

## Build and run

Linux, a C11 compiler, make, pthreads, and Python 3 are required. The default
build needs neither liburing nor a CUDA SDK:

```sh
make -C tests/eval
make -C tests/eval check
python3 tests/eval/run.py --suite portable
```

The runner creates and removes a private temporary regular file. By default it
uses 1 MiB + 17 bytes, 64 KiB chunks, three complete passes, and two CPU-work
settings. It verifies every emitted result before printing JSON. Override with
`--bytes N --chunk N --iterations N`; the runner limits its input file to 1 GiB.
Reserve that much free space under the system temporary directory.

To build and exercise the optional io_uring comparisons, install liburing's
development package and pkg-config, then run:

```sh
make -C tests/eval ENABLE_URING=1
make -C tests/eval ENABLE_URING=1 check
python3 tests/eval/run.py --suite io-uring
```

Changing `ENABLE_URING` rebuilds the pipeline executable. The `io_uring-fixed`
backend registers the read buffer; its socket operation is ordinary SEND. It
does not use SEND_ZC, and buffer registration does not establish NIC zero-copy
or any shared DMA mapping. All backends submit one logical operation at a time;
this suite is a serial cost comparison rather than a queue-depth throughput
benchmark. No selected backend silently changes to POSIX or another backend.

CUDA uses the installed driver through `dlopen("libcuda.so.1")`:

```sh
python3 tests/eval/run.py --suite cuda
```

This requests both directions and both memory types. It requires a usable CUDA
device and enough device/pinned memory for one chunk plus guards. It initializes
synthetic checkpoint data, checks GPU readback and guards, and compares the
entire saved file. It does not load a model, run inference, or establish
application-consistent checkpoint semantics. There is no CPU replacement for a
missing GPU and no HostRegister fallback for a failed pinned allocation.

| Component | Build | Functional coverage | Device evidence |
| --- | --- | --- | --- |
| POSIX file → local TCP | Default | Full byte comparison, tails, counters, guards, EINTR and partial I/O | Ordinary host file/socket behavior only |
| io_uring READ + SEND | `ENABLE_URING=1` | Full byte comparison and corruption/truncation rejection | No physical NVMe/NIC or current session claim |
| Registered-buffer READ + ordinary SEND | `ENABLE_URING=1` | Full byte comparison and corruption/truncation rejection | Buffer registration only; no network zero-copy claim |
| CUDA pageable/pinned staging, load/checkpoint | Default build; runtime driver required | CLI/dependency refusal, result-validator checks, and device-dependent data verification | Requires an actual CUDA device for transfer execution |
| xdev_ext shared-page session/provider | Separate existing selftests | See linked guest tests and their actual acceptance requirements | Physical device/topology/performance validation remains separate |

The CUDA result-validator tests use metadata fixtures to reject malformed
records. They do not emulate CUDA or certify a GPU run. The optional io_uring
contract tests accept an explicit capability refusal when that backend was not
built or the host disallows io_uring; the separate `--suite io-uring` command
must exit zero before claiming that its workloads ran.

## Individual program interfaces

Use a dedicated, immutable regular input file. The programs reject directories,
raw block devices, out-of-bounds lengths, zero lengths, invalid numbers, and
unknown backend names. They never create or overwrite the input file.

```sh
tests/eval/build/bench_file_pipeline \
  --file INPUT --bytes N --backend posix \
  --chunk 65536 --iterations 3 --compute-bytes 256

# Backend: posix | io_uring | io_uring-fixed
# --block-size is an alias for --chunk.

tests/eval/build/bench_cuda_staging \
  --direction load --memory pinned --input INPUT --bytes N --chunk 65536

tests/eval/build/bench_cuda_staging \
  --direction checkpoint --memory pageable --output NEW_FILE --bytes N --chunk 65536
```

For CUDA, `--host-memory` aliases `--memory` and `--chunk-size` aliases `--chunk`.
`--cuda-library PATH` selects an explicit driver library; it never retries a
different library. Checkpoint output is created with `O_EXCL` and mode 0600, so
an existing path is refused. A failed run removes its own partial output.
Successful checkpoint output remains for inspection. File I/O is always
buffered: there is no hidden O_DIRECT-to-buffered transition or cache flushing.
The standalone programs cap chunks at 16 MiB and requested file ranges at 1 TiB;
the pipeline caps iterations at one million. The final partial chunk counts
only actual payload bytes. TCP listens only on loopback, on a kernel-chosen
port, with bounded socket waits.

`--fault corrupt|truncate|backend-error` on the pipeline is solely for negative
validation. It must exit nonzero, without a success result. The public checks
also inject real short pread/send calls and EINTR using the test-only
`short_io_shim.c`. The shim is never loaded by normal benchmark commands.

## Completion, timing, and result validation

A successful program emits one JSON object; a failed program emits diagnostics
and no successful result. Exit codes are 0 for a fully validated run, 1 for an
I/O/CUDA/data/validation failure, 2 for invalid arguments, and 4 for an explicitly
unavailable optional backend/driver/device. A runner propagates optional exit 4
as `not_run_capability` or `not_run_hardware` on stderr, never as a passing suite.
The portable suite is mandatory and cannot succeed through a skip.

The pipeline result identifies `backend`,
`route=buffered-file-to-tcp-loopback`, and
`completion=receiver-full-byte-compare`. `read_bytes`, `sent_bytes`, and
`verified_bytes` must each equal `bytes * iterations`. `chunks` counts complete
logical read/send chunks, including each final partial chunk. The receiver
reads an independent reference from the immutable file and compares every
received byte in order, checks for early EOF or extra bytes, and checks guards.
A successful send alone is insufficient. This completion scope does not imply
remote delivery, protocol ACK, storage durability, or native NIC DMA.

`compute_bytes` counts the actual bytes visited by the CPU checksum, limited by
`--compute-bytes` per chunk and by the valid tail. `compute_checksum` consumes
the result. `elapsed_ns` is monotonic wall time from the producer loop through
receiver completion, including reference reads and verification. `cpu_us` is
process user + system CPU time over that interval, including the receiver.
Allocation, file creation, TCP setup, ring setup, and registration are outside
these intervals. There is no warmup or cache eviction; runner-created input is
likely cached. These correctness-focused timings should not be interpreted as
isolated device throughput.

CUDA results identify `backend=cuda_pageable_staging` or
`cuda_pinned_staging`, `direction`, and the ordered route
`buffered-file-host-cuda` or `cuda-host-buffered-file`. `io_bytes` and
`verified_bytes` equal the requested payload. `file_ns` covers pread or pwrite
(and checkpoint fsync); `transfer_ns` covers the requested synchronous transfer
and CUDA synchronization. `elapsed_ns` and `cpu_us` additionally include payload
initialization, full validation readback, guards, and checkpoint file rereads.
Driver/context/allocation setup and cleanup are outside timing. CUDA cleanup
and final file close are checked before any success record. Checkpoint
completion explicitly includes fsync and a full file reread, without claiming
power-loss persistence of the underlying device.

`run.py` rejects nonzero backend exits, missing/incorrect route and completion,
missing counters, short totals, and invalid timing/count types. The functional
checks mutate those records and exercise actual stream corruption/truncation.
No performance threshold or historical result is embedded here.
