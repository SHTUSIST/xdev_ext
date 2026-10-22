# Application call shapes and transparent frontend boundaries

This directory makes the Redis/FIO/HFT integration audit reproducible without copying the old preload implementations. It tests ordinary libc calls and classifies actual custom requests separately from compatible fallback. These are deterministic call-shape workloads, not runs of Redis, FIO, or a trading application. There are no performance results here.

| Application shape | Current frontend route | Executable verification |
|---|---|---|
| Positional libc `pread`/`pwrite`, including 64-bit variants and admitted positional vectors | Custom requests only for an allowlisted ordinary file opened with `O_DIRECT`, known DIO alignment, eligible buffer/offset/length and available runtime | Rebuild the existing DB workload; compare full output, return/errno trace, independent whole-file digest and every file byte; exact custom request/error counts versus its eligible-call tally |
| FIO native `io_uring` or `io_submit` calls, direct syscalls, statically linked callers | Outside this libc interposition interface | No claim of interception; use an explicit adapter if this interface is required |
| Connected blocking IPv4 UDP `send`, `sendto(..., NULL, 0)`, single-vector `sendmsg` | Eligible positive payloads use the socket custom path when explicitly enabled | Rebuild the existing UDP smoke workload: all three datagrams compared in full, exactly 3 custom sends / 25 bytes / 0 errors |
| Aligned positional log writes plus connected UDP, as two independent HFT primitives | Same file and socket admission rules above | File and UDP groups above verify the two primitives independently; no atomic log/send, log durability or remote ACK claim |
| Small 64B `O_DIRECT` log write at offset 1 | Ineligible, stays in libc; a rejecting filesystem returns its libc error | New fixture compares result/errno and every byte of the final 8192B file with libc; custom read/write/send requests all zero |
| Redis-style TCP `send`, `write`, `writev`; ordinary buffered file `read`/`write` and shared file position | Compatible libc behavior, without custom acceleration | New fixture checks 17 rounds × 3 TCP messages × 257 bytes, stream EOF, receive guards, full file contents and the 64B probe; zero model custom requests |

`writev` here is the non-positional stream operation. Admitted positional `pwritev` is a different supported interface. A zero custom count with correct bytes proves compatibility. It cannot establish acceleration. The common shared write statistics include custom UDP sends; `custom_send_count` and the model's separate `send_sqes` distinguish those from positional writes.

## Run

From the repository root, with a C11 compiler, GNU make, Python 3, pthreads, and a filesystem accepting ordinary `O_DIRECT` files:

```sh
make -C tests/eval/apps check
python3 tests/eval/apps/run.py
```

The standalone Makefile rebuilds the current frontend, its existing **test-only userspace kernel model**, and the existing DB and UDP workloads under `build/`. It does not load modules or require root. The runner scrubs inherited `XDEV_EXT_*` settings, creates only disposable regular files, binds only loopback port 0, uses bounded process timeouts, and fails on any nonzero workload exit. An unavailable `O_DIRECT` prerequisite is a suite failure with the child exit status (including exit 4) in the diagnostic; it is never printed as PASS.

The DB workload uses up to several MiB of scratch space and intentionally includes short reads and failing calls. Its expected custom error counts come from the exact eligible-error tally; successful positional and UDP paths must match their exact counts. Model completion is CPU/host software evidence. It does not prove that a real custom kernel opcode, DMA provider, physical device or application benchmark ran.

To retain raw per-process output and complete files, choose a new empty directory:

```sh
python3 tests/eval/apps/run.py --output tests/eval/apps/build/retained-run
```

Successful stdout lines identify `evidence=host-model` and distinguish `custom_sends=3` from `custom_requests=0 scope=compatibility`. The final line records `real_thirdparty_app_runs=0 physical_dma_evidence=0`. Failures exit 1 and print `FAIL`; CLI misuse exits 2. `test_contract.py` executes the real suite, then checks rejection of an actual whole-file byte corruption/truncation, altered or missing custom counters, duplicate reports, an altered return/errno trace, a false acceleration claim for fallback, and nonzero exit with a PASS marker.

## Matching-kernel evidence

The existing [`xdev_ext_preload_mech_guest.sh`](../../../kernel/tools/testing/selftests/xdev_ext_preload/xdev_ext_preload_mech_guest.sh) separately runs the UDP smoke and DB workload on a matching guest kernel. Its host validator checks exact custom counters against the DB's eligible-call tally. The guest mechanism workload also covers bounded connected UDP, lifecycle and concurrent session/provider tests. Use those actual guest artifacts and their recorded source SHA to substantiate real custom execution. Running this directory alone does not supply that evidence, and the new TCP/64B fallback fixture runs on the host model rather than inside that guest.

## Optional actual FIO

No FIO executable is needed for the suite. Verify that a chosen executable reports a version such as `fio-3.x`; a Python Fiona command named `fio` is a different program. The following optional example requires a matching custom kernel and dynamic libc positional calls from the selected FIO build. It was not executed by the call-shape suite:

```sh
make -C tests/eval/apps
fio --version
scratch=$(mktemp "$(pwd)/tests/eval/apps/build/fio.XXXXXX")
trap 'rm -f "$scratch"' EXIT HUP INT TERM
LD_PRELOAD="$(pwd)/tests/eval/apps/build/libio_uring_unified.so" \
XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_PATHS="$scratch" \
XDEV_EXT_PRELOAD_FRAME_SIZE=4096 XDEV_EXT_PRELOAD_REPORT=1 \
fio --name=positional-verify --filename="$scratch" --size=4m \
    --ioengine=psync --direct=1 --bs=4k --rw=write \
    --verify=crc32c --do_verify=1 --iodepth=1 --numjobs=1
```

Keep FIO verification output and the frontend reports together. FIO success alone does not establish custom execution; inspect nonzero positional custom counts, their errors, and complete verification results for the exact build/configuration. Do not relabel a native `io_uring` engine run as preload acceleration. The suite also does not launch an installed Redis server or infer Redis transaction/AOF correctness from the TCP fixture.

## Reuse and remaining interface work

The new fixture and runner are GPL-2.0. The DB workload, UDP smoke, frontend and model retain their existing SPDX notices and are compiled directly from the current repository, rather than vendored copies. Selected historical FIO/HFT/Redis C wrappers were used only to identify call shapes. Their global ring/UMEM buffers, fixed-offset submissions and old opcode construction are not imported. No historical configuration or benchmark result is part of this suite.

Supporting TCP/vector stream takeover, shared-offset asynchronous submission, or a smaller-than-DIO-alignment direct log would require explicit new API/admission/lifecycle semantics and separate correctness tests. None follows automatically from reusing the existing safe positional and connected-UDP shapes.
