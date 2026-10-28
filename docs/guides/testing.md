# Testing

Performance comparisons follow the [evaluation policy](../reference/performance-policy.md).

Tests have different requirements and establish different properties. Record the project revision, configuration, command, complete output, exit status and relevant tool versions for each run.

| Tier | Entry point or location | Establishes |
|---|---|---|
| Compact host tests | `python3 tools/ci/test_host.py` | Behavior of the selected software tests without a full kernel tree or device access |
| Component selftests | `tests/core/`, `tests/compute/`, `tests/integration/` | Component-specific admission, plan, lifecycle and failure behavior; requirements vary by target |
| Kernel/BPF build and load | Matching kernel build and BTF | Compilation, linkage, ABI and verifier acceptance for that configuration |
| Isolated guest | Integration and guest fixtures under selftests | Actual execution of the selected custom kernel interfaces with the guest's software devices |
| Physical devices | A supported device/provider combination | Execution on the recorded devices and topology; performance requires separate measurements |

## Canonical test entrypoints

Use `python3 tools/test.py <canonical-test> [args...]` or
`make test TEST=<canonical-test> ARGS="..."` for an individual test. The runner
creates an isolated `build/source-view`, resolves canonical inputs through
`source-layout.json`, and preserves the child exit status. Native/logical
paths in the view support existing relative includes; the view is not a Git
checkout. For a Makefile target, use
`python3 tools/run.py --cwd <canonical-directory> make <target>`.

## First check

From the repository root:

```bash
python3 tools/ci/test_host.py
```

The script defaults to both components and enables UndefinedBehaviorSanitizer. Use `--component kernel` or `--component gpu` to select one component, `--verbose` for program output, or `--no-sanitize` when the host runtime is unavailable; record those choices. `CC` selects the compiler. The script's test selection defines its scope. Preserve failures and skips in the result; do not infer that every repository test ran from this entry point alone. A test that uses a CPU copy, fake ring, mocked completion, or software compression provider cannot prove physical DMA or hardware acceleration.

## Source preparation tests

The source-assembly regression suite uses tiny local Git repositories and performs no network fetch:

```bash
python3 tools/test.py tests/integration/build/test_prepare_sources.py -v
```

It checks pin/ref identity, overlay preservation, conflicts, archive/link safety, and preparation error paths. It does not download or build the complete public upstream trees.

## Component tests

After [preparing the Linux sources](build.md), individual Linux selftests can use their Makefile targets, for example:

```bash
make prepare-linux
make -C build/assembled/linux/tools/testing/selftests/xdev_ext_mech_tools run_tests
```

Read the selected target's Makefile and requirements before choosing it. Some tests require sanitizer runtimes, libbpf, matching BTF, root capabilities, a custom kernel, or devices. The full kernel selftest framework is supplied by source preparation in `build/assembled/linux`; the compact source view does not contain every upstream selftest helper.

## Comparison workloads and application call shapes

[`tests/benchmarks/`](../../tests/benchmarks/README.md) provides file-to-loopback-TCP comparisons using POSIX or optional io_uring, plus optional CUDA pageable/pinned staging. Programs compare every byte and reject failed, truncated or corrupted runs. Their documented timing includes validation work; they do not measure the current shared-page session or physical device performance.

[`tests/benchmarks/apps/`](../../tests/benchmarks/apps/README.md) reuses the current positional-file and UDP workloads with the test-only userspace kernel model, and checks compatible TCP/buffered-file/small-direct-I/O fallback. Exact counters distinguish custom requests from fallback. These are reproducible call shapes; actual Redis/FIO application runs and actual guest execution require separate evidence.

[`tests/benchmarks/gds/`](../../tests/benchmarks/gds/README.md) provides an optional native cuFile load/checkpoint comparison, with official SDK types, exact bytes and native-path counters. Missing dependencies or devices refuse execution; SDK-dependent host checks cannot certify a GPU transfer.

[`tests/compute/iaa/syscall/`](../../tests/compute/iaa/syscall/README.md) adapts the five-case IAA syscall gate to the current UAPI. `python3 tools/run.py --cwd tests/compute/iaa/syscall make all check` builds the native executable and runs host observation/lifetime fixtures. Its separate native command requires a matching kernel and provider, and checks exact completion, produced length, full bytes, guards, statistics and teardown. CryptoAPI software fallback means that even native syscall success requires separate evidence before attributing execution to IAA hardware.

## Guest and device runs

A guest fixture can exercise the actual kernel path while using a software device or simulated provider. Report that device model with the result. Verify the tested kernel, BPF objects and providers match the intended revision and configuration.

The integration harness's `--compat` run also exercises four simultaneous frontend workloads: four threads in one process and four independent processes with two threads each, using both the socket-only route and the existing CE–CE–socket route. Every actor sends 65 datagrams with distinct actor/round data at 31, 257 and 1023 bytes. Validation checks all destination bytes and guards, exact per-actor session/stage/STOP counts, process file-descriptor counts, and observed overlapping call intervals. Cross-process runs also require overlap across distinct process IDs. Caller overlap establishes concurrent application execution; it does not establish simultaneous native DMA acceptance. Keep the whole-guest timeout enabled for blocked calls or teardown.

The standalone workload and evidence-validator checks need no custom kernel:

```bash
python3 tools/test.py tests/core/frontend/xdev_ext_preload_concurrency_test.py
```

This host command uses ordinary loopback UDP and deliberately corrupted/serialized variants. Fast libc sends may finish without observed call overlap; the host profile reports that separately after checking complete actor data and resources. The guest verdict still requires measured overlap. Synthetic runtime counter fixtures test the validator; actual custom-kernel execution requires the guest run.

For a transfer, check complete destination bytes, source immutability where required, guard regions, native submission/completion counts, final ownership, and STOP results. For a fault-injection case, state the expected refusal, failure, or UNKNOWN outcome before running it. A deliberately failed transfer can pass its fault test without becoming a successful transfer.

Performance claims require an explicit workload, actual physical devices, topology, timing definition, repetitions, and retained output. Module compilation and software-device guest correctness do not supply those measurements.

## Repository CI

The [host workflow](../../.github/workflows/host.yml) is configured to run the compact checks with GCC, plus source preparation/layout regressions, mechanism and CE source contracts, peer lifetime checks, integration harness/validator regressions, and GPU source/fence checks. The mechanism source step runs 49 source checks and the actual CE registry admission/cleanup checks directly from the tracked overlay, needs no upstream Linux tree, and rejects failures or skips in its captured output. The compact checks also include CE ownership and concurrent frontend payload regressions. These jobs do not boot a guest or execute physical device DMA.

`python3 tools/run.py --cwd tests/compute/nvidia make run-host-bookkeeping` extracts the actual host registration and metadata-query function bodies and checks base-page counts, allocation and quota rollback, pin ownership, lock pairing, and optional frame metadata. It compiles four integer configurations with UBSan, using allocation/GUP stubs; it does not pin kernel pages or run a GPU. Huge-page hints use base-page registration until physical segment continuity is established.

`python3 tools/run.py --cwd tests/benchmarks make hft-check` runs the [HFT-shaped replay](../../tests/benchmarks/hft/README.md)
software producer/receiver, independent complete-packet oracle, concurrent actor,
SEND_ZC ownership, replay-isolation and hardware-entry contract checks. Physical
execution uses its separate admission-gated entry and an actual remote peer;
host fixtures and capability refusals do not establish DMA or performance.

`python3 tools/run.py --cwd tests/benchmarks make cuda-host-check` tests the registered-host compute workload's
scalar orchestration, full-round oracle, guard corruption, error/UNKNOWN retention
and missing-compiler handling. `cuda_host_compute/build.py` separately compiles
the real CUDA kernel with official NVCC without running it. Physical mapped-host
GPU correctness requires a separate device run; the scalar fixture certifies no
pinning, DMA or performance result.

The GCC job also runs the existing reliable control admission and native completion map teardown regressions: two STOP/ACK BUILD cases and five mapping/UNKNOWN ownership cases. The same scripts are registered in the mechanism selftest Makefile; they execute extracted production functions and require no device or guest.

The GCC job builds the actual positional frontend and existing host kernel
model before running the sendmsg metadata and positional scalar/vector
invalid-memory regressions. The positional test compares all twelve exported
API names against the host libc and direct syscalls, including complete file
and mapping bytes, partial metadata, protected payload pages, and permissions
changed after acceptance. Missing O_DIRECT/model takeover capability fails;
it does not turn the test into all-skips. These checks establish host API and
request-publication behavior, not custom-kernel execution, DMA or performance.

Run the same pair through the isolated source view from the canonical checkout:

```bash
python3 tools/run.py --cwd tests/benchmarks/apps make build/libio_uring_unified.so build/libxdev_ext_preload_kernel_model.so
XDEV_EXT_PRELOAD_TEST_DIR="$PWD/build/source-view/tests/eval/apps/build" timeout 300 python3 tools/test.py tests/core/frontend/xdev_ext_preload_efault_test.py
timeout 300 python3 tools/test.py tests/core/frontend/xdev_ext_preload_positional_efault_test.py --build-dir "$PWD/build/source-view/tests/eval/apps/build"
```

Set `CC=gcc` for the build and test fixture compiler. Clang remains required
for BPF bytecode; general host Clang validation is not part of the default
workflow. With prepared Linux sources,
both scripts also belong to the preload selftest's `run_tests` target. Inspect
the complete TAP output for `not ok` and skips: the Linux selftest runner can
return zero even when an individual test fails. The CI step runs these two
scripts directly with pipefail and a 300-second timeout for each script, and
additionally rejects failed or skipped cases in its captured output. The
preload selftest directory also sets a 300-second per-test timeout for the
882-child positional matrix; the global selftest runner is unchanged.

The same CI step runs `xdev_ext_preload_payload_integrity_test.py`. It compiles
the real ordinary-libc workload and a loopback-only fault fixture, requiring
source and receiver to match independently generated bytes. Joint source/wire
corruption, 4097-byte and seven-byte fallback corruption, middle/last receive
corruption and truncation must fail. Both the Python test and its C inputs
are installed by the preload selftest Makefile. This is host correctness,
not a device/provider substitute or a physical DMA result.
