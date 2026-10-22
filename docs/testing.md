# Testing

Tests have different requirements and establish different properties. Record the project revision, configuration, command, complete output, exit status and relevant tool versions for each run.

| Tier | Entry point or location | Establishes |
|---|---|---|
| Compact host tests | `python3 scripts/test_host.py` | Behavior of the selected software tests without a full kernel tree or device access |
| Component selftests | `kernel/tools/testing/selftests/`, `gpu/tests/` | Component-specific admission, plan, lifecycle and failure behavior; requirements vary by target |
| Kernel/BPF build and load | Matching kernel build and BTF | Compilation, linkage, ABI and verifier acceptance for that configuration |
| Isolated guest | Integration and guest fixtures under selftests | Actual execution of the selected custom kernel interfaces with the guest's software devices |
| Physical devices | A supported device/provider combination | Execution on the recorded devices and topology; performance requires separate measurements |

## First check

From the repository root:

```bash
python3 scripts/test_host.py
```

The script defaults to both components and enables UndefinedBehaviorSanitizer. Use `--component kernel` or `--component gpu` to select one component, `--verbose` for program output, or `--no-sanitize` when the host runtime is unavailable; record those choices. `CC` selects the compiler. The script's test selection defines its scope. Preserve failures and skips in the result; do not infer that every repository test ran from this entry point alone. A test that uses a CPU copy, fake ring, mocked completion, or software compression provider cannot prove physical DMA or hardware acceleration.

## Source preparation tests

The source-assembly regression suite uses tiny local Git repositories and performs no network fetch:

```bash
python3 -m unittest discover -s tests -p test_prepare_sources.py -v
```

It checks pin/ref identity, overlay preservation, conflicts, archive/link safety, and preparation error paths. It does not download or build the complete public upstream trees.

## Component tests

After [preparing the Linux sources](build.md), individual Linux selftests can use their Makefile targets, for example:

```bash
make -C kernel/tools/testing/selftests/xdev_ext_mech_tools run_tests
```

Read the selected target's Makefile and requirements before choosing it. Some tests require sanitizer runtimes, libbpf, matching BTF, root capabilities, a custom kernel, or devices. The full kernel selftest framework is supplied by source preparation.

## Comparison workloads and application call shapes

[`tests/eval/`](../tests/eval/README.md) provides file-to-loopback-TCP comparisons using POSIX or optional io_uring, plus optional CUDA pageable/pinned staging. Programs compare every byte and reject failed, truncated or corrupted runs. Their documented timing includes validation work; they do not measure the current shared-page session or physical device performance.

[`tests/eval/apps/`](../tests/eval/apps/README.md) reuses the current positional-file and UDP workloads with the test-only userspace kernel model, and checks compatible TCP/buffered-file/small-direct-I/O fallback. Exact counters distinguish custom requests from fallback. These are reproducible call shapes; actual Redis/FIO application runs and actual guest execution require separate evidence.

[`tests/eval/gds/`](../tests/eval/gds/README.md) provides an optional native cuFile load/checkpoint comparison, with official SDK types, exact bytes and native-path counters. Missing dependencies or devices refuse execution; SDK-dependent host checks cannot certify a GPU transfer.

[`tests/iaa/`](../tests/iaa/README.md) adapts the five-case IAA syscall gate to the current UAPI. `make -C tests/iaa all check` builds the native executable and runs host observation/lifetime fixtures. Its separate native command requires a matching kernel and provider, and checks exact completion, produced length, full bytes, guards, statistics and teardown. CryptoAPI software fallback means that even native syscall success requires separate evidence before attributing execution to IAA hardware.

## Guest and device runs

A guest fixture can exercise the actual kernel path while using a software device or simulated provider. Report that device model with the result. Verify the tested kernel, BPF objects and providers match the intended revision and configuration.

The integration harness's `--compat` run also exercises four simultaneous frontend workloads: four threads in one process and four independent processes with two threads each, using both the socket-only route and the existing CE–CE–socket route. Every actor sends 65 datagrams with distinct actor/round data at 31, 257 and 1023 bytes. Validation checks all destination bytes and guards, exact per-actor session/stage/STOP counts, process file-descriptor counts, and observed overlapping call intervals. Cross-process runs also require overlap across distinct process IDs. Caller overlap establishes concurrent application execution; it does not establish simultaneous native DMA acceptance. Keep the whole-guest timeout enabled for blocked calls or teardown.

The standalone workload and evidence-validator checks need no custom kernel:

```bash
python3 kernel/tools/testing/selftests/xdev_ext_preload/xdev_ext_preload_concurrency_test.py
```

This host command uses ordinary loopback UDP and deliberately corrupted/serialized variants. Fast libc sends may finish without observed call overlap; the host profile reports that separately after checking complete actor data and resources. The guest verdict still requires measured overlap. Synthetic runtime counter fixtures test the validator; actual custom-kernel execution requires the guest run.

For a transfer, check complete destination bytes, source immutability where required, guard regions, native submission/completion counts, final ownership, and STOP results. For a fault-injection case, state the expected refusal, failure, or UNKNOWN outcome before running it. A deliberately failed transfer can pass its fault test without becoming a successful transfer.

Performance claims require an explicit workload, actual physical devices, topology, timing definition, repetitions, and retained output. Module compilation and software-device guest correctness do not supply those measurements.

## Repository CI

The [host workflow](../.github/workflows/host.yml) is configured to run the compact checks with GCC and Clang, plus source preparation/layout regressions, mechanism and CE source contracts, peer lifetime checks, integration harness/validator regressions, and GPU source/fence checks. The mechanism source step runs 49 source checks and the actual CE registry admission/cleanup checks directly from the tracked overlay, needs no upstream Linux tree, and rejects failures or skips in its captured output. The compact checks also include CE ownership and concurrent frontend payload regressions. These jobs do not boot a guest or execute physical device DMA.

Both compiler jobs also run the existing reliable control admission and native completion map teardown regressions: two STOP/ACK BUILD cases and five mapping/UNKNOWN ownership cases. The same scripts are registered in the mechanism selftest Makefile; they execute extracted production functions and require no device or guest.
