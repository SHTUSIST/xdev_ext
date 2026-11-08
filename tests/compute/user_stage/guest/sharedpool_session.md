# Actual kernel sharedpool custody qualification

`sharedpool_session_guest` uses two distinct single-stage USER sessions on one
ring and one IOU UMEM. It exercises real kernel borrowing, USER ready/completion,
CREATE_PROGRAMS reports and STOP_REPORT. It has no kernel model and performs no
NVMe/GPU DMA or performance measurement.

## Build and run

Build the optional target against the existing source view, built libxdev_ext
archive and benchmark support headers; it does not build a kernel or rebuild
the supplied archive:

```sh
make -C USER_GUEST_DIR KERNEL_SRC=KERNEL_VIEW \
  SHAREDPOOL_LIBXDEV=EXISTING_LIBXDEV_ARCHIVE \
  SHAREDPOOL_COMMON=BENCHMARK_COMMON_DIR sharedpool_session_guest
```

`BENCHMARK_COMMON_DIR` contains the existing `fd_check.h` (the logical view uses
`tests/eval/common`). Reuse the existing `chain_plan.bpf.o`; only its
`chain_user_ops` map is attached by the public library. CREATE_PROGRAMS uses the
global default selector `-1`, not an explicit PRIVATE link. This utility does
not qualify PRIVATE-program isolation.

```sh
./sharedpool_session_guest --case all --plan-obj CHAIN_PLAN_OBJECT
```

The executable must run inside the project kernel; successful host compilation
or component tests do not satisfy this requirement. Run the guest under the
existing VM watchdog as well: user-space deadlines can reject a late syscall
return but cannot interrupt a kernel syscall that never returns.

## Cases and failure oracles

Each case creates a fresh ring, UMEM and two independent session IDs. `all` runs
these cases in order, stopping at the first failure. They can also run separately
by replacing `all` with a case name.

| Case | Interleaving | Required evidence |
| --- | --- | --- |
| `returned-stop` | A completes; B borrows the same indices and holds its grant; A stops. | B's original live ticket, READY entry, frame/ring metadata, counters, payload and guards remain unchanged; B completes the original batch. |
| `busy-start` | A holds its grant; A repeats START; B attempts the same frames. | Both attempts return exactly `-EBUSY`; B remains idle, A's grant/data/guards remain unchanged; after A's completion B can borrow and complete. |
| `concurrent-start` | Two threads share a release gate and issue A/B START on the same frame indices. | Exactly one succeeds and the other returns `-EBUSY`; the loser remains idle and another attempt while the winner holds also returns `-EBUSY`; the winner's grant is unchanged; the loser succeeds after the winner finishes. Two failures are never a pass. The ring lock may serialize the syscalls; this is a contention litmus, not an exhaustive scheduler exploration. |
| `stale-completion` | A completes; B holds the same physical frames; A republishes its old ticket with a deliberately invalid old output length. | A's done consumer advances to exactly 2 and its reject count to exactly 1, with no second completion/publication; B's original grant and bytes remain unchanged both after this rejection and after A's STOP. A timeout or unconsumed entry never counts as rejection. |
| `strict-stop` | Both USER stages use `XDEV_EXT_USER_F_STRICT_ASYNC`; A holds a grant; a second thread begins A's STOP_REPORT; B attempts the same indices before A acknowledges quiescence. | Observe `K_DRAINING` and `K_STOPPED`, the original nonzero ticket and an unfinished STOP; B returns exactly `-EBUSY` and stays idle, and A's complete grant and bytes are unchanged. Then the CPU owner posts status 0 for the original ticket; STOP must return successfully with a consumed done, one completed/aborted batch, no sequester or error, and a cleared ticket. Only then does B borrow and complete. |

The fixed layout uses a 4 KiB group across two noncontiguous frames with header
and tail guards. All 8 KiB in the two held frames are compared, and every byte of
the six-frame pool is checked against its initial pattern. There is no synthetic
producer that rewrites a payload; this validates preservation and custody, not a
storage or GPU transformation.

USER has a 60-second lease deadline; individual waits, hold observation and the
complete case use smaller bounded budgets. The strict case must acknowledge
quiescence within the kernel's `XDEV_EXT_USER_STRICT_GRACE_MS` interval, currently
one second. Missing that interval fails qualification; it is not treated as a
successful cancellation and does not by itself identify a custody defect.
These clocks enforce correctness deadlines and no elapsed-time or rate result
is emitted.

Both sessions have independent validated report IDs and terminal eventfds.
Known USER grants are relinquished before normal teardown. In `strict-stop`,
STOP runs concurrently only to expose its drain boundary. A kick ioctl can race
successful unbind after done publication; `-ENOTCONN` is accepted only when the
successful STOP report and exact ring indices prove the original done was
consumed. It never causes a second completion submission.

Shared resources close once after synchronous releases, and the complete FD
check precedes the final `SHAREDPOOL_KERNEL_QUALIFICATION=PASS` line. Unknown
delivery or failed teardown skips explicit resource cleanup and reports failure.
The command then exits; this does not establish a long-lived userspace recovery
owner, and kernel/provider lifetime protection across process exit needs separate
validation. Stderr contains case, ID, race and STOP diagnostics; cleanup success
cannot change a failed case's verdict.

## Meaning of USER completion

`XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL` permits the control mapping; it does not
select strict external-async lifetime semantics. The first four cases use the
legacy synchronous USER contract and cooperative completion. STOP can cancel
legacy CPU USER work. It cannot revoke a CPU mapping or prove that a worker
which ignores the contract has stopped writing into that mapping.

The strict case selects `XDEV_EXT_USER_F_STRICT_ASYNC` on the stage itself.
Its status-0 completion is the owner's assertion that all previous uses have
quiesced. Here the owner is CPU code with no outstanding external operation.
The test therefore validates the kernel lifetime handshake, not a GPU fence,
DMA completion, cache visibility, or a malicious/still-running worker. A real
GPU owner must synchronize its operation before publishing that assertion.

An UNKNOWN outcome must prevent downstream reuse and retain uncertain
resources. This guest deliberately does not declare UNKNOWN a recoverable
success or inject an unreclaimable owner into `all`; UNKNOWN, grace expiry and
late-callback classification have separate extracted-production CPU contracts.
Actual cross-session UNKNOWN/quarantine in a disposable project-kernel VM
remains an additional required qualification.

## Acceptance layers

| Layer | Existing entry | What a pass establishes | What still needs another layer |
| --- | --- | --- | --- |
| CPU verdict components | `make test TEST=tests/compute/user_stage/test_sharedpool_session.py` | Executes the guest's actual observation predicates with deterministic invalid snapshots, start-result combinations, stale-done counters and drain boundaries. It replaces no syscall because it calls none. | No kernel execution, scheduling, frame borrowing or DMA. |
| CPU extracted-production kernel contracts | Existing lifecycle ordered-frame and strict USER tests under `tests/core/lifecycle/runtime` and `tests/compute/user_stage` | Exercises extracted kernel transition functions with explicit fixture boundaries; useful for STOP ownership and UNKNOWN/late completion counterexamples. | Shared structs and simulated native boundaries are not a booted kernel or real physical pages. |
| Real kernel USER custody | `sharedpool_session_guest --case all --plan-obj CHAIN_PLAN_OBJECT` in the project-kernel guest | Actual same-ring IOU_UMEM loans, live USER grants, rejection, STOP drain, resource release and reborrow under the listed cooperative interleavings. | Neither physical NVMe/GPU DMA nor GPU synchronization; finite cases do not establish sustained batching. |
| Software CE data path | Existing software-CE path documented in the chains README and its qualification runner | Coordinator/provider wiring, byte transfer and guard checks for that selected software path. | A CPU/software copy cannot certify physical DMA or device visibility. |
| Physical NVMe/GPU DMA | `chain_bench --two-session-correctness nvme-gpu-correctness.json`, with the actual native devices and project kernel specified by the chains README | Only an actually completed, validated native run qualifies NVMe READ into shared IOU_UMEM followed by CE H2D and GPU readback. Preserve the selected backend, completion/STOP evidence and guard checks. | Sustained batch pipelining, overlapping queues, UNKNOWN recovery and device-reset/lifetime testing need separate workloads. |

These are acceptance definitions and commands, not execution results. Missing
kernel, BPF/libbpf build dependencies, software-provider runtime or native
hardware must be reported as NOT RUN for the affected layer. Never infer a
higher layer's pass from a lower layer's result.
