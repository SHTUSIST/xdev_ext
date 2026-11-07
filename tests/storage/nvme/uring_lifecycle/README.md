# Native NVMe io_uring lifecycle regression

This test executes the current production issue, binding, unwind, end-io and
task-work functions as C, using explicit replacements for external kernel APIs.
It checks the composition that pure lifecycle transition tests cannot cover.
It is a **Host boundary regression**, not a kernel object build, real BPF
execution, io-wq/task-work scheduling test, or physical DMA test.

## What runs

`run.py` reuses `SourceSelection`, production function extraction and portable
headers from the existing native Host fixtures. It selects the actual
`nvme_uring_cmd_io()`, `nvme_uring_cmd_end_io()`, `nvme_uring_task_cb()`,
binding token operations and lifecycle headers. It records the selected
source hashes and checks that they did not change while the tests ran.

The fixture replaces fixed-buffer import, allocation, BIO mapping, policy
invocation, request submission and task-work publication at their API
boundaries. Request and BIO objects have real Host allocations. The
`io_uring_cmd_done()` replacement immediately frees `op_data`, matching the
pinned kernel cleanup boundary; ASan can therefore catch a later sidecar
access. The fixture's enclosing async-data object remains embedded in the
test command and does not model its kernel cache lifetime.

The eleven cases are:

1. Request allocation returns `-EAGAIN` twice, then succeeds.
2. User/BIO mapping returns `-EAGAIN` twice, then succeeds.
3. Request allocation fails with `-ENOMEM`.
4. User/BIO mapping fails with `-EFAULT`.
5. Policy invocation returns `-EAGAIN`; issue returns terminal `-EBUSY`.
6. Policy returns a terminal decision; issue returns `-EPERM`.
7. Final admission returns `-EAGAIN`; issue returns terminal `-EBUSY`.
8. Final admission detects stale identity and returns `-ESTALE`.
9. Task-work consumes completion before the block layer frees the request.
10. A cancelled request completes with `IO_URING_F_TASK_DEAD` and `-EINTR`.
11. Task-work runs inside the `end_io` publication call, so `io_uring_cmd_done()`
    frees the sidecar before `end_io` returns; ASan reports any `end_io` access
    to the sidecar after publication.

The retry cases change the simulated userspace iovec after its first import
and advance each local mapping iterator. They require one import and an
unchanged saved vector on reissue. They also require zero policy calls and
zero submissions on every failed pre-dispatch attempt, followed by one policy
call and one `blk_execute_rq_nowait()` call on successful issue.

Terminal and completion cases count allocation/free, BIO map/unmap, policy
pin/unpin, invocation/completion and done. They check cleanup ordering,
request ownership transfer, live-sidecar repeated unwind, and token release
before done. The extracted binding implementation uses its real atomic token
consumption operation.

With `--mutations`, four copies of the extracted source independently remove
post-policy errno conversion, repeat vector import, repeat request submission,
or omit policy completion. A mutant counts as caught only when it compiles,
exits with the designated assertion, and emits exactly one matching FAIL line.
Crashes, compiler errors, sanitizer findings and unrelated assertions do not
count as successful mutation checks.

## Run the Host regression

Run from the canonical repository root. GCC, Python 3, ASan and UBSan are
required. The output directory passed to the runner must not already exist.

```sh
STOR11B_OUT="$(mktemp -d)"
CC=gcc python3 tests/storage/nvme/uring_lifecycle/run.py \
  --source-root "$PWD" --out "$STOR11B_OUT/uring" --mutations

python3 tests/storage/native_member_7b/verify.py \
  --source-root "$PWD" --out "$STOR11B_OUT/native-member-7b"
```

The first command emits `result.json`, extracted C, build logs and run logs.
A successful baseline ends with:

```text
HOST_LIFECYCLE_PASS cases=11 kernel_scheduler=not_run physical_dma=not_run
```

The existing `native_member_7b` suite remains responsible for its state,
adapter and lifecycle mutation coverage. This regression does not copy its
transition tables. Host CI invokes both suites independently.

### Limits of the Host result

- Repeated NONBLOCK calls followed by a blocking call simulate driver reentry.
  They do not execute the core io-wq flags or the IOPOLL retry loop.
- Task-work-before-request-free is a serial interleaving after `end_io`
  returns; the publication case runs task-work synchronously inside the
  publication call. It does not test publication concurrency or cross-CPU memory order.
- TASK_DEAD is an injected flag. Actual process exit, fallback task-work and
  inflight drain do not execute.
- Import/map and policy pin/invoke are explicit replacements. No fixed pages,
  BPF VM, registry detach, RCU grace period or physical DMA is exercised.
- BUILD-stage execution is explicitly unsupported in this fixture. Its result
  applies to the binding policy path.
- A second callback on a freed sidecar is not a supported test operation.
  State-helper idempotence and token `xchg` do not provide callback storage
  lifetime. The legal path still depends on one block end-io and one task-work
  consumption per accepted request.

## Reused guest regression: opted-in pre-dispatch retry

The existing `../passthru/nvme_sgl_gap_runtime.c` now runs its wide,
160-segment fixed vector once with `NVME_URING_CMD_F_XDEV_EXT` before running
the original ordinary control. This reuses its natural NONBLOCK mapping
`-EAGAIN`, io-wq trace, bounce accounting, fixed registration and O_DIRECT
data oracle.

The opted-in arm uses a distinct seed and checks that data immediately. The
ordinary arm restores the original seed so that the existing whole-image
oracle remains valid. A poisoned ring retains its potential pending import
vectors until process exit.

The diagnostic marker is `XDEV_EXT_NVME_SGL_OPT_IN_RETRY`; it is emitted even
when a check fails. A successful run requires exit status 0, no failed TAP
checks, `XDEV_EXT_NVME_SGL_GAP_RESULT=PASS`, and a passing host-side whole-image
oracle. The opted-in checks require the expected data, a mapping `-EAGAIN`,
io-wq reissue, and one matched bounce allocation/free. The ordinary
`XDEV_EXT_NVME_SGL_BOUNCE_CONTROL` diagnostic marker is preserved.

This guest arm does **not** attach a BPF policy or count tokens or hardware
submissions. Its ring is not IOPOLL. It is an executable pre-dispatch retry
case, not the complete KVM acceptance suite below.

Compile the canonical modified source using the existing logical header view:

```sh
python3 tools/layout.py view
gcc -std=gnu11 -O2 -g -Wall -Wextra -Werror -static \
  -iquote build/source-view/kernel/tools/testing/selftests/nvme_xdev_ext_passthru \
  tests/storage/nvme/passthru/nvme_sgl_gap_runtime.c \
  -o build/nvme_sgl_gap_runtime-stor11b
python3 tests/storage/nvme/passthru/nvme_sgl_profile_test.py
```

In an already provisioned disposable guest, copy the binary to
`/opt/stor11b/nvme_sgl_gap_runtime`, resolve the dedicated controller by serial,
and run the following with its corresponding device names:

```sh
/opt/stor11b/nvme_sgl_gap_runtime \
  --controller nvme0 --block nvme0n1 --generic ng0n1 \
  --tracefs /sys/kernel/tracing --allow-write
```

The names above are examples, not an instruction to select the host's first
NVMe device. The runtime verifies model `QEMU NVMe Ctrl`, serial
`UBRSGL0001`, namespace geometry and the dedicated guest setup before its
destructive checks. Use a newly created disposable QEMU raw image, never a
physical host namespace. Preserve the existing host-side whole-image oracle.

Running without device-selection arguments returns KSFT_SKIP (4), which is
not a runtime PASS. Incomplete or invalid device arguments and setup failures
are errors. The current general zero-copy KVM wrapper has no SGL-specific switch; this
document does not claim an existing end-to-end wrapper for this new arm.

## Remaining KVM acceptance protocol (design, not implemented here)

Use the repository's pinned Linux source plus the current product overlay,
a matching build provenance/config, actual io_uring and NVMe, BPF/BTF support
for the chosen binding program, tracing/kprobes, and a KASAN/lockdep debug
profile. Record the kernel commit, overlay commit/patch hash, config, QEMU
version, device model, serial and image hash. The host kernel is not a
substitute for this guest build.

Keep one outstanding command per case initially. Assign a unique
`user_data`, correlate it with the driver command/request, and use a real
attached policy with per-command dispatch/completion counters. Observe
request allocation/free, user BIO unmap, policy pin/unpin, submission and
done. Any dropped trace events or unobserved injection invalidate that case.

Required cases and their oracles:

- **Pre-dispatch retry:** one allocation or mapping EAGAIN, followed by success;
  then repeated EAGAIN in a separate IOPOLL case. Require no policy or submit
  on failed attempts; the accepted command has dispatch=1, submit=1,
  completion=1 and balanced resources. Mutate userspace iovec only after an
  observed first import, without changing the saved descriptor.
- **Post-dispatch failure:** inject EAGAIN from policy or final admission, and
  a hard stale-identity failure. Require terminal EBUSY/ESTALE, no async
  request submission, no second policy call, and one release of each acquired
  token. A dispatch failure may unpin locally before a token is published.
- **Allocation/user-map failure:** inject ENOMEM/EFAULT at the exact intended
  call. Require zero policy and submit; a partially constructed map is cleaned
  by the mapping function, without a second driver unmap.
- **PCI DMA preparation failure:** inject a transient resource failure after
  policy/acceptance and before the NVMe SQ copy. Require one policy call and
  one `blk_execute_rq_nowait()`. Block-layer `queue_rq()` retries may exceed
  one: count actual SQ copies/accepted device commands separately. A failed
  map must unwind partial DMA state before retry; permanent failures must
  still complete and release the command.
- **Completion and exit:** delay task-work, exercise completion before and
  after block request release, then close/kill a process with an accepted
  command. Require the real TASK_DEAD/fallback/drain path, token lifetime
  through completion, exactly one done, and no KASAN/lockdep findings. Record
  whether the command was accepted before exit; otherwise the case did not
  reach the intended ownership boundary.
- **Cross-ring IOPOLL:** share one NVMe poll queue between two rings; let B
  complete A's request while A's task-work is delayed, then force tag reuse
  before A polls again. Inspect the inherited `pdu->req` borrow, request
  generation and queue/hctx lifetime. `iopoll_completed` is set only at done;
  a queue reference alone is not a reference to that request instance. The
  preallocated tag pool means a Host malloc/free UAF is not a faithful oracle.
  The current source audit did not close this lifetime proof; it is not a
  demonstrated STOR-11B regression.
- **Duplicate completion:** exercise stale/duplicate device completion handling
  through a supported controller/test injection path and verify the block
  callback is delivered once. Do not call a saved `end_io` or `task_cb`
  pointer after its request was freed. Supporting arbitrary duplicate driver
  callbacks would require a separate lifetime/serialization design, not an
  enum check inside this state machine.

Failure injection must be request-scoped and record a hit. Do not assume a
static function is eligible for fail_function or return-value injection.
Where the existing kernel has no supported hook, a small test-only hook and
its activation control remain additional work.

BIO mapping before policy is not PCI DMA mapping. The latter occurs in
`nvme_prep_rq()` after the command has been accepted and may cause a block
request requeue rather than an io_uring command reissue. Treating both as a
single pre-dispatch stage would miss this distinction.

None of these KVM scheduling, real BPF or DMA fault cases is established by
a successful Host run. Report missing prerequisites as NOT RUN, not PASS.
