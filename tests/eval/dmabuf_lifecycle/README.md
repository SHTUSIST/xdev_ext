# Production lifecycle and Linux dma_fence local experiment

This compares one producer and one consumer with equal valid-length checks and
successful-operation denominators. It measures local synchronization primitives,
not dma-buf end-to-end throughput, DMA, or device performance. No performance
result is included. The retired `kernel/xdev_ext_sm_fence_bench` is not reused.

`lifecycle_core.h` is shared by the real Linux module and the host contract. Its
life arm calls the default production `claim`, `publish(refs=1, len)`, `acquire`,
and `put` API directly. The fence arm uses separate producer/consumer Linux
`dma_fence` objects, real callbacks, signal, get/put, and custom final release.
A signaled-before-add `-ENOENT` explicitly observes the same completion. A held
fence reference delays embedded-object destruction, while a completed payload
can already recycle. Operations are not reused, including after cleanup.

Each operation has independent fences/locks. Callers serialize entry points for
one operation; the module's completion barriers order its producer and consumer
contexts. This experiment does not claim a general concurrent wrapper API.
Cleanup follows joined workers; registered callbacks are removed under the
fence lock, private refs are put once, and embedded storage survives final
release. No RCU work is scheduled by the custom release callback.

Build against a fully built matching Linux tree with its genuine Module.symvers:

```
make KDIR=/path/to/matching/kernel/build
```

A prepared headers/output tree without Module.symvers can compile the real
`lifecycle_bench.o` target; it cannot complete MODPOST/link. Do not fabricate
symbol versions or suppress MODPOST errors. GCC and Clang object/module builds
and actual matching-kernel execution are separate evidence.

Host checks (GCC and Clang must be on PATH):

```
python3 -m unittest discover -s tests/eval/dmabuf_lifecycle -p 'test_*.py' -v
```

The frozen fixture replaces Linux runtime dependencies only. Its output says
`host-contract: non-kernel-runtime; no timing evidence`. It cannot establish
Linux scheduling, locking, RCU, allocation failure injection, or runtime safety.

The runner never loads a module without `--execute`. Dry runs neither require a
built module nor create output directories:

```
python3 tests/eval/dmabuf_lifecycle/run.py --mode check --iterations 8 \
  --module tests/eval/dmabuf_lifecycle/lifecycle_bench.ko --output /path/to/result --dry-run
```

In a separately authorized, matching disposable kernel, with debugfs already
mounted, replace `--dry-run` with `--execute`. Do not load this on a shared host.
The module synchronously runs both signal orders, identity/duplicate/held-ref
checks, two real kthreads with completion-controlled interleaving, callback
registration failure before registration 1/2, allocation-failure handling, and
teardown checks. Every benchmark array element is used once. Init fails on any
failed check. Debugfs produces a result only after all checks succeed. The
runner preserves load/unload errors and validates the full report. These
checks are implemented; a host build does not mean they have executed.

For explicit negative kernel checks, `insmod ... mode=check iterations=8
fail_alloc_at=1` or `=2` must fail with ENOMEM, and `fail_callback_at=1` or `=2`
must fail with ENOMEM. Successful check already exercises both callback cleanup
failure paths and the allocation helper's injected NULL path. Verify these
negative loads and check-only execution under lockdep/KASAN in the matching
guest before claiming runtime acceptance. No timing fields appear in check.

Time mode additionally requires an audited `--environment-manifest` JSON with
`kind=physical`, `physical=true`, `hypervisor=false`. The runner's own detected
hypervisor overrides that assertion; the x86 module also refuses hypervisors.
Unknown, fixture, and VM environments cannot time. Non-x86 time is unavailable.
The manifest is operator evidence, not automatic physical-machine attestation.
Both module and runner must use committed sources: Kbuild embeds exact Git SHA
and production-header SHA256; the runner verifies these and records the loaded
module hash and running release. A missing debugfs mount is never auto-mounted.

The time path is explicitly serial process context. It reports aggregate
prepare, completion, full-cycle, and separate allocation nanoseconds, each with
its successful denominator. Completion includes necessary valid-length
observation and consumer completion. Prepare includes callback registration and
per-operation fence context allocation. Full-cycle includes prepare, completion,
and ref/callback cleanup plus loop/timestamp overhead; it excludes setup array
allocation and the final full oracle. Allocation is a separate raw total, so
amortization must be explicit. Two-context checks occur outside timed samples.

Both arms allocate the same array of wrappers once through `kvcalloc`, with no
steady allocation calls. The reported allocation count counts helper calls,
not the allocator's internal page allocations. Equal wrapper sizes retain the
unused fence storage in the life arm; this controls this experiment's storage
layout, not the compact production pool's memory cost. Both orders are checked;
reported time uses callback-first, with registration in prepare. Do not infer
end-to-end speedup or dma-buf limitations from any local ratio.

Each runner invocation requires a new output directory and refuses an existing
`/sys/module/lifecycle_bench` or benchmark debugfs directory/result. It verifies
`modinfo -F name` before loading. A fresh random `run_nonce` is passed to the
module, then checked against that module's read-only sysfs parameter and its
new debugfs document; sysfs and report mode/iterations must also match the
request. An unverified module instance is retained and reported, never unloaded
by guessing its ownership. This prevents accidental stale/wrong producer
attribution; it does not defend against a hostile root-controlled kernel.

`raw-report.json` preserves the module document unchanged. `result.json` starts
as an unsealed, noneligible running receipt, then is atomically finalized only
after validation and unload checks. Failed unload, loader exceptions, or
surviving module/debugfs resources produce status failed and
`performance_eligible=false`, while preserving raw and command receipts. No
force unload is used. A refused reused output directory is left untouched;
its existing files belong to the previous invocation, and the new invocation
reports refusal on stdout.
