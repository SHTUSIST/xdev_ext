# Extracted core FANOUT regression

Run from the repository root:

```sh
python3 kernel/tools/testing/selftests/xdev_ext_mech/fanout_scheduler/run.py \
  --json-output /tmp/fanout-scheduler.json
python3 kernel/tools/testing/selftests/xdev_ext_mech/fanout_scheduler/produced_test.py
python3 kernel/tools/testing/selftests/xdev_ext_mech/fanout_scheduler/recycle_test.py
```

`run.py` compiles the production scheduler, completion handoff, lifecycle
headers and frame-release implementation under UBSan. Device submission,
descriptor construction, OS work queues and session teardown are fixture
boundaries. **There is no DMA, real NVMe/AF_XDP completion, wire data or KVM
execution here.** Cases invoke the real completion entry points using fake
device callbacks. They do not test CREATE or the FANOUT bind fix; the poll
binding regression and lifecycle guest cover those separate boundaries.

The original eleven cases already covered both completion orders, inline
completion, duplicate/late callbacks, preaccept EAGAIN, consumer failure,
STOP, quarantine, same-class consumers and a dependent stage. The additional
cases test error ordering in the other direction, explicit delayed consumers
in both directions, stale tickets after actual batch/frame reuse, and an error
arriving from the last delayed consumer after its peer succeeded, in both
completion orders. The
terminal fixture now calls production `xdev_ext_mech_frames_release()` instead
of substituting a direct lifecycle release.

For `NVMe READ -> {NVMe WRITE, AF_XDP TX}` the normal expected observations are:

| Boundary | Lifecycle and provider custody |
| --- | --- |
| Producer callback | One READY publication, two references, valid length 128; provider still INFLIGHT |
| Both consumers submitted | Both stage claims live over the same frame index and generation |
| First consumer callback | One reference and the other stage's busy bit; OUT_PENDING, unchanged generation, no recycle |
| Delayed peer | 64 extra worker drains preserve that state; producer claim and allocator loan are refused |
| Last consumer callback | FREE, zero references/busy bits, generation advances once; provider still INFLIGHT |
| Worker group barrier | Production frame release changes custody to K_FREE and calls provider recycle exactly once |

Terminal consumers do not publish another READY state: the last reference
goes directly to FREE. READY can reappear when a dependent consumer remains,
or when a preaccept refusal leaves a reference without an active claim.

`fail` and `fail-reverse` use four-stage plans: one failing fanout member
cancels the unissued dependent reference but preserves the accepted peer's
reference. Neither the dependent nor the next producer may start. After the
accepted peer completes, the group aborts once and recycles once. An ambiguous
completion (`quarantine`) instead retains the frame, its live claim and
SEQUESTERED provider custody; recycling stays zero.

`late-error` and `late-error-reverse` first complete one fanout member
successfully in a four-stage plan. Two references remain: the delayed peer
and the unissued dependent. One extra idle worker drain preserves custody
and refuses reuse. The delayed peer then returns `-EIO`; the core cancels the
dependent reference, frees the frame, retains the native error, and aborts
and recycles once. This exercises a different reference budget from the
first-callback failures without multiplying identical idle-drain assertions.

The JSON report records per-stage submissions/completions, callback invocations,
READY publications, midpoint references and busy bits, delayed drains, terminal
groups, provider recycle calls and final lifecycle/custody. Midpoint fields are
sampled only by the non-inline, non-EAGAIN, non-quarantine cases. Stage counters
are `[producer, NVMe consumer, AF_XDP consumer, optional dependent]`:

* Ordinary success/error/delay: submitted and completed `[1,1,1,0]`.
* `dependent`: `[1,1,1,1]`.
* `reuse`: `[2,2,2,0]`, two READY publications and two recycle calls, generation 2;
  three callback invocations per stage include one rejected stale ticket.
* `quarantine`: no recycle, one outstanding reference and AF_XDP busy bit.

Current complete run: 17 cases and 745 assertions. Of these, 256 assertions
come from four cases repeating the same idle-drain check 64 times; those
repetitions do not add independent schedules. These are deterministic
interleavings in a single-threaded fixture, not a kernel memory-ordering or
concurrency stress test. `produced_test.py` separately checks partial producer
lengths and empty-tail retirement; `recycle_test.py` checks a terminal CPU
transform's valid span across recycling.

The sibling `lifecycle_runtime/fanout_trace_test.py` and
`fanout_validate_test.py` currently run from a full product overlay through
the host CI source-tree entry point. They are not installed selftests and
must not be treated as available from a standalone installed kernel test tree.
