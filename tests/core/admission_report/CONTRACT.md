# Failed CREATE value report contract

The caller must receive the actual CREATE result, failed stage, failed execution
phase, original admission caps and requester identity as an owned value. The
report remains readable after session, endpoint and ring release. It must not
re-run describe, admission or premap to reconstruct an explanation.

The accepted design is docs' xdomain-admission-diagnostics plan, Task 1. This test
area deliberately adds no device/provider implementation and no kernel report
cache. Host extraction runs are software control-flow evidence, not DMA evidence.

## Wire compatibility

Keep old CREATE=1, STAGE_CAPS=8 and STOP_REPORT=9, the old CREATE layout and caps
layout unchanged. Reserve CREATE_REPORT=10; a future collision requires an
explicit integration decision rather than renumbering any established opcode.
New envelope fields use fixed width integers and aligned u64, no pointers.
Envelope {u32 size, version; create; report} has version 1, create.session_id=0
and every report byte zero on input. Copy the complete input once; validate
before allocation, provider, device or BPF operations. Bad size/nonzero output
returns -EINVAL, unsupported version -EOPNOTSUPP, copy fault -EFAULT. Unknown op
on an older kernel may be -EINVAL. Neither the fixture nor lib may synthesize a
successful report or retry CREATE when a kernel lacks the new operation.

A successful syscall means the complete report was copied out. report.result is
the original CREATE 0/-errno. result, rollback_errno and cleanup are independent.
Failed CREATE sets every report/caps/observed session_id to zero; failed_stage is
the actual stage or UINT32_MAX if the failure has no stage. Success has phase=0
and a nonzero session ID. Phase numbers 1..15 follow the accepted plan's actual
execution locations; no need to invent one failure injection per phase.

Report valid bits REQUESTER=1, DESCRIBED=2, DECIDED=4, CAPS=8, OBSERVED=16,
POST_ROLLBACK_RETENTION=32 distinguish zero facts from unavailable facts.
Describe=-EIO stops before decision. Describe=-EOPNOTSUPP continues through the
real decision with backing=0. Premap failure preserves the completed decision's
reachability/refused/backing, reports the original premap errno, and never marks
mapping ESTABLISHED. Only no-topology may be forced by an administrator.
Requester's PCI domain/bus/devfn are values, never pointer addresses. A temporary
PCI ref fixes the actual requester across cleanup; every acquired ref is put
exactly once on success, release, quarantine and failed copyout. No BDF relookup.

## Cleanup and publication

cleanup NONE=0 means no session existed; RELEASED=1 means actual free path;
RETAINED=2 means checked-unbind/quarantine path. A nonzero release return does
not imply RETAINED: last_err may be returned after all resources were freed.
UNKNOWN must preserve pool/files/module/callback custody. No id=0 STATS/STOP or
ENOENT lookup may serve as proof of safe release. RETAINED blocks recreate and
close with EBUSY; only an explicit later release authority can change that.

Original CREATE retains its existing put_user-before-activate ordering and error
priority. New CREATE_REPORT binds/prepares/activates while unpublished and with
progress_ready false. Only after complete successful report copyout may the
nonfailing publication step link the session and enable progress. A successful
CREATE whose report copyout faults rolls back exactly once and is never linked,
progressed or retried. Failure-report copyout fault does not cause a second
CREATE or a second release. Original failure errno survives rollback failure.

Failed class attach may free its private requester/endpoint before returning;
copy facts to stage-owned value storage before that happens. Outer CREATE reads
only that value. No callback modifies the caller's saved report. Cleanup-time
retention sampling has POST_ROLLBACK_RETENTION and clears the earlier RETENTION
valid bit; it must not claim a common atomic capture time.

## Executable coverage and honest limits

run.py compiles unmodified production function bodies and real admission rules.
The fixture supplies existing OS/topology/provider/BPF boundaries. It executes
old CREATE, real session_bind, real requester_bind, real checked release and
real STAGE_CAPS. Current behavior records show why a new value-report interface
is necessary. Old CREATE remains a passing characterization; only the numeric new operation
is a feature RED against the unimplemented dispatcher.

The runner sends a fixed numeric opcode 10 with the independent 496-byte v1
wire envelope through the actual register dispatcher. The original dispatcher
returns -EINVAL for the valid operation; that executed failure is the new-feature
RED. It is not a missing-symbol or compile-failure RED. The original CREATE gap
remains a passing characterization: old CREATE intentionally preserves errno-only
behavior. --frozen-input replays the earlier emitted production functions and
exact copied header set, so RED remains reproducible while another author writes
production code. Replayed function hashes are recorded with the original receipt.

Current executable conformance covers the main requester refusals, bind/prepare
stage attribution, describe unsupported/error, premap once, cleanup disposition,
primary/rollback errno separation, temporary PCI-reference balance, requester BDF,
failed report zero IDs, success and failure copyout rollback, copyout-before-
publication, owned report survival after free/ring destruction, old ABI layout,
and every nonzero output byte plus size/version/id/read-fault validation before
device/BPF side effects. A positive supported operation gates malformed-input
checks so an old unknown-op EINVAL cannot pass those tests accidentally.

Blocked outside this host boundary: Task 2 dynamic observed diagnostics and real
requester-retention ledger composition; full kernel/device execution and actual
asynchronous publication/remove interleavings. Retention is an explicit stable
ledger API boundary here. No lib or ctl behavior is certified by these tests.

## Publication admission regression

The fixture extracts the complete production session_admits predicate and
batch_get_locked allocator; the generation-current test boundary only fixes the
registered ops generation as current. It supplies one real free batch object.
The user copyout boundary attempts that real batch admission while CREATE is
activated but unpublished. Report paths must return ESHUTDOWN with unchanged
session refs/inflight. Failed copyout must release refs=1/inflight=0 and never
free accepted custody. Each of the three list-insertion boundaries independently
attempts admission; all three attempts must remain denied. After complete list
publication the success path admits an actual batch, increments refs/inflight,
and returns them after completion.

A sequential STOP event inside successful copyout must still deliver result=0
and a valid ID, leave the session stopped, and keep later admission closed. Old
CREATE uses the original behavior and remains able to admit after return. These
are deterministic callback-boundary schedules, not proof of concurrent SMP lock
interleavings or an actual RX device path. Original missing-op RED artifacts are
retained unchanged. Older --frozen-input probes lacking the actual batch helper
are recompiled exactly with their original case list; no current production
helper or fabricated replacement is silently mixed into an old snapshot.
