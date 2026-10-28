# XDOMAIN two-host checker

This checker coordinates real GPU-backed XDOMAIN sessions through the production
GPU adapter, peer registration ioctl, mechanism controller, and observer BPF
object. The CPU handles scalar metadata and the bounded verifier summary. It
never reads GPU payload bytes.

Each GPU adapter call records its owner-thread diagnostic snapshot in the durable
JSONL: the public operation, logical checker status, original CUDA result, system
errno, guard error, and validity flags. Reading this snapshot makes no extra CUDA
call. Missing-object OPEN failures and guard-only refusals preserve their actual
source; a timeout is not relabeled as a returned CUDA error.

The SDK-free tests exercise the wire protocol, offset oracle, evidence rules,
and process retention. They do not establish physical DMA, GPU visibility, or
performance. Physical cases remain in `case_registry.CASES` and report
`awaiting-physical-execution` until their required physical evidence exists.
`UNVERIFIED_FORCED` is a separate outcome; it is not a topology pass.

## Software checks

Run from the product worktree root:

```sh
python3 -I -m unittest discover -s tests/eval/xdomain -p test_contract.py -v
python3 -I -m unittest discover -s tests/eval/xdomain -p test_retention.py -v
python3 -I -m unittest discover -s tests/eval/xdomain -p test_oracle.py -v
python3 -I -m unittest discover -s tests/eval/xdomain -p test_cases.py -v
```

Retention tests link the real supervisor and shared authority guard to an
independent blocking owner. Their explicit test-only teardown can kill a
surrogate with no real device resources. Production coordinator cleanup never
kills, terminates, cancels, joins, or reaps an owner whose release is unproved.

## Physical runtime prerequisites

Build with the official CUDA SDK and the matching kernel UAPI. Load the actual
`xdomain_check.bpf.o`, whose maps are declared in `observer_contract.h`; a missing
record, lost observation, global observer error, or incompatible layout fails
closed. The underlying service must expose both its immutable `xdev_ext_link`
token and the versioned `xdev_ext_link_state` incarnation snapshot. An unknown or
inactive link does not yield invented incarnation values.

Each agent requires a root-generated kernel build receipt with
`source_commit`, `kernel_build_id`, `kernel_release`, `config_text`, and the
original artifact paths. It compares the running `/sys/kernel/notes` GNU
build-id and `uname` release with that receipt. SHA comes from the matched build
receipt, not from parsing `uname`. This is research provenance, not a
cryptographic attestation scheme. Preserve the receipt and running kernel
configuration alongside the result.

`--exclusive-creator` records the operator's experiment prerequisite: no other
local creator or external GPU owner is participating. It is not a detector for
noncooperating processes. The agent also inventories MPS processes; an
unreadable inventory or an active MPS server prevents admission. A project-owned
0700 runtime directory and a shared `xdomain-create.lock` serialize cooperating
CREATE collectors. The collector opens `/dev/kmsg` read-only, preserves a cursor,
and records one bounded invocation window without clearing shared diagnostics.
A failed CREATE remains HELD and never triggers a STAGE_CAPS query or automatic
CREATE retry.

An agent is launched with an argv array equivalent to:

```sh
xdomain_agent --identity /PRIVATE/identity.json \
  --evidence-dir /PRIVATE/owner-evidence \
  --kernel-receipt /PRIVATE/kernel-build.json --exclusive-creator \
  --thunderbolt-log /PRIVATE/thunderbolt.jsonl \
  --thunderbolt-receipt /PRIVATE/thunderbolt-receipt.json \
  --helpers-dir /PRIVATE/xdomain-runtime
```

The identity file contains version, run_id, exact sha, role (`tx` or `rx`), case,
direction, and epoch. The evidence directory must be owned by the caller and
have mode 0700. Before any GPU/context/peer resource acquisition, the process
blocks ordinary termination signals, ignores SIGPIPE, and creates and fsyncs
both its durable evidence file and directory.

## Coordinator

```sh
python3 tests/eval/xdomain/two_host_check.py \
  --config /PRIVATE/run.json \
  --tx-argv /PRIVATE/tx-argv.json --rx-argv /PRIVATE/rx-argv.json \
  --evidence-dir /PRIVATE/coordinator-evidence
```

Each argv file is a nonempty JSON array of strings. Launches use `shell=False`
and independent sessions. `run(config, agent_argv=None)` exposes the same
production coordinator as a Python API; an explicit `{'tx': [...], 'rx': [...]}`
argument overrides `config['agent_argv']`. Optional role-indexed
`config['kernel_receipt']` values append the corresponding agent option.

The coordinator dispatches all thirteen registered cases. Physical action cases
require their bounded action provider before acquisition; absent prerequisites or
raw action evidence remain incomplete. Strict CREATE refusal remains HELD with
its actual errno, admission window and raw records; it grants no cleanup rights.

The production owner imports the deployed `platform_facts.py` through a fixed
`/usr/bin/python3 -I` metadata child and JSON pipes, checking the current local
boot, build, NHI ancestry, token and channel. `--helpers-dir` defaults to the
executable directory; it must contain the actual inventoried runtime helpers,
including `native_barrier.py` and `check_protocol.py`. CLI evidence paths alone
never prove the prerequisite.

After GPU fill and before CREATE, each owner creates one exclusive tracefs
instance for `xdev_ext:native_event`, with nop/mono and a 4096 KiB buffer. It
records the actual event format, raw trace and per-CPU loss counters. Missing
counters, loss, capacity overflow or unknown clocks cannot establish acceptance.
`wait {until: accepted-native-inflight, max_age_ms: ...}` returns only an actual
full pending native group qualified by `native_barrier.py`, retaining
START_ACCEPTED and zero cleanup authority. `acceptance_seq` denotes a one-based
raw ledger row, never a kernel acceptance counter. Continued action evidence
seals only the owner's instance and retains the original pending request identity;
a post-STOP read preserves the existing DRAINED_SAFE permissions. STOP timing
uses the target's actual CLOCK_MONOTONIC invocation interval. Private owner
metadata is removed from the payload and exposed as `evidence.stop_action` or
`evidence.link_up` by the supervisor. Trace collection cannot prove quiescence.
Destructor and failure paths retain active trace instances and resource FDs;
only explicit safe close removes the owner's own instance.

An actual CREATE_UNKNOWN response may wait for its same-command bounded
admission capture. HELD is immediately durable; the original command deadline,
cancel, signal, EOF, EPIPE and evidence-write failure still produce HELD without
waiting for the owner. A late result never restores authority.

The configuration supplies the identity base (without role/request_id), mode,
groups, first_seq, seed, GPU BDFs and NVIDIA nodes by role, link tokens by role,
channel, flags, observer/PTX paths, deadline_ms, evidence_dir, and geometry.
Geometry fields are allocation_bytes, group_bytes, frame_size, seg_len, depth,
and native_elems. Original capacity-negative requests are refused before
prepare; they are never silently clamped. Single-group mode requires one group
and depth one. Invoke separately with a fresh epoch/seed/sequence identity for
each independently verified single-group epoch. Bulk-static mode performs one
fill and one START for its configured groups, with no active-session CUDA access.

The coordinator validates both preflights and prepares both endpoints, starts
RX before TX, waits for settled actual stats, and obtains two complete matching
successful STOP receipts. It reads observer records in single-part pages of at
most 32 ordinals. The independent oracle joins each host's descriptor stream,
rejects overlap within a group, applies later successful transport groups as
last writers across groups, and retains untouched receiver guards. RX verifies
the resulting complete allocation; TX separately verifies its unchanged full
source allocation. Both verifications carry the same pair of STOP receipts.
Only then can either endpoint close its resources.

## Wire and retention

Every frame is a four-byte big-endian byte length followed by UTF-8 JSON, with a
1 MiB maximum. Duplicate/unknown keys, nonfinite/floating values, malformed
identity, invalid integer ranges, and impossible phase/permission combinations
are rejected. Requests use increasing host/epoch request IDs.

Observe uses `{first_ordinal, limit}` with limit 1..32 and a single-part response
containing records, next_ordinal, total, and error_bits. Verify uses begin,
contiguous extent parts of at most 1024 extents each, and end. The assembled
metadata limit is 64 MiB. The first part establishes an absolute local deadline;
subsequent parts do not extend it. The owner is not dispatched before the final
count and identity checks. It checks additions, allocation bounds, full coverage,
STOP receipts, and the nonzero launch cookie before any dependent GPU launch.

SIGTERM/SIGHUP/SIGINT, input EOF, output EPIPE, cancel, deadline, and unknown
resource outcomes latch sticky HELD independently of a blocked owner. The
supervisor also latches its actual shared guard when an owner exception escapes.
An owner error in a resource phase also latches HELD according to the actual
guard, regardless of the phase claimed in its result. Errors in actual NEW,
FAILED_SAFE, or CLOSED do not create an additional hold. A returned owner error
is preserved in the terminal response and durable record; an earlier supervisor
hold keeps its first error.
It fsyncs a terminal inventory and parks the process. A late successful
CUDA return cannot authorize CREATE, START, reuse, or cleanup. HELD always has
zero cleanup permissions. Failure reports preserve owner PID, durable path,
identity, phase, and hold reasons for manual recovery. If no identity-validated
owner receipt exists, owner PID and durable path are null; the separately named
transport PID and coordinator log are not substitutes for remote owner evidence.
Coordinator process exit
is not a device-release proof.
