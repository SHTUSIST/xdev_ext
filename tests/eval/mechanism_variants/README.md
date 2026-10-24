# Bounded NVMe mechanism substitution: test contract

This is functional evidence of the implementation's mechanism space. Choosing
another LBA is already an XRP capability. Different data selections are not an
equivalent-workload performance comparison. Host callbacks and software guests
provide correctness evidence only; no guest timing is reported.

## Frozen interface

Two independently compiled sources are required here: `nvme_reverse.bpf.c` and
`nvme_gray.bpf.c`. Each object exports `mv_nvme_build`, `mv_nvme_complete`, and
the struct_ops map `mv_nvme_ops`. Both use the existing NVMe class and provider;
no device-pair-specific custody or recycle branch is required. No new kernel
ABI or raw claim/generation write access is requested.

Each BUILD uses `mctx->base.request_id` (the real batch ID, **not** `src_offset`
or a renumbered capture index). Let `x = request_id & 7`:

| Object | slot function | independent expected slots for x=0..7 |
| --- | --- | --- |
| reverse | reverse three bits of x | 0,4,2,6,1,5,3,7 |
| gray | x XOR (x shifted right one) | 0,1,3,2,6,7,5,4 |

The fixed test geometry is READ, `window_slba=2048`, `window_nlb=64`,
`lba_shift=9`, `group_bytes=length=4096`, eight whole slots. SLBA is
`window_slba + slot * 8`; NLB is eight and all other descriptor fields remain
under existing admission rules. Unsupported geometry aborts BUILD. COMPLETE
uses normal success NEXT / error ABORT behavior. The same C/provider SHA,
normalized CREATE, policy, input image, request-ID sequence and downstream
endpoint are used for A and B. A new session loads the other object; this does
not assert live-session replacement. Record whether actual IDs begin at 0 or
1; capture and oracle do not subtract that origin.

The source window contains 64 distinct 512-byte blocks. For absolute LBA L,
concatenate SHA256(`ASCII("xdev-ext-e2-lba-v1") || byte(0) || LE64(L) || LE32(piece)`)
for piece 0..15, where `byte(0)` is one NUL byte.
The test oracle uses Python hashlib and literal expected slot tables, never a
BPF mapping helper. Seed a private guest image, not a host device.

## Commands and evidence limits

Run `make -C tests/eval/mechanism_variants/tests check` for the actual A/B
callbacks as host C plus the production `nvme_xdev_ext_mech_validate` helper.
This is not the full `nvme_xdev_ext_class_validate` path or a provider test.
Run `make -C tests/eval/mechanism_variants/tests bpf CLANG=clang-14
VMLINUX_BTF=<target-vmlinux>` to compile real BPF target ELF objects using the
target's BTF. Actual verifier load/attach must run against that target kernel.

`make ... baseline-red` deliberately executes the pre-feature checked-in
`nvme_s0.bpf.c` callback against reverse expectations. It fails at request_id 1
(linear SLBA 2056; reverse expects 2080). It is a one-time behavioral RED
demonstration, not a fallback implementation or a final acceptance target.

Run `E2_CAPTURE_DIR=<private-capture> python3 -m unittest discover -s
tests/eval/mechanism_variants/tests -p 'test_guest_capture.py' -v` for the
complete guest gate. Absence of artifacts fails. Captures stay private.
Reuse the existing NVMe-to-NIC chain (or its already implemented
NVMe-to-CE-to-CE-to-NIC counterpart); do not add a virtual device. Both objects
must traverse full class validation and the same native provider and produce
the independently checked **entire** NIC sink payload. A CE software stand-in
must retain that designation in its evidence.

The separate `test_assertion_selfcheck.py` uses explicitly synthetic fixture
artifacts to check that the assertions themselves run and reject changed
setup/source/sink, guest timing, wrong accepted SLBA, early recycle and a
negative that increases accepted count. They also accept pre-ticket validation
and legal stage-local ticket/generation changes, while rejecting a changed
ticket or frame generation within one accepted native operation, a different
plan stage, or a foreign session. Their PASS is assertion self-validation,
not BPF, verifier, guest or provider execution evidence.

## capture.json v1

Top-level keys are `schema="xdev-ext-e2-v1"`,
`evidence_kind="guest-correctness"`, `timing_claim="none"`,
`chain="nvme_nic"` (or `"nvme_ce_ce_nic"`), `source` (relative image path),
`runs` (exact keys `reverse`, `gray`) and `negatives`.

Each run records `configuration`, `request_ids` (16 actual consecutive IDs,
starting 0 or 1), `bpf_object` (relative BPF ELF), `bpf_sha256`, `verifier_log`,
`program_id`, `verifier_accepted`, `raw_trace`, `events` (relative JSON array) and `sink`
(relative full downstream payload). Configuration is compared structurally
and contains `kernel_git_sha`, `core_sha256`, `nvme_provider_sha256`,
`input_sha256`, `nvme` (exact geometry above), `create` (all normalized fixed
CREATE fields, including the unchanged endpoint/chain/pool/depth settings)
and `policy` (actual immutable values). Normalize only ephemeral fd numbers,
addresses and the BPF object/map attachment; retain their corresponding
resource specifications. Do not hide actual policy/setup changes in hashes
or a hand-written `same_setup=true` field.

Each real request has ordered events `class_validate`, `provider_accept`,
`native_complete`, `downstream_complete`, `frame_recycle`. Each contains `seq`
(globally increasing), actual `session_id`, `batch_id`, `request_id`, `stage`,
`ticket`, `frames` (actual frame indices, in the same order), and parallel
`frame_generations` (the actual life token/generation for each index at that
boundary). All events of a run must belong to its actual session. The BPF
invocation assigns `request_id = batch_id`; a raw trace that records only
`batch_id` can map it to `request_id` by this declared rule, without renumbering.

The first two events additionally record `slba`, `nlb` (decoded count, not
zero-based encoding), `bytes`, `direction="read"`. Link validation to native
acceptance by their identical `(session_id,batch_id,request_id,stage,SLBA,NLB,
bytes,direction)` plan and frame indices. `class_validate` records `result=0`
and `ticket=0`, explicitly meaning that this native operation has no allocated
ticket yet. In the core, BUILD/class validation precedes lifecycle acquire and
`completion_begin`; validation's frame generation may legitimately be zero
or differ from the subsequently acquired generation. Do not insert a future
native ticket into an earlier raw validation event.

`provider_accept` and `native_complete` additionally carry native request
`cookie` and must match on `(session_id,batch_id,request_id,stage,ticket,cookie,
frames,frame_generations)`. Their ticket, cookie and acquired frame generations
are nonzero; NVMe is stage 0. `native_complete` must be captured at the matching
native callback, before handoff releases or republishes its claims. This
preserves the immutable identity of each actual accepted operation.

Across stages, retain logical record identity `(session_id,batch_id,request_id)`
and the actual stage-local ticket, frame indices and frame generations. Do
not copy the earlier NVMe ticket/generation onto downstream/recycle events.
The downstream and recycle stage is the configured terminal stage: 1 for
NVMe→NIC and 3 for NVMe→CE→CE→NIC. The downstream stage's native ticket and
lifecycle generation can legitimately differ, including a generation
increment during consumer acquire or an L lifecycle publication/claim change.
`ops_generation`, if a separate genuine mechanism-generation hook supplies it,
is supplementary metadata; it is not the frame life token and is not invented
from the native trace's `generation` field.

Events must be captured at the named real boundaries; reconstructing them
from expected SLBAs or final bytes is not evidence.
Only NVMe provider accepts belong in `provider_accept` (downstream native
accepts, if captured, use separately named events and a separate raw trace).
The compact event array is derived from, and delivered with, the raw trace.

`negatives` has exactly `outside_window`, `reserved_cdw2`, and `old_ticket`.
The first two enter real `class_validate`, record result -34/-1 respectively,
`accepted_before`, `accepted_after`, and `trace` (relative raw trace path).
The mutated BPF scratch must reach the full class boundary, not a duplicate
userspace validator. The completion negative uses `entry=
"xdev_ext_mech_batch_complete"`, `old_ticket`, `current_ticket`,
`accepted_before/after`, `published_before/after`, `current_state_before/after`
(complete comparable current-batch custody snapshot), and a raw `trace`.
Replay through the actual native completion entrance after reuse; do not
pretend BPF can write a raw ticket, claim or generation. Existing actual-core
fixture coverage may supply this separate negative when clearly labeled;
it does not become guest/provider evidence by being packaged together.

The compact trace schema does not itself authenticate data collection. The
integrator must audit each producer hook and archive actual command, kernel
SHA/config, verifier output and raw trace with the capture. BPF ELF compilation
alone does not imply verifier acceptance; fixture/generated event rows do not
satisfy the guest gate.

## Existing guest runner integration

Build the real UDP sink with `make -C tests/eval/mechanism_variants sink
BUILD=<guestbin>` and the two real BPF objects with `make -C
tests/eval/mechanism_variants/tests bpf BUILD_DIR=<guestbin> CLANG=clang-14
VMLINUX_BTF=<final-target-vmlinux>`. `image.py seed` creates a new ordinary
fragment file; it refuses device paths. Seed only the integrator's private
QEMU image at LBA 2048, then run inside that private guest:

```
E2_PRIVATE_GUEST=yes guest_run.sh BIN_DIR SOURCE_NG TX_IF SINK_IP PEER_MAC NEW_CAPTURE_DIR TRACE_CTL
```

The runner uses the existing AF_XDP zero-copy path with depth 1, 4096-byte
groups and 16 requests, with no silent copy fallback. It recreates the NVMe
session/object for each variant, retains actual attach/program metadata,
setup, raw traces and all 65536 NIC sink bytes. Its expected batch IDs 1..16
must be confirmed from the trace. On the host, `image.py verify <sink>
--variant reverse` (or `gray`) `--first-request-id 1` independently checks
every LBA's bytes.

`TRACE_CTL begin|end NAME OUT` owns collection. The provided `trace_ctl.sh`
uses a private tracefs instance and writes `OUT/NAME.trace`, the real event
format and per-CPU trace statistics; it rejects marker-only captures and
nonzero trace overruns/drops. The runner also executes the existing
`nvme_s0` modes 1/2 as actual out-of-window/reserved-plan negatives. A CLI
failure is insufficient: the trace gate must verify the real class errno
and no native acceptance. The separate old-ticket completion-entry negative
and raw-to-compact capture assembly remain integrator responsibilities.

### Actual CREATE, verifier log and raw-event adapter

The runner now invokes `mv_ctl`, an observational wrapper which includes the
existing ctl implementation. It preserves both existing actual libc syscall
sites. Before the real CREATE syscall it saves the entire 200-byte request
and actual fd `fstat`/rdev/access flags plus AF_XDP `getsockname` resource
specifications. After the call it saves actual output bytes, syscall return,
errno and session ID. It records no self-declared CREATE-success boolean.
The wrapper also requests real successful verifier logs from modern libbpf;
`NAME-verifier.log` is the kernel's buffer, while attach logs and queried
program/link metadata remain separate artifacts.

Build with the same modern libbpf already used by the integrated guest tools:

```
make -C tests/eval/mechanism_variants sink ctl BUILD=<guestbin> \
  CPPFLAGS=-I<existing-libbpf>/include LIBBPF_LIBS=<existing-libbpf>/libbpf.a
```

Copy `mv_ctl`, `mv_sink`, both variant objects, the existing `nxp_mech.bpf.o`
and `nvme_s0.bpf.o`, `guest_run.sh`, and `trace_ctl.sh` into the private guest.
Archive all resulting capture files on the host. No guest Python is needed.

Audit A/B against the actual CREATE inputs and bound resources:

```
python3 inspect_create.py CAPTURE/reverse-create reverse-create.json
python3 inspect_create.py CAPTURE/gray-create gray-create.json --compare CAPTURE/reverse-create
```

The normalized object retains every input byte other than process-local fd
numbers. Actual fd numbers and ephemeral inodes remain in the raw resource
artifact; comparison preserves fd-alias relationships, rdev, file type,
access flags and actual AF_XDP binding. Session ID is validated against the
real syscall result and retained separately. No pointed-to configuration is
omitted for the E2 unreliable AF_XDP configuration (`flags/arg0/arg1=0`).
Other pointer-based protocols require their own pointed-data capture and are
outside this E2 runner.

Decode actual hook lines with their target event format and loss statistics:

```
python3 decode_trace.py CAPTURE/reverse.trace reverse-events.json \
  --format CAPTURE/reverse-event-format.txt --stats CAPTURE/reverse-trace-stats.txt \
  --create-prefix CAPTURE/reverse-create
python3 decode_trace.py CAPTURE/outside_window.trace outside.json --negative \
  --format CAPTURE/outside_window-event-format.txt --stats CAPTURE/outside_window-trace-stats.txt \
  --create-prefix CAPTURE/outside_window-create
```

Repeat for Gray and reserved-cdw2. The adapter groups actual per-frame rows,
retains their raw line numbers/timestamps, requires the raw trace's session
to equal the successful CREATE result, and refuses missing, duplicated,
reordered or changed native claims. Only the genuine NVMe `native_submit`
phase becomes `provider_accept`; terminal-stage downstream/recycle events
remain their actual stage-local observations. It does not reconstruct events
from expected slot mappings or sink bytes and does not create the final
manifest's verifier-acceptance or kernel-build claims. Trace format/stats
checks do not independently authenticate a forged producer; the integrator's
hook and artifact audit remains required.

### UMEM guards and the separate old-ticket software observation

Only the E2 frontend's explicit `E2_UMEM_CAPTURE` mode observes the actual
`XDP_UMEM_REG` arguments and initializes that real registered mapping. It saves
all registered bytes before use. Before the existing ctl closes the owning
ring, the frontend issues a real synchronous STOP; only a successful return
permits a complete after snapshot, guard scan and subsequent close/unmap.
A failed STOP retains the resources until the private guest is terminated.
Normal ctl behavior has no guard instrumentation without the explicit flag.

The frontend records actual registration/STOP returns, geometry and session;
it also checks every byte outside the header/payload region allowed by the
actual CREATE layout. `guard.py` independently reads the complete before/after
bytes and applies the tighter union of the actual traced frame addresses and
lengths, checking every unused frame byte too. The before pattern is defined
per absolute UMEM offset as `(0xa7 + offset*131 + floor(offset/chunk)*17) & 255`.
The host uses its own byte oracle. Full snapshots may be gzip-compressed for
bounded serial transport; decompression has an explicit size limit.

```
python3 guard.py CAPTURE/reverse-guards reverse-events.json CAPTURE/reverse-create
```

The old-ticket completion negative is separately produced on the host from
the established actual-core fixture, retaining its provider/OS host boundary:

```
python3 export_old_ticket.py FINAL_KERNEL_DIRECTORY NEW_SOFTWARE_EVIDENCE_DIRECTORY
```

This invokes the real extracted `xdev_ext_mech_batch_complete` with the old
ticket after the existing fixture's second acceptance. The output retains
full before/after lifecycle, completion, custody, queue, acceptance and
publication observations, actual source SHA/hashes, compilation command and
raw output. It is `actual-core-host-fixture` evidence and is never inserted
into the guest native trace. Re-run it against the final integrated checkout.

### Dedicated KVM mode and authoritative host validator

Use the existing private KVM harness with `--mechanism-variants`. It is an
exclusive E2-only campaign: sixteen requests, depth one, NVMe READ and the
source signature window at absolute LBA2048. It refuses CE, fault, reliable,
compatibility, peer and other optional campaigns. An explicit
`--mechanism-variants-timeout SECONDS` controls the outer timeout; the default
budget is inherited, with no claim that an unrun campaign finishes within it.
The same flag is required for `--run-only`, which verifies exact source,
configuration, dedicated-mode identity, frontend/BPF/tool and source hashes.

The mode builds its actual BPF objects against the final target vmlinux, using
the prepared target's existing libbpf/bpftool sources without downloads. Both
whole disk images must remain unchanged. Its private source-before image is
created from the same seeded bytes as source.raw. Ordinary chain validation
does not run in this mode.

The guest uses the existing private NICs, exports the complete actual source
window, sink bytes, BPF objects, raw trace/format/per-CPU statistics, verifier
buffer, queried program/map/link metadata, CREATE request/results/resources,
negative logs, and compressed complete UMEM snapshots. `export_artifacts.sh`
frames each file with name/length/SHA256 and a final complete manifest. The
host rejects unsafe paths, duplicate/truncated/unlisted files, hash/length
mismatches and explicit size/count overruns. `CAPTURED` is never a PASS verdict.
The shared AF_XDP object's actual initial map images are observed immediately
before the existing libbpf load, after its configuration writes.

```
bash kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh \
 --scratch /tmp/xdev-ext-e2e.PRIVATE --source PRODUCT/kernel \
 --mechanism-variants --mechanism-variants-timeout 600
python3 tests/eval/mechanism_variants/validate_e2.py \
 --source-root PRODUCT --scratch /tmp/xdev-ext-e2e.PRIVATE \
 --evidence /tmp/xdev-ext-e2e.PRIVATE/evidence
```

The validator always re-extracts and checks actual serial artifacts, actual
CREATE/session/resource identity, native immutable claims, both complete sink
payloads through the frozen independent guest gate, UMEM bytes, illegal-plan
rejections, and separately labeled actual-core old-ticket software evidence.
It writes `e2-capture/`, `e2-validation.json`, `e2-frozen-gate.log`, and only then
prints `XDEV_EXT_E2_KVM=PASS scope=guest-correctness old_ticket=actual-core-host-fixture performance_claim=none`.
The harness stores that exact line in `evidence/result.txt`. The current
implementation requires the actual final target run; parser/transport fixture
PASS results are not target execution evidence.

The native NIC audit separately handles the real driver's session-zero rows.
`driver_audit.py` uses actual in-session `descriptor_bind` pool pointers and
wire spans to associate each driver `native_submit` and `native_complete` with
its record/frame. It requires a complete fresh-pool native sequence, matching
accepted/completed spans, and driver completion before terminal record
completion. A failed/unknown event or `trace_invalid` on a bound pool is fatal.
Other pools remain explicit raw-line exclusions. It does not assign the core's
session/ticket to raw driver events. The host validator archives this audit as
`VARIANT-driver-audit.json` and references it from the compact decoder's scope
receipt, retaining all original rows unchanged.
