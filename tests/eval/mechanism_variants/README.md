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
negative that increases accepted count. Its PASS is assertion self-validation,
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
(globally increasing), `request_id`, `batch_id`, `ticket`, `ops_generation`
(the actual pinned NVMe mechanism generation) and `frames` (actual frame
indices, in the same order). The first two additionally record `slba`, `nlb`
(decoded count, not zero-based encoding), `bytes`, `direction="read"`;
class_validate records `result=0`. `ticket` is the NVMe native ticket retained
for correlating this request; a downstream stage's own ticket is a separate
field if recorded. Events must be captured at the named real boundaries;
reconstructing them from expected SLBAs or final bytes is not evidence.
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
