# Native-view transition evidence

Follow the [evaluation policy](../PERFORMANCE_POLICY.md) for baseline changes, comparison eligibility and performance claims.

This directory plans the existing shared-page `chains` workloads, associates
native events with records and frames, and verifies retained raw evidence.
No physical experiment has been run for this implementation. Python fixtures
exercise software contracts; they are never DMA or performance evidence.

```
python3 -m unittest discover -s tests/eval/native_views -p 'test_*.py' -v
python3 tests/eval/native_views/run.py --manifest RUN.json --output OUT --dry-run
python3 tests/eval/native_views/run.py --manifest RUN.json --output OUT --validate-only
python3 tests/eval/native_views/run.py --manifest RUN.json --output OUT --execute
python3 tests/eval/native_views/run.py --manifest RUN.json --output OUT \
    --import-collection RECEIPT.json
```

Dry-run and validation do not execute a child or create an output directory.
Execution requires the explicit option, a physical manifest, an existing
chains recipe and the native trace collector. The existing chains hardware
gate still checks the running host; manifest assertions cannot bypass it.
Missing native probes or immutable identity mappings make the arm unavailable
before its workload starts. There is no source preparation, device binding,
module loading or implicit `--prepare-source` here. An explicitly executed
paired chains workload uses the rig's declared destination NVMe window, as
documented by `../chains/README.md`.

A recipe names `chain` (`nvme-nic` or `nic-nvme`), `rig`, `records`, `pairs`,
`arms` and a fixed `seed`. `warmup_records` defaults to the existing chains
value 4. U-poll and U-event invoke `userspace-shared` with poll and eventfd;
K-BPF invokes `session` with the real BPF plan. Eventfd TX completion can still
poll. K-C is unavailable without a verified equivalent C implementation.
`batch > 1` is unavailable because chains has no native batching option;
record burst is not a substitute. `record_bytes`, `depth`, offered `load`,
zero-copy AF_XDP mode and repetition counts are passed explicitly. At execution,
each independent pair runs once per arm and alternate pairs reverse arm order.
All arms retain the same fixed data seed. Missing or failed arms stay in the
receipt. A nonzero child return code is a failure, not a successful observation.

`contract.validate_run` separates parse/baseline admission from performance
admission. The complete schema example is `fixtures/builders.py`; those
identities describe synthetic fixtures, not a physical configuration. In a
physical manifest, additionally declare observed `cpu_budget`, `numa`, `iommu`,
`group_bytes`, `segments_per_group`, `inflight_bytes`, `native_batch` and
`processing`. Depth is an in-flight group count; a record can contain several
groups/frames. Workload configuration hashes should cover common work and
exclude the intentionally different arm/wait strategy. These declarations
alone do not verify any measurement.

`analyze.summarize_events` requires explicit `stages[].after` dependencies and
`records[]` frame identities. Association uses run, session, record, frame,
generation and stage. Record-level admit/terminal events use frame -1 and stage
`record`. Native submit means accepted request; native completion means the
matched native software completion boundary. Rejected duplicate/stale events
do not complete work. Accepted foreign identities, failed or duplicate native
completions, missing frames and premature recycling invalidate the record.
Accepted work must use declared stages and the correct native-frame or
record-endpoint scope. Unknown accepted event types are errors. Optional
observations and explicit ERROR/cancel/stale diagnostics cannot stand in for
native work; rejected/resource observations remain in `diagnostics`.
Fan-out validates every declared consumer and releases after the last one;
it does not assert that a backend supports arbitrary dependency graphs.

Normalized `generation` identifies the immutable logical record. A raw
`frame_generation` can advance between native stages. Within one stage,
accepted submit and complete must retain the same supplied frame_generation,
ticket and cookie. EC's explicit K mapping uses the immutable batch_key as
logical generation and retains the raw stage-local token separately; U uses
its immutable journal generation. Runtime-ID binding is a separate collector
prerequisite and does not change the predeclared expected record denominator.

A record's latency is terminal minus admit. Inter-completion gaps remain a
separate statistic. A dependency gap uses predecessor native-complete and
successor accepted-submit from the same CLOCK_MONOTONIC host domain; user CQE
observation cannot replace native completion. Unknown probes/clocks/lost traces
produce `null` with reasons, never zero. Necessary CPU/CRC, admission, sync and
queue work are included in an observed gap; no unmeasured decomposition is
invented. Endpoint matching is exact: local TX is not remote receive, NVMe
write completion is not durability, and host memory is not GPU residency.

## Raw collection/import interface

The separately implemented `../native_trace/collector.py` provides:

```python
collect(manifest, command, output_dir, *, tracefs_root=..., correctness_only=False)
decode_trace(manifest, raw_text, metadata)  # deterministic normalized events
```

A collection receipt retains its real `returncode` and `status` (`ok`, `failed`
or `unavailable`), reasons, and `artifacts`. Each artifact is `{path, sha256}`
pointing to retained bytes. Required kinds are `raw_trace`, `events` (JSONL),
`trace_metadata`, `cpu_samples`, `system_cpu_before`, `system_cpu_after`, `workload_stdout`,
`workload_stderr`, `oracle` and `zero_copy`. U arms additionally require the immutable cookie `journal`
artifact; metadata.journal_artifact must link the same raw path/hash.
Paths must remain accessible when
importing; use absolute paths for movable receipts. Hashes establish file
integrity, not that a physical experiment happened.

`analyze.import_collection(manifest, receipt)` returns status, imported manifest,
summary, errors and `performance_eligible`. It verifies hashes and identities,
re-decodes raw trace using this checkout's collector, and requires exact equality
with retained normalized events. It derives record latency, effective payload
throughput and CPU per record rather than accepting the manifest's metrics.
Positive-duration complete samples, zero dropped events and all admission gates
are required for eligibility. A missing decoder, probe, mapping or artifact is
unknown/unavailable. Corrupt artifacts, failed oracle/children and invalid causal
events remain failures. Fixture/host/VM provenance never becomes eligible.

`trace_metadata` has schema_version 1 and binds `run_id`, `exact_sha`,
`config_hash`, `arm`, `clock`, `clock_domain`, `endpoint`, `physical`,
`environment`, `evidence_kind`, `complete_boundary` and `submit_boundary` to the
run. It records `trace_dropped`, actual `cpu_tick_hz` and the observed common
configuration fields listed above. `probes.native_complete` and
`probes.native_submit` each name the actual `source` and `layer=native_provider`.
These must come from successful probe resolution/capture, not input assertions.
The collector must preserve raw event formats, cookie/record mappings, clock
selection and loss accounting needed for deterministic decoding.

CPU input is the hashed `cpu_samples` JSONL stream containing actual aggregate
and every `cpuN` row with monotonic read brackets. The collector's 10 ms default
period, finite byte cap and failure metadata are described in
[the collector README](../native_trace/README.md). The importer verifies its
hash, replays the verified native endpoints and derives
`total_cpu_ns_bounds: {lower, upper, ...coverage}`. The window starts at first
measured `record_admit` and ends at last measured `record_terminal`; warmup
identities never select its endpoints. Pipelining can overlap remaining warmup
work with this window, so warmup CPU is not necessarily absent. The stream's
outer reads enclose that window; entirely interior reads supply the lower
counter-delta bound, or zero when no interior pair exists. Read widths, sample
indices, maximum inter-read gap and endpoint slack accompany the bounds.
The importer rejects missing coverage, failed/duplicate/missing endpoints,
wrong clocks, hotplug and counter regression. An explicit sampler error
refuses CPU qualification even if the incomplete stream happens to cover the
window. A metadata label cannot turn whole-command snapshots into this proof.

Busy user/nice/system/IRQ/softirq ticks are counted once via the aggregate;
idle/iowait/steal and extra guest columns are excluded. These bounds retain
counter quantization and cannot perfectly attribute workload CPU. Background,
sampler, peer and receiver-oracle work can overlap the measured window. They
do not establish that oracle CPU is excluded. Whole-command snapshots remain
diagnostic. Legacy nonphysical fixtures retain their old integer counter
parsing tests and can never pass physical performance admission.

Bounds-only imports set `total_cpu_ns` and `metrics.cpu_ns_per_record` to null;
`metrics.cpu_ns_per_record_bounds` divides each bound by verified measured
completed records. Both raw total bounds and the per-record bounds are checked
again during performance validation, so edited derived metrics cannot qualify.
A paired right-minus-left interval is `[right.lower-left.upper,
right.upper-left.lower]`; pair means average the respective interval endpoints.
Unknown inputs stay null. Overlapping uncertainty bounds do not establish CPU
savings, and CPU savings alone do not establish throughput improvement.

`oracle` points to the actual existing `xdev-chain-campaign-v1` campaign.json,
not a newly asserted pass boolean. Each receipt covers one arm/pair/size/load.
The importer matches chain, size, seed, arm/wait; requires sender/receiver
status and exits to pass; verifies the receiver's full file oracle byte count
including warmup; and retains the chains hardware-gate evidence. The independent retained post-command readback is outside the measured
window; the receiver's own oracle can overlap sender work. A zero exit alone is insufficient.

`zero_copy` is a raw native-provider mapping observation with schema_version 1,
`run_id`, `exact_sha`, `source=native_provider`, actual `afxdp_mode=zc`,
`nvme_bounces=0` and `payload_copy_bytes=0`. `frames` associates session, record,
frame and generation with an observed `backing_id`, `valid_bytes`, and
`native_views`: each view contains `kind` (`nvme`/`afxdp`), its `backing_id`,
`offset_bytes` and `length_bytes`. Both native classes must reference the same
backing and cover the full same measured payload span. Native views here
describe payload byte ranges, excluding unrelated protocol-header ranges.
IOV/SG pieces can differ in segmentation and ordering; their interval unions
must agree. Within one class's measured logical native view, pieces must not
overlap or duplicate bytes; interval merging cannot excuse repeated payload.
This minimal E1 proof has one view group per class. Aliasing by distinct
consumers/operations needs explicit validated groups, not unscoped repeated
ranges. The event analyzer's separately declared fan-out remains supported.
A one-frame record defaults to payload span [0, record_bytes).
For multiple frames, each observation must explicitly provide
`record_offset_bytes`, `payload_offset_bytes` and `payload_bytes`; all frame
payloads together must cover every record byte without holes or overlaps.
`valid_bytes` is a bound, not evidence that a tiny mapping covers a record.
Different DMA-domain addresses need not be equal.
The collector must obtain those observations from the measured native path;
ordinary interface success or caller-supplied zero-copy flags do not suffice.
Missing mapping/no-bounce instrumentation makes eligibility unavailable.

Pair comparisons check the common workload/endpoint/clock/configuration and
all visible recipe fields, including chain, rig, seed, records and warmup.
The actual warmup default 4 is canonicalized; only intentional arm/wait
selection differs. Unknown future recipe parameters are compared too, so an
equal claimed configuration hash cannot conceal visible work differences.
Stage topology and expected record/frame declarations also must match. They
preserve right-minus-left negatives and unknowns. Pair aggregation uses each
run pair once, unweighted by record count, and retains exclusions. It does not
claim statistical confidence from a small pair count or turn thousands of
records into independent repetitions. Predeclare exclusions and main/boundary
points; start with at least five independent pairs and report uncertainty.

Physical native hooks, immutable U cookie mappings, steady-state whole-host
CPU samples, verified backing/no-bounce observations, complete post-oracle
capture and trace-on/off perturbation measurements are external prerequisites.
The software test suite passing does not close these runtime requirements.

## Predeclared logical workload and runtime ID binding

Runtime capture explicitly declares `trace.sessions` with two fixed logical
roles: `{logical_id: 7, role: "sender", measured: true}` and
`{logical_id: 8, role: "receiver", measured: false}`. Each can also declare
`protocol_session_id` for the actual fixed NXP session configuration. Actual
kernel session numbers, allocated frame slots and process IDs are not guessed
in advance. Both roles must be proven by hashed CREATE/U journal sideband and
actual session/pool binding events before receiver observations can be excluded.
Process identity includes TGID and process start identity; a cookie alone does
not distinguish different user processes.

Before capture, freeze recipe records, warmup, seed, bytes, stages and a complete
`trace.layout`: ordered `{frame_id: ordinal, offset_bytes, length_bytes}` spans
covering [0, record_bytes). Every expected record lists these logical frame
ordinals. Records include warmup and measured entries: record_id and logical
generation are the fixed range [0, warmup_records + records), and every entry
explicitly sets `measured` false for warmup and true for the measured suffix.
No successful subset is used to rebuild this denominator. Current runtime
support is burst=1, nvme-nic. K explicitly fixes batch_key_origin=1 and
`generation_mapping=batch_key_relative`; U fixes origin=0 and uses immutable
journal generation. Actual first keys must match the predeclared origin;
missing keys are never compressed or shifted into a successful range.

The collector's pure `derive_mapped_manifest(manifest, raw, metadata)` preserves
all original fields and appends exactly `runtime_mapping_version=1`,
`runtime_bindings` and `runtime_frames`. It saves that output as the hashed
`mapped_manifest` artifact. Native frame slots remain `native_frame_id`;
logical `frame_id` stays the declared ordinal. Stage-local frame_generation,
raw frame offset/length, native session, TGID and process start identity remain
in the bindings. Per-operation native submit/completion identities, addresses,
lengths and classes must match; raw resource reuse uses native allocation and
owner identity, not an ordinal reused in every logical record.

The importer reruns both pure decoder and mapper against retained raw trace and
hashed K/U sideband, compares typed JSON exactly with the saved events/mapping,
and checks every frozen expectation remains unchanged. False cannot replace
integer generation zero. Layout spans must also agree with native backing
proofs. `collection_manifest` preserves the original input plan separately from
derived metrics; replay checks it rather than treating derived counters as new
expectations. Warmup stays in completeness checks but is excluded from measured
latency, throughput and completed-record statistics.

Runtime imports additionally require hashed `oracle_spec`, `oracle_expected`
and `oracle_readback` artifacts. They verify the actual receiver spec's frozen
shape/count, full expected byte denominator and every retained readback byte,
with bounded-memory comparisons and hashes checked during the comparison.
Missing raw proof, whole-command CPU scope and absent native backing remain
unavailable; no truth flag substitutes for those observations.

`test_runtime_import.py` uses the actual sibling collector/mapper. An isolated
implementation checkout can set `NATIVE_TRACE_COLLECTOR` to a read-only real
collector path while dependencies are integrated. Its synthetic raw inputs and
real software child receipt remain marked nonphysical; no test starts a device
workload or certifies DMA/performance.

Self-contained CI requires both `tests/eval/native_views/` and
`tests/eval/native_trace/{collector.py,cpu_sampling.py,test_collector_behavior.py}` in the same
checkout: the latter's `raw` helper supplies the frozen event ABI fixture.
Run unittest discovery for each directory separately; no external device,
privilege or tracing mount is needed for these software tests. An isolated
checkout must explicitly locate that actual collector using the environment
variable above. The decoder dependency must enforce numeric kernel `ts_ns`,
immutable opcode/aux and request identities, and complete, unique per-frame
record endpoints before any record-level collapse. Import/mapper GREEN results
cannot certify a decoder version that fails those independent requirements.

Post-oracle validation also binds receiver seed, depth, load and represented
arm/wait fields to the input plan. It independently generates the canonical
byte-pattern digest from that plan's seed and complete group range using the
existing `tests/eval/chains/run.py::group_bytes` oracle. Two equally wrong
retained files therefore fail. File comparisons stream in chunks; canonical
pattern generation holds at most one declared record at a time. The chains
runner is consequently another required same-checkout CI dependency.
Raw events rejected by the current decoder, or differing from the retained
JSONL, do not enter latency/throughput calculations. Current-ABI integration
fixtures use explicit kernel `ts_ns` and read opcode; they do not request the
collector's separately marked legacy text-fixture mode.
