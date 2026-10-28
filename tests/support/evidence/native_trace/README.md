# Native trace collection

Follow the [evaluation policy](../PERFORMANCE_POLICY.md) for baseline changes, comparison eligibility and performance claims.

`collector.py` exposes `collect(manifest, argv, output_dir, *, tracefs_root,
correctness_only=False)` and `decode_trace(manifest, raw_text, metadata)`.
It uses the real `xdev_ext:native_event` tracepoint from the running kernel.
No BPF toolchain or user-CQE substitute is used for native completion.

A capture uses a fresh, bounded, non-overwriting private tracefs instance,
`trace_clock=mono`, all CPUs, and unique begin/end markers. It retains the
resolved event format, enabled events, CPU mask, buffer configuration, per-CPU
loss counters, raw trace, real child stdout/stderr, and full `/proc/stat`
before/after the command. A timeout terminates only the command's owned process
group. Removing the private instance leaves global tracing configuration alone.

Admission checks actual tracefs, the compiled
`abi=xdev-native-v1-nvme-xsk-batch` event format, native nanosecond timestamps,
actual NVMe and PCI NIC devices, audited `ice` driver support,
required running symbols, running kernel config hash, and the collector's
source HEAD. Other drivers, unsupported direction/batching, missing probes,
wrong clocks, and missing immutable record mapping are unavailable before the
workload starts. Manifest `physical`, `correctness_pass`, and event-availability
flags cannot enable tracing or satisfy these checks.

The initial physical path is `nvme-nic`, passthrough vectors, AF_XDP zero-copy,
record burst 1. The existing `chains/run.py` runner supplies the actual
campaign and file/block receiver oracle. `collect` uses a fresh output directory
and performs another actual post-command destination read, retaining every
readback/expected byte and its hash. Child exit zero is insufficient. This
readback requires read permission on the configured receiver destination.

The trace configuration declares `record_mapping: "batch_key_div_burst"`,
`burst: 1`, and a `stage_map` from native integer stage to the manifest's
stage IDs. K additionally declares `generation_mapping: "batch_key_relative"` and
`batch_key_origin: 1`, while U uses origin 0. Logical record `generation`
uses the immutable batch key minus that predeclared origin. The actual raw
batch key remains in every native work event. The independent
`frame_generation` retains the actual stage-local lifecycle token; a native
submit/completion must have matching token, ticket, cookie, address, and span.
Tokens can legitimately differ between stages. Expected records/frame IDs and
warmup/timed ranges must be fixed before capture; observing fewer successful
events never reduces those expectations.

K descriptor identities come from actual prequeue `descriptor_bind` events,
then the common driver's per-pool accepted/completed descriptor sequence.
U identities come from the workload's immutable submit-side JSONL journal;
`XDEV_EXT_NATIVE_JOURNAL_DIR` points to a private owned directory. Journal bytes
are retained and hash verified on each offline decode. U vectors can map one
command to several frames. Native TX descriptor address and descriptor length
are checked separately from payload length. Missing/ambiguous cookie mappings,
sequence gaps, duplicate work, overflows, cancellation, loss, and unpaid
completion/binding debt invalidate decoding.

`class_validate`, `downstream_complete`, `frame_recycle`, `native_span`,
`session_bind`, `pool_bind`, `region_span`, `dma_span`, `dma_seal`,
`dma_unmap`, and `dma_tx` remain explicit observation-only records. Their
raw acceptance flag is preserved as `probe_accepted`; they cannot satisfy a
native submit/completion or record endpoint. Local TX completion cannot become
a remote receive/ACK endpoint. Missing endpoints stay absent, so an analyzer
must report unavailable E2E intervals.

Whole-command `/proc/stat` before/after snapshots remain diagnostics. One
`CpuSampler` additionally retains actual aggregate and all `cpuN` rows in hashed
`cpu_samples` JSONL, with `CLOCK_MONOTONIC` `before_ns`/`after_ns` read brackets.
The default period is 10 ms; retained bytes are capped at 64 MiB, with a 1 MiB
limit per CPU-row snapshot. Only CPU rows are retained in the periodic stream.
The worker stops and joins after command exit, timeout or error; a read/size
failure preserves its incomplete stream and makes CPU unavailable.
`cpu_sample_period_seconds` and `cpu_sampler_error` are retained in metadata.

`cpu_interval_scope: "native_interval_counter_bounds"` identifies this input,
but cannot qualify it by itself. The importer replays the hashed raw sample
stream against verified events for every declared measured record. Its window
runs from first measured `record_admit` to last measured `record_terminal` in
the same monotonic host domain. The nearest reads entirely outside the window
bound the busy-counter delta from above; the widest pair of reads entirely
inside it bounds the delta from below. Without an interior pair, the lower
bound is zero. No interpolation or exact CPU total is produced. Replay retains
selected sample indices, counter bounds, read widths, observed inter-read gap
and endpoint slack. Missing covering reads, invalid endpoints, CPU-set changes,
regression, or sampler failure refuse CPU qualification.

These are quantized whole-host counter bounds. Tick granularity, sampler
work, unrelated activity and peer/receiver oracle work remain included. Warmup
record identities are excluded from endpoint selection; pipelining can let the
first measured admission precede the last warmup terminal, so this does not
exclude all warmup CPU. Receiver validation can overlap the sender's measured
window. Tracing/sampling perturbation still needs separate runtime evidence.
Native backing qualification is derived separately from the actual mapping and
descriptor observations described below, never from manifest flags. Capture
status `ok` remains distinct from physical performance eligibility.

## Automatic native backing export

After the actual workload and complete byte oracle, the collector invokes
`derive_native_backing(plan, raw_trace, metadata)` and writes
`native-backing.json` itself. A workload-created file or symlink is discarded;
its contents cannot supply evidence. Missing or uncertified observations leave
the proof unavailable, with the reason retained in trace metadata.

The initial route is NVMe READ followed by audited ice AF_XDP zero-copy TX,
for K-BPF, U-poll and U-event. NVMe records source physical spans and the
actual mapped DMA ranges at submission-queue command insertion, in both
single and batched paths. Each whole-command seal requires complete,
positively checked direct/IOMMU translations. XSK records actual new/reused
pool mappings and unmap; ice records the DMA address written into each
single/batch transmit descriptor. Unknown DMA backends, mapping checks that
cannot certify the original backing, unaligned pools, TX metadata and
multi-buffer descriptors are not silently qualified.

Reconstruction resolves actual request and pool lifetimes through verified
owner, native command, record/generation and frame bindings. Sequential
request-pointer reuse is legal when completed lifetimes are unambiguous;
overlapping/duplicate attempts are refused. NVMe normally unmaps before its
native completion callback, so its map must be valid at the command-insertion
seal. The NIC map must remain valid through its matching native completion.

Every payload byte is compared in order, using actual K admission or immutable
U journal payload anchors and observed UMEM pages. Packet headers are excluded
at recorded payload boundaries, not an assumed header size. Different SG
segmentation and different device DMA addresses may still reference the same
ordered physical bytes. A partial-page UMEM registration can use a rounded
DMA mapping, but the descriptor and payload must stay within registered bytes.

The v1 export retains the full physical ranges and an explicit
`payload_copy_scope`. Its zero bounce/copy fields describe only the verified
NVMe-to-native-AF_XDP payload boundary, not arbitrary process-wide CPU copies,
remote receipt, GPU/NHI paths or cryptographic attestation. The importer
reconstructs the full export from hashed raw trace/journal and compares typed
JSON; editing the file and recomputing its hash cannot substitute for matching
observations. No fio result, throughput number, interface success or
caller-supplied zero counter supplies a missing mapping check. Actual physical
execution and tracing-on/off perturbation still need runtime qualification.

Runtime sessions are predeclared, for example:

```json
{"sessions": [{"logical_id": 7, "protocol_session_id": 270019,
               "role": "sender", "measured": true},
              {"logical_id": 8, "protocol_session_id": 270019,
               "role": "receiver", "measured": false}],
 "layout": [{"frame_id": 0, "offset_bytes": 0, "length_bytes": 4096}]}
```

These fields belong in `manifest.trace`. The layout must describe the actual
predeclared record segmentation; the example is a one-frame shape, not an MTU
or hardware recommendation. Native `frame_ordinal/frame_offset/frame_length`
from admission/binding or the immutable U iovec journal must match the complete
layout at every stage. Normalized `frame_id` is the logical ordinal; actual
pool slot is retained as `native_frame_id`, and the stage-local generation and
byte spans are retained independently. Neither native pool slot nor kernel
session ID has to be guessed before CREATE.

K's real CREATE sideband must agree with the raw `session_bind` event, owner
TGID, `/proc/self/stat` process-start ticks, clock tick rate, initial batch key,
group count, warmup and burst. U's header and native command/pool observations
must agree on actual owner and process-start ticks, so equal command cookies
in sender and receiver cannot be merged. The unmeasured receiver is excluded
only after its predeclared role has a verified runtime binding. Missing roles,
process identity mismatches and missing binding files refuse normalization.

`derive_mapped_manifest(manifest, raw_text, metadata)` returns the original
manifest plus `runtime_mapping_version`, `runtime_bindings` and `runtime_frames`.
All original expected records, frame IDs, seed, layout and denominators remain
unchanged. The collector retains this as `mapped_manifest`; an importer can
recompute it from hashed raw/journal bytes and compare it exactly. Missing work
never reduces the expected record set.

Only the Intel `ice` TX/CQE/teardown paths have the complete initial source
coverage. `mlx5_core` remains unavailable until its teardown completion path
is covered. No physical workload, enabled/disabled tracing perturbation run,
qualified CPU bounds, or physical backing/no-bounce success is implied by
the host software tests.

Run parser/admission contracts with:

```sh
python3 -m unittest discover -s tests/eval/native_trace -v
python3 -m py_compile tests/eval/native_trace/collector.py
```

These are host software checks, not DMA or physical performance results.

With `correctness_only=True`, the existing chains command must itself carry
`--correctness-only`. This path observes actual host/VM identity and existing
block/NVMe-generic/NIC nodes, permits real `virtio_net` as well as `ice`, and
records `physical=false`, `evidence_kind=correctness-only`. It keeps the same
native probe, immutable identity, FIFO, loss and oracle checks. It never
produces performance eligibility. The generic `PrivateTrace` loader has no
physical-device admission and can be reused by an independent correctness
adapter; the adapter must retain formats and per-CPU loss counters itself.

K per-point helpers can have zero owner fields when running on kernel workers.
Their actual native session inherits owner identity only from the verified
CREATE event and matching sideband. Nonzero conflicting owner fields are
errors. `native_event_origin_tgid` and `native_event_process_start_ticks`
preserve those raw per-point values alongside the bound origin identity.

Record endpoints are aggregated only after each phase covers exactly the
manifest's declared logical frame set, once per frame. Duplicate or partial
sets and conflicting acceptance/status/owner values invalidate decoding.
`endpoint_frames` retains every per-frame endpoint row, including native slot,
lifecycle generation and timestamps. Entirely absent phases stay absent for
an analyzer's unavailable result.

The current native ABI requires an integer `ts_ns` on every raw event,
including binding/resource events and events from other origins. It never
falls back to trace text. Old parser fixtures can opt into the separate
`xdev-native-fixture-text-v0` ABI only with explicit fixture evidence,
physical=false, performance_eligible=false and no compiled event formats;
that compatibility path cannot admit a current native/physical capture.

NVMe submit/completion must preserve the complete class-specific `aux`
opcode/length value. `trace.native_directions` may map stage IDs to `read` or
`write`; the supported `nvme-nic` recipe also declares a measured NVMe read.
XSK `aux` is the native batch count and can differ between submit and complete
without changing the identity or byte span of the individual descriptor.


Selected CPU counter replay uses `cpu_sampling.parse_cpu_set`, `busy_ticks`
and `interval_bounds`. Explicit selected IDs are summed once from `cpuN`
rows. Busy includes user, nice, system, irq and softirq; steal and extra guest
fields are excluded. Raw tokens must fit unsigned 64-bit; totals use Python
integers. Decreasing iowait is reported as unreliable without becoming busy.
Native record replay retains the existing first-admit to last-terminal envelope,
with outward-rounded interior/enclosing bounds, read widths and endpoint slack.

The existing sampler now records actual Linux boot ID, online/possible CPU IDs,
`CLOCK_MONOTONIC` and its optional caller-provided clock domain around each
bounded proc read. Changing identity invalidates the stream. A missing clock
domain remains diagnostic and cannot qualify a selected result. This does not
add a sampler, alter benchmark timers or establish workload placement.

A selected import requires matching manifest/collection `cpu_scope`, raw sample
identity and native clock domain. Only an unchanged explicit all-online set can
qualify containment in this implementation; subset scopes remain HOLD until
actual worker, IRQ and background-work placement proof is available. All-online
busy includes background work and sampler overhead; it does not prove idle or
dedicated hardware. Held results expose no primary CPU cost/bounds, and paired
selected sets must match exact IDs. Historical synthetic fixture arithmetic is
retained solely for decoder compatibility and proves no physical eligibility.
Collector option propagation, all-arm readiness/timer adapters, span-union
replay and subset placement evidence remain separate integration requirements.
