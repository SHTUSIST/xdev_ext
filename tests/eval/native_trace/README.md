# Native trace collection

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
`session_bind`, `pool_bind`, and `region_span` remain explicit observation-only records. Their
raw acceptance flag is preserved as `probe_accepted`; they cannot satisfy a
native submit/completion or record endpoint. Local TX completion cannot become
a remote receive/ACK endpoint. Missing endpoints stay absent, so an analyzer
must report unavailable E2E intervals.

CPU snapshots currently cover the whole command, including setup/drain/oracle:
metadata says `cpu_interval_scope: "whole_command"`. They do not prove
steady-state CPU/record. Native backing/no-bounce proof is also required
separately; the collector never creates it from manifest booleans or page-span
similarity. Consequently capture status `ok` is distinct from physical
performance eligibility. The independent importer verifies all retained hashes,
re-decodes raw events, and validates the actual campaign/byte denominators.

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
steady-state CPU interval, or physical backing/no-bounce success is implied by
the host software tests.

Run parser/admission contracts with:

```sh
python3 -m unittest discover -s tests/eval/native_trace -p 'test_collector*.py' -v
python3 -m py_compile tests/eval/native_trace/collector.py
```

These are host software checks, not DMA or physical performance results.
