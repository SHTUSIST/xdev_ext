# Mooncake baseline plans and execution

This directory prepares Mooncake E4 storage-to-GPU and E7 host-memory-to-remote-GPU
baseline commands and executes a selected cell after qualification. Read the
[performance evaluation policy](../../../docs/reference/performance-policy.md)
before changing comparison geometry or interpreting results.

The fixed upstream source is
[Mooncake d01447808d10af78011e9203d53796a15a032a03](https://github.com/kvcache-ai/Mooncake/tree/d01447808d10af78011e9203d53796a15a032a03).
Its existing `tebench` and documented `pinned_staging` configuration are preserved.
The planner changes no Mooncake algorithm, scheduling, timer, license or backend.
E4 includes `iouring-default`, `iouring-pinned` and `gds-compat`; E7 includes `tcp`.
Every plan contains both `native` and `xdev_ext` profiles. These are requested
campaign labels; a plan does not establish the kernel actually running.

## Supported operations

```sh
python3 tests/benchmarks/mooncake/run.py \
  --mode dry-run --experiment e4 \
  --shape /absolute/path/e4-shape.json --rig /absolute/path/rig.json \
  --source-root /absolute/path/Mooncake \
  --tebench /absolute/path/build/mooncake-transfer-engine/benchmark/tebench \
  --output-dir /absolute/path/new-plan
```

`dry-run` validates JSON, checks declared files and writes only plan, config,
command and receipt JSON inside its output directory. It does not start a
process, load a driver, probe a device, connect to a peer, create a workload file
or install a dependency. Valid input returns 0 with `status=planned`,
`execution=none` and `performance_claim=none`. A missing binary produces
`needs_build=true`; planned commands are not build or device validation.

`--mode check-setup` without qualification preserves the declaration-only setup
refusal, exit 4. With `--qualification`, `--profile` and `--cell-id`, it checks
retained receipts, current fixed Git source/clean submodule, binary/runtime ELF
identity and the local rig/input match. The only checker subprocesses are bounded
read-only Git and `/usr/bin/readelf`; it never runs a loader, GPU probe or tebench.
A qualified setup returns 0 with `execution=none`; missing evidence returns 4.

`--mode run` without qualification preserves exit 4 before requiring a new
profile/cell selection. With qualification it uses those same checks and then
executes exactly the selected cell
on its selected local profile. The operator invokes the action directly; a
`physical_run_authorized=true` declaration alone cannot enable it. There is no
permission-token service, source-file manifest or validation-cache database.
Existing correctness, route and CPU observations remain retained evidence
statements, distinguished from current file/Git/ELF checks. A build with CUDA
`stubs` in its actual RUNPATH or resolved library paths is refused at runtime
qualification even if compile/link succeeded.

```sh
python3 tests/benchmarks/mooncake/run.py --mode run --experiment e4 \
  --shape /campaign/e4-shape.json --rig /campaign/rig.json \
  --source-root /campaign/Mooncake --tebench /campaign/build/tebench \
  --profile native --cell-id native-iouring-default-b1048576-q1-r0 \
  --qualification /campaign/qualification.json --output-dir /campaign/new-result
```

Qualification has exactly this small schema. Paths can be absolute or relative
to the qualification file; receipt/raw evidence must exist as bounded ordinary
files. JSON is limited to 1 MiB, raw supporting logs to 64 MiB. Only critical
source/build/runtime identities receive necessary pre-execution checks; ordinary
logs receive no mandatory digest.

```json
{
  "schema_version": 1,
  "build_receipt": "root-build-receipt.json",
  "runtime_receipt": "runtime.json",
  "correctness_receipt": "correctness/result.json",
  "budget_receipt": "cpu-budget.json"
}
```

The build receipt uses the retained GCC target-build format: fixed source query,
clean source result, submodule identity, compiler/SDK output, actual target byte
count/SHA256, CMake feature entries and linked-library evidence. The runtime
receipt contains `schema_version=1`, `source_revision`, `tebench_sha256`,
`profile`, `endpoint`, `kernel_release`, `libraries`, `library_search_dirs`,
`evidence`, and the applicable rig GPU/driver/CUDA identities. Each library is
`{needed,path}` with SHA256 for libcuda, libcudart and GDS's libcufile. It covers
every current direct DT_NEEDED/SONAME, exact selected search order and retained
loader-resolution evidence. No loader is invoked to collect that evidence here.
Unrelated opaque resolver-log bytes are preserved. Required library mapping
lines must be valid UTF-8, and ASCII error markers refuse setup even beside
opaque bytes; the existing stream and line limits still apply.

The separate correctness receipt contains `status=passed`,
`scope=separate-upstream-roundtrip`, fixed source/profile/experiment/arm,
covered block/batch/worker shape, matching rig identities and raw evidence paths.
The budget receipt contains fixed source/profile/endpoint, rig `cpuset`,
`cpu_budget_description` and evidence paths. Input/extent/exclusive-window and
E7 route/link receipts stay in the existing rig. Missing or mismatched evidence
is refused rather than interpreted as a measurement. Where recorded, E7
`host_id`, `address`, `interface` and `rpc_port` match the endpoint owning the
receipt; `source_host_id` and `destination_host_id` match the declared host pair.
Absent optional identity fields remain compatible with otherwise valid retained
evidence. These comparisons do not rerun a route observation. Recorded input ranges and
where-recorded `stat`/top-level `st_dev`, `st_ino`, `st_size`, `st_mtime_ns` facts
are checked against current file metadata; no new stat manifest is required. A successful child alone
does not prove the GPU, pinned, cuFile compatibility or USB4 path.

Invalid JSON, invalid types or geometry, overflow, duplicate values/keys, unknown
fields and unsafe output paths return 2. JSON inputs must be ordinary files no
larger than 1 MiB, without a final symlink. Individual text values are limited to
4096 bytes. Input/dependency paths cannot name `/dev`, include `..` or contain
control characters. Spaces and shell metacharacters are preserved as literal
argv elements. Output must be new or empty, outside the upstream source tree,
without symlink components; existing artifacts are never overwritten. Source
protection checks both the declared path and its resolved filesystem path, so
an upstream source symlink alias cannot redirect artifacts into the actual tree.

## Shape

For E4, use this JSON object. Lists can contain fewer cells for a software plan,
but default and pinned arms always use the same geometry.

```json
{
  "schema_version": 1,
  "experiment": "e4",
  "block_bytes": [4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304],
  "batch_requests": [1, 8, 32],
  "worker_threads": 1,
  "buffer_bytes": 1073741824,
  "target_bytes": 1073741824,
  "target_offset": 0,
  "duration_seconds": 10,
  "repetitions": 5,
  "op_type": "read",
  "target_access": "random",
  "pinned_slot_kib": 4096,
  "pinned_slots": 32,
  "gpu_ordinal": 0
}
```

E7 uses the same fields except `experiment=e7`, `op_type=write` and
`target_access=fixed`; remove both `pinned_slot_kib` and `pinned_slots`.

Every cell fixes start=max for block, batch and worker counts. Logical request
depth is `worker_threads * batch_requests`, not observed NVMe queue depth.
Each worker submits one batch and waits for the whole batch to complete. E4
randomizes the offset of a contiguous batch within a per-thread window, with
replacement and without consecutive duplicate offsets. This is not independent
random selection of each request, or a pass visiting each block once.

Block sizes must be positive multiples of 4096. Maximum batch bytes across all
workers must fit both buffers and the target. E7 additionally requires
`target_offset + worker_threads * max_batch_bytes <= buffer_bytes`, where
`max_batch_bytes = max(block_bytes) * max(batch_requests)`. The entire declared
target range need not be allocated when the fixed request span fits. Both E4
and E7 require
`(gpu_ordinal + worker_threads) * max_batch_bytes <= buffer_bytes`: the fixed
upstream uses the selected ordinal in its local buffer stride. The planner
rejects incompatible geometry without rewriting the ordinal or enlarging buffers.
All these additions and products are checked against unsigned 64-bit bounds.
E4 target bytes must divide evenly
among workers; every per-thread window must be 4096 aligned and hold at least
two maximum batches. A pinned slot covers a maximum single request, and the
number of slots covers logical request depth. Pool rounding and size products
are checked for overflow. Sizes and offsets fit unsigned 64-bit; counts fit
signed 32-bit, with zero allowed only for GPU ordinal, NUMA node and byte offset.
Even a start=max upstream case doubles its loop variables after execution, so
`max(block_bytes) <= UINT64_MAX // 2` and
`worker_threads <= INT32_MAX // 2` are required. Batch counts retain their
signed 32-bit bound, which is safely below the unsigned doubling limit.
Ports are 1..65535. The full profile/arm/block/batch/repetition product must fit
100000 cells before output creation.

## Rig declarations

An empty rig object can expose all setup omissions in a nonexecuting plan. Any
missing command input is represented by a visible `UNRESOLVED` placeholder and
listed in `setup_missing`; such commands are not runnable. A complete E4 rig
provides these fields:

- Identity: `schema_version=1`, `execution`, `kernel_release`,
  `kernel_source_revision`, `nvidia_driver_version`, `cuda_version`,
  `cufile_version`, `gpu_uuid`, `gpu_pci_bdf`, `gpu_model`, `source_revision`.
- Budget: `cpuset`, `numa_node`, `cpu_budget_description`.
- Evidence declarations: boolean `physical_run_authorized`, boolean
  `source_tree_verified`, and `build_receipt`.
- Input: absolute `input_file`, boolean `input_initialized`,
  `input_validation_receipt`, `filesystem`, `mount_options`,
  `namespace_identity`, `namespace_capacity_bytes`, `file_extent_receipt` and
  `exclusive_window_receipt`.

`build_receipt` can refer to retained evidence, but a reference alone cannot prove
build features. A metadata object can declare boolean `USE_TENT`, `USE_CUDA`,
`liburing` and `cufile`; these declarations still do not independently qualify
source identity, a build or a device path. Missing required compile features
produce `NEEDS_BUILD`. `cufile` and its version are relevant to GDS, not E7 TCP.
Other receipt fields accept a nonempty reference or object; empty objects are
reported as missing evidence during setup. No arbitrary rig
field is executed or interpreted as a command.

E7 adds `endpoints.source` and `endpoints.destination`. Each endpoint contains
`host_id`, `address`, `rpc_port`, `interface`, `mtu`, `cpuset`, `numa_node`,
`cpu_budget_description`, `kernel_release`, `kernel_source_revision`,
`route_receipt` and `usb4_link_receipt`. Top-level GPU/CUDA identity describes
the destination. Endpoint CPU lists prefix both commands explicitly with
`taskset --cpu-list`, and each endpoint's declared RPC port is passed explicitly.
Neither an interface name nor an address declaration
proves traffic uses USB4. The original RPC and transport worker pools are
preserved; one benchmark worker does not mean the complete path uses one CPU.

E4 `input_file` must contain no comma and must not end in whitespace trimmed by
upstream (`space`, `tab`, `CR`, `LF`); upstream interprets commas as multiple
targets and trims target tokens. The planner rejects these names rather than
silently trimming or encoding a different path. Internal spaces and literal
shell metacharacters remain valid single argv elements.

E4 files must already contain fully written and validated input. Allocation,
seeding and validation are outside the timed workload; `fallocate` alone does
not establish media contents. Plans never create or seed files. A future
comparison must prove identical namespace/window mapping before raw-device
access; the planner never touches a namespace, filesystem or GPU.

## Generated commands and evidence

`plan.json` contains all cells, requested geometry, source revision, setup
omissions and explicit access/completion semantics. Per-cell paths are relative
descendants of the output directory. `command.json` stores `argv`, explicit
`env`, config path and `needs_build`; configs and receipts have no fabricated
measurement fields in nonexecuting plans. Executed cells additionally preserve
`stdout.raw`, `stderr.raw`, `native.jsonl`, `process.json`, `receipt.json` and
`parsed-native.json` when parsable. `summary.json` retains every planned cell,
including unselected/refused rows; one selected success does not complete both
profiles or the entire matrix.

E4 uses the real `--backend=tent --metadata_type=p2p --xport_type=iouring`
CLI. The configuration key is spelled `transports/io_uring`. Default sets
`pinned_staging=false`. Pinned sets `pinned_staging=true`, `staging_slot_kb`
and `staging_slots`. GDS uses `--xport_type=gds`, an empty TENT config and
`CUFILE_FORCE_COMPAT_MODE=true`; it never retries iouring under a GDS label.

E7 source commands allocate DRAM and WRITE to the remote VRAM target. Commands
include a separate `target_command` for the destination. The source contains
only the nonexecuting `{FRESH_TARGET_SEGMENT_NAME}` segment placeholder and
`target_segment_source=fresh-target-stdout`. Execution obtains the segment from
the current target banner and validates campaign/cell/profile, both hosts, launch
UUID, GPU identity and allocation scope. There is no SSH workflow.

The command `env` mapping is the explicitly requested configuration, not a copy
of ambient environment variables. The executor clears conflicting
`MC_IOURING_*`, `MC_FORCE_TCP`, `MOONCAKE_LOCAL_HOSTNAME` and other undeclared
Mooncake/GDS overrides, uses a small fixed environment and records removed
variable names without their values. Arguments are passed without a shell.

Pinned pools can fall back to pageable buffers if allocation fails, requests
exceed the slot or slots run out. Pool-success and no-fallback evidence are
required before reporting the pinned route. Compatibility mode also needs
actual cuFile evidence; Mooncake's GDS transport uses the batch API, whose
availability must be demonstrated on the chosen SDK. No plan proves direct
GDS, pinned transfer, DMA or zero-copy.

All plans record `ratio_eligible=false` and `residency_qualification=pending`.
The existing NVMe/GPU runner has different random access, slot-ring, oracle and
timer contracts; its results cannot be paired with tebench by matching numeric
QD and block size. Keep native tebench metrics and negative results. Do not
convert them into an invented `io_ns` or infer macro speedup.

`--check_consistency=true` changes upstream work to WRITE/READ round trips;
that separate correctness campaign must use an authorized writable scratch
file and must not be reported as read-only performance. Upstream random mode
cannot use `write_seed/read_verify` and exports no full per-random-READ byte
oracle. These scope limits remain visible.

## E7 local endpoint handoff

Use the same `--campaign-id`, `--profile` and `--cell-id` at both endpoints.
The destination invocation adds `--endpoint destination --source-completion
/campaign/new-destination/source-inbox.json`; that inbox must be absent under
its new output directory and cannot conflict with generated artifacts. It
prints the path to its fresh `target-ready.json` and keeps its owned target alive.
The source invocation adds `--endpoint source --ready-receipt
/campaign/copied-target-ready.json`, using the newly transferred destination
receipt, and emits `source-completion.json` in its output root. Ready evidence
binds destination taskset/transport/VRAM/GPU/buffer/RPC semantics and the actual
`target_config` hostname to the current destination rig. Legitimate host-local
binary/config/output paths may differ; no remote artifact is opened locally. Transfer that
small file to the destination inbox. Transfer/orchestration is the operator's
existing tooling; this runner performs no network setup, SSH or uploads.

The destination verifies the source host, target launch, segment and successful
source exit/cleanup before stopping its target. Source-only success is
`source_completed` with `e7_qualification=awaiting_destination_final` and no
performance claim or published final E7 metric fields; native numbers remain
nested local evidence. The matching destination final receipt qualifies the
limited source/target lifetime obligation. Bad or missing completion still
triggers bounded stop/reaping and retains a failed result. The destination's
final receipt is needed to qualify E7 lifetime; a source result alone cannot do
so. Target-ready allocation evidence is explicitly the upstream banner scope,
not a physical mapping trace.

## Process and metric qualification

Initiator lifetime has a `duration_seconds+120` hang bound; target readiness is
bounded to 120 seconds and total target lifetime to `duration_seconds+240`.
After readiness the target's owned collector continuously drains both streams,
even while its caller sleeps. Collector shutdown and reaping are synchronized;
ready printing, receipt handling and interrupts share an unconditional cleanup
boundary. Timeout/output overflow/interrupt sends one TERM to the owned process group,
then KILL after five seconds if needed, with exit and cleanup recorded. Each raw
stream is capped at 64 MiB and native JSONL at 1 MiB. Overflow retains the prefix
and byte counts and cannot qualify a result. No retry or transport fallback is
relabeled as the requested arm.

The parser requires exactly one complete fixed-source `target_metrics` JSONL
row and one target matching the selected block/batch/workers/operation/segment.
It verifies positive completed-batch counts, exact bytes and native
throughput/latency arithmetic, rejecting nonfinite, duplicate, missing or
mismatched data. Native `*_gbps` denotes decimal GB/s. Wrapper spawn-to-reap time
is diagnostic and never substituted for native Tx/wall metrics. A buffered-I/O
warning, pinned fallback, missing exact `IOUringTransport:` pool success, error
or unresolved warning prevents route qualification. Unrelated opaque raw bytes
are retained; required parsed evidence must be valid, and ASCII failure/warning
markers are checked even beside invalid UTF-8. Ready lines are parsed
incrementally with a 1 MiB line bound. Retained cuFile/USB4 evidence is required for
those routes.

Upstream NUMA binding can expand a taskset-only CPU mask, so disclose the full
all-thread budget or provide evidence of existing effective cpuset constraints;
the runner creates no cgroup or scheduler setting. Random warmup advances each
worker's RNG before measurement, so equal seeds do not establish identical timed
address sequences. Preserve upstream setup, warmup, complete-batch waits, native
timers and negative results. Private host controls are always
`execution=contract-fixture`/`performance_claim=none` and export no summary
benchmark values. A fixture route may be source-scoped `qualified` when its
required logs/receipts pass, but missing TCP/GDS route evidence refuses fixtures
as well. These labels establish software behavior only.

## Building the existing dependency

Prepare the fixed source and its exact pybind11 gitlink independently. Required
dependencies include GCC/G++, CMake, the official CUDA SDK, liburing, gflags,
glog, JsonCpp, ASIO and NUMA. GDS additionally requires `cufile.h` and
`libcufile.so`. The planner does not download or install dependencies.

```sh
cmake -S "$MOONCAKE_SOURCE" -B "$MOONCAKE_BUILD" \
  -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_BUILD_TYPE=Release -DUSE_TENT=ON -DUSE_CUDA=ON \
  -DBUILD_BENCHMARK=ON -DBUILD_UNIT_TESTS=OFF -DBUILD_EXAMPLES=OFF \
  -DWITH_TE=ON -DWITH_STORE=OFF -DWITH_STORE_RUST=OFF \
  -DCUDAToolkit_ROOT="$CUDA_ROOT" \
  -DCUFILE_INCLUDE="$CUFILE_INCLUDE" -DCUFILE_LIB="$CUFILE_LIBRARY"
cmake --build "$MOONCAKE_BUILD" --target tebench --parallel "$BUILD_JOBS"
```

Retain configure/build logs, CMakeCache, source/submodule identity and SDK
versions. TENT discovers liburing and cuFile targets automatically; unsupported
`USE_IO_URING` or `USE_GDS` variables do not prove those transports were built.
The target binary is
`$MOONCAKE_BUILD/mooncake-transfer-engine/benchmark/tebench`. A successful build
or `--help` still establishes no physical execution qualification.
