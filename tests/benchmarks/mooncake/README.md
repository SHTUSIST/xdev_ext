# Mooncake baseline command plans

This directory prepares Mooncake E4 storage-to-GPU and E7 host-memory-to-remote-GPU
baseline commands. It does not execute benchmarks. Read the
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

`--mode check-setup` aggregates missing declarations, source/binary and compile
feature metadata, without starting `tebench`. This delivery has no independently
qualified physical execution evidence, so setup remains `setup_refused`, exit 4.
`--mode run` also always returns `setup_refused`, exit 4. Setting
`physical_run_authorized=true` in a JSON file cannot enable execution.

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
measurement fields. There are no raw output files, native JSONL or performance
numbers because no benchmark runs.

E4 uses the real `--backend=tent --metadata_type=p2p --xport_type=iouring`
CLI. The configuration key is spelled `transports/io_uring`. Default sets
`pinned_staging=false`. Pinned sets `pinned_staging=true`, `staging_slot_kb`
and `staging_slots`. GDS uses `--xport_type=gds`, an empty TENT config and
`CUFILE_FORCE_COMPAT_MODE=true`; it never retries iouring under a GDS label.

E7 source commands allocate DRAM and WRITE to the remote VRAM target. Commands
include a separate `target_command` for the destination. The source contains
only the nonexecuting `{FRESH_TARGET_SEGMENT_NAME}` segment placeholder and
`target_segment_source=fresh-target-stdout`. A future launcher must obtain a
fresh segment from that target's current stdout before executing anything;
this planner implements no launcher or SSH workflow.

The command `env` mapping is the explicitly requested configuration, not a copy
of ambient environment variables. A future executor must clear conflicting
`MC_IOURING_*`, `MC_FORCE_TCP`, `MOONCAKE_LOCAL_HOSTNAME` and other undeclared
Mooncake/GDS overrides, rather than merge them into the plan silently.

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
