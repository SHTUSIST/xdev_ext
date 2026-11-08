# xdev_ext KV connector for vLLM 0.33.0

`XdevExtConnector` lets vLLM 0.33.0 load the KV cache of a prompt prefix
that is stored on an NVMe SSD, through the xdev_ext K-KV restore path
(`tests/benchmarks/kv_restore`), instead of recomputing it. On host 2 the
`kv_restore restore --dst ce-vmm` worker receives the prefix from host 1 over
Thunderbolt (host 1 runs `kv_restore serve`: NVMe READ and XDOMAIN send). The
GPU copy engine writes the prefix into a contiguous staging range of a CUDA VMM
allocation. A GPU kernel then copies it into vLLM's paged KV blocks. On one host,
`kv_restore local-verify --dst ce-vmm` reads the local NVMe instead; that mode
checks function only.

The connector is written against vLLM 0.33.0 (tag commit
`4ba787ec9959e566d3b587a796dff07673324da5`):
`vllm/distributed/kv_transfer/kv_connector/v1/base.py` and the
`LMCacheMPConnector` and `ExampleConnector` that ship with it.

Nothing in this directory has run with vLLM, a GPU or Thunderbolt hardware.
See "What has been checked" below.

## Use

```sh
python -m pip install --no-deps src/compute/vllm/kv_connector
vllm serve MODEL --kv-transfer-config '{
  "kv_connector": "XdevExtConnector",
  "kv_connector_module_path": "xdev_kv_vllm.connector",
  "kv_role": "kv_consumer",
  "kv_load_failure_policy": "recompute",
  "kv_connector_extra_config": {
    "xdev_ext.index": "/path/kv.index",
    "xdev_ext.model_key": "qwen3-8b-bf16",
    "xdev_ext.pool_bytes": 5368709120,
    "xdev_ext.worker_argv": ["/path/kv_restore", "restore", "--dst", "ce-vmm",
      "--gpu-bdf", "0000:01:00.0", "--ce-dev", "/dev/nvidia0",
      "--ce-prog", "/path/kv_ce_place.bpf.o", "--frame-bytes", "4096",
      "--group-bytes", "131072", "--depth", "32", "--window", "32", "--early",
      "--window-slba", "2048", "--window-nlb", "83886080", "--lba-bytes", "512",
      "--pool-bytes", "5368709120", "--peer", "HOST1_TB0:7700", "--service", "SERVICE"]}}'
```

The connector refuses to start when `kv_load_failure_policy` is not
`recompute`, because a failed restore must be recomputed. It also refuses a
model with more than one KV cache group, a model that is not full attention,
and tensor or pipeline parallelism.

Keys of `kv_connector_extra_config` (an unknown `xdev_ext.` key is an error):

| key | meaning |
| --- | --- |
| `xdev_ext.index` | prefix index file (format below); required |
| `xdev_ext.model_key` | model name inside the prefix hash, for example `qwen3-8b-bf16`; required |
| `xdev_ext.pool_bytes` | staging allocation size; must equal the worker's `--pool-bytes`; required |
| `xdev_ext.worker_argv` | the restore worker command; required in the worker process |
| `xdev_ext.load_mode` | `async` (default) or `sync` |
| `xdev_ext.group_bytes`, `xdev_ext.lba_bytes` | restore group and LBA size (131072, 512); must match the worker |
| `xdev_ext.ordinal_file` | file that keeps the next restore ordinal across vLLM restarts |
| `xdev_ext.ordinal_base` | first ordinal when no file exists (1) |
| `xdev_ext.max_restarts` | worker replacements after failures before loading is disabled (3) |
| `xdev_ext.ready_timeout_s`, `xdev_ext.go_timeout_s` | worker setup and per-restore deadlines (300, 600) |
| `xdev_ext.worker_log`, `xdev_ext.stats_file` | worker stderr; one JSON line per load |
| `xdev_ext.scatter` | `triton` (default) or `torch` |
| `xdev_ext.gpu_bdf` | PCI address the vLLM GPU must have (the worker's GPU) |

The vLLM worker process starts the restore worker as its child, so vLLM needs
the privileges `kv_restore` needs (root in the K-KV runs). Being the parent
also gives it the ptrace access that `pidfd_getfd` requires under Yama scope 1.
The restore worker allocates `xdev_ext.pool_bytes` of GPU memory, plus its own
CUDA context, after vLLM has sized its KV cache. `--gpu-memory-utilization`
must therefore leave that much memory free. Mapping the allocation into vLLM
uses no further GPU memory.

Host 1's `kv_restore serve` refuses a restore whose keys it has already used.
Every vLLM start therefore needs a larger ordinal than the last one: keep
`xdev_ext.ordinal_file`, or restart `serve` together with vLLM.

## Stored prefixes

The stored KV and the index come from the K-KV benchmark tools
(`tests/benchmarks/kv_restore`). Each object holds its KV in the order of
vLLM blocks. Within one block the order is attention layer, then that layer's
`[H, N, C]` page: H KV heads, N tokens of the block, and C elements per
(head, token) cell. A cell holds K and then V, which is how vLLM 0.33.0 stores
it. A prefix whose length is a whole number of blocks is therefore the first
`prefix tokens × bytes per token` bytes of its object.

The index is a text file:

```text
xdev-kv-index 2 dtype=bfloat16
prefix HASH object=NAME slba=N offset=N bytes=N tokens=N [fnv1a=0x...]
```

HASH chains SHA-256 over whole blocks of u32 token ids. The chain starts from
a block that names the model key and the layout: block size, number of
layers, number of heads and cell bytes. Two consequences follow. First, the
hashes of a P-token prefix are the first P / block_size hashes of every longer
prompt that starts with it. Second, a prefix stored for another model key or
layout never matches. The connector offers the longest stored prefix of at most
prompt length − 1 tokens whose restore fits the staging allocation. The layer
order is the order of the layer numbers in vLLM's layer names
(`model.layers.<n>.`).

## How a load runs

The scheduler process reads the index. When a prompt's stored prefix P is
longer than vLLM's own computed tokens C, the connector reports P − C external
tokens. The restore starts at the last block boundary at or before C whose byte
offset is a whole group, because the worker reads whole groups. It reads
whole groups, never past P rounded up to a group.

In the worker process, `register_kv_caches` checks that every layer cache is a
`[B, H, N, C]` view with the heads and cells of the stored layout. It then
starts the restore worker and maps the worker's staging allocation. The
worker exports that allocation as a file descriptor; `KV_READY` reports it as
`vmm_export_fd` and `vmm_bytes`. The connector duplicates the descriptor with
`pidfd_getfd`, imports it with `cuMemImportFromShareableHandle` and maps it
on the same GPU.

- `async` (default, the same scheme as `LMCacheMPConnector`):
  `get_num_new_matched_tokens` returns `(P - C, True)`, so vLLM keeps the
  request waiting. A background thread sends one `GO` per load. Loads run one
  at a time, and each lands at staging offset 0. The thread then copies every
  layer into the request's blocks on a separate CUDA stream. That stream first
  waits for an event recorded in `start_load_kv`, so the step's block zeroing
  has finished. The thread waits for the copy, then reports the request in
  `finished_recving`. A load that fails is also reported in `failed_recving`,
  and vLLM recomputes the whole request.
- `sync`: `get_num_new_matched_tokens` returns `(P - C, False)`. The scheduler
  packs one step's loads into the staging allocation, and a load that does
  not fit is offered as a miss. `start_load_kv` queues the restores after the
  previous step's copies have finished reading staging.
  `wait_for_layer_load(layer)` waits for each restore of the step and copies
  that layer on the current stream, before the layer's attention. When a
  restore or a copy fails, or when a layer has not been copied by the end of
  the step, the request's loaded blocks are reported in
  `get_block_ids_with_load_errors`. vLLM then discards that request's output
  of the step and recomputes. In this mode the connector asks for piecewise
  CUDA graphs.

A load counts as good only when every check below passes:

- The worker answered `ok`.
- The `KV_RESULT` carries exactly the requested bytes.
- The destination is `ce-vmm` at the requested frame.
- No payload byte was copied by the CPU.
- Every layer was copied.

When a restore fails after its START, the worker session takes no more work,
so the connector replaces the worker; after `xdev_ext.max_restarts`
replacements it stops loading and every stored prefix is recomputed. A refusal
before START keeps the worker. When `KV_BYE` reports `retained` (the kernel
does not know who owns the DMA), the connector keeps that staging mapping until
the process exits.

The copy kernel (`scatter.py`, Triton) runs one program per 16 tokens and per
KV head. It addresses vLLM's layer view through the view's own strides, so
every vLLM KV cache layout works; offsets are 64-bit. `layout.py` defines the
two index functions; the torch version and the Triton kernel are tested against
them element by element.

## Correctness hook

`python -m xdev_kv_vllm.verify generate` runs vLLM offline at temperature 0,
once with the connector and once without. Each prompt runs separately. The
command records the output token ids and the connector's load rows from
`xdev_ext.stats_file`. `verify compare` passes a prompt only when all three
hold:

- The restored run loaded exactly the stored prefix length.
- No load of that prompt failed. A silent fallback to recompute is therefore
  not a pass.
- The first 16 greedy tokens equal those of the run without the connector.

## What has been checked

Typed prefix hashes use domain version 2 and include canonical tensor dtype.
BF16 and FP16 differ even when byte geometry matches. The connector checks
the actual cache spec and registered tensor dtypes against `cache_dtype`
(using `model_config.dtype` when `auto`) and optional `xdev_ext.kv_dtype`.
Unknown or inconsistent metadata is refused. The dump producer validates
actual tensors, records dtype in its sidecar, and pack checks its prefix
hash against tokens/layout/dtype before writing an index-v2 dtype header.
`kv_dump.py vllm --kv-dtype bfloat16` is the approved default; explicit
FP16 is also supported.

Legacy raw index-v1/manifest readers remain available to the benchmark and
C worker. The connector refuses an untyped index with a rebuild message.
Keep original files and use a new checked dump directory before repacking;
two-byte cells alone cannot prove an old payload was BF16 or FP16.

Sync mode requires actual `KV_READY.role=restore`. A local-verify worker
poisons its whole staging allocation before each GO and is refused before
VMM import in sync mode. Async local-verify remains available: its scatter
and fence finish before the next restore. Unknown worker roles are refused.
The first-16-token hook above is bounded evidence, not proof of complete
application or KV correctness.

- Host tests (`tests/compute/vllm/kv_connector`, no vLLM, torch or GPU) cover
  the index mapping, the index format and the scheduler and worker rules,
  including failures. They drive a stand-in worker process that speaks the
  protocol, and check the connector's methods against vLLM 0.33.0's interface
  (`vllm_stub.py`).
- `test_scatter.py` checks the torch copy, and the Triton kernel under
  `TRITON_INTERPRET=1`, against `layout.py` on the CPU.
- `test_staging.py` checks the descriptor transfer. Its CUDA import part needs
  a GPU.

Not yet run: the Triton kernel compiled for a GPU, the staging import on a
GPU, vLLM itself, and any restore on hardware.
