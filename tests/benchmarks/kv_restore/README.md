# K-KV: KV-cache restore from host 1's SSD into host 2's GPU memory

Follow the [evaluation policy](../PERFORMANCE_POLICY.md) for baseline changes,
comparison eligibility and performance claims.

A KV cache computed on one GPU host is stored on host 1's NVMe SSD. Host 2,
connected to host 1 by one Thunderbolt/USB4 cable, restores a prefix of it
into its own GPU memory. The metric is the KV restore latency: from host 2's
request to the KV being resident in host 2's GPU memory. Each restore also
records CPU core-seconds on both hosts and, when the memory-controller
counters exist, host 2's memory traffic per KV byte. The arms are:

| Arm | Host 1 | Host 2 |
| --- | --- | --- |
| `xdev-ext` | `kv_restore serve`: NVMe READ and XDOMAIN TX in one session worker | `kv_restore restore`: XDOMAIN RX into frames of a CUDA allocation |
| `nvmeof` | kernel NVMe-oF/TCP target (`run.py nvmeof-target`) | `nvmeof_worker`: `pread` of the LBA range, `cuMemcpyHtoD` per chunk |
| `mooncake` | Mooncake Store real client with SSD offload (`mooncake_worker.py host1-load`) | `mooncake_worker.py host2-restore`: `batch_get_into` into a registered CUDA buffer |
| recompute | none | an operator-provided prefill command (`run.py recompute`) |

Nothing in this directory has run on Thunderbolt hardware. The host tests and
the KVM run below check correctness only and produce no performance number.

## Files

- `kv_layout.py`: models, the KV manifest, restore plans and the payload pattern.
- `kv_plan.h`, `kv_pattern.h`: the same plan and pattern in C for the workers;
  `kv_plan_cli.c` exposes them to `test_plan_crosscheck.py`.
- `kv_nvme_read.bpf.c`: host 1's NVMe program (key-based READ, PRIVATE).
- `kv_ce_place.bpf.c`, `kv_ce_place.h`: host 2's copy-engine program for the
  CE VMM destination (below).
- `kv_restore.c`: the xdev_ext worker (`serve`, `restore`, `local-verify`).
- `nvmeof_worker.c`, `mooncake_worker.py`: the baseline workers.
- `kv_protocol.py`: the worker line protocol; `kv_cpu.py`: CPU markers and the
  host-1 agent; `run.py`: orchestration; `analyze.py`: metrics and verdicts.
- `guest/`: the KVM correctness run of `kv_restore local-verify`.

## KV layout and restore plan

A manifest describes host 1's KV window, the stage window of host 1's NVMe
session, and the objects in it. Each object is one contiguous LBA extent
holding the KV cache of one context in token-chunk order, so a P-token prefix
is the first P × bytes_per_token bytes. Qwen3-14B uses 163,840 bytes per token
and Qwen3-8B BF16 147,456 bytes per token; prefixes of 4K, 16K and 32K tokens
are 0.56 to 5.00 GiB.

```json
{"schema": 1, "kind": "kv-layout", "lba_bytes": 512,
 "window": {"slba": 2048, "nlb": 83886080},
 "objects": [{"name": "qwen3-14b-ctx0", "model": "qwen3-14b", "tokens": 32768,
              "seed": 1, "slba": 2048, "nlb": 10485760}]}
```

A restore moves whole groups (default 128 KiB). Host 1's NVMe stage reads slot `key mod slots` of its
window, where slots is the window length in groups. A restore with ordinal r
uses keys `r × slots + slot0` to `r × slots + slot0 + groups − 1`, where slot0
is the object's first slot, so key i reads group i of the object and every
later restore uses larger keys. The program uses the batch key, not the batch
id: the core assigns keys in START order and restores a key when it retries a
frame allocation, while a batch id consumed by such a retry is lost
(`xdev_ext_mech_start_more`, `xdev_ext_mech_batch_get_locked`).

Host 2 lends destination frames `dst_frame0` onward once, in order
(`START_F_USER_FRAMES | START_F_ORDERED_FRAMES` without `RECYCLE`), so group
i lands at frame `dst_frame0 + i × frames_per_group` and the KV is contiguous in
GPU memory after the final notification. Frames lent this way return to the
application instead of being reused inside the START; a START without user
frames would reuse frames and overwrite earlier groups. Host 1 recycles a
staging ring of depth groups (`RECYCLE`). One START lends at most 65,536 frame
indices (libxdev_ext), so a 5 GiB restore needs frames of at least 128 KiB.
The default geometry is 128 KiB groups of one 128 KiB frame, depth 32 and an
XDOMAIN window of 32 groups (`arg1 = window << 32`). A group may carry up to
256 KiB (64 NHI frames), but nvme-pci caps one transfer at
`dma_opt_mapping_size()` (drivers/nvme/host/pci.c), which is 128 KiB with an
IOMMU DMA domain (`iova_rcache_range()`, drivers/iommu/iova.c). With larger
groups on such a host the NVMe program refuses every batch (`max_nlb`) and the
first restore aborts at BUILD; the KVM run below checks that case.

## CE VMM destination (GPUs without GPUDirect RDMA)

A GeForce GPU refuses the PEER pool: `nvidia_p2p_get_pages_persistent` cannot
pin its memory. `--dst ce-vmm` (restore and local-verify; the defaults stay
`peer` and `dmabuf`) gives such a host 2 another destination: the receiving
stage writes each group into a recycled ring of host frames (the ring's
XDEV_EXT UMEM, 4096-byte frames, so `--frame-bytes 4096`), and a CE stage with
`XDEV_EXT_CE_STAGE_F_TARGET_RANGE` copies the group with the GPU copy engine
into a CUDA VMM allocation of `--pool-bytes`. The allocation is exported as a
POSIX file descriptor and attached to `--ce-dev /dev/nvidiaN`, so CREATE
claims it. `kv_ce_place.bpf.c` (`--ce-prog`, PRIVATE) puts batch key k at
`dst_off + (k - first_key) * group_bytes`; the worker writes the restore's
first key, group count and `dst_off = dst_frame0 * frame_bytes` into the
program's `.bss` before each START. The KV ends where the PEER layout puts
it, contiguous from `dst_frame0`. Host 2's START lends only the ring
(min(groups, depth) groups, `START_F_RECYCLE`), so the 65,536-index limit no
longer bounds the restore (`host2_ring` in `kv_plan.h` and `kv_layout.py`).

Every `KV_RESULT` reports `dst`, `payload_path` and `cpu_copy_bytes`: the
payload bytes the worker copies with the CPU between t0 and t1. None of the
worker's paths copies payload, so the value is 0 by construction of the code,
not a measurement. With ce-vmm a restore also fails unless the CE stage
completed exactly one command per group. local-verify with ce-vmm checks the
whole allocation through CUDA after the clock: pattern inside the restore,
poison elsewhere. `run.py run --arm xdev-ext --dst ce-vmm --ce-dev
/dev/nvidiaN --ce-prog build/kv_ce_place.bpf.o --frame-bytes 4096` passes
these options; `analyze.py` reports `host2_cpu_copy_bytes` per point and,
against `nvmeof`, the host-2 criterion: no copied payload byte and host-2
CPU core-seconds per GB at most half of the baseline's. Because the copy
count is a property of the worker's code, a zero is reported as
`copy_verdict: by_construction`, never as a measured pass; the measured
quantity behind the same claim is `host2_memory_bytes_per_byte`. `run.json`
records the arm's `dst`, and `analyze.py` refuses to pool peer and ce-vmm
runs of one arm.

The kernel admits a range-target CE stage next to one NVMe stage or after one
XDOMAIN receive stage on an IOU_UMEM pool (`xdev_ext_decl_ce_check`,
src/core/include/linux/xdev_ext_family_core.h). local-verify (NVMe READ, then
CE) has run on an RTX 5090; restore (XDOMAIN RX, then CE) is admitted but has
not moved data yet, because no Thunderbolt pair exists. The CE program sees
the receiver's own batch key (START first_seq onward), and XDOMAIN v1 binds
received groups to receive batches in order, so group k lands at
first_key + k only while both hosts use the same first_seq and group count;
the RESTORE line checks that. A CE stage without the range flag can only
write its batch's ring slot, which does not keep the KV contiguous.

## Worker protocol

Every worker sets up once and then talks line by line on stdin/stdout:
`KV_READY {json}` after setup (`KV_ERROR {json}` and a nonzero exit if setup
fails); `GO run=ID ordinal=R object_slba=S bytes=B dst_frame0=D seed=X
verify=0|1` answered by one `KV_RESULT {json}`; `QUIT` answered by
`KV_BYE {json}`. A worker refuses a GO whose keys do not exceed the keys it
already used. With `verify=1` the worker compares the destination with the
pattern after the clock stopped. `kv_restore --dry-run` opens no device and
answers GO with the plan only.

`KV_READY` of `kv_restore` also carries `setup_ns`, the CLOCK_MONOTONIC
duration in nanoseconds of each set-up step for the E7 overhead table:
`control_open`; for each loaded program (`nvme_prog`, `xdomain_prog`,
`ce_prog`) `_open`, `_load_verify` (`bpf_object__load()`, including the
kernel verifier) and `_attach`; `cuda_alloc`, `ce_device_open`,
`ce_vmm_attach`, `memory_register`, `session_open` (UMEM or PEER pool),
`xdomain_link_discover`, `create`, `peer_connect` (includes waiting for the
peer) and `total`. A step the role or destination does not perform, and
every step of a dry run, is `null`. XDOMAIN login happens in the kernel when
the cable comes up and is not in this list.

`kv_restore restore` starts its receive batches, sends `RESTORE` to host 1's
`serve` over TCP, and waits for the session's final notification. Host 1
recomputes the plan from its own window and refuses a request whose keys or
group count differ. Latency is CLOCK_MONOTONIC on host 2 from just before its
START to the return of its final wait. A session whose restore did not finish
takes no further work. `KV_BYE` reports `retained` when closing found DMA
ownership unknown; the worker then keeps every resource.

## Running

Build in the source view (`python3 tools/layout.py view`), in
`tests/eval/kv_restore`:

```sh
make driver                                     # kv_restore, nvmeof_worker; libbpf >= 1.0
make bpf VMLINUX_BTF=/sys/kernel/btf/vmlinux CLANG=clang  # kv_nvme_read, kv_ce_place
```

Common steps, as root: write the pattern to host 1's extents (this overwrites
them) and start the CPU agent on host 1.

```sh
python3 run.py prepare-nvme --manifest kv.json --device /dev/nvme0n1 --i-understand-this-overwrites
python3 kv_cpu.py agent --listen HOST1_TB0:7701 --token-file token --allow-drop-caches
```

`xdev-ext`: attach `examples/network/xdomain_peer.bpf.o` as the XDOMAIN class
default, or pass `--xdomain-prog` to load it as a PRIVATE instance.

```sh
# host 1
kv_restore serve --nvme /dev/ng0n1 --nvme-prog build/kv_nvme_read.bpf.o --listen HOST1_TB0:7700 \
  --service SERVICE --window-slba 2048 --window-nlb 83886080 --lba-bytes 512 \
  --group-bytes 131072 --frame-bytes 131072 --depth 32 --window 32 --early
# host 2
python3 run.py run --arm xdev-ext --manifest kv.json --object qwen3-14b-ctx0 --repetitions 10 \
  --host1-agent HOST1_TB0:7701 --token-file token --drop-caches-host1 --drop-caches-host2 \
  --worker-bin build/kv_restore --gpu-bdf 0000:01:00.0 --gpu-node /dev/nvidia0 \
  --pool-bytes 5368709120 --peer HOST1_TB0:7700 --service SERVICE --output results/xdev-ext
```

`nvmeof`: on host 1 `run.py nvmeof-target up --device /dev/nvme0n1 --addr
HOST1_TB0 --nqn NQN` (`down` reverses it); on host 2 `nvme connect -t tcp -a
HOST1_TB0 -s 4420 -n NQN`, then `run.py run --arm nvmeof --device /dev/nvmeXnY`
with the same manifest. The namespace is the same device, so the arm reads the
same LBAs. The worker's defaults are untuned: buffered reads into pageable
memory, one thread, 1 MiB chunks, one `cuCtxSynchronize` before the clock
stops.

`mooncake`: build Mooncake d01447808d10af78011e9203d53796a15a032a03 with the
store enabled; on host 1 start `mooncake_master -enable_offload=true` and
`mooncake_worker.py host1-load --manifest kv.json --local-hostname HOST1_TB0
--master HOST1_TB0:50051 --ssd-offload-path DIR`; on host 2 `run.py run --arm
mooncake --local-hostname HOST2_TB0 --master HOST1_TB0:50051`. Host 1 keeps
Mooncake's factory configuration apart from SSD offload, so its DRAM segment is
16 MiB and the KV is stored as 4 MiB chunks. Host 2 contributes no DRAM segment
(`global_segment_size` 0), so no replica can land in host 2's DRAM. Every
restore is refused unless each chunk has a complete local-disk replica and no
complete memory replica; each record also states whether a memory replica
existed after the restore.

recompute: `run.py recompute --command 'TEMPLATE {model} {prompt_tokens}'`
times the operator's command. If its last stdout line is a JSON object with
`prefill_seconds`, the analysis uses that value instead of the wall time.

`run.py run` records an idle window first, then for every restore: page cache
drop on the hosts that were asked for it, CPU markers on both hosts, optional
`perf stat --control` counters enabled only around the restore
(`--perf-events`; check that the `amd_umc_*` events exist before relying on
them), one GO and one row in `results.jsonl`. `analyze.py results/*` derives
the planned metrics and verdicts; it needs at least 10 successful runs per arm
and prefix for a latency verdict.

## Tests

`make check` runs the C plan test against the kernel's own CREATE, START and
XDOMAIN rules, the BPF callbacks with the production SQE admission helper,
and the Python tests. Those tests use regular files, a fake configfs tree, a
recording stand-in of `mooncake.store`, a fake worker and a loopback agent.
`test_worker_contract.py` builds `kv_restore` (libbpf >= 1.0) and checks its
dry-run plans against `kv_layout.py`.

`guest/kv_restore_kvm.sh` boots a private KVM guest with one QEMU NVMe disk
and runs `kv_restore local-verify`: NVMe READ with the key-based program into
a system-heap dma-buf PEER pool, with host 2's ordered destination placement.
The oracle requires pattern bytes in each destination range, poison
everywhere else, a digest equal to the host's, exact cumulative counts,
planned refusals before any START and a clean exit. Run C uses 256 KiB groups:
when the guest reports a 128 KiB maximum transfer (`--viommu`), its first
restore must abort at BUILD with no native command and every later request
must be refused. The guest run exercises
neither XDOMAIN, nor GPU memory, nor Thunderbolt; the two-host XDOMAIN chain
is composed only in the host fixture `tests/network/xdomain/chain`.
