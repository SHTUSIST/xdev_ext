# NVMe<->GPU comparison arms

[Performance evaluation policy](../PERFORMANCE_POLICY.md)

Programs and a runner that compare the xdev_ext session with the strongest
host-staged path and with GPUDirect Storage, for loads (NVMe -> GPU) and
saves (GPU -> NVMe) of 4 KiB to 4 MiB I/Os at queue depths 1 to 256,
sequential or random. This directory contains code only; it holds no
measurement, and VM timings are not performance data.

| Arm | Program | Route |
| --- | --- | --- |
| `session` | `session_nvme_ce.c` | load `[NVMe READ, CE H2D]`, save `[CE D2H, NVMe WRITE]`: one two-stage session on the ring's XDEV_EXT UMEM |
| `uring-cuda` | `bench_uring_cuda.cc` | io_uring `O_DIRECT` READ_FIXED/WRITE_FIXED into `cudaHostRegister`ed staging slots, `cudaMemcpyAsync` on streams |
| `gds-batch` | `bench_cufile_batch.cc --api batch` | `cuFileBatchIOSubmit`/`GetStatus`, two batch handles |
| `gds-async` | `bench_cufile_batch.cc --api async` | `cuFileReadAsync`/`cuFileWriteAsync` on registered CUDA streams |
| `gds-direct` | `../gds/run.py` | synchronous cuFile, qd 1, sequential, whole-window destination only (delegated; it creates its own file) |

The session arm ports the NVMe -> UMEM -> GPU -> UMEM -> NVMe chain idea of
`archive/conduit-legacy/eval/benchmark-code/bench_full_pipeline.c` (git blob
`69e46d263a35d1d5b3825c401597700c8ea15978`). That program issued every
`pread`/`cuMemcpy`/`pwrite` from user space; here the kernel session owns
every step of every group and the CPU copies no payload.

## Shared contract

`nvme_gpu_core.h` holds the logic every arm shares; `test_core.c` checks it.

- **Geometry.** `size` is a 4 KiB multiple in 4 KiB..4 MiB, `qd` 1..256,
  `window` a multiple of `size` with at least `qd` blocks, `passes` 1..1000.
- **Schedule.** Each pass visits every block of the window once: `seq` in
  order, `rand` as `(a*i + b) mod n` with `gcd(a, n) = 1`, `a` and `b` derived
  from the seed and the pass.
- **Queue-depth meaning.** The staged baseline's `qd` bounds NVMe commands;
  it retains its original `2*qd` host slots and overlapping CUDA copies.
  NVMe QD is not the whole pipeline's logical depth, so equal numeric `qd`
  values do not establish equal credits across arms. The original batch
  implementation has two `ceil(qd/2)` waves; the runner excludes odd `qd > 1`
  batch cells from equal-QD collection because they can admit `qd+1` I/Os.
  Batch QD 1, even batch depths and odd async depths remain supported.
- **Payload.** 64-bit word `w` of the window holds `(w ^ mix(seed)) * odd`, so
  every word encodes its own position: misplaced, stale or torn data never
  matches, and a block image names its block.
- **Device layout (`--destination`).** `slot-ring`, the default, is the
  session's layout: a ring of `qd` device slots of one block each, schedule
  position `i` in slot `i mod qd`. A load rewrites a slot only after the copy
  that last wrote it completed, so at most `qd` blocks are in flight, the
  bound the session's depth sets. `window` places block `b` at device offset
  `b*size` over the whole window. Every record carries `destination`, and
  `run.py` refuses a record whose layout differs from the campaign's, so the
  two layouts are never paired. The session runs only `slot-ring`;
  `gds-direct` only `window`.
- **Completion wait (`--completion-wait`).** `block`, the default, makes each
  baseline sleep when nothing progressed: `uring-cuda` on its oldest
  outstanding operation (`io_uring_wait_cqe_timeout` for an NVMe command,
  `cudaEventSynchronize` on a `cudaEventBlockingSync` event for a copy);
  `gds-batch` in `cuFileBatchIOGetStatus` with `min_nr` equal to the oldest
  wave's outstanding I/Os and the campaign deadline as timeout; `gds-async`
  in `cudaEventSynchronize` on the oldest stream's blocking event. Whether
  libcufile sleeps or spins inside `GetStatus` is not verified here. `poll`
  spins with zero-timeout status calls, `io_uring_peek_cqe` and
  `cudaEventQuery`. The session always sleeps on its eventfd. Every record
  carries `completion_wait`; poll records have `cpu_us` and `host_busy_us`
  close to the wall time by construction, so they are excluded from any CPU
  cost comparison.
- **Timed region.** First submission to last completion of a pass. Seeding
  and the oracle are outside it; no arm checks data per I/O. Session wall,
  process-CPU and host-busy intervals include its final `es_settle` check.
- **Oracle.** After each pass the destination is read back once and compared
  completely. The destination starts each pass as a sentinel (the payload of
  the complemented seed). Staged and cuFile arms: on the slot ring, slot `d`
  must hold the block of the last schedule position sent to it (load), and
  the file block of position `i` must be the image of slot `i mod qd`, which
  was seeded with block `i mod qd` (save); with `window`, the device window
  (load) or the file window (save) must equal the payload.
- **Records.** One JSON line on stdout, only after the oracle and all cleanup
  succeeded. `cpu_us` is the process's user+system time; `host_busy_us` is
  the busy time of all CPUs from `/proc/stat` over the timed region, which
  also counts the session's kernel worker and interrupt work (10 ms
  granularity on most kernels, so it needs long campaigns).
  `uring-cuda` adds `nvme_stage_ns` and `copy_stage_ns`, the summed
  submit-to-reap times of its NVMe commands and copies; they overlap, so they
  are a breakdown, not a split of `io_ns`.
- **Exit codes.** 0 verified, 1 failure, 2 usage, 4 a missing capability
  (SDK, device, driver, filesystem feature, attached program), with `SKIP` on
  stderr and nothing on stdout.
- **Durability.** Shared-file arms do not flush inside the timed region: a
  save completes when the NVMe or cuFile write completes. The synchronous
  delegate checkpoint includes `fsync` and has a separate timing contract.

## Session arm specifics

- The struct_ops programs `nxp_nvme_ops` (`nxp_mech.bpf.o`, `nvme_mode=0`,
  `key_base` 1) and `ce_plan_ops` (`ce_plan.bpf.o`) must be attached;
  otherwise CREATE fails and the arm exits 4.
- Batch `k` reads or writes LBA `slba + k*size/lba` (the plan is linear in the
  batch key), so only `--pattern seq` runs; `rand` exits 4. The session depth
  limit `XDEV_EXT_MECH_MAX_DEPTH` is 64, so `qd > 64` exits 4.
- Kernel gap: a CE stage can only copy within its batch's window slot.
  `xdev_ext_ce_validate()` (`kernel/io_uring/xdev_ext_mech_ce.c`, lines
  404-436) computes the slot's offset with `xdev_ext_mech_window_offset()`
  (line 425; `kernel/io_uring/xdev_ext_mech_window.h`, lines 13-24: offset
  `slot * group_bytes`) and returns `-ERANGE` (line 434) for any copy outside
  `[slot*group_bytes, (slot+1)*group_bytes)`. A CE plan program cannot place
  a block at its LBA order over a larger device window; the kernel refuses
  it, whatever the plan computes. The session therefore lands blocks in a
  ring of `qd` slots, and the baselines use the same ring by default. (Line
  numbers are those of main 8e0238a.)
- A batch's slot is the index of the batch object the kernel reuses
  (`xdev_ext_mech_batch_slot()`, `kernel/io_uring/xdev_ext_mech.c` line 911
  at 8e0238a), not a function of the batch key, so the session oracle cannot
  name the block each slot must hold. The load
  oracle checks that all `qd` slots hold whole, distinct blocks of the window
  (every block when `window/size == qd`; with more blocks, the last block
  copied into each slot, and the stage counters cover the rest). The save
  oracle seeds slot `s` with block `s` and checks that every group of the
  file window is an exact image of some slot and that every slot's image
  appears. `run.py` requires `slots_used == qd` in both directions.
- `--file` names the same blocks as `--ng`/`--slba`: a block device, or a
  regular file whose window is one physically contiguous extent run.
  `run.py` derives the LBA window from FIEMAP and the partition offset and
  refuses a file it cannot map. Before any session cell it runs one small
  read-only load through `--ng`; unless that reads back the file's own bytes,
  no session cell runs, so a wrong window never receives a raw NVMe WRITE.
- With `/dev/xdev_ext_ce_sim` (the CPU copy-engine stand-in) a record says
  `execution=kvm-ce-sim`, `performance_claim=none`. `guest_correctness.sh`
  runs both directions in an xdev_ext KVM guest with that stand-in; it is not
  run by the host checks.

## Build and run

```sh
make -C tests/eval/nvme_gpu            # host build of the session arm
make -C tests/eval/nvme_gpu check      # host contract tests
make -C tests/eval/nvme_gpu cuda-build CUDA_ROOT=/usr/local/cuda   # needs an official SDK

python3 tests/eval/nvme_gpu/run.py --arms gds-direct,gds-batch,gds-async,uring-cuda,session \
  --sizes 4096..4194304 --qd 1,32,256 --pattern seq,rand --pairs 5 \
  --window-bytes 1073741824 --destination slot-ring --completion-wait block \
  --directory DIR --cuda-root /usr/local/cuda --ng /dev/ng0n1 --ce-dev /dev/nvidia0 --ce-alloc
```

`--window-bytes` must hold `max(qd)` blocks of the largest size (here
256 x 4 MiB = 1 GiB). With `--destination slot-ring`, `gds-direct` is
`not_run`; run it in a separate `--destination window` campaign, which in
turn leaves the session `not_run`.

`run.py` creates one temporary file of `--window-bytes` in `DIR` for the
session, staged and batch/async arms, runs every cell `--pairs` times in
alternating arm order, validates each record against an independent schema
and count oracle, and prints the
records. Cells an arm cannot run (session with `rand`, `qd > 64` or
`window`; batch with odd `qd > 1`; `gds-direct` beyond qd 1 sequential or
with `slot-ring`) are reported as `not_run`. Without an
NVIDIA control device the CUDA arms are `not_run`; nothing ran means exit 4.
The synchronous `gds-direct` delegate instead creates an independent file and
retains guarded operation history. Its `io_ns` sums synchronous call/completion
intervals and includes checkpoint `fsync`; the other arms use per-pass wall
time without a timed flush. `pair` is an alternating repetition index, not an
equivalence claim. The runner emits raw records and no equivalent-work ratio.
Its build step invokes the actual delegate with `--build-only`: success is 0,
an unavailable SDK/capability remains 4, and a fatal child failure remains 1.
The CUDA arms compile with the host C++ compiler against the SDK's headers
and `libcudart`/`libcufile`; see the [CUDA build compatibility notes](../README.md#cuda-arms-against-one-official-sdk)
for official-SDK compile/link checks and older-SDK limits. Before any campaign on the GPU host, run
`make -C tests/eval/nvme_gpu cuda-build` against the official SDK and one
small cell of `gds-batch` and `gds-async`: whether cuFile's level-3
statistics count batch and stream-async I/O as NVFS/P2P operations has not
been checked; if they do not, both arms exit 4 on every cell.

Not here: the SPDK arm (`../spdk`), BaM (`../bam`), and LLM load/save
macro workloads.

The shared [session guest driver](../session_guest/README.md) builds this arm
for the existing correctness-only KVM suite, with independent byte/guard
oracles and strict counts, STOP and descriptor checks.
