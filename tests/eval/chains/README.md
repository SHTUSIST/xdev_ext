# Multi-stage chains: one session versus per-pair composition

This directory runs pipelines of three or four device stages, the
composability experiment the OSDI review asks for (E1), the mechanism
ablations (E7) and the size/pool/depth/concurrency sweeps (E10). Nothing here
has produced a timing number yet: timing needs physical NVMe, NIC, GPU and IAA
devices, and the correctness mode has so far only been compiled and unit
tested on a host. The guest correctness run is still to be done.

## Arms

- `session`: the whole chain is one mechanism session. It is created once with
  `IORING_REGISTER_XDEV_EXT_MECH` CREATE, gets one terminal `NOTIFY_ARM` and
  one `START` per window, and the process blocks once on the eventfd.
  Implemented in `chain_session.c`.
- `staged`: the strongest per-pair Linux composition built here. Every buffer
  is allocated and registered once. NVMe uses io_uring `READ_FIXED`/`WRITE_FIXED`
  on the `O_DIRECT` block device. The GPU uses CUDA `cuMemHostRegister` with
  asynchronous H2D/D2H on one stream per slot. NIC TX uses io_uring
  `SENDMSG_ZC` on a UDP socket; NIC RX uses `RECVMSG` straight into the slot.
  Up to `depth` groups are in flight. Implemented in `chain_staged.c`. Its
  NIC leg has two known weaknesses, described under "Staged NIC leg" below.
- `userspace-shared`: one process registers one hugepage region as AF_XDP
  UMEM, as io_uring fixed buffers and with CUDA, and sequences the stages
  itself. This arm is `../userspace_orchestrator/` (E2).

User-space senders write the same NXP segment header as the session's AF_XDP
TX plan (`chain_nxp.h`). `test_chain_spec.c` checks that header against the
kernel's receive parser `xdev_ext_mp_rx_parse`. So any arm can feed any
receiver.

## Chains

| chain | stages | status |
|---|---|---|
| `nvme-gpu-nic` | NVMe READ, CE H2D, CE D2H, AF_XDP TX | runs; paired with `nic-gpu-nvme` |
| `nic-gpu-nvme` | AF_XDP RX, CE H2D, CE D2H, NVMe WRITE | runs; the receiver compares its NVMe window |
| `nvme-iaa-gpu` | NVMe READ, IAA decompress, CE H2D | runs (session); staged is CPU zlib, correctness only |
| `nvme-nic`, `nic-nvme` | the two-stage pair, for E7 | runs |
| `nic-iaa-gpu` | AF_XDP RX, IAA, CE | refused, see below |
| `nvme-crc-nic` | NVMe, in-frame CPU transform, NIC | refused: `unsupported: in-frame transform not implemented` |

Reading the live code turned up these limits. Each refusal says which one it
hit.

1. `nic-iaa-gpu` cannot be one session. `xdev_ext_mech_create_check`
   (`kernel/io_uring/xdev_ext_mech_step.h`) requires an AF_XDP stage to use the
   socket's UMEM (`XDEV_EXT_MECH_POOL_XSK`).
   `xdev_ext_mech_transform_reserve` (`kernel/io_uring/xdev_ext_mech.c`) requires
   the IAA destination leases to come from the io_uring UMEM
   (`XDEV_EXT_MECH_POOL_IOU_UMEM`). `nvme-iaa-gpu` is the IAA chain that can run.
2. The IAA class admits at most `CRYPTO_ACOMP_DST_MAX` = 131072 bytes of
   source and of destination per batch (`xdev_ext_iaa_bind` checks the
   capacity, `xdev_ext_iaa_validate` the source length, in
   `kernel/io_uring/iaa/xdev_ext_mech_iaa.c`). run.py therefore caps an
   `nvme-iaa-gpu` group at 128 KiB, and a larger record is a burst of such
   groups. chain_bench refuses a larger `group_bytes` or `capacity` for an
   IAA stage with a reason that names the limit.
3. A CE stage copies only inside one window slot of the session's
   `group_bytes` (`xdev_ext_ce_validate` in `kernel/io_uring/xdev_ext_mech_ce.c`).
   An IAA output larger than `group_bytes` therefore cannot reach the GPU. In
   `nvme-iaa-gpu` each record on NVMe is the compressed stream zero-padded to
   the uncompressed size. The NVMe stage then reads the full uncompressed size,
   so compression saves no NVMe bandwidth in this chain.
4. No mechanism class registers `default_build`, so a build that returns
   `XDEV_EXT_MECH_BUILD_DEFAULT` aborts with `-EOPNOTSUPP`. The `--plan default`
   ablation is refused until a class gains one.
5. `nvme-crc-nic` needs a class that claims a frame exclusively, rewrites it in
   place and republishes it (audit CAS-8/F9). The BPF frame view is read-only.
6. A batch holds at most 32 frames (`XDEV_EXT_MECH_MAX_FRAMES`) and a session
   at most 64 batches in flight (`XDEV_EXT_MECH_MAX_DEPTH`). A NIC chain's
   group is therefore at most 32 NXP segments (32 x 1432 bytes at MTU 1500).
   A larger record is a burst of several groups. Depths above 64 are refused.
7. The XDP redirect helper attaches one program per interface, so concurrent
   sessions (`--sweep sessions=`) are refused for chains with AF_XDP. They are
   run for `nvme-iaa-gpu`. One struct_ops plan per class is live at a time, so
   concurrent sessions need every plan they use, `chain_iaa_ops` included,
   attached once system-wide (rig `attached`); run.py refuses otherwise.

## Measurement

Two loads, chosen with `--load` (spec `load`):

- `sustained` (the default for timed runs) admits the whole campaign at once.
  The session arm issues one `START` for every batch of the campaign; the
  staged and user-space arms run one window over the whole campaign. Up to
  `depth` batches stay in flight in every arm. A record (`burst` batches)
  counts as complete when (r + 1) x `burst` batches of the campaign have
  finished. The session reports only counts, so all arms use this rule
  (`chain_timing.h`). Each completion is one `CLOCK_MONOTONIC_RAW` read into
  an array allocated and touched before the campaign. The result carries the
  completions of the measured records relative to the end of the warmup, and
  the absolute start `t0_ns`. run.py reports the campaign's bytes over its
  wall time as `gbytes_per_s` (median over `--pairs`), and the gaps between
  completions as p50/p99/p999. For concurrent sessions it merges every
  session's completions on the one system clock: all their bytes over the
  span from the earliest `t0_ns` to the last completion.
- `closed` offers one record at a time: one `START` (session) or one
  pipelined group set (staged, user-space) per window, drained before the
  next. `CLOCK_MONOTONIC_RAW` is read before the `START` and after the
  terminal wake. `start_per: run` makes one window of the whole campaign; it
  exists only under this load. The summary labels its throughput
  `gbytes_per_s_closed_loop_at_p50`.

How the session arm sees completions in the sustained load:

- Socket UMEM chains (every NIC chain) issue no `NOTIFY_ARM`. The eventfd then
  keeps the legacy one count per finished batch
  (`xdev_ext_mech_notify_locked`), and the process blocks on it (`observer`:
  `eventfd-count`).
- io_uring UMEM chains (`nvme-iaa-gpu`) start with `USER_FRAMES|RECYCLE`. The
  kernel holds every wake until such a `START` drains (`start_return_pending`),
  so the process polls `STATS` instead (`observer`: `stats-poll`). Those calls
  are reported as `observer_syscalls`, apart from the application's
  `syscalls`. Their CPU time is part of `getrusage`.

Other rules:

- Receivers' first interval includes waiting for the sender; the warmup
  records absorb it.
- In correctness mode, a STATS check after every closed window and (with
  `every_window`) the GPU window check run between windows, outside the
  interval. A timed session run skips the per-window STATS, so the system calls
  it reports are the application's own: per closed record one `NOTIFY_ARM`,
  one `START`, then `poll` and `read` on the eventfd. The final STATS still
  checks every batch. No checksum or hash of the payload runs inside a window.
- The NXP CRC32C is the wire protocol's, computed in the same place by every
  arm, with hardware CRC32C in every arm. The session's plan calls the kfunc
  `bpf_xdev_ext_frame_crc32c`, which calls the kernel's `crc32c()`
  (`xdev_ext_mech_ops.c`). On x86-64 that is `crc32c_arch` in
  `arch/x86/lib/crc32.c`: the SSE4.2 `crc32q` instruction, and three
  interleaved streams combined with PCLMULQDQ from 512 bytes on. The staged
  and user-space arms use `chain_crc32c_fast()` (`chain_crc.h`): `crc32q`,
  three interleaved 256-byte streams from 768 bytes on, combined through
  precomputed shift tables. Their result names the implementation in
  `wire_crc`; `table` means the CPU lacked SSE4.2 and the comparison is not
  fair. The byte-table `chain_crc32c()` is only the test oracle.
- After the campaign come the counter assertions: every stage completed every
  batch; no rejects, aborts or protocol errors. `published` counts frames whose
  custody went back to user space, not copies. A socket UMEM chain lends no
  frames, so it must publish none. An io_uring UMEM chain lends frames with
  every `START` and gets each of them back once the `START` drains
  (`xdev_ext_mech_frames_release`, `xdev_ext_mech_return_idle`), so
  `published` must equal the sum of `nr_user_frames` over the campaign's
  `START`s (`chain_counters_bad` in `chain_check.h`).
- Then one full readback is compared byte for byte. For a receiver, the
  readback is its NVMe window, read with `O_DIRECT`. For `nvme-iaa-gpu`, it is
  the GPU window: every written slot must hold exactly the group its first 8
  bytes name, no group may sit in two slots, and the newest groups must be
  present. Which slot a session batch uses is the kernel's choice: the free
  batch list is LIFO (`xdev_ext_mech_batch_put_locked` adds at the head,
  `xdev_ext_mech_batch_get_locked` takes the head), so a later batch can
  overwrite any finished group except the very last. The session check
  therefore requires only the last group. The staged arm puts group g in slot
  g mod depth and reuses a slot only after its group finished, so it requires
  the last min(depth, groups) groups.
- CPU payload copies are listed by source:
  - `afxdp-copy-mode`
  - `nvme-kvm-bounce` (the `xdev_ext_mech_bounces` counter of KVM_BOUNCE kernels)
  - `ce-sim-cpu-standin`
  - `iaa-deflate-generic-cpu`
  - `socket-receive-copy`
  - `staged-cpu-zlib`

  A timed session run lists the sources its spec declares (`declared`) and
  fails on any other. Only the E7 copy-mode ablation (`afxdp_mode: copy`)
  declares one, `afxdp-copy-mode`, so the zero-copy and copy variants are both
  timed and both report their copies. The CE simulator and deflate-generic are
  refused in timing mode. The staged arm reports its copies but is not
  required to have none.
- `getrusage` context switches, CPU time and the system calls the arm issued
  are recorded outside the measured part.
- A correctness-mode result carries no timing field at all.
- A timed spec started directly, without run.py's admission, is refused
  (exit 4) when `/sys/hypervisor/type` or the `/proc/cpuinfo` `hypervisor`
  flag shows a virtual machine (`chain_env_virtual`).

### Staged NIC leg

Two choices in `chain_staged.c` may make the staged arm weaker than the best
possible per-pair composition. Neither is measured yet.

- The receiver keeps exactly one `RECVMSG` outstanding, so every datagram costs
  one completion round trip through `io_uring_enter`. A multishot `RECVMSG`
  with a provided buffer ring, or batched receives, would amortise that. It
  was not used because each datagram must land at its own offset inside the
  slot, which a provided buffer ring does not express.
- The sender keeps one group's linked `SENDMSG_ZC` chain in flight at a time,
  so groups leave in order, and each send pins its payload pages again.
  `SEND_ZC` with `IORING_RECVSEND_FIXED_BUF` would use the registered buffer,
  but it sends one contiguous span. The NXP header would then have to sit
  right before each segment's payload in the registered buffer, which needs
  per-segment headroom in the staged buffers. That layout is not built.

Expected effect: per-datagram system call and page-pinning cost on the staged
side, which grows as segments get smaller. Read staged NIC results with that in
mind.

## Running

The rig file describes the host's devices; run.py never invents one:

```json
{"nvme_src": {"ng": "/dev/ng0n1", "block": "/dev/nvme0n1", "slba": 0, "nlb": 1048576, "lba_bytes": 512},
 "nvme_dst": {"ng": "/dev/ng1n1", "block": "/dev/nvme1n1", "slba": 0, "nlb": 1048576, "lba_bytes": 512},
 "tx": {"ifname": "eth0", "queue": 0, "mac": "02:00:00:00:00:01", "ip": "192.0.2.1", "port": 54321, "mtu": 1500},
 "rx": {"ifname": "eth1", "queue": 0, "mac": "02:00:00:00:00:02", "ip": "192.0.2.2", "port": 12345, "mtu": 1500},
 "ce": {"dev": "/dev/xdev_ext_ce_sim", "len": 2097152, "tx_va": 0, "rx_va": 2097152, "alloc": "given", "bdf": ""},
 "attached": ["nxp_nvme_ops", "nxp_afxdp_ops", "ce_plan_ops"],
 "plans": {"nxp": "/opt/xdev_ext/nxp_mech.bpf.o", "ce": "/opt/xdev_ext/ce_plan.bpf.o", "iaa": ".build/chain_plan.bpf.o"},
 "iaa_counts_pin": "",
 "nxp_session": 270019, "iaa_software": true, "rx_netns": "", "timeout_ms": 60000}
```

The fields that need explaining:

- `attached` lists the struct_ops plans already live system-wide. One plan per
  class is live at a time, so paired chains need every plan they use attached
  once. chain_bench loads a plan itself only when its class is not in this
  list. The KVM harness attaches `nxp_mech` (with `nxp_session=270019`) and
  `ce_plan`.
- `ce.len` is the size of each end's GPU window, starting at `tx_va` or `rx_va`.
  It must hold `depth` x `group_bytes`. When both ends run on this host
  through one CE device, the two windows must not overlap; run.py refuses
  overlapping windows.
- For a timed run, hardware_gate.py resolves `ce.dev` to its GPU the way
  `kernel/tools/xdev_ext_gpu_identity.c` does (`/dev/nvidiaN` with minor N,
  then `/sys/dev/char/MAJ:MIN/device` or the
  `/proc/driver/nvidia/gpus/<bdf>/information` entry with that minor) and
  refuses unless it is the GPU `ce.bdf` names.
- `iaa_counts_pin` is the bpffs path of `chain_counts` when `chain_iaa_ops`
  is attached system-wide (it is then in `attached`). chain_bench reads the
  IAA plan counters from it; with concurrent sessions they cover every
  session (`iaa_plan.scope`: `system-wide-pin`).
- `rx_netns` runs the receiver in a network namespace. The staged arm needs it
  when both ends are on one host, because otherwise the kernel delivers UDP to
  a local address over loopback.
- `--prepare-source` writes the expected bytes into the source window before
  the campaign. Each run uses a fresh seed, so stale bytes on the device cannot
  pass the comparison.

```sh
make CLANG=clang-21 bench bpf     # needs libbpf >= 1.0, libelf, zlib; LIBBPF_CFLAGS/LIBBPF_LIBS override
make check                        # host tests only

# KVM guest, CE simulator and deflate-generic: no timing is produced.
# Both loads run (closed and sustained) unless --load picks one.
python3 run.py --rig rig.json --chain nvme-gpu-nic,nvme-iaa-gpu,nvme-nic \
    --sizes 4096,65536,256K --arms session,staged --correctness-only --prepare-source

# Physical testbed: hardware_gate.admit() must pass first, otherwise exit 4.
python3 run.py --rig rig.json --chain nvme-gpu-nic --sizes 4K..4M \
    --arms staged,userspace-shared,session --pairs 5
python3 run.py ... --ablate afxdp-mode,start-per,plan          # E7
python3 run.py ... --sweep frame=4K..2M,pool=64M..64G,qd=1..256,sessions=1..64   # E10
python3 run.py ... --role sender --seed 7    # paired chains across two hosts
```

`--pairs N` repeats every case N times, alternating the arm order
(A B, B A, ...). `--sweep` changes one parameter at a time from the base; the
`qd` sweep runs under the sustained load unless `--load closed` is given.
`--dry-run` writes the specs without running anything.

Results go under `.results/<mode>-<time>/`. Each case has its own directory
with its specs and reference bytes. `campaign.json` holds every row and, for
timed runs, p50/p99/p999 and throughput per (chain, record size, arm, variant,
load).

Exit codes: 0 every case passed, 1 a case failed, 2 invalid arguments,
4 nothing was admitted. chain_bench itself uses the same codes. Its `--check`
and `test_chain_spec --validate` print the stage list a spec would create,
without opening a device.

## Files

- `chain_bench.c`: the entry point.
- `chain_session.c`, `chain_staged.c`: the two arms.
- `chain_spec.h`: the JSON spec, the catalog, validation and refusals.
- `chain_check.h`: the post-campaign counter assertions, the copy policy and
  the hypervisor check.
- `chain_timing.h`: record completions of the sustained load.
- `chain_crc.h`: the hardware CRC32C of the user-space arms.
- `chain_json.h`: the strict JSON subset.
- `chain_oracle.h`: expected bytes, CRC32C and the window checks.
- `chain_nxp.h`: NXP headers for user-space senders and receivers.
- `chain_cuda.h`: the CUDA driver API through `dlopen`.
- `uring_min.h`: raw io_uring.
- `chain_plan.bpf.c`: the IAA struct_ops plan.
- `run.py`, `hardware_gate.py`: the campaign driver and the physical admission.
- `test_chain_spec.c`, `test_run.py`: the host tests.

The AF_XDP socket helpers and the struct_ops loading in `chain_session.c` are
adapted from `kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl.c` at 8e0238a (git
blob `3ccfcf58fb2b85c5eef73e025f15d576c2a9c96c`). The IAA plan follows the
layout of `selftests/xdev_ext_mech/iaa_transform/iaa_pair.bpf.c`.

## Not yet verified

The runtime paths have been compiled with gcc and clang (`-Werror`) but have
not run against a session. These behaviours are still to be observed in the
guest:

- CREATE of the 3- and 4-stage lists;
- the sustained session path: one `START` of the whole campaign, the legacy
  per-batch eventfd counts, and STATS polling under `RECYCLE`;
- `published` equal to the frames lent, for `nvme-iaa-gpu` (inferred from
  `xdev_ext_mech_frames_release` and `xdev_ext_mech_return_idle`);
- AF_XDP RX feeding CE stages;
- IAA on a pool that also has `START` user frames;
- the staged `SENDMSG_ZC` notification order;
- `IORING_SETUP_COOP_TASKRUN` completions while spinning.
