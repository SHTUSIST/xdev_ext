# GPU<->NIC comparison arms

Scenario microbenchmarks that move data between a NIC and GPU memory in one
direction: ingest (NIC -> GPU, `--direction nic-gpu`) and egress
(GPU -> NIC, `--direction gpu-nic`). They are shaped like GPU-facing network
services; they are not those services. This directory contains code only; it
holds no measurement, and VM timings are not performance data.

| Arm | Program | Route |
| --- | --- | --- |
| `session` | `session_gpu_nic.c` | ingest `[AF_XDP RX, CE H2D]`, egress `[CE D2H, AF_XDP TX]`: one session on the AF_XDP socket's UMEM |
| `afxdp-cuda` | `afxdp_cuda.cu` | AF_XDP UMEM registered once with `cudaHostRegister`; per group one `cudaMemcpy2DAsync` (pitch `frame_size`) between UMEM chunks and the device slot plus one tail copy, on streams, completion by events |
| `udp-pinned-cuda` | `udp_pinned_cuda.cu` | UDP `recvmmsg`/`sendmmsg` scattering or gathering [header, payload at its group offset] into or out of `cudaHostAlloc` group buffers; one `cudaMemcpyAsync` per group on streams |
| peer | `nxp_peer.c` | the far end on an ordinary UDP socket: `send` feeds ingest, `recv` verifies egress |

## Can a copy-engine stage be the first or last stage?

The arms need sessions whose CE stage is the last (ingest) or the first
(egress) stage. `test_ce_stage_position.c` compiles the kernel's own
admission rules unchanged (`io_uring/xdev_ext_mech_step.h` for CREATE and
START, `net/xdp/xsk_xdev_ext_mech_core.h` for AF_XDP stages) and checks
`[AF_XDP RX, CE H2D]`, `[CE D2H, AF_XDP TX]`, `[NVMe READ, CE H2D]` and
`[CE D2H, NVMe WRITE]`, each with negative controls. All four are admitted;
`xdev_ext_ce_bind()` checks only the direction and flags. The CE class has no
transform flag, so a CE D2H first stage is a producer whose frames start
FREE. This covers admission only; binding, the BPF plans and completions
need the guest run.

## Shared contract

`gpu_nic_core.h` holds the logic every arm and the peer share; `test_core.c`
checks it.

- **Wire.** Every arm and the peer speak the NXP2 WRITE format of the
  session's `nxp_afxdp_ops` program, through the same
  `xdev_ext_mech_prog.h` functions (`xdev_ext_mp_tx_encode`,
  `xdev_ext_mp_rx_parse`, `xdev_ext_mp_rx_order`): Ethernet, IPv4, UDP, a
  40-byte header, CRC32C over header and payload. Every arm does the same
  per-packet protocol work, so the same peer serves all arms. The test checks
  that a baseline's packet passes the session's own RX parser.
- **Groups.** A message of `size` bytes travels as `size / group_bytes`
  groups; `group_bytes` is the largest power of two that is at most the
  message and at most 32 frames of the session layout for the link MTU
  (32768 bytes at MTU 1500). Group `g` is generation `g + 1` and carries
  block `g mod window_groups` of the `../nvme_gpu/nvme_gpu_core.h` payload.
- **Shapes.** `--sizes 64..4194304`, or `--shape ingest` (one microbatch of
  8 x 4096 int32 token ids with attention mask and labels, 393216 bytes) or
  `--shape egress` (one 4 MiB response).
- **GPU placement.** Every arm puts group `g` in device slot `g mod depth`
  (the session: the slot of the batch object carrying it). A message of
  several groups is therefore not contiguous in GPU memory in any arm. This
  is a kernel gap, not a missing plan program: `xdev_ext_ce_validate()`
  (`kernel/io_uring/xdev_ext_mech_ce.c`, lines 404-436 at main 8e0238a)
  takes the batch slot's offset from `xdev_ext_mech_window_offset()` (line
  425; `kernel/io_uring/xdev_ext_mech_window.h`, lines 13-24: `slot *
  group_bytes`) and returns `-ERANGE` (line 434) for any copy outside
  `[slot*group_bytes, (slot+1)*group_bytes)`. A CE plan that placed a group
  by its message offset would be refused by the kernel.
- **Copy calls.** Every baseline record carries `seg_len`, `frames`,
  `copies_per_group`, `copy_calls` (all CUDA copy calls of the campaign) and
  `fallback_groups`. `udp-pinned-cuda` copies each group with one call in
  each direction: `recvmmsg` scatters every datagram into its own 40-byte
  header buffer and its payload at the segment's offset in one contiguous
  pinned group buffer (a longer datagram is truncated and refused), and
  `sendmmsg` gathers the same two pieces. `afxdp-cuda` egress gives slot `s`
  the fixed UMEM chunks `[s*frames, (s+1)*frames)` and copies with one
  `cudaMemcpy2DAsync` of the full segments plus one copy of the shorter last
  segment (2 calls at MTU 1500: 22 x 1432 + 1264 bytes for a 32768-byte
  group). `afxdp-cuda` ingest uses the same 2D copy once a group is complete
  when its payloads sit at one pitch in consecutive chunks; when the NIC
  filled the group's chunks out of pitch it copies each segment and counts
  the group in `fallback_groups`. `run.py` checks
  `copy_calls == (groups - fallback_groups) * copies_per_group +
  fallback_groups * frames`.
- **Completion wait.** `--completion-wait block` (the default) makes the
  baselines sleep when nothing progressed: `cudaEventSynchronize` on
  `cudaEventBlockingSync` events for copies, `poll()` for UDP datagrams and
  AF_XDP RX data, and for AF_XDP TX completions a 50 us nap between
  completion-ring checks, because an AF_XDP socket has no TX-completion
  wakeup (`xsk_poll()`, `kernel/net/xdp/xsk.c` lines 1604-1635, reports only
  RX data and TX ring room). `poll` spins. The session always sleeps on its
  eventfd. Every record carries `completion_wait`; poll records have CPU
  fields close to the wall time by construction and are excluded from any
  CPU cost comparison.
- **Ingest oracle.** After the campaign every used device slot must hold one
  whole, distinct group block; unused slots keep the sentinel.
- **Egress oracle.** Slot `s` is seeded with block `s`; `nxp_peer recv
  --expect slots:DEPTH` checks every segment's protocol CRC, that every
  segment of a group is the same slot image, and that groups and segments
  arrive complete and in order. It derives the payload CRC from the protocol
  CRC it computes anyway (CRC32C is linear), so it makes no second pass over
  the payload.
- **Timed region.** Ingest: from the READY line on stderr (all setup done)
  to the last group's completion, which includes the sender's start; use
  campaigns much longer than that start-up, and the peer's `stream_ns` for
  the sender's view. Egress: from START or the first copy to the last TX
  completion (session: terminal wake).
- **CPU.** `cpu_us` is the process's user+system time; `host_busy_us` is the
  busy time of all CPUs from `/proc/stat`, which also counts the session's
  kernel worker and softirq work.
- **Exit codes.** 0 verified, 1 failure, 2 usage, 4 a missing capability,
  with `SKIP` on stderr and nothing on stdout. An ingest arm that exits 4
  before READY is recorded as a `not_run` cell with its SKIP reason.

The session arm needs `nxp_afxdp_ops` (`nxp_mech.bpf.o` with
`nxp_session` equal to `--wire-session`) and `ce_plan_ops` (`ce_plan.bpf.o`)
attached. With `/dev/xdev_ext_ce_sim` its record says
`execution=kvm-ce-sim`, `performance_claim=none`. A KVM correctness run uses
two linked guest interfaces with the peer in its own network namespace (UDP
between two local addresses never leaves the host stack): ingest runs
`session_gpu_nic --direction ingest` on one interface and `nxp_peer send` in
the namespace; egress runs `nxp_peer recv --expect slots:DEPTH` in the
namespace and `session_gpu_nic --direction egress` on the other interface.

## Build and run

```sh
make -C tests/eval/gpu_nic             # host builds: session arm and peer
make -C tests/eval/gpu_nic check       # host contract tests (peer over loopback UDP)
make -C tests/eval/gpu_nic cuda-build CUDA_ROOT=/usr/local/cuda   # needs an official SDK

python3 tests/eval/gpu_nic/run.py --direction nic-gpu --sizes 64..4194304 \
  --arms afxdp-cuda,udp-pinned-cuda,session --pairs 5 --ifname IF \
  --local-ip A --peer-ip B --peer-mac MAC --peer-exec "ssh peer-host" \
  --peer-binary /path/on/peer/nxp_peer --ce-dev /dev/nvidia0 --ce-alloc
```

`run.py` starts the listening side first (the arm for ingest, the peer for
egress), waits for its READY line, starts the other side, and validates both
records. The CUDA programs contain no device code; they build with `nvcc`
when found, otherwise with the host C++ compiler against the SDK headers and
`libcudart`. They have not been compiled against an official SDK in this
repository's checks.

Not here: GPUDirect RDMA (`nvidia-peermem`), DPDK `gpudev`, devmem TCP with
GPU memory and the NCCL network path, which the reviewer also listed, and a
per-message latency measurement inside the session.
