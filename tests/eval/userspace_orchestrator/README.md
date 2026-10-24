# User-space shared-region baseline (reviewer E2)

Follow the [evaluation policy](../PERFORMANCE_POLICY.md) for baseline changes, comparison eligibility and performance claims.

The question this baseline answers: what does the kernel-owned lifecycle buy
over one user process that registers the same memory with every subsystem and
sequences the stages itself? `uo_bench` is that process. Nothing here has been
timed yet; physical devices are required, and the guest correctness run is
still to be done.

## What it does

`uo_bench` maps one 16 MiB region in 2 MiB hugepages. That is 4096 chunks of
4 KiB, the same pool size the session arm's AF_XDP socket uses. The region is
registered three times:

- as the AF_XDP UMEM (`XDP_UMEM_REG`, the socket bound zero-copy or copy as
  requested, never downgraded);
- as io_uring fixed buffers (`IORING_REGISTER_BUFFERS`);
- in a `UO_CUDA=1` build, with `cuMemHostRegister`. CUDA is loaded with
  `dlopen("libcuda.so.1")`, so no CUDA SDK is needed to build it.

Slot `k` of `depth` owns chunks `[k * F, (k + 1) * F)` for a group of `F` NXP
segments. Each segment's payload sits at the NXP header room inside its chunk,
with the 82 header bytes right before it, so a chunk is ready to transmit as it
is.

The sender (`nvme-nic`, `nvme-gpu-nic`) does, per group:

1. One vectored NVMe passthrough `uring_cmd` (`NVME_URING_CMD_IO_VEC`) on
   `/dev/ngXnY`, whose I/O vectors are the payload spans of the slot's chunks.
2. With a GPU, H2D then D2H of every span on the slot's stream, in place.
3. The NXP header with its CRC32C written in each chunk's headroom, then the
   segments on the AF_XDP TX ring in group order, then one `sendto` kick.
4. When the completion ring returns every chunk of the slot, the slot is free.

The receiver (`nic-nvme`, `nic-gpu-nvme`) installs an XDP redirect for the
peer's flow. It parses each RX descriptor with the session's own receive check
(`xdev_ext_mp_rx_parse`, then the NXP CRC). It requires the next segment of
the group it is collecting, as the session's receiver does. Then come the
optional GPU round trip and one vectored passthrough WRITE of the received
spans, and the chunks go back to the fill ring.

Datagrams are byte-compatible with the session's AF_XDP plan
(`../chains/chain_nxp.h`, checked in `test_uo_core.c`). So `uo_bench`
interoperates with session or staged peers.

`nvme_io: read-fixed` uses `READ_FIXED`/`WRITE_FIXED` on the `O_DIRECT` block
device, one per segment. It is refused for the NXP layout at MTU 1500: 1432-byte
segments at offset 360 are neither whole LBAs nor LBA-aligned.

The passthrough SQEs retain per-command user-vector import and do not request
`IORING_URING_CMD_FIXED`. Registration above describes setup; the `read-fixed`
mode selects the registered buffers. The passthrough zero-copy qualification
remains the SGL condition below.

The vectored passthrough path needs an NVMe controller with SGL support. That
is the same requirement the session's NVMe class has in ZEROCOPY builds. On
such a controller the queue has no virt boundary, and 4-byte-aligned vectors
map without a copy. Without SGL support, `blk_rq_map_user_iov`
(`kernel/block/blk-map.c`) would bounce the data through kernel pages. That
bounce cannot be seen from user space, and `uo_bench` does not detect it.

## Loads

- `load: closed` admits one record (`burst` groups), drains it, and times the
  interval; the next record starts after that.
- `load: sustained` admits the whole campaign at once. Up to `depth` groups
  stay in flight, and every record's completion time goes into an array
  allocated before the campaign. A record counts as complete when
  (r + 1) x `burst` groups have finished, the same rule the session arm uses
  (`../chains/chain_timing.h`). run.py reports the campaign's bytes over its
  wall time as throughput, and the gaps between record completions as
  p50/p99/p999. Timed runs default to this load.

## Waiting and costs

- `--wait poll` spins on the io_uring completion ring and the AF_XDP rings. The
  ring is created with `IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG`,
  so the process enters the kernel only when `IORING_SQ_TASKRUN` says
  completion work is waiting for it.
- `--wait eventfd` registers an eventfd with the ring and blocks in `poll()` on
  it and on the socket (`POLLIN` for receive). AF_XDP has no wakeup for its TX
  completion ring. A sender with only transmits outstanding therefore spins
  on that ring in this mode too. The 1 ms `poll()` timeout is only a fallback.
- The result reports the system calls this process issued during the
  campaign, wakeups, and `getrusage` voluntary and involuntary context switches
  and user/system CPU time. All of these are taken outside the timed windows.
  It also reports the CPU bytes read for the NXP CRC; this CRC is the wire
  protocol's, and the session computes the same one in its BPF plan. Both use
  hardware CRC32C: the session's kfunc calls the kernel's `crc32c()` (on
  x86-64 the SSE4.2 `crc32q` instruction, three interleaved streams from
  512 bytes on), and this process uses `chain_crc32c_fast()` of
  `../chains/chain_crc.h` (`crc32q`, three interleaved 256-byte streams,
  combined through precomputed shift tables). The result's `wire_crc` field
  names the implementation that ran; `table` means the CPU lacked SSE4.2.
- A timed spec started directly, without run.py's hardware admission, is
  refused (exit 4) when `/sys/hypervisor/type` or the `/proc/cpuinfo`
  `hypervisor` flag shows a virtual machine.
- `run.py --loc` prints the application lines of code each arm needs: this
  data path, against the session arm's configure/START/wait code.

## Running

`run.py` is a front end of `../chains/run.py` with the `userspace-shared` arm,
the same rig file, pairing, oracle, hardware admission and exit codes:

```sh
make bench                    # UO_CUDA=1 for the GPU chains; libbpf, libelf, zlib
make check                    # host tests only
python3 run.py --rig ../chains/rig.json --chain nvme-nic --wait poll,eventfd \
    --depth 1..64 --sizes 4096..65536 --correctness-only --prepare-source
python3 run.py --rig rig.json --chain nvme-nic,nvme-gpu-nic --wait poll,eventfd \
    --depth 1..64 --sizes 4096..4194304 --with-session --pairs 5
```

- `--depth` takes a power-of-two list or range. The first value is the base;
  the rest form a depth sweep.
- `--with-session` adds the session arm to the same cases.
- Depths above 64 are refused. 64 is the session's `XDEV_EXT_MECH_MAX_DEPTH`,
  and the two arms are compared at equal depth.
- Hugepages must be reserved (`vm.nr_hugepages` of at least 8). Otherwise
  uo_bench exits 4.

Not implemented, and refused with exit 4:

- IAA chains: user-space IAA needs QPL or accel-config.
- `nvme-crc-nic`: the session side has no in-frame transform to compare with.

## Not yet verified

The program compiles with gcc and clang (`-Werror`, with and without
`UO_CUDA`). Its spec, frame map, passthrough command and wire format are host
tested. No run against devices has happened yet.
