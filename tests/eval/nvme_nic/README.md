# NVMe↔NIC paired evaluation (reviewer E3)

This harness compares four ways of moving NVMe data to the network
(forward, NVMe→NIC) and network data to NVMe (reverse, NIC→NVMe) for unit
sizes 4 KiB–4 MiB and queue depths 1–128. It contains source and commands
only, with no measurements. Software and loopback results establish no
physical DMA or performance property.

| Arm | Forward (NVMe→NIC) | Reverse (NIC→NVMe) |
|---|---|---|
| `posix` | O_DIRECT `pread` of the unit, then UDP GSO `sendmsg` with header and payload iovecs; `qd` threads | `recvmmsg` into the unit buffer at each datagram's position, then O_DIRECT `pwrite`; one thread (`effective_qd=1`) |
| `uring` | `READ_FIXED` into a once-registered slot, then `SENDMSG_ZC` with `IORING_RECVSEND_FIXED_BUF` (registered vector) and GSO; slot reused only after every NOTIF; `ZC_COPIED` reports counted | `READV_FIXED` per datagram (header slot + payload position) into the registered slot, posted as `IOSQE_IO_LINK` chains of up to 256 receives, one chain at a time; then `WRITE_FIXED` of the unit, up to `qd` writes outstanding |
| `splice` | page-cache `splice` file→pipe→UDP socket per datagram, header `write` into the pipe; labelled buffered, page cache dropped for the window before each trial | none: a UDP socket cannot splice into a file (refused with exit 2) |
| `session` | xdev_ext session NVMe READ → AF_XDP zero-copy TX on shared UMEM pages, one START and one eventfd wake per trial | AF_XDP zero-copy RX → NVMe WRITE, XDP redirect of the peer's flow only, one wake per burst |

Every arm sends or receives the same datagrams. A unit of `size` bytes is
split into groups (the session batch: the largest power of two ≤ `size` and ≤
32 segments) and each group into datagrams of `seg` payload bytes, where
`seg = min(MTU−68, 3736)` rounded down to 8, which is the ctl tool's layout.
Each datagram carries the 40-byte NXP2 header (`xdev_ext_mp_tx_encode`) with a
zero checksum field. No arm and no receiver computes a per-datagram checksum.
The session policy `nnb_bench.bpf.c` is derived from
`kernel/tools/xdev_ext_mech/nxp_mech.bpf.c`. It drops the CRC32C, supports
multi-frame groups, and wraps NVMe slots modulo the window. Payload bytes are
splitmix64 of the window offset and seed, so every arm and trial moves
identical bytes.

Equal-work rules: every arm reads or writes the same window offsets in the
same order of generations and sends identical wire bytes to the same peer
port. The session's live batches are bounded by `XDEV_EXT_MECH_MAX_DEPTH=64`,
so the record carries `session_depth = min(64, qd × groups_per_unit)` and the
resulting `effective_qd`; nothing is capped silently. `effective_qd` is
rounded up to whole units, so every record also carries `inflight_bytes`, the
payload bytes the arm keeps in flight at most: `qd × size` for posix forward
and uring, `size` for the synchronous posix reverse loop (`effective_qd=1`),
`qd × seg` for splice (one datagram per thread in its pipe), and
`session_depth × group` for the session. At 4 MiB and qd 1 with a 1500-byte
MTU the session has 64 batches of 32 KiB, 2 MiB in flight, where the baselines
have 4 MiB; compare arms with this field, not with `effective_qd`.

The uring arm needs `SENDMSG_ZC` with fixed vectors and `READV_FIXED`. Both
are in the product 6.16-rc7 tree and were added upstream in Linux 6.15; that
release number is recalled, not checked against an upstream changelog here.
A probe cannot show the fixed-vector form of
`SENDMSG_ZC`, so both directions require `READV_FIXED`, and an older kernel,
including 6.1–6.14 with `SENDMSG_ZC`, refuses with exit 4 before any trial.
Reverse receives on one socket are linked because unlinked ones do not
complete in posting order. Each `READV_FIXED` that finds the socket empty arms
a non-exclusive poll entry at the head of the wait queue, so a wakeup reaches
the newest request first and it takes the oldest datagram. A linked request is
issued only after the previous one completed, so receive k of a chain takes
datagram k, and the next chain is posted only after the current one
completed. Receive concurrency on the socket is therefore one, while up to
`qd` unit writes stay outstanding. A short or failed receive cancels the rest
of the chain and fails the trial. This ordering follows from reading the
6.16-rc7 tree (`io_uring/opdef.c`, `io_uring/poll.c`, `io_uring/rw.c`); it has
not yet been run on a kernel that supports `READV_FIXED`.

The comparison does not include SPDK+DPDK, devmem TCP, or io_uring zero-copy
receive (`RECV_ZC`).

## Files

- `nnb_wire.h`: geometry, NXP2 header, generator and control messages
- `nnb_producer.c`, `nnb_uring.c`, `nnb_session.c`, `nnb.h`: producer and arms
- `nnb_peer.c`: C peer
- `nnb_bench.bpf.c`: session policy
- `run.py`: entry point
- `gate.py`: physical admission
- `results.py`: record validation and summaries
- `test_wire.c`, `test_bpf_body.c`, `test_latency.c`, `test_uring_shape.c`,
  `test_offline.py`, `test_loopback.py`: tests

## Timing and completion

The producer runs one configuration (direction, size, qd) per invocation. It
sets each arm up once, runs `--warmup` trials per arm, then `--pairs` pairs.
Within each pair the arm order is a seeded random permutation. Last comes one
integrity trial per arm. All timestamps come from `CLOCK_MONOTONIC_RAW` on the
producer.

- Forward `local_release_ns` runs from the first read to the local completion
  of every send of every unit. For posix that is `sendmsg` returning, for uring
  every result CQE and NOTIF, and for the session the eventfd wake followed by
  an exact `STATS` check. `receipt_ns` extends the same interval to the peer's
  count receipt, which is requested after the trial.
- Reverse `durable_ns` runs from the first `GO` to the completion of every
  unit's NVMe write. Units arrive in bursts of `qd` units. The peer's per-burst
  `SENT` receipt is read after the burst completes locally.
- `cpu_user_us` and `cpu_sys_us` cover the producer process only. Work in
  softirq context and in kernel workers is not attributed to the process, so
  these fields are not cycles per byte.
- Latency distribution: posix, splice and uring stamp every unit twice into
  arrays preallocated before the trial, which costs two clock reads per unit
  and no per-byte work. Forward, a unit's latency runs from its read being
  issued to its last send completing locally (for uring, its last result CQE
  and NOTIF). Reverse, it runs from the producer seeing the unit's first
  datagram to the unit's NVMe write completing. After the trial the producer
  checks that every unit has both stamps, then records nearest-rank
  `lat_min_ns`, `lat_p50_ns`, `lat_p90_ns`, `lat_p99_ns`, `lat_p999_ns` and
  `lat_max_ns`, with `lat_samples` equal to the unit count. Correctness and
  integrity records carry only `lat_samples`. Raw per-unit samples are not
  printed.
- The session arm has no per-unit latency: user space sees one eventfd wake
  per trial and `STATS` holds counters, not per-batch times. Its records carry
  `lat_samples=0`. A session latency mode, for example one notify target per
  batch at qd 1 or per-batch kernel timestamps, is not implemented.
- `window_passes` is how many times a trial covers the window. Each splice
  trial drops the window's page cache once before it starts, so when
  `window_passes` > 1 the later passes of a splice trial read the page cache,
  not NVMe. O_DIRECT arms are unaffected. Use a window of at least
  `units × size` for cold splice reads.

During timed trials the C peer only parses headers and sets one bit per
datagram. Its data socket has `UDP_GRO`, so one receive buffer carries a whole
GSO run (up to 64 KiB), which the peer splits at the GRO segment size; the
receipt reports the number of receive buffers as `peer_buffers`. The peer is
still a single receive thread and the forward direction is not paced, so above
the peer's receive capacity datagrams are lost and the trial fails with
`missing>0`, not with a result. Check `peer_buffers` and any failed
configurations before reading forward results at high rates. Duplicates, malformed datagrams, foreign datagrams and missing
datagrams are all counted, and every timed trial requires zero duplicates,
zero malformed and zero missing. The integrity trial has no timing fields. It
covers the whole window once and ends in one full byte compare against the
independent generator: forward, the peer reassembles the window; reverse, the
producer first fills the window with a poison pattern (untimed) and reads it
back with O_DIRECT afterwards. UDP loss and reordering fail the trial. They
are never retried or repaired.

## Software correctness (no timing)

```sh
make -C tests/eval/nvme_nic                 # posix, splice; uring/session refuse with exit 4
make -C tests/eval/nvme_nic check
python3 tests/eval/nvme_nic/run.py --correctness-only --loopback --arms posix,splice
python3 tests/eval/nvme_nic/run.py --correctness-only --loopback --direction rev --arms posix
```

`check` runs these host tests:

- `test_wire`: geometry, header and generator against the product's
  `xdev_ext_mech_prog.h` and ctl layout.
- `test_bpf_body`: the policy body as host C with stubbed kfuncs.
- `test_latency`: the producer's per-unit latency percentiles and missing-stamp
  refusal, plus one measured-format record printed by the real `run_trial`
  with synthetic stamps, which `test_offline.py` validates.
- `test_uring_shape` (`ENABLE_URING=1`): the reverse uring receive chain and
  the 6.15 probe, against a real ring whose receive SQEs are never submitted.
- `test_offline.py`: CLI, independent Python oracle, admission refusals and
  validator mutations.
- `test_loopback.py`: real producer and peer over 127.0.0.1, including the
  `--fault` negative cases, which must fail, a failed `pthread_create` partway
  through setup (exit 1, no hang), and peer GRO coalescing.  `make check`
  runs only `test_offline.py`; run `make loopback-check` on a dedicated host,
  because unpaced loopback UDP loses datagrams when the receive buffer fills
  and every loss is reported as an error.

`--correctness-only` without `--loopback` runs the same arms, the session arm
included, in a KVM guest against given devices and a peer, and emits no
timing.

## Physical measurement

Build on both hosts from the same pinned product commit. The producer needs
the strict kernel for the session arm. The peer may run a standard kernel.

```sh
make -C tests/eval/nvme_nic ENABLE_URING=1 ENABLE_SESSION=1
make -C tests/eval/nvme_nic hardware-bpf VMLINUX_BTF=/sys/kernel/btf/vmlinux   # producer
tests/eval/nvme_nic/.build/nnb_peer --control-bind CTL_IP:CTL_PORT --data-bind PEER_IP:PEER_PORT   # peer
python3 tests/eval/nvme_nic/run.py --direction fwd --prepare-window --allow-window-write \
  --sizes 4096..4194304 --qd 1,8,32,128 --arms posix,uring,splice,session --pairs 5 \
  --ifname IF --queue 0 --source /dev/nvmeXnY --ng /dev/ngXnY --slba SLBA --nlb NLB \
  --local-ip LOCAL_IP --local-mac LOCAL_MAC --peer CTL_IP:CTL_PORT --peer-ip PEER_IP \
  --peer-mac PEER_MAC --peer-port PEER_PORT
python3 tests/eval/nvme_nic/run.py --direction rev --allow-window-write ...   # same devices
```

`nlb × LBA` must be a multiple of 4 MiB. `--prepare-window` writes the
generator into the forward window once. Reverse runs overwrite the window, so
both need `--allow-window-write`. `--rate-mbps N` paces the peer's reverse
sending, at the same offered load for every arm.

`gate.py` observes the following before any workload, window write or peer
traffic, and refuses with exit 4 otherwise:

- positive DMI evidence and no hypervisor;
- a PCI NIC with a non-virtual driver;
- matching NVMe block and generic devices on PCI;
- a running kernel config with `CONFIG_XDEV_EXT_MECH_ZEROCOPY=y` when the
  session arm is selected;
- a local IP and MAC that belong to the NIC, and a peer that is not local;
- binaries built with the requested backends.

Each configuration prints one JSON line with the validated raw records, every
sample, the payload rate per sample, the per-unit latency percentiles of every
trial, `inflight_bytes`, `window_passes`, the uring `zc_copied/notifs`
fraction, and the session `xsk_zerocopy` flag. Paired ratios against `posix`
keep slower results.

The producer exits 4 only when an arm's setup fails with `EOPNOTSUPP`,
`ENODEV`, `ENOENT` or `ECONNREFUSED`, or when the peer or the prepared window
is unavailable before the first trial. Any other setup error, for example a
session `CREATE` rejected with `EINVAL`, exits 1.

## Provenance

- `nnb_producer.c` ports the three-arm read→send comparison idea from
  `archive/conduit-legacy/eval/benchmark-code/bench_pipeline.c`. That file is
  archived and untracked; sha256
  `0dbf6975ab9bb2b080f2d5c397504ce15943dbc84b78fb505c89a41884286204`, git blob
  `200250e0727986933f9773aed9eac09c7fc8b89d`. Its obsolete UMEM opcodes,
  in-loop printing and single reused buffer are not imported.
- The session setup adapts the AF_XDP, struct_ops and global-patching helpers
  of `kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl.c` (`nvme-nic` and
  `nic-nvme`) and of `tests/eval/hft/hft_session.c`.
- `gate.py` adapts `tests/eval/hft/hardware_gate.py`.

All references are at product HEAD `8e0238a`.
