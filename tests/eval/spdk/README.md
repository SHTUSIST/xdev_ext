# SPDK NVMe -> TCP pipeline arm

A native SPDK comparison arm: queue depth 1 raw namespace read with the
official SPDK user-space NVMe driver, an optional little-endian uint64 sum
over the first `--calc-bytes` of each block, then a send of the block over a
loopback TCP connection to a receiver thread. It is the SPDK row next to the
kernel paths of `../nvme_nic` and `../gds`. No result from this directory has
been produced yet: the native modes need a built SPDK and an isolated,
userspace-bound NVMe namespace, and no VM timing is performance data.

## Modes

| Mode | What runs | Device |
| --- | --- | --- |
| `plan` | prints the read schedule (`scheduled_lbas`) as one JSON line | none |
| `offline-check` | a regular reference file feeds the same TCP producer and receiver; every received byte is compared afterwards | none, no SPDK |
| `native-correctness` | official SPDK reads, the TCP producer and receiver, full byte comparison afterwards; no timing | the named namespace |
| `native-performance` | as above, plus `measured_ns` from the first measured read to the delivery of the last measured byte | the named namespace, not in a VM |

Every mode needs `--traddr DDDD:BB:DD.F`, `--nsid`, `--sector-size` (512 or
4096), `--namespace-lbas`, `--start-lba` and `--window-lbas`; there is no
default device and no "first active namespace". Read `i` of the campaign
(warmup included) reads LBA `start_lba + slot(i) * block/sector` where
`slot(i)` is the original unsigned xorshift* sequence modulo the number of
whole blocks in the window. The reference file holds exactly the window's
bytes; it is read only after the campaign, to check the capture, and its
SHA-256 is recorded once before the first read. The namespace is never
written. The capture must be a new file.

Both native modes need `--ack-isolated-read-only` and `--spdk-root DIR` (a
built official SPDK tree); `native-performance` also needs
`--allow-performance`. Before any native binary runs, `run.py` checks, in
this order: the arguments and gates, the reference and capture, the SDK
(headers and `build/lib/pkgconfig/spdk_nvme.pc`), and the target. The target
check (`native_prerequisites()`) is read-only: the PCI function exists, has
the NVMe class, is already bound to `vfio-pci` (with an accessible
`/dev/vfio/<group>`) or `uio_pci_generic`, free hugepages exist and a
hugetlbfs is mounted. Nothing is bound, unbound, reserved or loaded by this
directory; prepare the device with SPDK's own tools before, outside it.

Exit codes: 0 pass, 1 runtime/integrity failure or an UNKNOWN command,
2 invalid input or missing gate, 4 unavailable SDK, device, namespace,
permission or prerequisite. A failure prints its reason on stderr and
nothing on stdout.

## Native ownership rules

`spdk_owner.h` is the state of the one outstanding read; `test_owner.c`
checks it on a host.

- A submission that returns 0 is accepted exactly once; a negative return is
  not accepted and never replayed.
- The buffer is reused only after the read's callback ran inside a
  completion poll that returned >= 0 while the qpair had no failure reason
  and the controller was not failed. A callback while the transport failed
  (the library may complete requests in software then) proves nothing, and
  a failed transport stays unproven.
- The controller is attached with `transport_retry_count = 0`. On PCIe the
  library otherwise resubmits a read whose completion it classifies as
  retryable (`lib/nvme/nvme_pcie_common.c`, `pqpair->retry_count`), which
  would replay an accepted read.
- At the deadline the read is UNKNOWN. The program requests an abort and
  polls for one more second. Without a healthy completion it becomes the
  quarantine owner: it prints `SPDK_PIPELINE_UNKNOWN pid=...` on stderr,
  closes its output, keeps the DMA buffer, qpair, controller and SPDK
  environment, and keeps polling until the read completes. `run.py` then
  returns 1 without waiting for or killing it. Killing that process gives up
  the DMA safety: the controller may still write the buffer's pages. If the
  controller has failed, this program cannot prove quiescence at all; that
  takes a controller reset, which is outside its remit.
- A known-idle run releases in reverse order (DMA buffer, qpair, controller,
  environment) and checks each return value.

The environment allowlist holds exactly `--traddr`, `shm_id = -1` gives a
private file prefix and `--no-shconf` (no shared primary process), and
`spdk_nvme_connect()` attaches only that controller. The namespace must be
active, use the NVM command set, have no metadata or protection
information, and match `--sector-size` and `--namespace-lbas` exactly;
otherwise the run stops before the first read.

## Build

```sh
make -C tests/eval/spdk check                     # host tests, no SDK
python3 tests/eval/spdk/build.py --print-commands --build-dir /abs/private/dir
python3 tests/eval/spdk/build.py --fetch-sdk --build-dir /abs/private/dir --jobs 8
python3 tests/eval/spdk/run.py --mode native-correctness --traddr 0000:5e:00.0 --nsid 1 \
  --sector-size 4096 --namespace-lbas N --start-lba S --window-lbas W \
  --reference window.bin --capture new.bin --spdk-root /abs/private/dir/spdk \
  --ack-isolated-read-only
```

`--fetch-sdk` clones SPDK `v25.05.1` (commit
`44b23be7c35469bc0aba4b942c08c935125e2315`, checked after the clone) with
the `dpdk` and `isa-l` submodules into `DIR/spdk`, configures it without
tests, examples, apps, shared libraries, FUSE/NVMe-CUSE and optional modules, builds it, and
links the arm the way SPDK's `doc/pkgconfig.md` links the static nvme
library (`--whole-archive -Bstatic` around `pkg-config --libs spdk_nvme
spdk_env_dpdk`, then `pkg-config --libs --static spdk_syslibs`). `DIR` must
be absolute, outside the repository, and absent or a mode-0700 directory of
the caller. SPDK's build prerequisites must already be installed: the
script never runs `scripts/pkgdep.sh`, so a missing prerequisite ends with
exit 4 and the log `DIR/spdk-build.log`. `run.py` builds the arm again for
each native run into a temporary directory, outside any timing.

`test_native.py` checks the native body's structure, the ownership state
machine, the build commands and refusals, and the target admission against a
fabricated sysfs tree. With `SPDK_INCLUDE_DIR` set to the `include/`
directory of an official checkout at the pinned tag, it also compiles the
native body with `-fsyntax-only` against those headers. None of this links
SPDK or touches a device; linking and the first native run are done on the
server.

## Origin and changes

Ported from the author's `archive/eval-legacy/bench_spdk_nvme_pipeline.c`
(raw SHA-256 `a11c028d94ab62d1f42059aa9e2ffdd8ba0e7aa14c1ed9535e73fd4fb2e6dd69`,
Git blob `900a53e8f906cf1bffb53f8f0604d9f9e0a0b11c`; the original file has no
licence notice and this note grants none). Kept: the QD1 read -> calculation
-> send loop, the xorshift* slot sequence bit for bit, the warmup, one DMA
buffer reused by every read, the single-core environment (`core_mask 0x1`),
the 4 MiB TCP send buffer and TCP_NODELAY. Changed, and why:

- Device selection: positional arguments with a default address and "first
  active namespace" became required, strictly parsed options; probe with a
  callback filter became an exact-address environment allowlist plus
  `spdk_nvme_connect()`.
- `opts_size` is set before `spdk_env_opts_init()`, which reads it (the
  original set it afterwards). The original's fixed 1024 MiB `mem_size` is
  left at SPDK's default.
- The window starts at `--start-lba` instead of LBA 0 and is given in LBAs;
  the namespace geometry is checked, not just the sector multiple.
- Completion: the original spun on a `volatile` flag with no deadline and
  ignored the polling result; now the owner state machine above.
- TCP: a fixed port, a 10 ms sleep to assume the receiver was ready, one
  `send` assumed complete and a byte counter stopped by a `volatile` flag
  became a private port-0 listener, bounded full send/receive loops, a
  delivery barrier and end-of-file.
- Timing: the original timed from the send of the last warmup block to the
  send of the last block. `native-performance` times from just before the
  first measured read (after the warmup bytes were delivered) to the
  delivery of the last measured byte, and reports nanoseconds instead of
  printing us/op and MiB/s.
- The calculation sums little-endian words and is reported (`calc_xor`) and
  checked, instead of feeding a `volatile` sink. The DMA buffer has 4 KiB
  guards on both sides; guards, every byte and the calculation are checked
  after the campaign, never inside it.
- The `uname -r` call through `system()` and unchecked cleanup are gone.
