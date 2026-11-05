# NVMe READ to XDOMAIN TX in one session worker

This host composition checks host 1's half of the "SSD on one machine, GPU
memory on the other, one Thunderbolt cable" chain without Thunderbolt
hardware: an NVMe READ fills frames; on that NVMe completion the same session
worker builds and submits the XDOMAIN stage, which sends exactly those frames
on the payload-only data ring with its RTS/CTS/ACK on the control ring; and a
source frame returns to the pool only after the peer's ACK and the local TX
completion. Host 2 receives into its own frames, writes them with an NVMe
WRITE, and acknowledges only after that write ends.

```sh
python3 tests/network/xdomain/chain/run.py --source-root "$SOURCE_ROOT" --output "$OUT"
ASAN_OPTIONS=detect_leaks=0 python3 tests/network/xdomain/chain/run.py \
  --source-root "$SOURCE_ROOT" --output "$OUT-sanitize" --sanitize
python3 tests/network/xdomain/chain/run.py --source-root "$SOURCE_ROOT" \
  --output "$OUT-mutant" --mutation NAME
```

Exit 0 means every selected case passed with a positive assertion count (or a
mutant was KILLED), 1 a behaviour failure (or a SURVIVED mutant), 2 a setup or
compile error. `--case NAME` selects one case. Leak detection is off in the
sanitizer run because sessions are never torn down in this composition.

## What runs, and what stands in

The runner assembles the native tree from `source-layout.json` in the output
directory and compiles one executable from these units:

| Unit | Production code compiled unchanged | Host boundary |
| --- | --- | --- |
| core | 105 functions of `io_uring/xdev_ext_mech.c` (the call-graph closure of the worker entry points: CREATE binds, buffers, PEER pool bind, START admission, run/acquire/build/submit, completion claim/publish/handoff, drain/landing, end/frame release, kick/progress, STOP), the compute transform hooks, the class registry of `xdev_ext_mech_ops.c` | kthread workers (one deterministic FIFO), per-class default program lookup, eventfd, tracepoints, allocation, the tail of CREATE after binding and the publication branch of START (flags 0) |
| pool | `io_uring/xdev_ext_mech_peer_pool.c` | pool claim returns a fixture authority file |
| NVMe | `drivers/nvme/host/xdev_ext_mech_nvme.c`, `io_uring/family/xdev_ext_storfam_block.c`, `xdev_ext_storfam.c`, plus `nvme_xdev_ext_peer_build_cmd` and `nvme_xdev_ext_mech_cmd_allowed`, `nvme_xdev_ext_capture_identity` | reduced NVMe host structures (`chain_nvme_host.h`), block request allocation; the controller model (below) |
| XDOMAIN | the existing stack fixture units: X3 main, X4 ring, X5 class, network family, X6 reference protocol program `xdomain_peer.bpf.c`, the probe unit, the NHI ring section of `drivers/thunderbolt/nhi.c` with MMIO/IRQ simulation | the stack environment (`stack_boundary.c`, `stack_nhi_boundary.h`) |
| programs | `nvme_s0.bpf.c` (NVMe build/complete) and `xdomain_peer.bpf.c`, called with the context `xdev_ext_mech_invoke()` builds | BPF verification/JIT and struct_ops are not run |
| boundary | | stage files, requester bind (records the requester; the real one is tested in `../dmabuf_requester`), lease provider, link byte copy, scheduler |

Seven environment edits of the stack fixture are made in the private copy and
listed in `fixture-edits.json` of each run: the family unit uses the real
core's `xdev_ext_mech_batch_session`; X6 builds the program context from real
batch accessors, reads the real session id, and gains a helper that runs the
NVMe program with the same kfunc views; the data-post record reads the real
session id and generation; the ring unit routes EARLY (v2) control dispatch
through a recorder as it already does for v1; and the real-NHI adapter, which copies no payload
in the stack tests, calls `chain_link_payload()` for each delivered data
frame. No production body and no existing assertion is edited.

Byte movement is the only thing the device models add. The lease provider
gives each requester (host 1 NVMe, host 1 NHI, host 2 NHI, host 2 NVMe) its
own DMA window, with the pages of the endpoint's frame memory at reversed
positions, so contiguity is never implied. The NVMe model reads the SGL of a
real submitted command and copies disk bytes to (READ) or from (WRITE) those
addresses; the link copies a delivered TX descriptor's bytes into the matched
RX descriptor's buffer. Every access must fall inside a live lease of that
device in the right direction, and no device may write bytes another live
lease covers; any violation fails the case.

## Host 1 frames from a system-heap DMA-BUF (`--pool dmabuf`)

With `--pool dmabuf`, host 1's frame memory is a system-heap DMA-BUF
registered through the real REGISTER ioctl and claimed by the real PEER pool
bind, and host 1's NVMe and NHI requester binds and every host 1 lease run
through the real requester bind, peer region core, DMA-BUF importer and peer
fd unit, compiled as in `../dmabuf_requester` (`chain_peer_bridge.c`). Those
units use the `tests/core/peer_dmabuf` kernel shim, whose `pci_dev` differs
from the other units', so each NVMe and NHI function gets a trusted, coherent,
unbounced twin there; the fake exporter's attachment for a twin maps the two
halves of the export at swapped positions of that device's window. Host 2
keeps the recording provider. The cases additionally require the real bind to
report host RAM with struct pages and an established host DMA mapping, and
every lease address to be the device's own attachment address; the
`dmabuf-lease-first-mapping` mutant (a lease uses whichever attachment came
first) is caught by `chain_same_worker`.

In this mode the two pages of each half are contiguous in the device window,
and the real NVMe SGL builder merges them into one 8 KiB data block; the
device models check such an access page by page.

## Host-page frames on both hosts (`--pool host`)

With `--pool host`, each endpoint's frame memory is its ring's IOU_UMEM pool
(obligation 42-XDOMAIN-HOST: the XDOMAIN class carries host pages, not only
PEER device memory). Production code added to the composition in this mode:

- the IOU_UMEM pool provider block of `io_uring/xdev_ext_umem.c`, from
  `struct io_xdev_ext_umem_mech` to `io_xdev_ext_umem_mech_pool_bind()`, with a
  fixture registration that stands in for `IORING_REGISTER_XDEV_EXT_UMEM`;
- `xdev_ext_mech_take_user_frames()`, through which START lends the UMEM
  frames (`USER_FRAMES | RECYCLE`; the admission and publication around that
  call follow `xdev_ext_mech_start()` in `chain_core.c.in`);
- the requester unit `io_uring/family/xdev_ext_requester.c`, compiled in the
  stack environment, which maps every pool page for each NHI. Its DMA API
  calls go to `chain_boundary.c`, which maps a page into that NHI's own window
  and records each map, unmap and sync. Both NHIs report that they need CPU
  synchronization, as a non-coherent controller would;
- the storage family's bio path for the NVMe stages. The NVMe model maps each
  bio piece into the controller's window when the request is submitted and
  unmaps it when the request ends, as nvme-pci does with the DMA API.

The family unit's calls to the requester's host bind, unbind, lease and
release go through `chain_boundary.c`, which forwards them unchanged, records
what the bind reported and keeps each granted element as a live NHI lease for
the device model. It also checks that the
address the requester returned is the NHI's mapping of exactly that pool page
and offset. After a run, the frames are back with user space (the START with
`RECYCLE` returns them when it drains), not in the kernel pool.

The eleven cases below run unchanged in this mode, with the requester checks
of `up()` replaced: an NVMe stage binds no requester (the block layer maps
each request), and each XDOMAIN stage binds its own NHI, whose bind reports
host RAM with struct pages and a host DMA-API mapping and maps every pool page
once, in the stage direction, without CPU sync. Five cases run only here:

| Case | Requirement |
| --- | --- |
| `host_sync_order` | every TX element is synchronized for the NHI after its lease and before its descriptor post; every RX buffer is synchronized for the NHI before its post and for the CPU after the link wrote it and before host 2's NVMe WRITE of that group is submitted; TX elements are never synchronized for the CPU; no mapping is unmapped while bound |
| `host_sync_order_early` | the same, with both XDOMAIN stages in EARLY mode |
| `host_unknown_retained` | host 1's TX descriptors never complete, then STOP: after the one-second STOP bound the batch ends with unknown device access, its frames are sequestered, its NHI host leases are retained, the NHI mapping is never unmapped, nothing is synchronized for the CPU, and the XDOMAIN stage's checked unbind returns `-EIO` |
| `host_misaligned_refused` | a UMEM registered 256 bytes into a page: CREATE fails with the requester's `-EINVAL` on both hosts and nothing is mapped |
| `host_destroy_unmaps` | four groups end quiesced, then each XDOMAIN stage is released in the order of the core's release decision (`chain_stage_unbind_now()`: the checked unbind, then the class unbind only when the checked unbind allowed it): the checked unbind allows release, and the class unbind, through the network family's fini, unmaps every pool page of that stage's NHI exactly once, with the page size, the stage direction and `DMA_ATTR_SKIP_CPU_SYNC` |

`host_run.py` is the same as `run.py --pool host`; the shared XDOMAIN host
runner (`tools/ci/check_xdomain_host.py`) runs it after `run.py`, because the
runner passes only `--source-root` and `--output` to an entry point.

## Cases

| Case | Requirement |
| --- | --- |
| `chain_same_worker` | four groups through two frames each, frames reused from the third group on; each READ issued by host 1's worker; after each NVMe completion the XDOMAIN stage of that batch is built by the same worker with no START in between; its TX descriptors, posted by the same worker, cover exactly the frames the READ filled and exactly the group's bytes; host 2's disk holds host 1's bytes in order (independent pattern of the disk address) |
| `reuse_waits_for_ack` | host 2's ACK held on the wire: no third READ, batch 1 frames out of the pool and still leased to the NHI; after release the reusing READ follows the first ACK and reuses batch 1's frames |
| `ack_before_local_done` | host 1's TX descriptor completions withheld: the ACK arrives, yet no reuse, frames stay leased; reuse only after both |
| `consumer_holds_ack` | host 2's NVMe WRITE withheld: no ACK leaves host 2 and host 1 does not finish; one ACK per group after the writes |
| `stale_ack_after_reuse` | after batch 3 occupies batch 1's frames, a copy of group 1's ACK is delivered through a real control RX descriptor: it is dispatched, finishes no batch, and the frames stay leased to group 3 until group 3's own ACK |
| `no_link_enodev` | an XDOMAIN stage whose token names no link: CREATE fails with `-ENODEV` |

Every case that moves data compares bytes at both ends against one oracle, a
pattern of host 1's disk byte address that the test computes itself. At host
1, the bytes the link read from host 1's frames for each TX element of group k
must be the bytes the k-th READ placed at those frame offsets (each frame
byte's position in the transfer comes from the READ's SGL order). At host 2,
the disk after the k-th WRITE must hold the k-th READ's bytes in order. The
link model keeps a copy of each delivered element for the first comparison and
checks nothing about content itself.

Each case except `no_link_enodev` also runs as `NAME_early`, with both
XDOMAIN stages in EARLY mode: the receiver grants buffers ahead, paired by the
batch key (both hosts START from the same first key), so the sender posts its
TX descriptors without an RTS/CTS round trip.

## Mutations

Each mutant changes production or reference-program lines in the private copy
so one claim becomes false, then runs the case that must catch it
(`--case NAME_early` runs the same mutant against the EARLY variant). KILLED
requires exit 1 and a named `CHAIN_ASSERT`; crashes, signals and compile
failures do not count.

| Mutant | Change | Caught by |
| --- | --- | --- |
| `publish-before-ack` | program and C gate publish TX without a remote ACK | `reuse_waits_for_ack` |
| `publish-before-local-done` | program and C gate publish TX before local completion | `ack_before_local_done` |
| `ack-before-consumer` | receiver marks the chain done at RX completion | `consumer_holds_ack` |
| `stale-ack-matches-reused-slot` | control lookup ignores the group number | `stale_ack_after_reuse` |
| `drain-in-completion-context` | the core continues an NVMe completion in the completion context | `chain_same_worker` |
| `tx-wrong-frame` | TX leases swap the two frames of a group | `chain_same_worker` |
| `dmabuf-lease-first-mapping` | (`--pool dmabuf`, set automatically) a host 1 lease uses the first attachment made, not its own device's | `chain_same_worker` |
| `host-release-always-quiesced` | (`--pool host`, set automatically, as for the rows below) the family releases a host lease as quiesced even after unknown device access | `host_unknown_retained` |
| `host-unbind-checked-passes` | the XDOMAIN checked unbind always allows release | `host_unknown_retained` |
| `host-no-device-sync` | the requester's lease no longer syncs for the device | `host_sync_order` |
| `host-no-cpu-sync` | a quiesced RX release no longer syncs for the CPU | `host_sync_order` |
| `host-post-peer-address` | the NHI descriptor takes the PEER lease field for every element | `chain_same_worker` |
| `host-lease-wrong-frame` | TX host leases name the other frame of the group | `chain_same_worker` |
| `host-peer-member` | an IOU_UMEM stage uses the PEER member, whose leases need a PEER authority | `chain_same_worker` |
| `review-fini-skips-host-unbind` | the network family's fini skips the host-page unbind, so a host-page stage takes the PEER unbind and its mapping is never unmapped | `host_destroy_unmaps` |

## Observation reported, not asserted

`chain_same_worker` prints `CHAIN_OBSERVE xdomain_groups_in_flight_max`. With
the current core and class it is 1: the XDOMAIN class is `F_ORDERED` without
`F_FIFO_ENQUEUE`, so `xdev_ext_mech_order_holds_ex()` keeps group N+1 parked
at the XDOMAIN TX stage while group N is in flight there, and group N leaves
that stage only after its ACK. The stack fixture's multiwindow case does not
show this because its core is a stand-in. This affects throughput only; the
cases do not assert it.

## Limits

Host software composition, not kernel execution: real kthread concurrency,
IRQ delivery, lockdep, RCU, BPF verification, IOMMU translation, PCIe ordering
and physical Thunderbolt DMA are not exercised, and nothing here measures
performance. The core's session teardown (reap, DESTROY) is outside this
composition: `host_destroy_unmaps` runs the class unbind of each XDOMAIN
stage in the order of `xdev_ext_mech_session_release_disposition()`, and the
core's own rule that a failed checked unbind quarantines the session without
a class unbind or pool release is checked in `tests/core/admission_report`.
Polling stages and per-stage program fds are also outside this composition. A mutant that ran the
protocol inline in the NHI control-RX callback was not usable: the existing
stack fixture's lock-context assertion in `stack_x6.c` aborts first, so it is
not listed.
