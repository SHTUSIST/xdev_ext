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

## Cases

| Case | Requirement |
| --- | --- |
| `chain_same_worker` | four groups through two frames each, frames reused from the third group on; each READ issued by host 1's worker; after each NVMe completion the XDOMAIN stage of that batch is built by the same worker with no START in between; its TX descriptors, posted by the same worker, cover exactly the frames the READ filled and exactly the group's bytes; host 2's disk holds host 1's bytes in order (independent pattern of the disk address) |
| `reuse_waits_for_ack` | host 2's ACK held on the wire: no third READ, batch 1 frames out of the pool and still leased to the NHI; after release the reusing READ follows the first ACK and reuses batch 1's frames |
| `ack_before_local_done` | host 1's TX descriptor completions withheld: the ACK arrives, yet no reuse, frames stay leased; reuse only after both |
| `consumer_holds_ack` | host 2's NVMe WRITE withheld: no ACK leaves host 2 and host 1 does not finish; one ACK per group after the writes |
| `stale_ack_after_reuse` | after batch 3 occupies batch 1's frames, a copy of group 1's ACK is delivered through a real control RX descriptor: it is dispatched, finishes no batch, and the frames stay leased to group 3 until group 3's own ACK |
| `no_link_enodev` | an XDOMAIN stage whose token names no link: CREATE fails with `-ENODEV` |

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
performance. Session teardown (reap, DESTROY), polling stages and
per-stage program fds are outside this composition. A mutant that ran the
protocol inline in the NHI control-RX callback was not usable: the existing
stack fixture's lock-context assertion in `stack_x6.c` aborts first, so it is
not listed.
