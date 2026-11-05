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

## In-flight window

Each XDOMAIN stage takes a window W in bits 32..63 of its `arg1` (the low half
stays the data channel). The five data cases above also run as `NAME_w2` and
`NAME_w4` (and `NAME_w2_early`, `NAME_w4_early`): both stages get window N,
depth max(2, N) and two frames per group, and every expectation is the same
requirement scaled to that depth; with every ACK, TX completion or consumer
held, the sender must fill its window. Further cases:

| Case | Requirement |
| --- | --- |
| `window_fills_w2`, `window_fills_w4` | depth W+2, host 2's NVMe WRITE held: host 1 reaches exactly W groups in flight at its XDOMAIN stage and host 2 holds exactly W; group W+1 is not announced; in ordinary mode all of this happens with no virtual time passing (no protocol or worker timer); after the release every group arrives in order |
| `window_waits_for_receiver` | sender window 4, receiver window 2: host 1 has in flight what host 2 holds plus one announced group (ordinary) or exactly what host 2 holds (EARLY, no grant yet for the next group) |
| `window_refills_receiver` | host 2's data completions held while host 1 already announced group 2; once released, group 1 moves on and group 2 is posted at host 2 in the same drain, without a timer |
| `window_next_after_cts` | host 2's CTS held until host 1 read ahead into every batch: only group 1 is announced; once the CTS is processed host 1 fills its window in the same drain (ordinary only) |
| `window_stop_unknown` | window 2, host 1's TX completions and host 2's ACKs held, STOP of host 1 with both groups in flight: past the 1 s stop grace neither group is reported delivered, no frame of either group returns to the pool or the application, not even after the held completions run late, and nothing is leased over retained bytes |
| `window_withdrawn_head` | host 2 not started: host 1's announced group 1 is withdrawn at 15 s and refused; host 2 starts right after the refusal; host 2 must write nothing, host 1 posts no data and reports neither group delivered (ordinary only) |

Every scheduler step checks: host 1 never has more groups in flight at its
XDOMAIN stage than its window, host 2 never has more than one group in its RX
stage (one posted group, version 1), and host 2 never holds more groups than
its window. `finished()` also checks receive-side credit on the record of real
data-ring posts: host 1 posts a group's data only after host 2 posted receive
buffers for that group, and host 2 posts the next group's buffers only after
every earlier buffer was filled.

A window of 1 must behave exactly as no window: without `--case`, the runner
runs each default case and its `NAME_w1` twin with `CHAIN_TRACE=1` and requires
the same event lines (a worker event's function address, which ASLR moves,
replaced by its order of first appearance); `w1_identity` in `result.json`
records both hashes.

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
| `window-release-at-announce` | the XDOMAIN class lets the next group pass once the previous one is announced, not once its data post was accepted | `window_withdrawn_head` |
| `window-bound-ignored` | the core no longer counts the window | `window_fills_w2` |
| `window-rx-released` | RX batches are released like TX ones (a second batch enters the RX stage) | `window_fills_w2` |
| `window-no-progress-kick` | no re-check of the ordered stage after a class pass | `window_next_after_cts` (also `window_refills_receiver`) |
| `window-bind-ignored` | the class accepts the window but does not hand it to the core | `window_fills_w2` |
| `stop-unknown-reused` | at link teardown a TX slot whose native completion is unknown is published as quiesced (existing rule) | `window_stop_unknown` |

The existing mutants are also killed on the window variants
(`--case NAME_w2`, `NAME_w4`, `NAME_w2_early`, `NAME_w4_early`).

## Observations

`chain_same_worker` prints `CHAIN_OBSERVE xdomain_groups_in_flight_max` (RTS
arrivals at host 2 minus ACK arrivals at host 1) and the peaks of groups in
flight at host 1's XDOMAIN stage and held by host 2. Without a window (or with
window 1) it is 1: the XDOMAIN class is `F_ORDERED`, so the next group waits
at host 1's XDOMAIN stage until the previous group's ACK, and the next group
enters host 2's RX stage only when the previous one ended its NVMe WRITE. The
cases assert it never exceeds the window; the `window_*` cases assert that it
reaches the window. Nothing here is a performance number.

## Limits

Host software composition, not kernel execution: real kthread concurrency,
IRQ delivery, lockdep, RCU, BPF verification, IOMMU translation, PCIe ordering
and physical Thunderbolt DMA are not exercised, and nothing here measures
performance. Session teardown (reap, DESTROY), polling stages and
per-stage program fds are outside this composition. A mutant that ran the
protocol inline in the NHI control-RX callback was not usable: the existing
stack fixture's lock-context assertion in `stack_x6.c` aborts first, so it is
not listed.
